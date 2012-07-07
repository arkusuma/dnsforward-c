#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LOCK_FILE "/tmp/dnsforward.pid"

struct GLOBAL {
	char *server;
	char *port;
	char *lock;
	int type;
	int server_sock;
	struct addrinfo server_info;
} G;

#define exit_error(str) do { \
	fprintf(stderr, "%d: ", __LINE__); \
	_exit_error(str); \
} while (0)

void _exit_error(const char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

void daemonize() {
	pid_t pid, sid;

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);
	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);

	sid = setsid();
	if (sid < 0)
		exit(EXIT_FAILURE);

	if (chdir("/") < 0)
		exit(EXIT_FAILURE);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	
	/* Ensure only one copy */
	int fd = open(G.lock, O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		syslog(LOG_INFO, "Could not open PID lock file %s, exiting", G.lock);
		exit(EXIT_FAILURE);
	}

	/* Try to lock file */
	struct flock fl = { F_WRLCK, SEEK_SET, 0, 0, 0 };
	if (fcntl(fd, F_SETLKW, &fl) < 0) {
		syslog(LOG_INFO, "Could not lock PID lock file %s, exiting", G.lock);
		exit(EXIT_FAILURE);
	}

	/* Get and format PID */
	char str[12];
	sprintf(str, "%d", getpid());
	write(fd, str, strlen(str));
}

#define TIMEOUT 2

void resolve(const void *buf, int len, struct sockaddr *from, int fromlen) {
	struct addrinfo *res;
	unsigned char rbuf[512];
	int rlen;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		exit(EXIT_FAILURE);
	if (pid > 0)
		return;

	res = &G.server_info;
	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0)
		exit_error("socket");

	// Setup alarm for connect()
	signal(SIGALRM, SIG_IGN);
	alarm(TIMEOUT);
	if (connect(sock, res->ai_addr, res->ai_addrlen) < 0)
		exit_error("connect");
	alarm(0);

	// Setup timeout for send() and recv()
	struct timeval tv;
	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		exit_error("setsockopt");
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
		exit_error("setsockopt");

	// Forward request to server
	if (G.type == SOCK_DGRAM) {
		if (send(sock, buf, len, 0) < 0)
			exit_error("send");
		if ((rlen = recv(sock, rbuf, sizeof(rbuf), 0)) < 0)
			exit_error("recv");
	} else {
		rbuf[0] = len >> 8;
		rbuf[1] = len;
		memcpy(rbuf + 2, buf, len);
		if (send(sock, rbuf, len + 2, 0) < 0)
			exit_error("send");
		if (recv(sock, rbuf, 2, MSG_WAITALL) < 0)
			exit_error("recv");
		rlen = (rbuf[0] << 8) + rbuf[1];
		if (recv(sock, rbuf, rlen, MSG_WAITALL) < 0)
			exit_error("recv");
	}
	close(sock);

	// Forward reply to client
	if (sendto(G.server_sock, rbuf, rlen, 0, from, fromlen) < 0)
		exit_error("sendto");

	exit(EXIT_SUCCESS);
}

void signal_handler(int sig) {
	wait(NULL);
}

void start_server() {
	struct addrinfo hints, *res;

	signal(SIGCHLD, signal_handler);

	// Get remote server info
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = G.type;
	if (getaddrinfo(G.server, G.port, &hints, &res) != 0)
		exit_error("getaddrinfo");
	memcpy(&G.server_info, res, sizeof(*res));

	// Get local server info
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
 	if (getaddrinfo(NULL, "53", &hints, &res) != 0)
		exit_error("getaddrinfo");

	G.server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (G.server_sock < 0)
		exit_error("socket");

	if (bind(G.server_sock, res->ai_addr, res->ai_addrlen) < 0)
		exit_error("bind");

	//daemonize();

	for (;;) {
		unsigned char buf[512];
		struct sockaddr_storage from;
		int fromlen, len;
		fromlen = sizeof(from);
		if ((len = recvfrom(G.server_sock, buf, sizeof(buf), 0,
						(struct sockaddr *) &from, &fromlen)) < 0)
			exit_error("recvfrom");

		resolve(buf, len, (struct sockaddr *) &from, fromlen);
	}
}

int main(int argc, char **argv) {
	if (argc < 4) {
		fprintf(stderr, 
				"Usage: dnsforward <server> <port> <type> [lock]\n"
				"Where:\n"
				"  server: IP address of remote DNS server\n"
				"  port:   remote DNS port\n"
				"  type:   server type, udp or tcp\n"
				"  lock:   lock file, will contain PID\n");
	}

	G.server = argv[1];
	G.port = argv[2];
	G.type = !strcmp("udp", argv[3]) ? SOCK_DGRAM : SOCK_STREAM;
	G.lock = argc > 4 ? argv[4] : LOCK_FILE;

	start_server();
	return 0;
}
