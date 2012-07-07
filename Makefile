NDK=/opt/android-ndk

CC=arm-linux-androideabi-gcc
CFLAGS=-Wall -I$(NDK)/platforms/android-8/arch-arm/usr/include
LDFLAGS=--sysroot=$(NDK)/platforms/android-8/arch-arm

all: dnsforward

dnsforward:

clean:
	rm -f dnsforward
