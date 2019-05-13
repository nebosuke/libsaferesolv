CFLAGS  = -D_GNU_SOURCE -Wall -std=c99 -O2 -fPIC -shared -lrt -ldl -lpthread -fvisibility=hidden
LIBS = libsaferesolv.so
CC = gcc

all: $(LIBS)

libsaferesolv.so: safe_resolv.c safe_resolv.version
	$(CC) $(CFLAGS) -ldl -Wl,--version-script=safe_resolv.version -o $@ $<

clean:
	$(RM) $(LIBS)
