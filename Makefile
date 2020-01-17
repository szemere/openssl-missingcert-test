all: tls13test

tls13test: tls13test.c
	$(CC) -pthread $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) tls13test.c -o tls13test $(LDLIBS) -lssl -lcrypto
