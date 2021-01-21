all: ssl_write_test

ssl_write_test: ssl_write_test.c
	$(CC) -pthread $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) ssl_write_test.c -o ssl_write_test $(LDLIBS) -lssl -lcrypto
