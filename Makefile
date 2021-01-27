all: ssl_write_test ssl_server_for_testing

ssl_write_test: ssl_write_test.c
	$(CC) -pthread $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) ssl_write_test.c -o ssl_write_test $(LDLIBS) -lssl -lcrypto

ssl_server_for_testing: ssl_server_for_testing.c
	$(CC) -pthread $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) ssl_server_for_testing.c -o ssl_server_for_testing $(LDLIBS) -lssl -lcrypto
