#include <stdio.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433
#define ADDRESS "127.0.0.1"

#define EXPIRED_CRT_FILE "/tmp/client_expired.crt"
#define KEY_FILE "/tmp/client.key"

void sleep_1msec()
{
    struct timespec ns = { .tv_sec = 0, .tv_nsec = 1000000};
    nanosleep(&ns, NULL);
}

int connect_to_server(const char *address, int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    inet_pton(AF_INET, address, &addr.sin_addr);

    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("Unable to connect");
            exit(EXIT_FAILURE);
        }
    }

    return s;
}

SSL_CTX *create_ssl_context(const SSL_METHOD *method)
{
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx)
{
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_num_tickets(ctx, 0);

/*
    if (SSL_CTX_use_certificate_file(ctx, EXPIRED_CRT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
*/
}

void try_sending_512bytes(SSL *ssl)
{
    const size_t buf_size = 512;
    char buf[buf_size];
    memset(buf, 'z', buf_size);

    while (1) {
        int w = SSL_write(ssl, buf, buf_size);
        fprintf(stderr, "SSL_write returned: %d ", w);

        if (w > 0) {
            fprintf(stderr,"SUCCESS\n");
            return;
        }

        int ssl_error_code = SSL_get_error(ssl, w);
        if (ssl_error_code == SSL_ERROR_WANT_READ || ssl_error_code == SSL_ERROR_WANT_WRITE) {
            fprintf(stderr, "EAGAIN\n");
            sleep_1msec();
            continue;
        }

        fprintf(stderr,"ERROR\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    // openssl s_server -Verify 42 -verify_return_error -tls1_3 -cert /tmp/server.crt -key /tmp/server.key -verifyCApath /tmp/CAdir/

    SSL_library_init();

    SSL_CTX *ctx = create_ssl_context(TLS_client_method());
    configure_ssl_context(ctx);

    int sock = connect_to_server(ADDRESS, PORT);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);

    try_sending_512bytes(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(sock);

    return 0;
}
