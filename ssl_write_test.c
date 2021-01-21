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

#define CRT_FILE "/conf/cert.d/clientcert_1_expired.pem"
#define KEY_FILE "/conf/cert.d/clientkey_1_expired.pem"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void mysleep()
{
    /* sleep 1 msec */
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
        if (errno != EINPROGRESS)
          {
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
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_num_tickets(ctx, 0);
    //SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    // if (SSL_CTX_use_certificate_file(ctx, CRT_FILE, SSL_FILETYPE_PEM) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

}

void client_send_data_in_chunks(SSL *ssl)
{
    const int to_send = 2048; // bigger than a single TCP packet

    const size_t buf_size = 512;
    char buf[buf_size];
    memset(buf, 'z', buf_size);

    int sent = 0;
    int remaining = to_send - sent;

    while (remaining != 0) {
        //sleep(1);
        int w = SSL_write(ssl, buf, MIN(remaining, buf_size));
        fprintf(stderr, "SSL_write returned: %d\n", w);

        if (w <= 0)
          {
              int ssl_error_code = SSL_get_error(ssl, w);
              ERR_print_errors_fp(stderr);

              if (ssl_error_code == SSL_ERROR_WANT_READ || ssl_error_code == SSL_ERROR_WANT_WRITE)
                {
                    fprintf(stderr, "SSL want read or write, continue.\n");
                    mysleep();
                    continue;
                }
            
              exit(EXIT_FAILURE);
          }

        sent += w;
        remaining = to_send - sent;
    }

    if (sent != to_send) {
        fprintf(stderr, "sent != to_send\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    // openssl s_server -accept %s:%d -Verify 42 -verify_return_error -cert /tmp/server.cert -key /tmp/server.key

    SSL_library_init();
    OPENSSL_init_ssl(0,NULL);
    //OpenSSL_add_all_algorithms();
    //SSL_load_error_strings();

    SSL_CTX *ctx = create_ssl_context(TLS_client_method());
    configure_ssl_context(ctx);

    int sock = connect_to_server(ADDRESS, PORT);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);

    // if (SSL_connect(ssl) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    client_send_data_in_chunks(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    close(sock);

    return 0;
}
