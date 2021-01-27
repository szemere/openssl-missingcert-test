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

#define CRT_FILE "/tmp/server.crt"
#define KEY_FILE "/tmp/server.key"


void ignore_sigpipe(void)
{
    struct sigaction sa;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;

    if (sigaction(SIGPIPE, &sa, NULL) != 0) {
        perror("Error ignoring SIGPIPE");
        exit(EXIT_FAILURE);
    }
}

int create_listen_socket(int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
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
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (SSL_CTX_use_certificate_file(ctx, CRT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

SSL *server_accept(int listen_sock, SSL_CTX *server_ctx)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int client = accept(listen_sock, (struct sockaddr*) &addr, &len);
    if (client < 0) {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(server_ctx);
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ssl;
}

void  read_everything(SSL *ssl)
{
    int buf_len = 1024;
    char buf[buf_len];

    while(1) {
        int r = SSL_read(ssl, buf, buf_len);
        fprintf(stderr, "SSL_read returned: %d\n", r);
        
        if (r <= 0) {
            int sslerr = SSL_get_error(ssl, r);
            ERR_print_errors_fp(stderr);
          
            if (sslerr == SSL_ERROR_SYSCALL) {
                perror("SSL_read returned SSL_ERROR_SYSCALL");
                return;
            }

            if (sslerr == SSL_ERROR_ZERO_RETURN) {
                fprintf(stderr, "The other end closed the connection.\n");
                return;
            }
        }
    }
}

int main(int argc, char **argv)
{
    SSL_library_init();

    ignore_sigpipe();

    SSL_CTX *server_ctx = create_ssl_context(TLS_server_method());
    configure_ssl_context(server_ctx);
    int listen_sock = create_listen_socket(PORT);

    SSL *ssl = server_accept(listen_sock, server_ctx);

    read_everything(ssl);

    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);

    close(listen_sock);
    SSL_CTX_free(server_ctx);

    return 0;
}
