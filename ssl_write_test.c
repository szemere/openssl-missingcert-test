#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#define PORT 4433
#define ADDRESS "127.0.0.1"
#define CRT_FILE "/tmp/localhost.crt"
#define KEY_FILE "/tmp/localhost.key"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

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

int connect_to_server(const char *address, int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    inet_pton(AF_INET, address, &addr.sin_addr);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
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

void log_keys(const SSL *ssl, const char *line)
{
    FILE *log = fopen("sslkeylog.txt", "a");
    fprintf(log, "%s\n", line);
    fclose(log);
}

void configure_ssl_context(SSL_CTX *ctx)
{
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_set_ecdh_auto(ctx, 1);
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_keylog_callback(ctx, log_keys);

    if (SSL_CTX_use_certificate_file(ctx, CRT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void client_send_4080_bytes_in_chunks(SSL *ssl)
{
    const int to_send = 4080;

    const size_t buf_size = 204; /* = 1; // more consistent reproduction */
    char buf[buf_size];
    memset(buf, 'z', buf_size);

    int sent = 0;
    int remaining = to_send - sent;

    while (remaining != 0) {
        int w = SSL_write(ssl, buf, MIN(remaining, buf_size));
        if (w <= 0)
            exit(EXIT_FAILURE);

        sent += w;
        remaining = to_send - sent;
    }

    if (sent != to_send) {
        fprintf(stderr, "sent != to_send\n");
        exit(EXIT_FAILURE);
    }
}

void *client_thread(void *arg)
{
    SSL_CTX *ctx = create_ssl_context(TLS_client_method());
    configure_ssl_context(ctx);

    int sock = connect_to_server(ADDRESS, PORT);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    client_send_4080_bytes_in_chunks(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    /* struct timespec ts = {0, 100000000};
    nanosleep(&ts, NULL); */

    /* shutdown(sock, SHUT_RDWR); */
    close(sock);

    return NULL;
}

pthread_t *client_thread_spawn(void)
{
    pthread_t *thread = calloc(1, sizeof(pthread_t));

    int err = pthread_create(thread, NULL, client_thread, NULL);
    if (err != 0) {
        fprintf(stderr, "Error creating thread\n");
        return NULL;
    }

    return thread;
}

void client_thread_wait_and_free(pthread_t *thread)
{
    int err = pthread_join(*thread, NULL);
    if (err != 0) {
        fprintf(stderr, "Error joining thread\n");
        return;
    }

    free(thread);
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

void server_read_all(SSL *ssl)
{
    int read = 0, r;
    char buf[128];
    while ((r = SSL_read(ssl, buf, 128)) > 0) {
        read += r;
    }

    int sslerr = SSL_get_error(ssl, r);
    if (sslerr == SSL_ERROR_SYSCALL) {
        perror("SSL_read returned SSL_ERROR_SYSCALL");
        ERR_print_errors_fp(stderr);
    }

    printf("read: %d (should be 4080)\n", read);
}

int main(int argc, char **argv)
{
    SSL_library_init();

    ignore_sigpipe();

    SSL_CTX *server_ctx = create_ssl_context(TLS_server_method());
    configure_ssl_context(server_ctx);
    int listen_sock = create_listen_socket(PORT);

    pthread_t *thread = client_thread_spawn();

    SSL *ssl = server_accept(listen_sock, server_ctx);

    server_read_all(ssl);

    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);

    close(listen_sock);
    SSL_CTX_free(server_ctx);

    client_thread_wait_and_free(thread);

    return 0;
}
