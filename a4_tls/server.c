#include <unistd.h>
#include <malloc.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void handle_ssl_error(char *err_message) {
    ERR_print_errors_fp(stderr);
    abort();
}

void handle_error(char *err_message) {
    fprintf(stderr, "%s", err_message);
    abort();
}

int CreateSocket(int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        handle_error("Can't bind port!\n");
    if (listen(sd, 10) != 0)
        handle_error("Can't configure listening port!\n");
    return sd;
}

SSL_CTX *InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
        handle_ssl_error("");
    return ctx;
}

void HandleConnection(SSL *ssl)
{
    char buf[1024];
    char reply[1024];
    int sd, bytes;

    if (SSL_accept(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0)
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            for (int i = 0; i < bytes; ++i)
                buf[i] = toupper(buf[i]);
            sprintf(reply, buf, buf);
            SSL_write(ssl, reply, strlen(reply));
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;

    if (argc != 2)
    {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(0);
    }
    SSL_library_init();

    portnum = argv[1];
    ctx = InitServerCTX();

    if (SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) <= 0)
        handle_ssl_error("");
    if (SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) <= 0)
        handle_ssl_error("");
    if (!SSL_CTX_check_private_key(ctx))
        handle_error("Private key does not match the public certificate\n");

    server = CreateSocket(atoi(portnum));
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr *)&addr, &len);
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        HandleConnection(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
}
