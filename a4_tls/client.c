#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

const int verify_depth = 2;

int CreateSocket(const char *hostname, int port)
{
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);
    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX *InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx,SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx,SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, verify_depth);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024], msg[1024];
    int bytes;
    char *hostname, *portnum;

    if (argc != 3)
    {
        printf("usage: %s <server_ip> <portnum>\n", argv[0]);
        exit(0);
    }
    SSL_library_init();
    hostname = argv[1];
    portnum = argv[2];

    ctx = InitCTX();
    server = CreateSocket(hostname, atoi(portnum));
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_CTX_load_verify_locations(ctx, "./ca-cert.pem", NULL) == 0)
        ERR_print_errors_fp(stderr);

    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
    {
        SSL_get_peer_certificate(ssl);
        int ret_val = SSL_get_verify_result(ssl);
        if (ret_val == X509_V_OK)
        {
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            printf("Message: ");
            scanf("%[^\n]%*c", msg);
            SSL_write(ssl, msg, strlen(msg));
            bytes = SSL_read(ssl, buf, sizeof(buf));
            buf[bytes] = 0;
            printf("Received: \"%s\"\n", buf);
        }
        else
        {
            printf("Server certificate verification failed!, %d\n", ret_val);
            ERR_print_errors_fp(stderr);
        }

        SSL_free(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
