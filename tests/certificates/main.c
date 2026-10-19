/* Real wolfSSL, with tools/build-wolfssl's options, against the local TLS
   fixture server. No certificate-verification overrides. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#ifdef USER_TICKS
long long pspkit_https_time(void) { return (long long)time(NULL); }
unsigned int LowResTimer(void) { return (unsigned int)pspkit_https_time(); }
long long TimeNowInMilliseconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000 + 1;
}
#endif
int pspkit_https_seed(unsigned char *out, unsigned int sz) {
    int fd = open("/dev/urandom", O_RDONLY);
    int ok = fd >= 0 && read(fd, out, sz) == (ssize_t)sz;
    if (fd >= 0) close(fd);
    return ok ? 0 : -1;
}
static int receive(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int n = (int)recv(*(int *)ctx, buf, (size_t)sz, 0);
    return n > 0 ? n : n == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_GENERAL;
}
static int send_data(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    int n = (int)send(*(int *)ctx, buf, (size_t)sz, 0);
    return n > 0 ? n : WOLFSSL_CBIO_ERR_GENERAL;
}
int main(int argc, char **argv) {
    wolfSSL_Init();
    if (argc == 3 && strcmp(argv[1], "--parse") == 0) {
        FILE *f = fopen(argv[2], "rb");
        unsigned char der[8192];
        if (!f) return 2;
        size_t n = fread(der, 1, sizeof(der), f);
        int bad = ferror(f) || !feof(f);
        fclose(f);
        if (bad) return 2;
        WOLFSSL_X509 *cert =
            wolfSSL_X509_load_certificate_buffer(der, (int)n, WOLFSSL_FILETYPE_ASN1);
        int parsed = cert != NULL;
        wolfSSL_X509_free(cert);
        wolfSSL_Cleanup();
        return parsed ? 0 : 1;
    }
    if (argc != 4) return 2;
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx || wolfSSL_CTX_load_verify_locations(ctx, argv[1], NULL) != WOLFSSL_SUCCESS) return 2;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_CTX_SetIORecv(ctx, receive);
    wolfSSL_CTX_SetIOSend(ctx, send_data);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in to = {.sin_family = AF_INET,
                             .sin_port = htons((unsigned short)atoi(argv[2])),
                             .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(fd, (struct sockaddr *)&to, sizeof(to))) return 2;
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) return 2;
    wolfSSL_SetIOReadCtx(ssl, &fd);
    wolfSSL_SetIOWriteCtx(ssl, &fd);
    if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, argv[3], (unsigned short)strlen(argv[3])) !=
            WOLFSSL_SUCCESS ||
        wolfSSL_check_domain_name(ssl, argv[3]) != WOLFSSL_SUCCESS)
        return 2;
    int rc = wolfSSL_connect(ssl);
    int error = rc == WOLFSSL_SUCCESS ? 0 : wolfSSL_get_error(ssl, rc);
    printf("handshake error=%d\n", error);
    int ok = error == 0;
    if (ok) {
        static const char request[] = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        char response[1024];
        ok = wolfSSL_write(ssl, request, sizeof(request) - 1) == (int)sizeof(request) - 1;
        int n = wolfSSL_read(ssl, response, sizeof(response) - 1);
        if (n > 0) response[n] = 0;
        ok = ok && n > 0 && strstr(response, "certificate fixture") != NULL;
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    wolfSSL_Cleanup();
    return ok ? 0 : error ? 1 : 2;
}
