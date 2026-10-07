/* wolfSSL itself, built for the PC the way tools/build-wolfssl builds it for
   the PSP, on a machine whose clock was never set: time() and gettimeofday()
   answer 0, as they do on a console with a flat battery. The server sends
   TLS 1.3 session tickets ahead of its answer, which is where a clock of 0
   used to end the connection with GETTIME_ERROR (-337). */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

/* ----------------------------------------------------- the dead clock */

static int clock_looks;
time_t time(time_t *t) {
    clock_looks++;
    if (t) *t = 0;
    return 0;
}
int gettimeofday(struct timeval *tv, void *tz) {
    clock_looks++;
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}

/* What src/https.c gives wolfSSL instead, as it reads at the moment of boot:
   tests/request holds the real functions to these values. */
long long pspkit_https_time(void) { return 1767225600; /* 2026-01-01 */ }
unsigned int LowResTimer(void) { return (unsigned int)pspkit_https_time(); }
long long TimeNowInMilliseconds(void) { return 1; }

int pspkit_https_seed(unsigned char *out, unsigned int sz) {
    int fd = open("/dev/urandom", O_RDONLY);
    int ok = fd >= 0 && read(fd, out, sz) == (ssize_t)sz;
    if (fd >= 0) close(fd);
    return ok ? 0 : -1;
}

/* ---------------------------------------------------------- the client */

static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    int n = (int)recv(*(int *)ctx, buf, (size_t)sz, 0);
    return n > 0 ? n : n == 0 ? WOLFSSL_CBIO_ERR_CONN_CLOSE : WOLFSSL_CBIO_ERR_GENERAL;
}
static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    int n = (int)send(*(int *)ctx, buf, (size_t)sz, 0);
    return n > 0 ? n : WOLFSSL_CBIO_ERR_GENERAL;
}

/* Dates pass, as in src/https.c; nothing else does. */
static int verify(int preverify, WOLFSSL_X509_STORE_CTX *store) {
    if (preverify) return 1;
    return store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E;
}

/* main CA.pem PORT */
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx || wolfSSL_CTX_load_verify_locations_ex(ctx, argv[1], NULL,
                    WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "clock: no context\n");
        return 2;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify);
    wolfSSL_CTX_SetIORecv(ctx, io_recv);
    wolfSSL_CTX_SetIOSend(ctx, io_send);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(argv[2])) };
    inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
    if (connect(fd, (struct sockaddr *)&to, sizeof(to))) {
        perror("clock: connect");
        return 2;
    }
    WOLFSSL *ssl = wolfSSL_new(ctx);
    wolfSSL_SetIOReadCtx(ssl, &fd);
    wolfSSL_SetIOWriteCtx(ssl, &fd);
    int rc = wolfSSL_connect(ssl);
    if (rc != WOLFSSL_SUCCESS) {
        fprintf(stderr, "clock: handshake %d\n", wolfSSL_get_error(ssl, rc));
        return 1;
    }
    static const char request[] = "GET / HTTP/1.0\r\n\r\n";
    wolfSSL_write(ssl, request, (int)sizeof(request) - 1);
    char buf[4096];
    long got = 0;
    while ((rc = wolfSSL_read(ssl, buf, (int)sizeof(buf))) > 0) got += rc;
    int end = wolfSSL_get_error(ssl, rc);

    int failed = 0;
    if (got <= 0 || end != WOLFSSL_ERROR_ZERO_RETURN) {
        fprintf(stderr, "clock: %ld bytes, then %d\n", got, end);
        failed = 1;
    }
    if (clock_looks) {
        fprintf(stderr, "clock: wolfSSL looked at the clock %d times\n", clock_looks);
        failed = 1;
    }
    printf("clock: %s\n", failed ? "FAILED" : "ok");
    return failed;
}
