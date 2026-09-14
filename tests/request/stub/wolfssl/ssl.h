/* wolfSSL as far as src/https.c calls it, for the host: a TLS session that
   is only a pipe, so the test reads the request and writes the response. */
#ifndef REQUEST_STUB_WOLFSSL_H
#define REQUEST_STUB_WOLFSSL_H

#include <time.h>

typedef struct WOLFSSL WOLFSSL;
typedef struct WOLFSSL_CTX WOLFSSL_CTX;
typedef struct WOLFSSL_METHOD WOLFSSL_METHOD;
typedef struct WOLFSSL_X509 WOLFSSL_X509;
typedef struct WOLFSSL_X509_NAME WOLFSSL_X509_NAME;
typedef struct WOLFSSL_ASN1_TIME WOLFSSL_ASN1_TIME;
typedef struct WOLFSSL_X509_STORE_CTX { int error, error_depth; } WOLFSSL_X509_STORE_CTX;

#define WOLFSSL_SUCCESS 1
#define WOLFSSL_ERROR_NONE 0
#define WOLFSSL_ERROR_WANT_READ 2
#define WOLFSSL_ERROR_WANT_WRITE 3
#define WOLFSSL_ERROR_ZERO_RETURN 6
#define WOLFSSL_CBIO_ERR_GENERAL -1
#define WOLFSSL_CBIO_ERR_WANT_READ -2
#define WOLFSSL_CBIO_ERR_WANT_WRITE -2
#define WOLFSSL_CBIO_ERR_CONN_RST -3
#define WOLFSSL_CBIO_ERR_TIMEOUT -5
#define WOLFSSL_CBIO_ERR_CONN_CLOSE -6
#define WOLFSSL_SNI_HOST_NAME 0
#define WOLFSSL_ECC_X25519 29
#define WOLFSSL_ECC_SECP256R1 23
#define WOLFSSL_FILETYPE_ASN1 2
#define WOLFSSL_FILETYPE_PEM 1
#define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 1
#define WOLFSSL_VERIFY_PEER 1
#define ASN_BEFORE_DATE_E -150
#define ASN_AFTER_DATE_E -151
#define ASN_SELF_SIGNED_E -156
#define ASN_NO_SIGNER_E -188

typedef int (*CallbackIORecv)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
typedef int (*CallbackIOSend)(WOLFSSL *ssl, char *buf, int sz, void *ctx);
typedef int (*VerifyCallback)(int preverify, WOLFSSL_X509_STORE_CTX *store);

int wolfSSL_Init(void);
int wolfSSL_Cleanup(void);
const char *wolfSSL_lib_version(void);
WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);
WOLFSSL_CTX *wolfSSL_CTX_new(WOLFSSL_METHOD *method);
void wolfSSL_CTX_free(WOLFSSL_CTX *ctx);
int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX *ctx, const unsigned char *in, long len,
                                      int format, int user_chain, unsigned flags);
void wolfSSL_CTX_set_verify(WOLFSSL_CTX *ctx, int mode, VerifyCallback verify);
void wolfSSL_CTX_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv recv);
void wolfSSL_CTX_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend send);
int wolfSSL_CTX_set_groups(WOLFSSL_CTX *ctx, int *groups, int count);

WOLFSSL *wolfSSL_new(WOLFSSL_CTX *ctx);
void wolfSSL_free(WOLFSSL *ssl);
int wolfSSL_shutdown(WOLFSSL *ssl);
int wolfSSL_set_cipher_list(WOLFSSL *ssl, const char *list);
void wolfSSL_SetIOReadCtx(WOLFSSL *ssl, void *ctx);
void wolfSSL_SetIOWriteCtx(WOLFSSL *ssl, void *ctx);
int wolfSSL_UseSNI(WOLFSSL *ssl, unsigned char type, const void *data, unsigned short size);
int wolfSSL_check_domain_name(WOLFSSL *ssl, const char *name);
int wolfSSL_check_ip_address(WOLFSSL *ssl, const char *address);
int wolfSSL_UseKeyShare(WOLFSSL *ssl, unsigned short group);
int wolfSSL_connect(WOLFSSL *ssl);
int wolfSSL_get_error(WOLFSSL *ssl, int ret);
char *wolfSSL_ERR_error_string(unsigned long error, char *out);
const char *wolfSSL_get_curve_name(WOLFSSL *ssl);
const char *wolfSSL_get_cipher(WOLFSSL *ssl);
int wolfSSL_write(WOLFSSL *ssl, const void *data, int size);
int wolfSSL_read(WOLFSSL *ssl, void *data, int size);

WOLFSSL_X509 *wolfSSL_X509_STORE_CTX_get_current_cert(WOLFSSL_X509_STORE_CTX *store);
WOLFSSL_ASN1_TIME *wolfSSL_X509_get_notAfter(WOLFSSL_X509 *cert);
int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME *t, struct tm *tm);
char *wolfSSL_X509_get_subjectCN(WOLFSSL_X509 *cert);
WOLFSSL_X509_NAME *wolfSSL_X509_get_issuer_name(WOLFSSL_X509 *cert);
char *wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME *name, char *out, int size);

#endif
