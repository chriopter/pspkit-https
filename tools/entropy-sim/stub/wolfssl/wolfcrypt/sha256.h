/* wc_Sha256 over OpenSSL's SHA-256, so entropy.c compiles unchanged. */
#ifndef SIM_SHA256_H
#define SIM_SHA256_H
#include <openssl/sha.h>
typedef unsigned char byte;
typedef unsigned int word32;
#define WC_SHA256_DIGEST_SIZE 32
typedef SHA256_CTX wc_Sha256;
static inline int wc_InitSha256(wc_Sha256 *s) { return SHA256_Init(s) == 1 ? 0 : -1; }
static inline int wc_Sha256Update(wc_Sha256 *s, const byte *d, word32 n) { return SHA256_Update(s, d, n) == 1 ? 0 : -1; }
/* A one-shot failure checks that a failed derivation never reaches disk. */
extern int sim_hash_fail;
static inline int wc_Sha256Final(wc_Sha256 *s, byte *out) {
    if (sim_hash_fail) { sim_hash_fail = 0; return -1; }
    return SHA256_Final(out, s) == 1 ? 0 : -1;
}
static inline void wc_Sha256Free(wc_Sha256 *s) { (void)s; }
#endif
