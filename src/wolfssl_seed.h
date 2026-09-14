/* Pulled into every wolfSSL translation unit with -include, so that
   wolfcrypt/src/random.c sees a declaration for the seed function it is told
   to call via -DCUSTOM_RAND_GENERATE_SEED. The definition is in src/entropy.c;
   the linker resolves it there. */
#ifndef PSPKIT_HTTPS_WOLFSSL_SEED_H
#define PSPKIT_HTTPS_WOLFSSL_SEED_H
extern int pspkit_https_seed(unsigned char *out, unsigned int sz);
#endif
