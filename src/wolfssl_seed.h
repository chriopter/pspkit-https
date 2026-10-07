/* Pulled into every wolfSSL translation unit with -include, so that
   wolfcrypt/src/random.c sees a declaration for the seed function it is told
   to call via -DCUSTOM_RAND_GENERATE_SEED. The definition is in src/entropy.c;
   the linker resolves it there. */
#ifndef PSPKIT_HTTPS_WOLFSSL_SEED_H
#define PSPKIT_HTTPS_WOLFSSL_SEED_H
extern int pspkit_https_seed(unsigned char *out, unsigned int sz);

/* The same for the time: wherever wolfSSL would call time(), it asks
   src/https.c, which does not read the console's clock. A macro and not a -D,
   so that no <time.h> has to come in ahead of each file's own includes; every
   caller in wolfSSL passes a null pointer, so the argument is dropped. Ahead
   of wolfSSL's headers this is the definition they keep; src/entropy.c
   includes this file after them, for the seed alone, and gets none. */
extern long long pspkit_https_time(void);
#ifndef XTIME
#define XTIME(t) ((time_t)pspkit_https_time())
#endif
#endif
