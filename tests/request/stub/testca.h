/* Forced in first, as tests/nettest does: defines ca_bundle.h's guard, so
   the build carries one made-up root instead of Mozilla's. The stubbed
   wolfSSL never reads it. */
#ifndef PSPKIT_HTTPS_CA_BUNDLE_H
#define PSPKIT_HTTPS_CA_BUNDLE_H
#define PSPKIT_HTTPS_TEST_CA
static const char PSPKIT_HTTPS_CA_PEM[] = "not a certificate\n";
#endif
