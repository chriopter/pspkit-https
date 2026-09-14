# The library's entropy.c and sweep.c, unchanged, on the host; and the first
# hardening, kept in hardened/, for the report's middle column.
#   make && ./sim selftest && python3 report.py compute WORK TESTDATA
KIT := ../..
CFLAGS := -pthread -O2 -Wall -Wextra -Wno-deprecated-declarations -Istub
DEPS := sim.c psp_stub.c sim.h stub/*.h stub/wolfssl/wolfcrypt/sha256.h

all: sim sim-hardened

sim: $(DEPS) $(KIT)/src/entropy.c $(KIT)/src/sweep.c $(KIT)/src/entropy_internal.h $(KIT)/include/pspkit-https/*.h
	$(CC) $(CFLAGS) -I$(KIT)/include -I$(KIT)/src -o $@ sim.c psp_stub.c $(KIT)/src/entropy.c $(KIT)/src/sweep.c -lcrypto -lm

sim-hardened: $(DEPS) hardened/src/*.c hardened/include/pspkit-https/*.h
	$(CC) $(CFLAGS) -Ihardened/include -Ihardened/src -o $@ sim.c psp_stub.c hardened/src/entropy.c hardened/src/sweep.c -lcrypto -lm

clean:
	rm -f sim sim-hardened
