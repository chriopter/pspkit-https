TARGET = nettest
OBJS = main.o
# testca.h is forced in first and defines ca_bundle.h's guard: the test
# trusts its own CA and nothing else. run writes it.
CFLAGS = -O2 -G0 -Wall -include testca.h
include ../../module.mk
ASFLAGS = $(CFLAGS)
EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = nettest
PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
