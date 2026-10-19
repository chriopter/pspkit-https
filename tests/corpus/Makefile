TARGET = corpus
OBJS = main.o
CFLAGS = -O2 -G0 -Wall -Wextra
include ../../module.mk
ASFLAGS = $(CFLAGS)
EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = pspkit-https corpus test
PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
