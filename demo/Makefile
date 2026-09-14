TARGET = demo
OBJS = main.o
CFLAGS = -O2 -G0 -Wall
include ../module.mk
ASFLAGS = $(CFLAGS)
EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = pspkit-https demo
PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
