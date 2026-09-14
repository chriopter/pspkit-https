# pspkit-https in an application's Makefile:
#
#   include lib/pspkit-https/module.mk
#
# after OBJS, CFLAGS and LIBS are set and before build.mak, which reads them.
# It adds the library's objects, its headers -- included as
# "pspkit-https/https.h" -- wolfSSL, and the PSP libraries they need.
# wolfSSL is built once, into build/wolfssl, by tools/build-wolfssl.
PSPKIT_HTTPS := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
PSPKIT_HTTPS_WOLFSSL := $(abspath $(PSPKIT_HTTPS)/build/wolfssl)

OBJS += $(PSPKIT_HTTPS)/src/https.o $(PSPKIT_HTTPS)/src/entropy.o \
        $(PSPKIT_HTTPS)/src/sweep.o $(PSPKIT_HTTPS)/src/sweep_ascii.o
CFLAGS += -I$(PSPKIT_HTTPS)/include -I$(PSPKIT_HTTPS_WOLFSSL)/include
LIBDIR += $(PSPKIT_HTTPS_WOLFSSL)/lib
# Every import stub library has to be linked from one place, or
# psp-fixup-imports finds its stubs in pieces ("stubs out of order") and the
# EBOOT may or may not run. psp-gcc's specs link sceUtility, sceRtc,
# sceNetInet and sceNetResolver themselves, after libc, so those are never
# named here. A user-mode build.mak also appends the debug screen, display,
# GE, controller, net and apctl stubs, so an application naming those again
# splits them; a kernel-mode build.mak does not, and keeps its own list.
# wolfSSL goes in front, and scePower is the one stub the library adds.
PSPKIT_HTTPS_SDK_STUBS := -lpsputility -lpsprtc -lpspnet_inet -lpspnet_resolver
ifneq ($(USE_KERNEL_LIBS),1)
PSPKIT_HTTPS_SDK_STUBS += -lpspdebug -lpspdisplay -lpspge -lpspctrl -lpspnet -lpspnet_apctl
endif
LIBS := -lwolfssl $(filter-out $(PSPKIT_HTTPS_SDK_STUBS),$(LIBS)) \
        $(filter-out $(LIBS),-lpsppower)
