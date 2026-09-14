# pspkit-https, as released: headers and two prebuilt libraries. In an
# application's Makefile, after OBJS, CFLAGS and LIBS and before build.mak:
#
#   include lib/pspkit-https-VERSION/module.mk
#
# The library calls into wolfSSL and wolfSSL calls back for its seed, so
# libpspkit-https comes before and after libwolfssl. Every import stub has
# to be linked from one place, or psp-fixup-imports finds it in pieces:
# psp-gcc links sceUtility, sceRtc, sceNetInet and sceNetResolver itself,
# after libc, and a user-mode build.mak appends the debug screen, display,
# GE, controller, net and apctl stubs, so none of those are named here.
PSPKIT_HTTPS := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

CFLAGS += -I$(PSPKIT_HTTPS)/include
LIBDIR += $(PSPKIT_HTTPS)/lib
PSPKIT_HTTPS_SDK_STUBS := -lpsputility -lpsprtc -lpspnet_inet -lpspnet_resolver
ifneq ($(USE_KERNEL_LIBS),1)
PSPKIT_HTTPS_SDK_STUBS += -lpspdebug -lpspdisplay -lpspge -lpspctrl -lpspnet -lpspnet_apctl
endif
LIBS := -lpspkit-https -lwolfssl -lpspkit-https \
        $(filter-out $(PSPKIT_HTTPS_SDK_STUBS),$(LIBS)) \
        $(filter-out $(LIBS),-lpsppower)
