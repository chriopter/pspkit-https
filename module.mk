# In an app's Makefile, after OBJS and LIBS:  include lib/pspkit-https/module.mk
PSPKIT_HTTPS := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CFLAGS += -I$(PSPKIT_HTTPS)
