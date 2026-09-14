# In an app's Makefile, after OBJS and LIBS:  include kit/https/module.mk
KIT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CFLAGS += -I$(KIT)
