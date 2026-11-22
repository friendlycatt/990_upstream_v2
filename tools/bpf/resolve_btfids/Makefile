# SPDX-License-Identifier: GPL-2.0-only
.DEFAULT_GOAL := all

include ../../scripts/Makefile.include

# This tool runs on the build host, even for a cross-compiled kernel.
CC = $(HOSTCC)
include ../../scripts/Makefile.arch

ifeq ($(srctree),)
srctree := $(abspath ../../..)
endif

ifeq ($(OUTPUT),)
OUTPUT := $(CURDIR)/
endif
OUTPUT := $(patsubst %/,%,$(OUTPUT))/

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s\n' "$(1)" "$(notdir $(2))";
MAKEFLAGS += --no-print-directory
endif

HOST_LIBELF_CFLAGS ?= $(shell pkg-config libelf --cflags 2>/dev/null)
HOST_LIBELF_LIBS ?= $(shell pkg-config libelf --libs 2>/dev/null || echo -lelf)

CPPFLAGS += -I$(srctree)/tools/include -I$(srctree)/tools/include/uapi \
	    $(HOST_LIBELF_CFLAGS)
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra

BINARY := $(OUTPUT)resolve_btfids
OBJECT := $(OUTPUT)main.o

all: $(BINARY)

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OBJECT): main.c Makefile | $(OUTPUT)
	$(call msg,HOSTCC,$@)
	$(Q)$(HOSTCC) $(CPPFLAGS) $(CFLAGS) $(KBUILD_HOSTCFLAGS) $(HOSTCFLAGS) \
		-MMD -MP -c $< -o $@

$(BINARY): $(OBJECT)
	$(call msg,HOSTLD,$@)
	$(Q)$(HOSTCC) $< $(LDFLAGS) $(KBUILD_HOSTLDFLAGS) $(HOSTLDFLAGS) \
		-o $@ $(HOST_LIBELF_LIBS) $(KBUILD_HOSTLDLIBS) $(HOSTLDLIBS)

clean:
	$(call msg,CLEAN,$(BINARY))
	$(Q)$(RM) $(BINARY) $(OBJECT) $(OUTPUT)main.d

-include $(OUTPUT)main.d

.PHONY: all clean
