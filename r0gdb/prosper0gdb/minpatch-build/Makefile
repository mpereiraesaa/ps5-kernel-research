# minpatch - the minimal one-shot patch test (port phase 2, rung 4).
# Same build as the sdk-build prosper0gdb payload (see ../sdk-build/Makefile
# for the full root-cause record in its header), with a different main.c:
# no dbg_enter, no stub session - pure CPL3 copyout reads.
#
# Sanitized repo copy: PS5_PAYLOAD_SDK and PS5_HOST are env/make-required.

SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_ROOT := $(abspath $(SELF_DIR)/../../..)
PS5_PAYLOAD_SDK ?= $(error Set PS5_PAYLOAD_SDK to the ps5-payload-sdk install path)
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

YASM := $(BUILD_ROOT)/tools/yasm-local/usr/bin/yasm
ifeq ($(wildcard $(YASM)),)
YASM := yasm
endif

PS5_HOST ?= $(error Set PS5_HOST to the console address)
PS5_PORT ?= 9021

ELF := minpatch.elf
CFLAGS := -Wall -g -O0

PROSPER0GDB_OPT := -O0
KSTUFF_HDR := $(SELF_DIR)/../../freebsd-headers
DBG_CFLAGS := -O0 -D__PS4__ -DPS5KEK -DNO_SYSARCH_GSBASE -nostdinc -isystem $(KSTUFF_HDR) \
              -fno-stack-protector -fPIE -ffreestanding

all: $(ELF)

r0run.o: $(SELF_DIR)/../r0run.asm
	$(YASM) -f elf64 -g dwarf2 $< -o $@

prosper0gdb.o: $(SELF_DIR)/../r0gdb.c $(SELF_DIR)/../offsets.c \
               $(SELF_DIR)/../offsets.h $(SELF_DIR)/../offsets/offset_list.txt \
               $(SELF_DIR)/../offsets/12_02.h r0run.o
	gcc $(PROSPER0GDB_OPT) -g -isystem $(KSTUFF_HDR) -nostdinc -nostdlib \
	  -fno-stack-protector -r -Wl,--unique='*' -ffunction-sections \
	  -fdata-sections -DPS5KEK $(SELF_DIR)/../r0gdb.c r0run.o \
	  $(SELF_DIR)/../offsets.c -o $@ -fPIE -ffreestanding \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables

dbg.o: $(SELF_DIR)/../../gdb_stub/dbg.c $(SELF_DIR)/../../gdb_stub/dbg.h \
       $(SELF_DIR)/../../gdb_stub/trap_state.h
	$(CC) $(DBG_CFLAGS) -c -o $@ $<

$(ELF): main.c dbg.o prosper0gdb.o
	$(CC) $(CFLAGS) -I$(SELF_DIR)/.. -I$(SELF_DIR)/../../lib \
	  -I$(SELF_DIR)/../../gdb_stub -o $@ main.c dbg.o prosper0gdb.o \
	  -Wl,--defsym,_end=__image_end

clean:
	rm -f $(ELF) dbg.o prosper0gdb.o r0run.o

test: $(ELF)
	python3 $(BUILD_ROOT)/../../../send_elf.py $(ELF) --host $(PS5_HOST) --port $(PS5_PORT) \
	  --wait-response --read-timeout 25
