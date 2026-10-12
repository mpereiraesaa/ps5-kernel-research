# prosper0gdb elfldr adapter, SDK-crt build (v3, verified live on console).
#
# Structure (see main.c header + ps5-kernel-research docs/07-evidence.md
# 2026-10-09 for the full root-cause record):
#   - prosper0gdb.o: kstuff's r0gdb.c + r0run.asm (yasm) + offsets.c,
#     relocatable -r link, host gcc, kstuff freebsd-headers.
#   - dbg.o: the GDB stub (../../gdb_stub/dbg.c), compiled against kstuff's
#     freebsd-headers (PS4/PS5 FreeBSD ABI, proven by upstream prosper0gdb
#     on PS5); undefined symbols resolve against the SDK libc at the
#     final link.
#   - main.c: SDK crt convention; payload_args via payload_get_args().
#   - Final link: prospero-clang + SDK crt/libc, ET_DYN, with
#     --defsym,_end=__image_end (prosper0gdb.o references _end).
#
# yasm: prosper0gdb_elfldr/tools/yasm-local/usr/bin/yasm (extracted from
# the Ubuntu yasm deb; apt-get download yasm + dpkg-deb -x if missing).

SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_ROOT := $(abspath $(SELF_DIR)/../../..)
# Sanitized repo copy: the SDK path and console address are never
# hardcoded here (the working sandbox Makefile carries the local
# values; this copy is the published recipe). Provide both via the
# environment or make variables.
PS5_PAYLOAD_SDK ?= $(error Set PS5_PAYLOAD_SDK to the ps5-payload-sdk install path)
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

YASM := $(BUILD_ROOT)/tools/yasm-local/usr/bin/yasm
ifeq ($(wildcard $(YASM)),)
YASM := yasm
endif

PS5_HOST ?= $(error Set PS5_HOST to the console address)
PS5_PORT ?= 9021

ELF := payload-elfldr-sdk.elf
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
