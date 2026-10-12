#!/usr/bin/env python3
"""Graduated safety test level 2: ring-0 gadget read with guarded teardown.

This client is deliberately fail-closed. It will not send the payload or
attempt the transition unless --ring0 is explicit, and it additionally
requires --verified-store-gadget to match the firmware offset-table entry.
The operator must have independently verified that exact firmware gadget's
instruction semantics and containing basic block before supplying the flag.

No client-side recovery is guaranteed after the transition begins. Any
ambiguous result parks the process and keeps the RSP socket open. A power
cycle remains the only documented recovery for a stuck target.
"""
import argparse
import sys

from stub_verify import *  # noqa: F401,F403 — Session, discover, connect_stub,
                          # read_offsets, constants, log, hexs, park, time

# `entered` remains for the legacy stub_verify3 import path; this client uses
# the conservative transition_attempted state instead.
RING0 = {"transition_attempted": False, "entered": False, "sock": None,
         "frame_restore": None}
TSS_FIELDS = (0x34, 0x3C, 0x4C)
CPU_COUNT = 16
TSS_STRIDE = 0x68
# Pinned to offsets/12_02.h. Provenance: the payload selects its table from
# the console's live sysctl FW version (offsets.c set_offsets() dispatches
# `case 0x1202: set_offsets_1202()`), and this console is 12.02 (0x12020000).
# Cross-validated on-console 2026-10-09: rdmsr_start/mov_rax_cr0 from this
# table produced the sane EFER (0x11d01)/CR0 (0x8005003b) reads. The initial
# pin here used the 13_60.h values by mistake and would have refused on a
# healthy console; corrected 2026-10-12 before any live level-2 run.
EXPECTED_FW_DELTAS = {
    "rdmsr_start": -0xA9E10A,
    "store_rax_rdi": -0xAA3EEE,
    "tss_array": 0x2E8AFE0,
    "idt": 0x2E88300,
}


def _is_kernel_address(value):
    # 48-bit canonical high-half address; reject the noncanonical gap below
    # FFFF:8000 even though its upper 16 bits are all ones.
    return isinstance(value, int) and 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF


def _park_after_ambiguous_transition(sock, why):
    """Keep the one-shot RSP connection alive whenever execution is uncertain."""
    if sock is not None and RING0["transition_attempted"]:
        park(sock, why)


def verify_ring0(stub_port, verified_store_gadget):
    log("=" * 60)
    log("LEVEL 2: guarded kernel-gadget read and restore")
    log("=" * 60)

    try:
        result = _verify_ring0_inner(stub_port, verified_store_gadget)
    except BaseException as e:
        why = "%s: %s" % (type(e).__name__, e)
        if RING0["sock"] is not None and RING0["transition_attempted"]:
            _park_after_ambiguous_transition(RING0["sock"], why)
            return 2
        sock = RING0["sock"]
        frame_restore = RING0["frame_restore"]
        if frame_restore is not None:
            session, addr, original = frame_restore
            try:
                session.write_mem(addr, original)
                if session.read_mem(addr, len(original)) != original:
                    raise RuntimeError("stack-frame restore readback mismatch")
                RING0["frame_restore"] = None
            except BaseException as restore_error:
                if sock is not None:
                    park(sock, "%s; pre-transition stack restore failed: %s" %
                         (why, restore_error))
                return 2
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        log("LEVEL 2 FAILED before transition: %s", why)
        return 1
    return 0 if result is True else 1


def _verify_ring0_inner(stub_port, verified_store_gadget):
    # Reset per invocation, including when imported and called repeatedly.
    RING0["transition_attempted"] = False
    RING0["entered"] = False
    RING0["sock"] = None
    RING0["frame_restore"] = None

    c, s, base, kdata = connect_stub(stub_port)
    RING0["sock"] = c
    log("[V2] connected; base=%s kdata=%s", hexs(base), hexs(kdata))

    offs = read_offsets(s, base)
    for name in ("rdmsr_start", "store_rax_rdi", "tss_array", "idt"):
        if not _is_kernel_address(offs[name]):
            raise RuntimeError("offset %s implausible: %s" % (name, hexs(offs[name])))
        delta = offs[name] - kdata
        log("[V2] offsets.%s = kdata%s", name, hexs(delta))
        if delta != EXPECTED_FW_DELTAS[name]:
            raise RuntimeError("offset %s does not match the pinned 12.02 table: got %s expected 0x%x" %
                               (name, hexs(delta), EXPECTED_FW_DELTAS[name]))

    if verified_store_gadget != offs["store_rax_rdi"]:
        raise RuntimeError(
            "--verified-store-gadget must exactly match this payload's "
            "store_rax_rdi offset (%s); got %s" %
            (hexs(offs["store_rax_rdi"]), hexs(verified_store_gadget)))

    # Save a real return frame before redirecting RIP to a C function. The
    # original stack word is restored only after the return is observed.
    entry_regs = s.read_regs()
    original_rip = entry_regs["rip"]
    original_rsp = entry_regs["rsp"]
    if not (0x10000 <= original_rip <= 0x00007FFFFFFFFFFF):
        raise RuntimeError("initial RIP is not a plausible user address: %s" % hexs(original_rip))
    if not (0x10000 <= original_rsp <= 0x00007FFFFFFFFFFF):
        raise RuntimeError("initial RSP is not a plausible user stack: %s" % hexs(original_rsp))
    frame_rsp = original_rsp - 8
    if frame_rsp & 0xF != 8:
        raise RuntimeError("cannot form ABI-aligned function entry frame from RSP=%s" % hexs(original_rsp))
    old_frame_word = s.read_mem(frame_rsp, 8)
    RING0["frame_restore"] = (s, frame_rsp, old_frame_word)
    s.write_mem(frame_rsp, original_rip.to_bytes(8, "little"))
    if s.read_mem(frame_rsp, 8) != original_rip.to_bytes(8, "little"):
        raise RuntimeError("could not verify r0gdb return frame")

    entry_regs["rsp"] = frame_rsp
    entry_regs["rip"] = base + SYM_R0GDB
    # A lost reply to G leaves it ambiguous whether the stub accepted the
    # replacement context. Conservatively park on every failure from here.
    RING0["transition_attempted"] = True
    s.write_regs(entry_regs)
    log("[V2] staged call frame; entering r0gdb at %s", hexs(entry_regs["rip"]))

    # From this point a timeout or lost reply is ambiguous: r0gdb_setup may
    # already have changed IDT/TSS state.
    stop = s.cont()
    log("[V2] first debugger stop: %r", stop)
    regs = s.read_regs()
    log("[V2] synthetic stop regs: rsp=%s rip=%s", hexs(regs["rsp"]), hexs(regs["rip"]))
    if not _is_kernel_address(regs["rsp"]):
        raise RuntimeError("debugger stop did not report the expected kernel-stack-shaped RSP")

    def step_setup(**kw):
        r = s.read_regs()
        for k, v in kw.items():
            r[k] = v
        s.write_regs(r)

    # Read EFER using the firmware table's kernel-text gadget.
    step_setup(rip=offs["rdmsr_start"], rcx=EFER_MSR, rax=0, rdx=0)
    efer = 0
    for _ in range(16):
        s.step()
        r = s.read_regs()
        efer = (r["rdx"] << 32) | r["rax"]
        if efer != 0:
            break
    log("[V2] EFER = %s", hexs(efer))
    if efer & 0x800 == 0:
        raise RuntimeError("EFER NXE not set; refusing restore/exit")

    # Use only the independently verified kernel-text store gadget. The old
    # base+GADGET_WRITE_QWORD path executed payload/user text at CPL0 and was
    # incompatible with the console's observed SMEP setting.
    wslot = offs["store_rax_rdi"]

    def kwrite(addr, val):
        if not _is_kernel_address(addr):
            raise RuntimeError("restore target is not canonical kernel data: %s" % hexs(addr))
        step_setup(rip=wslot, rdi=addr, rax=val)
        s.step()
        r = s.read_regs()
        if r["rip"] != wslot + 3:
            raise RuntimeError("store gadget did not stop after expected 3-byte store at %s" % hexs(addr))
        actual = int.from_bytes(s.read_mem(addr, 8), "little")
        if actual != val:
            raise RuntimeError("restore readback mismatch at %s: got %s expected %s" %
                               (hexs(addr), hexs(actual), hexs(val)))

    # Snapshot the helper's original-state buffers before changing anything.
    og = s.read_mem(base + SYM_OG_TSS, CPU_COUNT * 3 * 8)
    tss = offs["tss_array"]
    current_tss = s.read_mem(tss, CPU_COUNT * TSS_STRIDE)
    tss_restore = []
    for cpu in range(CPU_COUNT):
        for j, field in enumerate(TSS_FIELDS):
            val = int.from_bytes(og[(cpu * 3 + j) * 8:(cpu * 3 + j + 1) * 8], "little")
            if val and not _is_kernel_address(val):
                raise RuntimeError("saved TSS IST value is implausible: cpu=%d field=%#x value=%s" %
                                   (cpu, field, hexs(val)))
            live = int.from_bytes(current_tss[cpu * TSS_STRIDE + field:
                                              cpu * TSS_STRIDE + field + 8], "little")
            if not _is_kernel_address(live):
                raise RuntimeError("live TSS IST is not a kernel pointer: cpu=%d field=%#x value=%s" %
                                   (cpu, field, hexs(live)))
            tss_restore.append((tss + cpu * TSS_STRIDE + field, val))
    for j, field in enumerate(TSS_FIELDS):
        live_values = [int.from_bytes(current_tss[cpu * TSS_STRIDE + field:
                                                   cpu * TSS_STRIDE + field + 8], "little")
                       for cpu in range(CPU_COUNT)]
        if len(set(live_values)) != 1:
            raise RuntimeError("TSS IST setup is inconsistent across CPUs at field %#x" % field)

    idt = offs["idt"]
    idt6_patched = int.from_bytes(s.read_mem(base + SYM_IDT6_PATCHED, 4), "little") != 0
    restore_gates = ([(6, SYM_OG_IDT6)] if idt6_patched else [])
    restore_gates += [(9, SYM_OG_IDT9), (179, SYM_OG_IDT179), (1, SYM_OG_IDT1)]
    idt_restore = []
    for vector, sym in restore_gates:
        raw = s.read_mem(base + sym, 16)
        selector = int.from_bytes(raw[2:4], "little")
        handler = (int.from_bytes(raw[0:2], "little") |
                   (int.from_bytes(raw[6:8], "little") << 16) |
                   (int.from_bytes(raw[8:12], "little") << 32))
        if selector != 0x20 or not _is_kernel_address(handler):
            raise RuntimeError("saved IDT vector %d is implausible" % vector)

        live = s.read_mem(idt + vector * 16, 16)
        expected_ist, expected_attr = {
            1: (4, 0x8E), 6: (4, 0x8E), 9: (3, 0xEE), 179: (6, 0xEE)
        }[vector]
        live_handler = (int.from_bytes(live[0:2], "little") |
                        (int.from_bytes(live[6:8], "little") << 16) |
                        (int.from_bytes(live[8:12], "little") << 32))
        if (int.from_bytes(live[2:4], "little") != 0x20 or
                live[4] != expected_ist or live[5] != expected_attr or
                not _is_kernel_address(live_handler)):
            raise RuntimeError("live IDT vector %d does not match the expected r0gdb gate" % vector)
        for half in range(2):
            val = int.from_bytes(raw[half * 8:(half + 1) * 8], "little")
            idt_restore.append((idt + vector * 16 + half * 8, val))

    # Restore every IST word, including zeros; setup overwrote all three fields.
    for addr, val in tss_restore:
        kwrite(addr, val)
    log("[V2] all TSS IST fields restored and read back")

    # Restore the IDT entries with vector 1 last, preserving the stub's
    # single-step path until the other modified gates are back.
    for addr, val in idt_restore:
        kwrite(addr, val)
    log("[V2] modified IDT gates restored and read back (vector 1 last)")

    # Return through the staged frame and wait for the actual stop packet.
    step_setup(rip=base + SYM_R0GDB_EXIT)
    exit_stop = s.cont(timeout=90)
    log("[V2] return stop: %r", exit_stop)
    returned = s.read_regs()
    if returned["rip"] != original_rip or returned["rsp"] != original_rsp:
        raise RuntimeError("r0gdb return did not restore original RIP/RSP: rip=%s rsp=%s" %
                           (hexs(returned["rip"]), hexs(returned["rsp"])))

    s.write_mem(frame_rsp, old_frame_word)
    if s.read_mem(frame_rsp, 8) != old_frame_word:
        raise RuntimeError("could not restore the original user-stack word")
    RING0["frame_restore"] = None
    RING0["transition_attempted"] = False
    c.close()
    RING0["sock"] = None
    log("[V2] verified userland return; frame restored; session closed")
    log("LEVEL 2 PASSED: EFER=%s; TSS/IDT restoration read back", hexs(efer))
    return True


def _parse_address(text):
    try:
        value = int(text, 0)
    except ValueError as e:
        raise argparse.ArgumentTypeError("address must be an integer such as 0xffffffff... or 1234") from e
    if not _is_kernel_address(value):
        raise argparse.ArgumentTypeError("address must be a canonical high-half kernel address")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ring0", action="store_true",
                        help="explicitly enable the ring-0 debugger transition")
    parser.add_argument("--verified-store-gadget", type=_parse_address,
                        help="exact firmware kernel store gadget independently verified offline")
    parser.add_argument("--recovery-plan-confirmed", action="store_true",
                        help="confirm the owner-approved console recovery plan is ready")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args()

    if not args.ring0:
        log("REFUSED: no payload sent; pass --ring0 only after reviewing the recovery plan")
        return 2
    if args.verified_store_gadget is None:
        log("REFUSED: no payload sent; --verified-store-gadget is required")
        return 2
    if not args.recovery_plan_confirmed:
        log("REFUSED: no payload sent; confirm the owner-approved recovery plan first")
        return 2

    stub_port = args.port if args.port is not None else discover(args.no_send)
    if stub_port is None:
        return 1

    return verify_ring0(stub_port, args.verified_store_gadget)


if __name__ == "__main__":
    sys.exit(main())
