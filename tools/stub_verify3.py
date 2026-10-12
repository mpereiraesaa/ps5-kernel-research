#!/usr/bin/env python3
"""stub_verify3 — graduated safety test level 3: ring-0 + EFER + CR0 + exit.

Level 3 = the hardened level-2 design plus one more kernel-text gadget:
CR0 via `mov_rax_cr0` (0f 20 c0), sanity-checked against kstuff's
is_sane_cr0 masks (known bits 0xe005003f, required PE|NE 0x80000001).

PORTED to the SMEP-safe design (2026-10-12): the old version restored
through the base+GADGET_WRITE_QWORD userland slot — stepping rip at
payload memory at CPL0, the live-confirmed SMEP #PF panic mode. This
version uses only the kernel-text `store_rax_rdi` gadget, exactly like
the hardened level 2: pinned 12.02 offset deltas, operator gates
(--ring0 / --verified-store-gadget / --recovery-plan-confirmed),
staged ABI return frame, validated TSS/IDT restore with per-store
readback, and a verified return to the exact original RIP/RSP.

CR4 remains out of scope: reading CR4 requires a kernel-text
`mov rax,cr4` gadget not yet located on 12.02; a userland gadget is an
SMEP violation (proven console panic).

Run stub_verify.py (level 1) and stub_verify2.py (level 2) first.
"""
import argparse
import sys

from stub_verify import *  # noqa: F401,F403 — Session, discover, connect_stub,
                           # read_offsets, constants, log, hexs, park, time

RING3 = {"transition_attempted": False, "sock": None, "frame_restore": None}
TSS_FIELDS = (0x34, 0x3C, 0x4C)
CPU_COUNT = 16
TSS_STRIDE = 0x68
CR0_KNOWN_BITS = 0xE005003F      # kstuff is_sane_cr0
CR0_REQUIRED_BITS = 0x80000001  # PE | NE

# Pinned to offsets/12_02.h. Provenance: the payload selects its table from
# the console's live sysctl FW version (offsets.c set_offsets() dispatches
# `case 0x1202: set_offsets_1202()`), and this console is 12.02 (0x12020000).
# Cross-validated on-console 2026-10-09: rdmsr_start/mov_rax_cr0 from this
# table produced the sane EFER (0x11d01)/CR0 (0x8005003b) reads.
EXPECTED_FW_DELTAS = {
    "rdmsr_start": -0xA9E10A,
    "mov_rax_cr0": -0xAA3C61,
    "store_rax_rdi": -0xAA3EEE,
    "tss_array": 0x2E8AFE0,
    "idt": 0x2E88300,
}


def _is_kernel_address(value):
    return value >> 48 == 0xFFFF


def verify_cr0(stub_port, verified_store_gadget):
    try:
        return _verify_cr0_inner(stub_port, verified_store_gadget)
    except Exception as e:
        why = "%s: %s" % (type(e).__name__, e)
        sock = RING3["sock"]
        if RING3["transition_attempted"] and sock is not None:
            # The transition was attempted: r0gdb_setup may already have
            # changed IDT/TSS state. Restore the staged user frame word if
            # possible, then hold the socket open.
            frame_restore = RING3["frame_restore"]
            if frame_restore is not None:
                session, addr, original = frame_restore
                try:
                    session.write_mem(addr, original)
                    if session.read_mem(addr, len(original)) != original:
                        raise RuntimeError("frame restore readback mismatch")
                    RING3["frame_restore"] = None
                except BaseException as restore_error:
                    park(sock, "%s; pre-transition frame restore failed: %s"
                         % (why, restore_error))
                    return 2
            park(sock, why)
            return 2
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        log("LEVEL 3 FAILED (pre-transition, nothing patched): %s", why)
        return 1


def _verify_cr0_inner(stub_port, verified_store_gadget):
    # Reset per invocation, including when imported and called repeatedly.
    RING3["transition_attempted"] = False
    RING3["sock"] = None
    RING3["frame_restore"] = None

    c, s, base, kdata = connect_stub(stub_port)
    RING3["sock"] = c
    log("[V3] connected; base=%s kdata=%s", hexs(base), hexs(kdata))

    offs = read_offsets(s, base)
    for name in ("rdmsr_start", "mov_rax_cr0", "store_rax_rdi",
                 "tss_array", "idt"):
        if not _is_kernel_address(offs[name]):
            raise RuntimeError("offset %s implausible: %s"
                               % (name, hexs(offs[name])))
        delta = offs[name] - kdata
        log("[V3] offsets.%s = kdata%s", name, hexs(delta))
        if delta != EXPECTED_FW_DELTAS[name]:
            raise RuntimeError("offset %s does not match the pinned 12.02 "
                                "table: got 0x%x expected 0x%x"
                                % (name, delta, EXPECTED_FW_DELTAS[name]))

    if verified_store_gadget != offs["store_rax_rdi"]:
        raise RuntimeError(
            "--verified-store-gadget must exactly match this payload's "
            "store_rax_rdi offset (%s); got %s"
            % (hexs(offs["store_rax_rdi"]), hexs(verified_store_gadget)))

    # Save a real return frame before redirecting RIP to a C function. The
    # original stack word is restored only after the return is observed.
    entry_regs = s.read_regs()
    original_rip = entry_regs["rip"]
    original_rsp = entry_regs["rsp"]
    if not (0x10000 <= original_rip <= 0x00007FFFFFFFFFFF):
        raise RuntimeError("initial RIP is not a plausible user address: %s"
                           % hexs(original_rip))
    if not (0x10000 <= original_rsp <= 0x00007FFFFFFFFFFF):
        raise RuntimeError("initial RSP is not a plausible user stack: %s"
                           % hexs(original_rsp))
    frame_rsp = original_rsp - 8
    if frame_rsp & 0xF != 8:
        raise RuntimeError("cannot form ABI-aligned function entry frame "
                           "from RSP=%s" % hexs(original_rsp))
    old_frame_word = s.read_mem(frame_rsp, 8)
    RING3["frame_restore"] = (s, frame_rsp, old_frame_word)
    s.write_mem(frame_rsp, original_rip.to_bytes(8, "little"))
    if s.read_mem(frame_rsp, 8) != original_rip.to_bytes(8, "little"):
        raise RuntimeError("could not verify r0gdb return frame")

    entry_regs["rsp"] = frame_rsp
    entry_regs["rip"] = base + SYM_R0GDB
    # A lost reply to G leaves it ambiguous whether the stub accepted the
    # replacement context. Conservatively park on every failure from here.
    RING3["transition_attempted"] = True
    s.write_regs(entry_regs)
    log("[V3] staged call frame; entering r0gdb at %s", hexs(entry_regs["rip"]))

    stop = s.cont()
    log("[V3] first debugger stop: %r", stop)
    regs = s.read_regs()
    log("[V3] synthetic stop regs: rsp=%s rip=%s",
        hexs(regs["rsp"]), hexs(regs["rip"]))
    if not _is_kernel_address(regs["rsp"]):
        raise RuntimeError("debugger stop did not report the expected "
                           "kernel-stack-shaped RSP")

    def step_setup(**kw):
        r = s.read_regs()
        for k, v in kw.items():
            r[k] = v
        s.write_regs(r)

    def rd_gadget(rip):
        step_setup(rip=rip, rax=0)
        s.step()
        return s.read_regs()

    # ---- EFER read (kernel-text rdmsr gadget) --------------------------
    step_setup(rip=offs["rdmsr_start"], rcx=EFER_MSR, rax=0, rdx=0)
    efer = 0
    for _ in range(16):
        s.step()
        r = s.read_regs()
        efer = (r["rdx"] << 32) | r["rax"]
        if efer != 0:
            break
    log("[V3] EFER = %s", hexs(efer))
    if efer & 0x800 == 0:
        raise RuntimeError("EFER NXE not set; refusing restore/exit")

    # ---- CR0 read (the level-3 addition, kernel-text gadget) ------------
    r = rd_gadget(offs["mov_rax_cr0"])
    cr0 = r["rax"]
    log("[V3] CR0 = %s (expect ~0x8005003b)", hexs(cr0))
    if cr0 & ~CR0_KNOWN_BITS:
        log("[V3] WARNING: CR0 has unknown bits: 0x%x", cr0 & ~CR0_KNOWN_BITS)
    if (cr0 & CR0_REQUIRED_BITS) != CR0_REQUIRED_BITS:
        raise RuntimeError("CR0 missing required bits (PE|NE): 0x%x" % cr0)

    # ---- restore (kernel-text store gadget only) ------------------------
    # The old base+GADGET_WRITE_QWORD path executed payload/user text at
    # CPL0 and was incompatible with the console's observed SMEP setting.
    wslot = offs["store_rax_rdi"]

    def kwrite(addr, val):
        if not _is_kernel_address(addr):
            raise RuntimeError("restore target is not canonical kernel "
                               "data: %s" % hexs(addr))
        step_setup(rip=wslot, rdi=addr, rax=val)
        s.step()
        r = s.read_regs()
        if r["rip"] != wslot + 3:
            raise RuntimeError("store gadget did not stop after the expected "
                               "3-byte store at %s" % hexs(addr))
        actual = int.from_bytes(s.read_mem(addr, 8), "little")
        if actual != val:
            raise RuntimeError("restore readback mismatch at %s: got %s "
                               "expected %s" % (hexs(addr), hexs(actual),
                                                hexs(val)))

    og = s.read_mem(base + SYM_OG_TSS, CPU_COUNT * 3 * 8)
    tss = offs["tss_array"]
    current_tss = s.read_mem(tss, CPU_COUNT * TSS_STRIDE)
    tss_restore = []
    for cpu in range(CPU_COUNT):
        for j, field in enumerate(TSS_FIELDS):
            val = int.from_bytes(og[(cpu * 3 + j) * 8:(cpu * 3 + j + 1) * 8],
                                 "little")
            if val and not _is_kernel_address(val):
                raise RuntimeError("saved TSS IST value is implausible: "
                                   "cpu=%d field=%#x value=%s"
                                   % (cpu, field, hexs(val)))
            live = int.from_bytes(
                current_tss[cpu * TSS_STRIDE + field:
                            cpu * TSS_STRIDE + field + 8], "little")
            if not _is_kernel_address(live):
                raise RuntimeError("live TSS IST is not a kernel pointer: "
                                   "cpu=%d field=%#x value=%s"
                                   % (cpu, field, hexs(live)))
            tss_restore.append((tss + cpu * TSS_STRIDE + field, val))
    for field in TSS_FIELDS:
        live_values = [int.from_bytes(
            current_tss[cpu * TSS_STRIDE + field:
                        cpu * TSS_STRIDE + field + 8], "little")
            for cpu in range(CPU_COUNT)]
        if len(set(live_values)) != 1:
            raise RuntimeError("TSS IST setup is inconsistent across CPUs "
                               "at field %#x" % field)

    idt = offs["idt"]
    idt6_patched = int.from_bytes(
        s.read_mem(base + SYM_IDT6_PATCHED, 4), "little") != 0
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
            raise RuntimeError("live IDT vector %d does not match the "
                               "expected r0gdb gate" % vector)
        for half in range(2):
            val = int.from_bytes(raw[half * 8:(half + 1) * 8], "little")
            idt_restore.append((idt + vector * 16 + half * 8, val))

    # Restore every IST word, including zeros; setup overwrote all fields.
    for addr, val in tss_restore:
        kwrite(addr, val)
    log("[V3] all TSS IST fields restored and read back")

    # Restore the IDT entries with vector 1 last.
    for addr, val in idt_restore:
        kwrite(addr, val)
    log("[V3] modified IDT gates restored and read back (vector 1 last)")

    # Return through the staged frame and wait for the actual stop packet.
    step_setup(rip=base + SYM_R0GDB_EXIT)
    exit_stop = s.cont(timeout=90)
    log("[V3] return stop: %r", exit_stop)
    returned = s.read_regs()
    if returned["rip"] != original_rip or returned["rsp"] != original_rsp:
        raise RuntimeError("r0gdb return did not restore original RIP/RSP: "
                           "rip=%s rsp=%s" % (hexs(returned["rip"]),
                                              hexs(returned["rsp"])))

    s.write_mem(frame_rsp, old_frame_word)
    if s.read_mem(frame_rsp, 8) != old_frame_word:
        raise RuntimeError("could not restore the original user-stack word")
    RING3["frame_restore"] = None
    RING3["transition_attempted"] = False
    c.close()
    RING3["sock"] = None
    log("[V3] verified userland return; frame restored; session closed")
    log("LEVEL 3 PASSED: EFER=%s CR0=%s; TSS/IDT restoration read back",
        hexs(efer), hexs(cr0))
    return True


def _parse_address(text):
    try:
        value = int(text, 0)
    except ValueError as e:
        raise argparse.ArgumentTypeError(
            "address must be an integer such as 0xffffffff... or 1234") from e
    if not _is_kernel_address(value):
        raise argparse.ArgumentTypeError(
            "address must be a canonical high-half kernel address")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ring0", action="store_true",
                        help="explicitly enable the ring-0 debugger transition")
    parser.add_argument("--verified-store-gadget", type=_parse_address,
                        help="exact firmware kernel store gadget "
                             "independently verified offline")
    parser.add_argument("--recovery-plan-confirmed", action="store_true",
                        help="confirm the owner-approved console recovery "
                             "plan is ready")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args()

    if not args.ring0:
        log("REFUSED: no payload sent; pass --ring0 only after reviewing "
            "the recovery plan")
        return 2
    if args.verified_store_gadget is None:
        log("REFUSED: no payload sent; --verified-store-gadget is required")
        return 2
    if not args.recovery_plan_confirmed:
        log("REFUSED: no payload sent; confirm the owner-approved recovery "
            "plan first")
        return 2

    stub_port = args.port if args.port is not None else discover(args.no_send)
    if stub_port is None:
        return 1

    return verify_cr0(stub_port, args.verified_store_gadget)


if __name__ == "__main__":
    sys.exit(main())
