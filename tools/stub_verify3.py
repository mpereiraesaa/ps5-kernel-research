#!/usr/bin/env python3
"""stub_verify3 — graduated safety test level 3: ring-0 + EFER + CR0 + exit.

Level 3 = level 2 plus one more kernel-text gadget: CR0 via
`mov_rax_cr0` (offset table entry; gadget verified to begin with
0f 20 c0). The value is sanity-checked against kstuff's is_sane_cr0
masks (known bits 0xe005003f, required PE|NE 0x80000001).

CR4 remains out of scope here: reading CR4 requires a kernel-text
`mov rax,cr4` gadget that has not been located on 12.02 — a userland
gadget is an SMEP violation (proven console panic).

Run stub_verify.py and stub_verify2.py first.
"""
import argparse
import sys

from stub_verify import *  # noqa: F401,F403 — Session, discover, connect_stub,
                           # read_offsets, constants, log, hexs, park, time
from stub_verify2 import RING0  # shared ring-0 parked-state tracker

CR0_KNOWN_BITS = 0xE005003F    # kstuff is_sane_cr0
CR0_REQUIRED_BITS = 0x80000001  # PE | NE


def _verify_cr0_inner(stub_port):
    log("=" * 60)
    log("LEVEL 3: ring-0 + EFER + CR0 + restore + exit")
    log("=" * 60)

    c, s, base, kdata = connect_stub(stub_port)
    RING0["sock"] = c
    log("[V3] connected; base=%s kdata=%s", hexs(base), hexs(kdata))

    offs = read_offsets(s, base)
    for name in ("rdmsr_start", "mov_rax_cr0", "tss_array", "idt"):
        if offs[name] >> 48 != 0xFFFF:
            c.close()
            raise RuntimeError("offset %s implausible: %s"
                               % (name, hexs(offs[name])))
        log("[V3] offsets.%s = kdata%s", name, hexs(offs[name] - kdata))

    # ---- ring-0 entry --------------------------------------------------
    regs = s.read_regs()
    regs["rip"] = base + SYM_R0GDB
    s.write_regs(regs)
    log("[V3] rip=r0gdb (%s); free-run entry...", hexs(regs["rip"]))
    stop = s.cont()
    log("[V3] stop after entry: %r", stop)
    regs = s.read_regs()
    if regs["rsp"] >> 48 != 0xFFFF:
        raise RuntimeError("rsp not kernel stack — ring-0 entry failed")
    RING0["entered"] = True
    log("[V3] RING-0 CONFIRMED (rsp=%s)", hexs(regs["rsp"]))

    def step_setup(**kw):
        r = s.read_regs()
        for k, v in kw.items():
            r[k] = v
        s.write_regs(r)

    def rd_gadget(rip):
        step_setup(rip=rip, rax=0)
        s.step()
        return s.read_regs()

    # ---- EFER read -----------------------------------------------------
    step_setup(rip=offs["rdmsr_start"], rcx=EFER_MSR, rax=0, rdx=0)
    efer = 0
    for i in range(16):
        s.step()
        r = s.read_regs()
        efer = (r["rdx"] << 32) | r["rax"]
        if efer != 0:
            break
    log("[V3] EFER = %s", hexs(efer))
    if efer & 0x800 == 0:
        raise RuntimeError("EFER NXE not set — EFER looks wrong")

    # ---- CR0 read (the NEW step for level 3) ---------------------------
    r = rd_gadget(offs["mov_rax_cr0"])
    cr0 = r["rax"]
    log("[V3] CR0 = %s (expect ~0x8005003b)", hexs(cr0))
    if cr0 & ~CR0_KNOWN_BITS:
        log("[V3] WARNING: CR0 unknown bits: 0x%x", cr0 & ~CR0_KNOWN_BITS)
    if (cr0 & CR0_REQUIRED_BITS) != CR0_REQUIRED_BITS:
        raise RuntimeError("CR0 missing required bits (PE|NE): 0x%x" % cr0)

    # ---- restore -------------------------------------------------------
    wslot = base + GADGET_WRITE_QWORD
    s.write_mem(wslot, bytes.fromhex("488901"))  # mov [rcx], rax

    def kwrite(addr, val):
        step_setup(rip=wslot, rcx=addr, rax=val)
        s.step()
        r = s.read_regs()
        if r["rip"] != wslot + 3:
            raise RuntimeError("store step mismatch at %s" % hexs(addr))

    og = s.read_mem(base + SYM_OG_TSS, 16 * 3 * 8)
    tss = offs["tss_array"]
    for cpu in range(16):
        for j, fo in enumerate((0x34, 0x3C, 0x4C)):
            val = int.from_bytes(og[(cpu*3+j)*8:(cpu*3+j)*8+8], "little")
            if val:
                kwrite(tss + cpu * 0x68 + fo, val)
    log("[V3] TSS IST restored")

    idt = offs["idt"]
    idt6_patched = int.from_bytes(
        s.read_mem(base + SYM_IDT6_PATCHED, 4), "little") != 0
    restore_gates = [(6, SYM_OG_IDT6)] if idt6_patched else []
    restore_gates += [(9, SYM_OG_IDT9), (179, SYM_OG_IDT179),
                      (1, SYM_OG_IDT1)]
    for num, sym in restore_gates:
        ent = s.read_mem(base + sym, 16)
        for half in range(2):
            val = int.from_bytes(ent[half*8:half*8+8], "little")
            kwrite(idt + num * 16 + half * 8, val)
    log("[V3] IDT gates restored (IDT 1 last)")

    # ---- exit ----------------------------------------------------------
    step_setup(rip=base + SYM_R0GDB_EXIT)
    s.cmd(b"c")
    c.close()
    log("[V3] clean exit")
    log("")
    log("LEVEL 3 PASSED: ring-0 + EFER (%s) + CR0 (%s) + restore + exit",
        hexs(efer), hexs(cr0))
    log("Next: the acpi_sleep_machdep probe (from ktext anchors)")
    return True


def verify_cr0(stub_port):
    try:
        return _verify_cr0_inner(stub_port)
    except Exception as e:
        why = "%s: %s" % (type(e).__name__, e)
        if RING0["sock"] is not None and RING0["entered"]:
            park(RING0["sock"], why)
            return 2
        log("LEVEL 3 FAILED (pre-entry, nothing patched): %s", why)
        return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args()

    stub_port = args.port if args.port is not None else discover(args.no_send)
    if stub_port is None:
        return 1

    return 0 if verify_cr0(stub_port) else 1


if __name__ == "__main__":
    sys.exit(main())
