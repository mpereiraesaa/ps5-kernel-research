#!/usr/bin/env python3
"""stub_verify — graduated safety test level 1 (userland only, zero risk).
Self-contained (no exec/import from r0gdb_session.py).

REGRESSION GATE: run this before ANY ring-0 session. It validates the
whole stub protocol against the payload build — handshake, register
layout, START_RIP_OFF/VERIFY_OFF constants, payload static offsets
(kdata, SYM_*), and m/M memory round-trips — with zero ring-0 risk.
If anything here regresses (payload layout change, protocol change,
constant drift), level 1 goes red BEFORE a ring-0 session can hang
the console on a bad assumption.

Required environment:
    PS5_HOST          console address (never hardcoded — sanitized repo)
    R0GDB_ELF         path to payload-elfldr-sdk.elf (the exact build
                      under test; default assumes the lab tree layout
                      relative to this file)
    R0GDB_SEND_ELF    path to send_elf.py (same default rule)

Port discovery — computed, not diffed:
  The stub binds the FIRST free port scanning up from 1234 (dbg.c:1279,
  `for(port = 1234; port < 65536 && brv; port++) bind`). So the expected
  stub port is simply the first port >= 1234 that the pre-scan finds
  closed. This avoids post-scan diffing entirely — a post-scan connect
  would STEAL the stub's single accept() and kill it (the stub reads
  exactly one byte, expects '+', and exits early on failure).

  The pre-scan is parallel (threads) because closed ports on this
  console appear to drop SYNs (no RST), so each miss costs the full
  connect timeout. A sequential scan of the old 1234-22000 range was
  measured at >120s with zero progress; the parallel 1234-1400 window
  completes in ~1-2s.

  NOTE: pre-scan probes DO connect to any zombie stub ports found.
  A zombie stub sitting in accept() will exit on our probe (its '+'
  read fails). That is acceptable — zombies are stale by definition —
  but it means the pre-scan can clean them as a side effect.

This test performs ZERO ring-0 operations. No IDT patching, no
kernel-text stepping, no gadget execution.

Usage:
    python3 stub_verify.py           # auto: pre-scan + send + computed port
    python3 stub_verify.py --port N  # manual: specific port
"""
import argparse
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

PS5 = os.environ.get("PS5_HOST", "")
PS5_ELFLDR_PORT = 9021
PORT_SCAN_LO = 1234
PORT_SCAN_HI = 1400          # stub takes the LOWEST free port; 1234-1400 is ample
SCAN_TIMEOUT = 0.5
SCAN_WORKERS = 64

HERE = os.path.dirname(os.path.abspath(__file__))
ELF_PATH = os.environ.get(
    "R0GDB_ELF",
    os.path.join(HERE, "kstuff-lite/prosper0gdb/sdk-build/payload-elfldr-sdk.elf"))
SEND_ELF = os.environ.get(
    "R0GDB_SEND_ELF",
    os.path.join(HERE, "../../send_elf.py"))
LOG_PATH = os.environ.get(
    "R0GDB_LOG",
    os.path.join(HERE, "session_protocol.log"))

if not PS5:
    raise RuntimeError(
        "Set PS5_HOST (the console address) to run the stub tools; "
        "the sanitized repo never hardcodes it.")

START_RIP_OFF = 0x4EF  # fault rip = base+0x4ef (verified on-console 2026-10-12:
                       # read at rip-0x4ef+0x228c0 returned exactly ELF@0x228c0
                       # with base=0x200000000; the old 0x4DF was a D/E typo)
VERIFY_OFF = 0x228C0
# Payload symbol offsets (link-relative vaddrs, from nm of the CURRENT build:
# sha256 345d23107c626fb3ebb3bb55a8a8b03ac5c88c7d67ebe5054b8c45eec814c830 —
# the deadlock-fix + oversize-recovery + auto-cleanup build (PRs
# #60+#62+#67); the BSS moved ~+0x11000 vs the f92401 build; #67 shifted
# r0gdb/r0gdb_exit again (+0x24E). Build is reproducible (rebuild = same sha)).
SYM_KDATA_BASE = 0x49508
SYM_OFFSETS = 0x5A5E0
SYM_OG_TSS = 0x495A0
SYM_OG_IDT1 = 0x49560
SYM_OG_IDT6 = 0x49570
SYM_OG_IDT9 = 0x49580
SYM_OG_IDT179 = 0x49590
SYM_IDT6_PATCHED = 0x4955C
SYM_R0GDB = 0x4876
SYM_R0GDB_EXIT = 0x479F
# The old gadget scratch slots (0x2AC80/0x2AC90, f92401 build): RETIRED for
# ring-0 use (SMEP: userland rip at CPL0 = #PF panic) AND stale in this build
# (that range is now live LOAD1 code). Ring-0 stores go through the
# kernel-text store_rax_rdi gadget.
# M-test scratch (level 1): the BSS segment tail (LOAD3 memsz ends 0x5B158;
# the last aligned slot, beyond every symbol — linker padding). The old
# 0x2AC00 scratch was tail padding of the f92401 LOAD1; live code now.
SYM_M_TEST = 0x5B148
EFER_MSR = 0xC0000080
OFFSET_LIST = os.environ.get(
    "R0GDB_OFFSET_LIST",
    os.path.join(HERE, "..", "r0gdb", "prosper0gdb", "offsets", "offset_list.txt"))

QWORD_REGS = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
              "r8","r9","r10","r11","r12","r13","r14","r15","rip"]
DWORD_REGS = ["eflags","cs","ss","ds","es","fs","gs"]
REG_BYTES = 168
REG_DATA_BYTES = 164
CORE_HEX = REG_BYTES * 2

T0 = time.time()
LOGF = open(LOG_PATH, "ab", buffering=0)

def log(fmt, *a):
    msg = ("[%9.3f] " % (time.time() - T0)) + (fmt % a if a else fmt)
    print(msg, flush=True)
    LOGF.write((msg + "\n").encode())

def hexs(v): return "0x%016x" % v

def _probe(port):
    try:
        c = socket.create_connection((PS5, port), timeout=SCAN_TIMEOUT)
        c.close()
        return port
    except OSError:
        return None

def scan_open_ports():
    """Parallel scan of PORT_SCAN_LO..PORT_SCAN_HI. Returns the open set."""
    ports = range(PORT_SCAN_LO, PORT_SCAN_HI + 1)
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        found = set(p for p in ex.map(_probe, ports) if p is not None)
    return found

def expected_stub_port(open_set):
    """The stub binds the first port >= 1234 that is free. Compute it."""
    for p in range(PORT_SCAN_LO, PORT_SCAN_HI + 1):
        if p not in open_set:
            return p
    return None

def send_payload():
    log("[0] sending payload...")
    r = subprocess.run(
        ["python3", SEND_ELF, ELF_PATH,
         "--host", PS5, "--port", str(PS5_ELFLDR_PORT),
         "--wait-response", "--read-timeout", "8"],
        capture_output=True, text=True, timeout=30)
    ck = sum(1 for l in r.stdout.splitlines()
            if l.startswith("[D") or l.startswith("[B1]"))
    log("[0] payload sent (%d checkpoints)", ck)
    return ck >= 3

def elf_vaddr_bytes(vaddr, size):
    with open(ELF_PATH, "rb") as f:
        eh = f.read(64)
        phoff = int.from_bytes(eh[32:40], "little")
        phent = int.from_bytes(eh[54:56], "little")
        phnum = int.from_bytes(eh[56:58], "little")
        f.seek(phoff)
        for _ in range(phnum):
            ph = f.read(phent)
            if int.from_bytes(ph[0:4], "little") == 1:
                off = int.from_bytes(ph[8:16], "little")
                va = int.from_bytes(ph[16:24], "little")
                fs = int.from_bytes(ph[32:40], "little")
                if va <= vaddr < va + fs:
                    f.seek(off + (vaddr - va))
                    return f.read(size)
    raise RuntimeError("vaddr not in PT_LOAD")

class Session:
    def __init__(self, sock):
        self.s = sock
        self.s.settimeout(60)
        self.buf = b""
        self.reg_padding = b"\0" * 4

    def send_packet(self, data):
        pkt = b"$" + data + b"#" + ("%02x" % (sum(data) & 0xFF)).encode()
        log(">> %s", pkt[:60].decode('ascii', 'replace'))
        self.s.sendall(pkt)

    def read_packet(self, timeout=60):
        deadline = time.monotonic() + timeout
        while b"$" not in self.buf:
            self._recv(deadline, "start")
        self.buf = self.buf[self.buf.index(b"$") + 1:]
        while b"#" not in self.buf or len(self.buf.split(b"#", 1)[1]) < 2:
            self._recv(deadline, "body")
        body, rest = self.buf.split(b"#", 1)
        self.buf = rest[2:]
        self.s.sendall(b"+")
        log("<< %s... (%d bytes)", body[:40].decode('ascii', 'replace'), len(body))
        if int(rest[:2], 16) != sum(body) & 0xFF:
            raise RuntimeError("checksum mismatch")
        return body

    def _recv(self, deadline, ctx):
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("timeout: " + ctx)
        self.s.settimeout(rem)
        chunk = self.s.recv(4096)
        if not chunk:
            raise ConnectionError("closed: " + ctx)
        self.buf += chunk

    def cmd(self, data, timeout=60):
        self.send_packet(data)
        return self.read_packet(timeout)

    def read_regs(self):
        body = self.cmd(b"g")
        if len(body) < CORE_HEX:
            raise RuntimeError("short g reply %d" % len(body))
        raw = bytes.fromhex(body[:CORE_HEX].decode())
        self.reg_padding = raw[REG_DATA_BYTES:REG_BYTES]
        regs = {}
        pos = 0
        for name in QWORD_REGS:
            regs[name] = int.from_bytes(raw[pos:pos+8], "little"); pos += 8
        for name in DWORD_REGS:
            regs[name] = int.from_bytes(raw[pos:pos+4], "little"); pos += 4
        return regs

    def write_regs(self, regs):
        body = b""
        for name in QWORD_REGS:
            body += regs[name].to_bytes(8, "little").hex().encode()
        for name in DWORD_REGS:
            body += regs[name].to_bytes(4, "little").hex().encode()
        body += self.reg_padding.hex().encode()
        if len(body) != CORE_HEX:
            raise RuntimeError("register packet size %d" % len(body))
        r = self.cmd(b"G" + body)
        if r != b"OK":
            raise RuntimeError("G reply: %r" % r)

    def step(self, timeout=60):
        r = self.cmd(b"s", timeout=timeout)
        if r != b"OK":
            raise RuntimeError("s reply: %r" % r)
        return self.read_packet(timeout=timeout)

    def cont(self, timeout=90):
        r = self.cmd(b"c", timeout=timeout)
        if r != b"OK":
            raise RuntimeError("c reply: %r" % r)
        return self.read_packet(timeout=timeout)

    def read_mem(self, addr, size):
        r = self.cmd(b"m%x,%x" % (addr, size))
        # Never test the first char for 'E' (valid data can start 0xE0-0xEF;
        # the stub never sends E-replies for m — a failed read is short).
        # Found live by level 2 (2026-10-12).
        if len(r) != size * 2:
            raise RuntimeError("m reply: %r" % r[:32])
        return bytes.fromhex(r.decode())

    def write_mem(self, addr, data):
        r = self.cmd(b"M%x,%x:" % (addr, len(data)) + data.hex().encode())
        if r != b"OK":
            raise RuntimeError("M reply: %r" % r)


def load_offset_fields():
    fields = []
    with open(OFFSET_LIST) as f:
        for line in f:
            line = line.strip()
            for kind in ("KDATA_OFFSET(", "ABSOLUTE_OFFSET(", "OPTIONAL_KDATA_OFFSET("):
                if line.startswith(kind):
                    fields.append(line[len(kind):].rstrip(")"))
    return fields


def read_offsets(s, base):
    """Read the payload's copy of the kernel offset table (payload memory)."""
    fields = load_offset_fields()
    fidx = {name: i for i, name in enumerate(fields)}
    raw = s.read_mem(base + SYM_OFFSETS, len(fields) * 8)
    return {name: int.from_bytes(raw[i*8:(i+1)*8], "little")
            for name, i in fidx.items()}


def connect_stub(stub_port):
    """Connect, '+', '?' handshake, base verification. Returns (sock, Session, base, kdata)."""
    c = socket.create_connection((PS5, stub_port), timeout=5)
    c.settimeout(10)
    c.sendall(b"+")   # the ONE connection the stub accepts; it expects '+' first
    s = Session(c)
    s.send_packet(b"?")
    r = s.read_packet(timeout=8)
    if not r.startswith(b"T"):
        c.close()
        raise RuntimeError("no T-packet from '?' (got %r)" % r[:20])
    regs = s.read_regs()
    base = regs["rip"] - START_RIP_OFF
    if s.read_mem(base + VERIFY_OFF, 16) != elf_vaddr_bytes(VERIFY_OFF, 16):
        c.close()
        raise RuntimeError("base verification mismatch")
    kdata = int.from_bytes(s.read_mem(base + SYM_KDATA_BASE, 8), "little")
    if kdata >> 48 != 0xFFFF:
        c.close()
        raise RuntimeError("kdata_base implausible: 0x%x" % kdata)
    return c, s, base, kdata


def park(sock, why):
    """Hold the socket open: the target may be in a modified state.
    Keeps a reference to sock so GC cannot close it."""
    try:
        log("!!! PARKED: %s", why)
        log("!!! Socket held open. POWER-CYCLE THE CONSOLE to end.")
        log("!!! Killing this script may PANIC the console.")
        log("!!! Protocol log: %s", LOG_PATH)
    except Exception:
        pass
    try:
        sock.settimeout(None)   # reference held for the duration
    except Exception:
        pass
    while True:
        try:
            time.sleep(3600)
        except BaseException:
            continue

def discover(no_send=False):
    """Anti-zombie port discovery: pre-scan, compute the port the stub WILL
    bind (first free >= 1234, matching dbg.c's bind loop), send the payload,
    return the port. Never post-scans — a post-scan probe would steal the
    stub's single accept() and kill it. Returns None on failure."""
    log("[0] pre-scanning ports %d-%d (parallel)...", PORT_SCAN_LO, PORT_SCAN_HI)
    pre = scan_open_ports()
    log("[0] pre-scan: open ports (zombies): %s",
        sorted(pre) if pre else "none")

    expect = expected_stub_port(pre)
    if expect is None:
        log("[0] FAIL: no free port in %d-%d", PORT_SCAN_LO, PORT_SCAN_HI)
        return None
    log("[0] computed stub port: %d (first free >= 1234)", expect)

    if not no_send:
        if not send_payload():
            log("[0] FAIL: payload send incomplete")
            return None
        # Grace period for bind+listen+accept setup.
        time.sleep(2)
    else:
        log("[0] --no-send: assuming stub already at %d", expect)
    return expect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args()

    stub_port = args.port if args.port is not None else discover(args.no_send)
    if stub_port is None:
        return 1

    log("=" * 60)
    log("LEVEL 1: userland-only verification (zero ring-0 risk)")
    log("=" * 60)

    try:
        c, s, base, kdata = connect_stub(stub_port)
    except Exception as e:
        log("FAIL: connect/verify: %s: %s", type(e).__name__, e)
        return 1
    log("[V1] handshake + registers + base (0x%x) + kdata (%s)  OK",
        base, hexs(kdata))

    # M write/read/restore test (payload's own memory)
    test_addr = base + SYM_M_TEST
    orig = s.read_mem(test_addr, 4)
    s.write_mem(test_addr, b"\xde\xad\xbe\xef")
    if s.read_mem(test_addr, 4) != b"\xde\xad\xbe\xef":
        log("FAIL: M write/read mismatch")
        return 1
    s.write_mem(test_addr, orig)
    if s.read_mem(test_addr, 4) != orig:
        log("FAIL: M restore mismatch")
        return 1
    log("[V1] M write/read/restore  OK")

    c.close()
    log("")
    log("LEVEL 1 PASSED")
    log("Next: stub_verify2.py (ring-0 entry + EFER)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
