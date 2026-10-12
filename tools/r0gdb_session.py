#!/usr/bin/env python3
"""r0gdb ring-0 session client (v5, computed-port anti-zombie harness).

v5.1 changes (2026-10-12, ported from the hardened level-2 design):
  - STAGE G uses ONLY the kernel-text store_rax_rdi gadget. The old path
    stepped rip at base+GADGET_WRITE_QWORD (userland payload memory) at
    CPL0 — the exact SMEP #PF panic mode live-confirmed on Oct 9 (the
    0f20e0 CR4 attempt). GADGET_WRITE_QWORD is retired for ring-0 use.
  - Stage G ports the full validation from level 2: per-store m readback,
    canonical-kernel targets, saved+live TSS IST checks (restoring every
    word INCLUDING zeros), saved+live IDT gate checks (selector/IST/attr
    per vector) before any write.
  - STAGE C stages an ABI-aligned call frame below the user rsp so the
    exit can be VERIFIED to return to the exact original RIP/RSP.
  - Stage B pins the live offset deltas to the 12.02 table (offsets.c
    selects set_offsets_1202() from the console's sysctl FW version).
  - All of this is PENDING LIVE VALIDATION via level 2 (stub_verify2.py)
    before any real session run.

v5 changes (2026-10-12, after on-console validation of stub_verify level 1):
  - COMPUTED PORT, never post-scan. The stub binds the first FREE port
    scanning up from 1234 (dbg.c bind loop), so the expected stub port is
    simply the first port >= 1234 that the PRE-scan finds closed. A
    post-scan would steal the stub's single accept() (it reads exactly
    one byte and exits if it is not '+') and silently kill it.
  - Pre-scan is PARALLEL (threads) over 1234-1400. Closed ports drop SYNs
    (no RST), so each miss costs the full connect timeout; the old
    sequential 1234-22000 scan took >120s with zero progress.
  - Pre-scan probes DO connect to zombie stub ports; a zombie sitting in
    accept() exits on the probe (its '+' read fails). Acceptable —
    zombies are stale — but the pre-scan can clean them as a side effect.
  - START_RIP_OFF corrected: 0x4DF -> 0x4EF (the fault rip is base+0x4ef;
    verified on-console: reading at rip-0x4ef+0x228c0 returned exactly
    the ELF bytes at vaddr 0x228c0 with base=0x200000000).

v4 changes (2026-10-12, after the zombie-port root-cause discovery):
  - STAGE 0: automatically send a fresh payload; connect only to the
    computed port (never to a pre-existing zombie).
  - If --no-send is passed, probe live ports for one that speaks RSP.

Protocol facts (gdb_stub/dbg.c, verified live on 2026-10-12):
  - '+' handshake byte consumes the one-shot accept; every stub reply must
    be ACKed with '+' (end_packet blocks on it).
  - g reply = the 168-byte struct regs (17 qwords + 7 dwords + 4 bytes
    alignment padding), encoded as 336 hex chars, then 'x' padding to 1120.
  - 'c' replies OK then free-runs. 's' replies OK then executes ONE
    instruction at ts.regs.rip (the r0gdb loop forces TF every round).
  - m/M packets are userland-only (kernel addresses fail EFAULT).
  - The first LOAD is RWE (gadget scratch at link 0x2ac50..0x2c000).

Hardening (from the 2026-10-09 crash):
  - PARK MODE: never close the socket on anomaly.
  - Byte-level protocol log (session_protocol.log).
  - All boot constants derived live from payload statics.
  - Clean exit restores IDT/TSS via mov-gadget single-steps.

Usage:
    python3 r0gdb_session.py              # auto: send payload + computed port
    python3 r0gdb_session.py --no-send    # manual: assume payload running
    python3 r0gdb_session.py --port 1234  # manual: specific port
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

PS5 = os.environ.get("PS5_HOST", "")
PS5_ELFLDR_PORT = 9021
PORT_SCAN_LO = 1234
PORT_SCAN_HI = 1400   # the stub binds the FIRST free port >= 1234; ample
SCAN_TIMEOUT = 0.5
SCAN_WORKERS = 64
HERE = os.path.dirname(os.path.abspath(__file__))
ELF_PATH = os.environ.get(
    "R0GDB_ELF",
    os.path.join(HERE, "kstuff-lite/prosper0gdb/sdk-build/payload-elfldr-sdk.elf"))
SEND_ELF = os.environ.get(
    "R0GDB_SEND_ELF",
    os.path.join(HERE, "../../send_elf.py"))
OFFSET_LIST = os.environ.get(
    "R0GDB_OFFSET_LIST",
    os.path.join(HERE, "..", "r0gdb", "prosper0gdb", "offsets", "offset_list.txt"))
LOG_PATH = os.environ.get(
    "R0GDB_LOG",
    os.path.join(HERE, "session_protocol.log"))

if not PS5:
    raise RuntimeError(
        "Set PS5_HOST (the console address) to run the stub tools; "
        "the sanitized repo never hardcodes it.")

# Payload symbol offsets (link-relative vaddrs, from nm of the CURRENT build:
# sha256 a8276b5aa26c47e042f9ee750bdbfab433da9db35174f6679bfd23bd37aaf2b4 —
# the deadlock-fix + oversize-recovery + auto-cleanup build (PRs
# #60+#62+#67); the BSS moved ~+0x11000 vs the f92401 build; #67 shifted
# r0gdb/r0gdb_exit again (+0x24E). Build is reproducible (rebuild = same sha)).
SYM_KDATA_BASE = 0x49508
SYM_OFFSETS = 0x5A600
SYM_OG_TSS = 0x495A0
SYM_OG_IDT1 = 0x49560
SYM_OG_IDT6 = 0x49570
SYM_OG_IDT9 = 0x49580
SYM_OG_IDT179 = 0x49590
SYM_IDT6_PATCHED = 0x4955C
SYM_R0GDB = 0x4993
SYM_R0GDB_EXIT = 0x480F

START_RIP_OFF = 0x4EF  # fault rip = base+0x4ef (verified on-console; 0x4DF was a
                       # typo; unchanged in the deadlock-fix build — the call
                       # dbg_enter at 0x4e9 is still 6 bytes)
VERIFY_OFF = 0x228C0   # any unique LOAD1 location; compared against THIS build's ELF
GADGET_RD_CR4 = 0x2AC80      # RETIRED (SMEP: userland rip at CPL0 = #PF panic) AND
                             # STALE in the current build (live LOAD1 code now)
GADGET_WRITE_QWORD = 0x2AC90  # RETIRED (same SMEP mode) AND STALE; stage G uses the
                              # kernel-text store_rax_rdi gadget from the offset table

EFER_MSR = 0xC0000080

QWORD_REGS = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
              "r8","r9","r10","r11","r12","r13","r14","r15","rip"]
DWORD_REGS = ["eflags","cs","ss","ds","es","fs","gs"]
REG_BYTES = 168
REG_DATA_BYTES = 164
CORE_HEX = REG_BYTES * 2
MAX_PACKET = 8192

T0 = time.time()
LOGF = open(LOG_PATH, "ab", buffering=0)


def log(fmt, *a):
    msg = ("[%9.3f] " % (time.time() - T0)) + (fmt % a if a else fmt)
    print(msg)
    LOGF.write((msg + "\n").encode())


class Parked(Exception):
    pass


# ==== ANTI-ZOMBIE HARNESS (stage 0) =========================================

def scan_open_ports(timeout=SCAN_TIMEOUT):
    """Parallel scan: return the set of TCP ports that accept connections.
    Closed ports on this console drop SYNs (no RST), so each miss costs the
    full connect timeout — hence threads, and hence the narrow window
    (the stub binds the first free port >= 1234 anyway)."""
    ports = range(PORT_SCAN_LO, PORT_SCAN_HI + 1)
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
        def probe(port):
            try:
                c = socket.create_connection((PS5, port), timeout=timeout)
                c.close()
                return port
            except OSError:
                return None
        found = set(p for p in ex.map(probe, ports) if p is not None)
    return found


def expected_stub_port(open_ports):
    """The stub binds the FIRST port >= 1234 whose bind succeeds (dbg.c).
    So the port it will take is the first closed port >= 1234."""
    for p in range(PORT_SCAN_LO, PORT_SCAN_HI + 1):
        if p not in open_ports:
            return p
    return None


def send_payload():
    """Send the r0gdb payload via elfldr."""
    log("[0] sending payload via elfldr (%s)...", ELF_PATH)
    result = subprocess.run(
        ["python3", SEND_ELF, ELF_PATH,
         "--host", PS5, "--port", str(PS5_ELFLDR_PORT),
         "--wait-response", "--read-timeout", "8"],
        capture_output=True, text=True, timeout=30)
    output = result.stdout
    # Count the D-checkpoints that appeared
    checkpoints = sum(1 for line in output.splitlines()
                     if line.startswith("[D") or line.startswith("[B1]"))
    log("[0] payload sent (%d checkpoint lines in output)", checkpoints)
    return checkpoints >= 3  # D1..D4 minimum


# ==== SESSION (RSP protocol) ================================================

class Session:
    def __init__(self, sock):
        self.s = sock
        self.s.settimeout(60)
        self.buf = b""
        self.reg_padding = b"\0" * (REG_BYTES - REG_DATA_BYTES)

    def send_packet(self, data: bytes):
        csum = sum(data) & 0xFF
        pkt = b"$" + data + b"#" + ("%02x" % csum).encode()
        log(">> %s", pkt[:72].decode('ascii', 'replace'))
        self.s.sendall(pkt)

    def read_packet(self, timeout=60) -> bytes:
        deadline = time.monotonic() + timeout
        while b"$" not in self.buf:
            self._recv(deadline, "packet start")
        i = self.buf.index(b"$")
        if i:
            log("!! discarded pre-frame: %s", self.buf[:i].hex())
        self.buf = self.buf[i + 1:]
        while True:
            marker = self.buf.find(b"#")
            if marker >= 0 and len(self.buf) >= marker + 3:
                break
            if len(self.buf) > MAX_PACKET + 3:
                raise Parked("RSP packet exceeds %d bytes" % MAX_PACKET)
            self._recv(deadline, "packet body")
        body, rest = self.buf.split(b"#", 1)
        checksum_bytes, self.buf = rest[:2], rest[2:]
        try:
            received = int(checksum_bytes, 16)
        except ValueError:
            received = -1
        calculated = sum(body) & 0xff
        self.s.sendall(b"+")  # ACK (stub blocks without it)
        log("<< %s... (%d bytes)", body[:48].decode('ascii', 'replace'), len(body))
        if received != calculated:
            raise Parked("RSP checksum mismatch: %r vs %02x" %
                         (checksum_bytes, calculated))
        return body

    def _recv(self, deadline, context):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timeout: %s" % context)
        self.s.settimeout(remaining)
        chunk = self.s.recv(4096)
        if not chunk:
            raise ConnectionError("stub closed: %s" % context)
        self.buf += chunk

    def cmd(self, data: bytes, timeout=60) -> bytes:
        self.send_packet(data)
        return self.read_packet(timeout)

    def read_regs(self) -> dict:
        body = self.cmd(b"g")
        if len(body) < CORE_HEX or len(body) > 1120 or \
           any(c != ord("x") for c in body[CORE_HEX:]):
            raise Parked("bad g reply len=%d" % len(body))
        raw = bytes.fromhex(body[:CORE_HEX].decode())
        self.reg_padding = raw[REG_DATA_BYTES:REG_BYTES]
        regs = {}
        pos = 0
        for name in QWORD_REGS:
            regs[name] = int.from_bytes(raw[pos:pos+8], "little")
            pos += 8
        for name in DWORD_REGS:
            regs[name] = int.from_bytes(raw[pos:pos+4], "little")
            pos += 4
        return regs

    def write_regs(self, regs: dict):
        body = b""
        for name in QWORD_REGS:
            body += regs[name].to_bytes(8, "little").hex().encode()
        for name in DWORD_REGS:
            body += regs[name].to_bytes(4, "little").hex().encode()
        body += self.reg_padding.hex().encode()
        if len(body) != CORE_HEX:
            raise Parked("register packet size %d" % len(body))
        r = self.cmd(b"G" + body)
        if r != b"OK":
            raise Parked("G reply: %r" % r)

    def read_mem(self, addr: int, size: int) -> bytes:
        r = self.cmd(b"m%x,%x" % (addr, size))
        # Never test the first char for 'E' (valid data can start 0xE0-0xEF;
        # the stub never sends E-replies for m — a failed read is short).
        # Found live by level 2 (2026-10-12).
        if len(r) != size * 2:
            raise Parked("m reply: %r" % r[:32])
        return bytes.fromhex(r.decode())

    def write_mem(self, addr: int, data: bytes):
        r = self.cmd(b"M%x,%x:" % (addr, len(data)) + data.hex().encode())
        if r != b"OK":
            raise Parked("M reply: %r" % r)

    def step(self, timeout=60) -> bytes:
        r = self.cmd(b"s", timeout=timeout)
        if r != b"OK":
            raise Parked("s reply: %r" % r)
        return self.read_packet(timeout=timeout)

    def cont(self, timeout=90) -> bytes:
        r = self.cmd(b"c", timeout=timeout)
        if r != b"OK":
            raise Parked("c reply: %r" % r)
        return self.read_packet(timeout=timeout)


# ==== HELPERS ================================================================

def hexs(v):
    return "0x%016x" % v


def _is_kernel_address(value):
    return value >> 48 == 0xFFFF


def elf_vaddr_bytes(vaddr: int, size: int) -> bytes:
    with open(ELF_PATH, "rb") as f:
        eh = f.read(64)
        phoff = int.from_bytes(eh[32:40], "little")
        phentsize = int.from_bytes(eh[54:56], "little")
        phnum = int.from_bytes(eh[56:58], "little")
        f.seek(phoff)
        for _ in range(phnum):
            ph = f.read(phentsize)
            p_type = int.from_bytes(ph[0:4], "little")
            p_offset = int.from_bytes(ph[8:16], "little")
            p_vaddr = int.from_bytes(ph[16:24], "little")
            p_filesz = int.from_bytes(ph[32:40], "little")
            if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
                f.seek(p_offset + (vaddr - p_vaddr))
                return f.read(size)
    raise Parked("vaddr %#x not in PT_LOAD" % vaddr)


def load_offset_fields():
    fields = []
    with open(OFFSET_LIST) as f:
        for line in f:
            line = line.strip()
            for kind in ("KDATA_OFFSET(", "ABSOLUTE_OFFSET(", "OPTIONAL_KDATA_OFFSET("):
                if line.startswith(kind):
                    fields.append(line[len(kind):].rstrip(")"))
    return fields


def park(sock, why):
    try:
        log("!!! PARKED: %s", why)
        log("!!! Socket held open. POWER-CYCLE THE CONSOLE to end.")
        log("!!! Killing this script may PANIC the console.")
        log("!!! Protocol log: %s", LOG_PATH)
    except Exception:
        pass
    try:
        sock.settimeout(None)
        while True:
            try:
                time.sleep(3600)
            except BaseException:
                continue
    except BaseException:
        while True:
            try:
                time.sleep(3600)
            except BaseException:
                continue


# ==== MAIN ==================================================================

def main():
    parser = argparse.ArgumentParser(description="r0gdb session client")
    parser.add_argument("--no-send", action="store_true",
                        help="don't send a payload (assume one is running)")
    parser.add_argument("--port", type=int, default=None,
                        help="connect to a specific port (bypasses scan)")
    args = parser.parse_args()

    for sig_name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            signal.signal(sig, sig.SIG_IGN)

    # ---- stage 0: anti-zombie payload delivery ----------------------------
    stub_port = args.port
    if stub_port is None:
        if args.no_send:
            log("[0] --no-send: scanning for live stub...")
            # Try all open ports, looking for one that responds to RSP
            for port in sorted(scan_open_ports()):
                try:
                    c = socket.create_connection((PS5, port), timeout=2)
                    c.settimeout(4)
                    c.sendall(b"+")
                    s = Session(c)
                    s.send_packet(b"?")
                    r = s.read_packet(timeout=4)
                    if r.startswith(b"T"):
                        stub_port = port
                        log("[0] found live stub on port %d", port)
                        break
                    c.close()
                except Exception:
                    try: c.close()
                    except: pass
        else:
            # Full auto: pre-scan → compute the port the stub WILL bind →
            # send → connect straight to it. NEVER post-scan: a post-scan
            # probe steals the stub's single accept() (it reads exactly
            # one byte and exits if it is not '+') and silently kills it.
            log("[0] pre-scanning ports %d-%d (parallel)...",
                PORT_SCAN_LO, PORT_SCAN_HI)
            pre = scan_open_ports()
            log("[0] pre-scan: %d open ports (zombies): %s",
                len(pre), sorted(pre) if len(pre) < 20 else "(many)")

            stub_port = expected_stub_port(pre)
            if stub_port is None:
                log("[0] FAIL: no free port in %d-%d",
                    PORT_SCAN_LO, PORT_SCAN_HI)
                return 1
            log("[0] computed stub port: %d (first free >= 1234, matching "
                "the stub's own bind loop)", stub_port)

            if not send_payload():
                log("[0] FAIL: payload send incomplete")
                return 1

            # Grace period for bind+listen+accept setup.
            time.sleep(2)

    if stub_port is None:
        log("FAIL: no stub port found")
        return 1

    # ---- stage A: connect + one-shot accept --------------------------------
    sock = None
    try:
        c = socket.create_connection((PS5, stub_port), timeout=5)
        c.settimeout(10)
        c.sendall(b"+")
        s = Session(c)
        s.send_packet(b"?")
        r = s.read_packet(timeout=8)
        log("[A] port %d: '?' -> %r", stub_port, r)
        if r.startswith(b"T"):
            sock = c
        else:
            park(c, "stub replied %r (not a T-packet)" % r)
            return 1
    except Exception as e:
        log("[A] FAIL: %s: %s", type(e).__name__, e)
        return 1
    log("[A] live stub acquired on port %d", stub_port)

    try:
        # ---- stage B: base + live constants --------------------------------
        s.cmd(b"?")
        regs = s.read_regs()
        log("[B] initial regs: rip=%s rsp=%s", hexs(regs["rip"]), hexs(regs["rsp"]))
        base = regs["rip"] - START_RIP_OFF
        expect = elf_vaddr_bytes(VERIFY_OFF, 16)
        got = s.read_mem(base + VERIFY_OFF, 16)
        if got != expect:
            raise Parked("base verification failed")
        log("[B] base VERIFIED: %s", hexs(base))

        kdata = int.from_bytes(s.read_mem(base + SYM_KDATA_BASE, 8), "little")
        log("[B] kdata_base (live) = %s", hexs(kdata))

        fields = load_offset_fields()
        fidx = {name: i for i, name in enumerate(fields)}
        raw = s.read_mem(base + SYM_OFFSETS, len(fields) * 8)
        offs = {name: int.from_bytes(raw[i*8:(i+1)*8], "little")
                for name, i in fidx.items()}
        for name in ("rdmsr_start", "mov_rax_cr0", "store_rax_rdi",
                     "tss_array", "idt"):
            if not _is_kernel_address(offs[name]):
                raise Parked("offset %s implausible: %s" % (name, hexs(offs[name])))
            log("[B] offsets.%s = kdata%s", name, hexs(offs[name] - kdata))

        # Pin the live table to offsets/12_02.h (the payload dispatches
        # set_offsets_1202() from this console's sysctl FW version; the
        # deltas are kdata-relative). Same pin as level 2.
        EXPECTED_FW_DELTAS = {
            "rdmsr_start": -0xA9E10A,
            "mov_rax_cr0": -0xAA3C61,
            "store_rax_rdi": -0xAA3EEE,
            "tss_array": 0x2E8AFE0,
            "idt": 0x2E88300,
        }
        for name, expected in EXPECTED_FW_DELTAS.items():
            delta = offs[name] - kdata
            if delta != expected:
                raise Parked("offset %s does not match the pinned 12.02 "
                             "table: got 0x%x expected 0x%x" %
                             (name, delta, expected))

        # ---- stage C: ring-0 entry (staged ABI call frame) -----------------
        # Ported from the hardened level-2 design: stage a real return frame
        # below the current rsp so the exit can be verified to return to the
        # exact original RIP/RSP.
        original_rip = regs["rip"]
        original_rsp = regs["rsp"]
        if not (0x10000 <= original_rip <= 0x00007FFFFFFFFFFF):
            raise Parked("initial RIP not a plausible user address: %s"
                         % hexs(original_rip))
        if not (0x10000 <= original_rsp <= 0x00007FFFFFFFFFFF):
            raise Parked("initial RSP not a plausible user stack: %s"
                         % hexs(original_rsp))
        frame_rsp = original_rsp - 8
        if frame_rsp & 0xF != 8:
            raise Parked("cannot form ABI-aligned frame from RSP=%s"
                         % hexs(original_rsp))
        old_frame_word = s.read_mem(frame_rsp, 8)
        s.write_mem(frame_rsp, original_rip.to_bytes(8, "little"))
        if s.read_mem(frame_rsp, 8) != original_rip.to_bytes(8, "little"):
            raise Parked("could not verify r0gdb return frame")
        regs["rsp"] = frame_rsp
        regs["rip"] = base + SYM_R0GDB
        s.write_regs(regs)
        log("[C] staged call frame; entering r0gdb at %s", hexs(regs["rip"]))
        stop = s.cont()
        log("[C] stop after entry: %r", stop)
        regs = s.read_regs()
        log("[C] rsp=%s rip=%s", hexs(regs["rsp"]), hexs(regs["rip"]))
        if not _is_kernel_address(regs["rsp"]):
            raise Parked("rsp not kernel stack — ring-0 entry failed")
        log("[C] RING-0 CONFIRMED (rsp=%s)", hexs(regs["rsp"]))

        def step_setup(**kw):
            r = s.read_regs()
            for k, v in kw.items():
                r[k] = v
            s.write_regs(r)

        def rd_gadget(rip):
            step_setup(rip=rip, rax=0)
            s.step()
            return s.read_regs()

        # ---- stage D: EFER sanity via rdmsr gadget ------------------------
        step_setup(rip=offs["rdmsr_start"], rcx=EFER_MSR, rax=0, rdx=0)
        efer = 0
        for i in range(16):
            s.step()
            r = s.read_regs()
            efer = (r["rdx"] << 32) | r["rax"]
            if efer != 0:
                break
        log("[D] EFER = %s (expect ~0xd01)", hexs(efer))
        if efer & 0x800 == 0:
            raise Parked("EFER looks wrong")

        # ---- stage E: live CR0 --------------------------------------------
        r = rd_gadget(offs["mov_rax_cr0"])
        log("[E] CR0 = %s", hexs(r["rax"]))

        # ---- stage F: live CR4 ---------------------------------------------
        # NOTE: userland gadget = SMEP violation = console panic (proven).
        # CR4 read requires a kernel-text gadget (not yet found on 12.02).
        log("[F] CR4: SKIPPED (no kernel-text mov rax,cr4 gadget; "
            "userland gadget = SMEP panic)")

        # ---- stage G: restore patched state ---------------------------------
        # Ported from the hardened level-2 design. ONLY the kernel-text
        # store_rax_rdi gadget: the old base+GADGET_WRITE_QWORD path stepped
        # rip at payload/user memory at CPL0 — the live-confirmed SMEP #PF
        # panic mode (Oct 9 CR4 attempt). GADGET_WRITE_QWORD is retired for
        # ring-0 use.
        wslot = offs["store_rax_rdi"]

        def kwrite(addr, val):
            if not _is_kernel_address(addr):
                raise Parked("restore target not canonical kernel data: %s"
                             % hexs(addr))
            step_setup(rip=wslot, rdi=addr, rax=val)
            s.step()
            r = s.read_regs()
            if r["rip"] != wslot + 3:
                raise Parked("store step mismatch at %s: rip=%s"
                             % (hexs(addr), hexs(r["rip"])))
            actual = int.from_bytes(s.read_mem(addr, 8), "little")
            if actual != val:
                raise Parked("store readback mismatch at %s: got %s expected %s"
                             % (hexs(addr), hexs(actual), hexs(val)))

        og = s.read_mem(base + SYM_OG_TSS, 16 * 3 * 8)
        tss = offs["tss_array"]
        current_tss = s.read_mem(tss, 16 * 0x68)
        tss_restore = []
        for cpu in range(16):
            for j, field in enumerate((0x34, 0x3C, 0x4C)):
                val = int.from_bytes(og[(cpu*3+j)*8:(cpu*3+j+1)*8], "little")
                if val and not _is_kernel_address(val):
                    raise Parked("saved TSS IST implausible: cpu=%d field=%#x"
                                 % (cpu, field))
                live = int.from_bytes(
                    current_tss[cpu*0x68+field:cpu*0x68+field+8], "little")
                if not _is_kernel_address(live):
                    raise Parked("live TSS IST not kernel pointer: cpu=%d "
                                 "field=%#x" % (cpu, field))
                tss_restore.append((tss + cpu * 0x68 + field, val))
        for field in (0x34, 0x3C, 0x4C):
            live_values = [int.from_bytes(
                current_tss[cpu*0x68+field:cpu*0x68+field+8], "little")
                for cpu in range(16)]
            if len(set(live_values)) != 1:
                raise Parked("TSS IST inconsistent across CPUs at field %#x"
                             % field)

        idt = offs["idt"]
        idt6_patched = int.from_bytes(
            s.read_mem(base + SYM_IDT6_PATCHED, 4), "little") != 0
        restore_gates = [(6, SYM_OG_IDT6)] if idt6_patched else []
        restore_gates += [(9, SYM_OG_IDT9), (179, SYM_OG_IDT179),
                          (1, SYM_OG_IDT1)]
        idt_restore = []
        for vector, sym in restore_gates:
            raw = s.read_mem(base + sym, 16)
            selector = int.from_bytes(raw[2:4], "little")
            handler = (int.from_bytes(raw[0:2], "little") |
                       (int.from_bytes(raw[6:8], "little") << 16) |
                       (int.from_bytes(raw[8:12], "little") << 32))
            if selector != 0x20 or not _is_kernel_address(handler):
                raise Parked("saved IDT vector %d implausible" % vector)
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
                raise Parked("live IDT vector %d does not match the expected "
                             "r0gdb gate" % vector)
            for half in range(2):
                val = int.from_bytes(raw[half*8:half*8+8], "little")
                idt_restore.append((idt + vector * 16 + half * 8, val))

        # Restore every IST word, including zeros; setup overwrote all three
        # fields (the old 'if val:' skip would have left patched zeros live).
        for addr, val in tss_restore:
            kwrite(addr, val)
        log("[G] TSS IST fields restored (incl. zeros) and read back")

        # Restore the IDT entries with vector 1 last, preserving the stub's
        # single-step path until the other modified gates are back.
        for addr, val in idt_restore:
            kwrite(addr, val)
        log("[G] IDT gates restored and read back (vector 1 last)")

        # ---- stage H: verified return ----------------------------------------
        step_setup(rip=base + SYM_R0GDB_EXIT)
        exit_stop = s.cont(timeout=90)
        log("[H] return stop: %r", exit_stop)
        returned = s.read_regs()
        if (returned["rip"] != original_rip or
                returned["rsp"] != original_rsp):
            raise Parked("r0gdb return did not restore original RIP/RSP: "
                         "rip=%s rsp=%s" % (hexs(returned["rip"]),
                                            hexs(returned["rsp"])))
        s.write_mem(frame_rsp, old_frame_word)
        if s.read_mem(frame_rsp, 8) != old_frame_word:
            raise Parked("could not restore the original user-stack word")
        sock.close()
        log("[H] verified userland return; frame word restored; closed")
        log("SESSION COMPLETE")
        return 0
    except Exception as e:
        park(sock, "%s: %s" % (type(e).__name__, e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
