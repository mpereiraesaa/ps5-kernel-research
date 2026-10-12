#!/usr/bin/env python3
"""experiment_exit — ring-0 experiment 1: the minimal window (enter, exit).

The smallest ring-0 session possible: staged-frame entry -> T05 synthetic
stop -> IMMEDIATE rip=r0gdb_exit -> 'c'. The stub (PR #67) then runs
r0gdb_cleanup() itself (SFMASK via run_in_kernel, then TSS ISTs, then IDT
gates last, each verified) and returns through the staged frame.

Purpose (the diagnosis for the two 2026-10-12 incidents):
- validates the exit + auto-cleanup path live for the first time
- if the console SURVIVES this milliseconds-scale patched window but died
  in the earlier ~0.3s-25min windows, the window duration is the variable
- no client-driven kernel writes (the auto-cleanup replaces the old
  stage-G restore), so --verified-store-gadget is not required

Accepted SUCCESS outcomes (observed, not assumed):
  (a) a stop packet with rip == original_rip  -> the verified return
  (b) a CLEAN EOF                             -> the process exited
      normally after cleanup + main return
Either way the post-run console liveness check is the real criterion.
A timeout is the freeze class -> park.

Run stub_verify.py (level 1) green on the same build first.
"""
import argparse
import sys

from stub_verify import *  # noqa: F401,F403

RING1 = {"attempted": False, "sock": None, "frame": None}


def _is_kernel_address(v):
    return v >> 48 == 0xFFFF


def experiment_exit(stub_port):
    try:
        return _inner(stub_port)
    except Exception as e:
        why = "%s: %s" % (type(e).__name__, e)
        sock = RING1["sock"]
        if RING1["attempted"] and sock is not None:
            frame = RING1["frame"]
            if frame is not None:
                session, addr, original = frame
                try:
                    session.write_mem(addr, original)
                    RING1["frame"] = None
                except BaseException:
                    pass
            park(sock, why)
            return 2
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        log("EXPERIMENT 1 FAILED (pre-attempt, nothing patched): %s", why)
        return 1


def _inner(stub_port):
    RING1["attempted"] = False
    RING1["sock"] = None
    RING1["frame"] = None

    c, s, base, kdata = connect_stub(stub_port)
    RING1["sock"] = c
    log("[E1] connected; base=%s kdata=%s", hexs(base), hexs(kdata))

    offs = read_offsets(s, base)
    for name in ("rdmsr_start", "tss_array", "idt"):
        delta = offs[name] - kdata
        if not _is_kernel_address(offs[name]):
            raise RuntimeError("offset %s implausible: %s" % (name, hexs(offs[name])))
        log("[E1] offsets.%s = kdata%s", name, hexs(delta))
    EXPECTED = {"rdmsr_start": -0xA9E10A, "tss_array": 0x2E8AFE0, "idt": 0x2E88300}
    for name, want in EXPECTED.items():
        if offs[name] - kdata != want:
            raise RuntimeError("offset %s not on the 12.02 pin: got 0x%x want 0x%x"
                               % (name, offs[name] - kdata, want))

    # Staged return frame (same as level 2).
    entry_regs = s.read_regs()
    original_rip = entry_regs["rip"]
    original_rsp = entry_regs["rsp"]
    if not (0x10000 <= original_rip <= 0x00007FFFFFFFFFFF):
        raise RuntimeError("initial RIP not a plausible user address: %s" % hexs(original_rip))
    if not (0x10000 <= original_rsp <= 0x00007FFFFFFFFFFF):
        raise RuntimeError("initial RSP not a plausible user stack: %s" % hexs(original_rsp))
    frame_rsp = original_rsp - 8
    if frame_rsp & 0xF != 8:
        raise RuntimeError("cannot form ABI-aligned frame from RSP=%s" % hexs(original_rsp))
    old_word = s.read_mem(frame_rsp, 8)
    RING1["frame"] = (s, frame_rsp, old_word)
    s.write_mem(frame_rsp, original_rip.to_bytes(8, "little"))
    if s.read_mem(frame_rsp, 8) != original_rip.to_bytes(8, "little"):
        raise RuntimeError("could not verify the staged frame word")

    # Ring-0 entry.
    entry_regs["rsp"] = frame_rsp
    entry_regs["rip"] = base + SYM_R0GDB
    RING1["attempted"] = True
    s.write_regs(entry_regs)
    log("[E1] staged frame; entering r0gdb at %s", hexs(entry_regs["rip"]))
    stop = s.cont()
    log("[E1] first debugger stop: %r", stop)
    regs = s.read_regs()
    log("[E1] synthetic stop: rsp=%s rip=%s", hexs(regs["rsp"]), hexs(regs["rip"]))
    if not _is_kernel_address(regs["rsp"]):
        raise RuntimeError("debugger stop did not report a kernel-stack RSP")

    # THE EXPERIMENT: exit immediately. No g, no G, no steps, no client
    # restores. The window is: entry -> exit -> auto-cleanup -> return.
    r = s.read_regs()
    r["rip"] = base + SYM_R0GDB_EXIT
    s.write_regs(r)
    log("[E1] rip=r0gdb_exit (%s); 'c' - the stub should run its own cleanup "
        "and return through the staged frame", hexs(r["rip"]))
    s.send_packet(b"c")

    outcome = "timeout"
    try:
        # Either a stop packet (verified return) or a clean EOF (process
        # exited normally after cleanup). Both are observed-success class.
        deadline_wait = 45
        reply = s.read_packet(timeout=deadline_wait)
        returned = s.read_regs()
        log("[E1] return stop: %r rip=%s rsp=%s", reply,
            hexs(returned["rip"]), hexs(returned["rsp"]))
        if (returned["rip"] == original_rip and
                returned["rsp"] == original_rsp):
            outcome = "verified-return"
            s.write_mem(frame_rsp, old_word)
            if s.read_mem(frame_rsp, 8) != old_word:
                raise RuntimeError("could not restore the staged frame word")
            RING1["frame"] = None
        else:
            outcome = "stop-with-unexpected-regs"
    except ConnectionError as e:
        outcome = "clean-eof(%s)" % type(e).__name__
    except TimeoutError:
        outcome = "timeout"

    log("[E1] OUTCOME: %s", outcome)
    if outcome == "verified-return":
        try:
            c.close()
        except OSError:
            pass
        RING1["sock"] = None
        log("EXPERIMENT 1: VERIFIED RETURN - exit + auto-cleanup returned to "
            "the exact original RIP/RSP. Console liveness is the final check.")
        return 0
    if outcome.startswith("clean-eof"):
        RING1["sock"] = None
        log("EXPERIMENT 1: CLEAN EOF - the stub exited its session, ran "
            "cleanup, returned through the frame, and the payload process "
            "ended normally. Console liveness is the final check.")
        return 0
    # timeout or unexpected stop: freeze class -> park
    park(c, "experiment-1 outcome: %s" % outcome)
    return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ring0", action="store_true",
                        help="explicitly enable the ring-0 experiment")
    parser.add_argument("--recovery-plan-confirmed", action="store_true",
                        help="confirm the owner-approved recovery plan is ready")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-send", action="store_true")
    args = parser.parse_args()

    if not args.ring0:
        log("REFUSED: pass --ring0 only after reviewing the recovery plan")
        return 2
    if not args.recovery_plan_confirmed:
        log("REFUSED: confirm the owner-approved recovery plan first")
        return 2

    stub_port = args.port if args.port is not None else discover(args.no_send)
    if stub_port is None:
        return 1
    return experiment_exit(stub_port)


if __name__ == "__main__":
    sys.exit(main())
