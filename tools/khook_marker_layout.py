#!/usr/bin/env python3
"""Audit four proposed journal stores against the pinned public khook source.

This checks source layout and selected restore-slot dependencies for the
11.60 test transaction. It does not validate register liveness, any FW 12.02
instruction bytes, or execute a
kernel chain. Pass khook.h, khook.c, and main.c from the same public commit.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


def _code(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


def _body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise ValueError(f"missing {signature}")
    opening = source.find("{", start)
    if opening < 0:
        raise ValueError(f"missing body for {signature}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise ValueError(f"unclosed body for {signature}")


def _constant(header: str, name: str) -> int:
    match = re.search(rf"^#define\s+{name}\s+(0x[0-9a-fA-F]+)\s*$", header, re.M)
    if match is None:
        raise ValueError(f"missing literal {name}")
    return int(match.group(1), 16)


def _between(source: str, start: str, end: str) -> str:
    if start not in source:
        raise ValueError(f"missing source anchor: {start}")
    tail = source.split(start, 1)[1]
    if end not in tail:
        raise ValueError(f"missing source anchor: {end}")
    return tail.split(end, 1)[0]


def _putq_count(body: str, target: str) -> int:
    return len(re.findall(rf"\boff\s*=\s*putq\({target},\s*off,", body))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def analyze(header: str, source: str, main: str) -> dict:
    h, c, m = _code(header), _code(source), _code(main)
    offsets = {name: _constant(h, name) for name in (
        "KH_OFF_CHAIN_ARM", "KH_OFF_CHAIN_CONT", "KH_OFF_RESUME",
        "KH_OFF_CHAIN_DISP", "KH_SCRATCH_MIN", "KH_OFF_BIG_CHAIN",
        "KH_SCRATCH_BIG")}

    store = _body(c, "int kh_chain_store(")
    store_calls = re.findall(r"kh_chain_([gq])\(chain,\s*([^)]*)\)", store)
    expected_store = [
        ("g", "KERNEL_GADGET_POP_RCX"), ("q", "kaddr"),
        ("g", "KERNEL_GADGET_POP_RAX"), ("q", "val"),
        ("g", "KERNEL_GADGET_ST_RCX_RAX")]
    _require(store_calls == expected_store,
             "store helper is not the pinned POP_RCX/POP_RAX/ST_RCX_RAX sequence")
    marker_bytes = len(store_calls) * 8

    install = _body(c, "int kh_install(")
    arm = _between(install, "off = KH_OFF_CHAIN_ARM;",
                   "if (off > KH_OFF_CHAIN_CONT)")
    continuation = _between(install, "off = KH_OFF_CHAIN_CONT;",
                            "if (off > KH_OFF_RESUME)")
    arm_words = _putq_count(arm, "img")
    continuation_words = _putq_count(continuation, "img")
    rip_words = _putq_count(continuation.split("kh->arm_rip_slot", 1)[0], "img")
    rsp_words = _putq_count(continuation.split("kh->arm_rsp_slot", 1)[0], "img")
    _require((arm_words, continuation_words, rip_words, rsp_words) == (5, 11, 6, 9),
             "arm/continuation word layout differs from pinned source")

    save_len_match = re.search(r"save_len\s*=\s*(0x[0-9a-fA-F]+)\s*;", install)
    big_cap_match = re.search(r"bigbuf\[(0x[0-9a-fA-F]+)\]", install)
    _require(save_len_match is not None and big_cap_match is not None,
             "missing big-chain size or save length")
    save_len = int(save_len_match.group(1), 16)
    big_cap = int(big_cap_match.group(1), 16)
    _require("restore_off = save_len + handler_len;" in install,
             "restore_off formula differs from pinned source")
    big_prefix = _between(install, "off = 0;", "if (handler_len)")
    _require(_putq_count(big_prefix, "bigbuf") * 8 == save_len,
             "register-save prefix differs from save_len")
    restore = _between(install, "off += handler_len;", "off = emit_resume_tail")
    restore_bytes = _putq_count(restore, "bigbuf") * 8
    _require(restore_bytes == 0x30 and all(
        f"slot_{reg} = big + restore_off + {delta};" in install
        for reg, delta in (("rdi", "0x08"), ("rsi", "0x18"), ("rdx", "0x28"))),
        "register-restore slots differ from pinned source")

    test = _body(m, "static int install_test_hook(")
    _require(test.count("kh_chain_store(&chain, oracle, COOKIE_VAL)") == 1,
             "test handler is not one kh_chain_store")
    _require("hook.oneshot   = 1;" in test and
             "kh_set_resume_rax(&hook, 0x12345678);" in test and
             not re.search(r"\bkh_set_resume_(?:rip|skip|rsi|rdi|rdx)\(", test),
             "test-hook resume options differ from pinned source")
    tail = _body(c, "static size_t emit_resume_tail(")
    _require(all(token in tail for token in (
        "if (kh->oneshot)", "KERNEL_GADGET_SET_DR7",
        "if (kh->resume_rax_set)", "KERNEL_GADGET_POP_RSP")),
        "one-shot return tail differs from pinned source")

    arm_start = offsets["KH_OFF_CHAIN_ARM"]
    cont_start = offsets["KH_OFF_CHAIN_CONT"]
    resume_start = offsets["KH_OFF_RESUME"]
    arm_end = arm_start + marker_bytes + arm_words * 8
    cont_end = cont_start + marker_bytes + continuation_words * 8
    _require(arm_end <= cont_start and cont_end <= resume_start,
             "arm markers overflow fixed first-image regions")
    arm_rip_slot = cont_start + marker_bytes + rip_words * 8
    arm_rsp_slot = cont_start + marker_bytes + rsp_words * 8

    handler_bytes = marker_bytes
    restore_off = save_len + marker_bytes + handler_bytes + marker_bytes
    # Pinned one-shot test: POP_RAX/zero/SET_DR7 (3 qwords), explicit RAX
    # restore (2), then POP_RSP/iret_tramp (2).
    tail_bytes = 7 * 8
    big_end = restore_off + restore_bytes + tail_bytes
    big_start = offsets["KH_OFF_BIG_CHAIN"]
    _require(big_end <= big_cap and big_start + big_cap <= offsets["KH_SCRATCH_BIG"],
             "dispatch plan exceeds the big-chain allocation")
    _require(offsets["KH_OFF_CHAIN_DISP"] + 0x10 <= offsets["KH_SCRATCH_MIN"],
             "dispatch stub leaves the first image")

    return {
        "reference": "11.60 khook test path; four 5-qword stores, no 12.02 gadget proof",
        "marker_bytes": marker_bytes,
        "arm": {"A1P": [arm_start, arm_start + marker_bytes],
                "original_chain": [arm_start + marker_bytes, arm_end],
                "limit": cont_start},
        "continuation": {"A1R": [cont_start, cont_start + marker_bytes],
                         "original_chain_and_iret": [cont_start + marker_bytes,
                                                     cont_end],
                         "arm_rip_slot": arm_rip_slot,
                         "arm_rsp_slot": arm_rsp_slot,
                         "limit": resume_start},
        "dispatch": {"save": [0, save_len],
                     "D1S": [save_len, save_len + marker_bytes],
                     "handler": [save_len + marker_bytes,
                                 save_len + marker_bytes + handler_bytes],
                     "D1O": [save_len + marker_bytes + handler_bytes,
                             restore_off],
                     "restore_off": restore_off,
                     "old_restore_off": save_len + handler_bytes,
                     "slot_rdi": restore_off + 0x08,
                     "slot_rsi": restore_off + 0x18,
                     "slot_rdx": restore_off + 0x28,
                     "end": big_end,
                     "capacity": big_cap},
        "source_sha256": {"khook_h": hashlib.sha256(header.encode()).hexdigest(),
                          "khook_c": hashlib.sha256(source.encode()).hexdigest(),
                          "main_c": hashlib.sha256(main.encode()).hexdigest()},
        "scope": "source geometry only; requires 12.02 bytes, liveness review, and runtime evidence",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--main", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.header.read_text(), args.source.read_text(),
                         args.main.read_text())
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
