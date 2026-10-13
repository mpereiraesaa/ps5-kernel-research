#!/usr/bin/env python3
"""Check two proposed KH2 entry contracts in a locally supplied text image.

The image and disassembly stay off-repo. A match checks instruction shape at
the supplied offsets, not firmware identity, runtime mapping, or execution.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


PIVOT = ("add rsp,0x28", "repz ret")
DBREG = (
    "mov dr0,rax",
    "mov rax,QWORD PTR [rdi+0x80]", "mov dr1,rax",
    "mov rax,QWORD PTR [rdi+0x88]", "mov dr2,rax",
    "mov rax,QWORD PTR [rdi+0x90]", "mov dr3,rax",
    "mov rax,QWORD PTR [rdi+0x98]", "mov dr6,rax",
    "mov rax,QWORD PTR [rdi+0xa0]", "mov dr7,rax",
    "mov r15,QWORD PTR [rdi]",
    "mov r14,QWORD PTR [rdi+0x8]",
    "mov r13,QWORD PTR [rdi+0x10]",
    "mov r12,QWORD PTR [rdi+0x18]",
    "mov rbp,QWORD PTR [rdi+0x20]",
    "mov rsp,QWORD PTR [rdi+0x28]",
    "mov rbx,QWORD PTR [rdi+0x30]",
    "mov rax,QWORD PTR [rdi+0x38]",
    "mov QWORD PTR [rsp],rax",
    "xor eax,eax", "ret",
)
INSN = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][^\n]*)$", re.IGNORECASE)


def parse_instructions(output):
    """Return anchored offsets and mnemonic/operand text, without raw bytes."""
    result = []
    for line in output.splitlines():
        match = INSN.match(line)
        if match:
            result.append((int(match.group(1), 16),
                           " ".join(match.group(2).split())))
    return result


def check_sequence(instructions, offset, expected, allow_plain_ret=False):
    observed = instructions[:len(expected)]
    actual = [item[1] for item in observed]
    if allow_plain_ret and len(actual) > 1 and actual[1] in ("ret", "rep ret"):
        actual[1] = "repz ret"
    anchored = bool(observed) and observed[0][0] == offset
    mismatch = (0 if not anchored else next(
        (index for index, want in enumerate(expected)
         if index >= len(observed) or actual[index] != want), None))
    return {
        "offset": hex(offset),
        "entry_anchored": anchored,
        "contract_match": anchored and mismatch is None,
        "first_mismatch_index": mismatch,
        "expected_instruction_count": len(expected),
        "observed": [item[1] for item in observed],
    }


def disassemble(path, offset, length):
    command = ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
               "-M", "intel", "--no-show-raw-insn",
               f"--start-address={offset}", f"--stop-address={offset + length}",
               str(path)]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                check=True, timeout=15)
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise ValueError(f"objdump failed: {exc}") from exc
    return parse_instructions(result.stdout)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as image:
        for chunk in iter(lambda: image.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect(path, firmware, pivot_offset, dbreg_offset):
    if not path.is_file():
        raise ValueError("text image must be a regular file")
    size = path.stat().st_size
    if (pivot_offset < 0 or dbreg_offset < 0 or
            pivot_offset + 8 > size or dbreg_offset + 0x60 > size):
        raise ValueError("candidate window falls outside text image")
    pivot = check_sequence(disassemble(path, pivot_offset, 8), pivot_offset,
                           PIVOT, allow_plain_ret=True)
    dbreg = check_sequence(disassemble(path, dbreg_offset, 0x60),
                           dbreg_offset, DBREG)
    return {"firmware_label": firmware, "text_sha256": sha256_file(path),
            "text_size": size, "pivot": pivot, "dbreg_resume": dbreg,
            "both_contracts_match": pivot["contract_match"] and dbreg["contract_match"],
            "scope": "bounded instruction-shape check; no runtime or full-chain proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", required=True, type=Path,
                        help="raw kernel text image; never copied into this repo")
    parser.add_argument("--firmware", required=True, help="provenance label only")
    parser.add_argument("--pivot-offset", required=True, type=lambda x: int(x, 0))
    parser.add_argument("--dbreg-offset", required=True, type=lambda x: int(x, 0))
    args = parser.parse_args()
    try:
        result = inspect(args.text, args.firmware, args.pivot_offset,
                         args.dbreg_offset)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0 if result["both_contracts_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
