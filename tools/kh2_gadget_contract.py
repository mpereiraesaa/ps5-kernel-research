#!/usr/bin/env python3
"""Check proposed KH2 gadget contracts in a locally supplied text image.

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
IRET = ("iretq",)
RET_TRAMP = ("ret",)
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
FULL_CONTRACTS = {
    "PIVOT_ADD_RSP28_RET": PIVOT,
    "IRETQ": IRET,
    **{f"POP_{reg}": (f"pop {reg.lower()}", "ret")
       for reg in ("RAX", "RCX", "RDI", "RSI", "RDX", "R8", "RSP")},
    "STORE_RCX_R8": ("mov QWORD PTR [rcx],r8", "ret"),
    "STORE_RDI8_RCX": ("mov QWORD PTR [rdi+0x8],rcx", "ret"),
    "OR_RCX_EAX": ("or DWORD PTR [rcx],eax", "ret"),
    "SET_DR7": ("mov dr7,rax", "mov eax,r8d", "ret"),
    "ST_RCX_RDX": ("mov QWORD PTR [rcx],rdx", "ret"),
    "ST_RCX_RAX": ("mov QWORD PTR [rcx],rax", "xor eax,eax", "ret"),
    "MOV_RAX_RSI": ("mov rax,rsi", "ret"),
    "MOV_RAX_RDI": ("mov rax,rdi", "ret"),
    "REP_MOVSB": ("rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]",
                  "nop", "repz ret"),
    "CLD": ("cld", "ret"),
    "RET_TRAMP": RET_TRAMP,
    "DBREG_RESUME": DBREG,
}
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
    actual = ["pop r8" if line == "rex.RXB pop r8" else
              "nop" if line == "xchg ax,ax" else line for line in actual]
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


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest key: {key}")
        result[key] = value
    return result


def parse_offset_manifest(path, firmware=None):
    try:
        manifest = json.loads(path.read_text(), object_pairs_hook=no_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read offset manifest: {exc}") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("offsets"), dict):
        raise ValueError("offset manifest needs an offsets object")
    if not isinstance(manifest.get("firmware"), str) or not manifest["firmware"]:
        raise ValueError("offset manifest needs a firmware label")
    if firmware is not None and manifest["firmware"] != firmware:
        raise ValueError("manifest firmware does not match --firmware")
    offsets = {}
    for name, value in manifest["offsets"].items():
        if name not in FULL_CONTRACTS:
            raise ValueError(f"unknown gadget name: {name}")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(f"invalid offset for {name}")
        try:
            offset = int(value, 0) if isinstance(value, str) else value
        except ValueError as exc:
            raise ValueError(f"invalid offset for {name}") from exc
        if offset < 0:
            raise ValueError(f"negative offset for {name}")
        offsets[name] = offset
    return offsets


def inspect_manifest(path, firmware, offsets):
    if not path.is_file():
        raise ValueError("text image must be a regular file")
    size = path.stat().st_size
    checked = {}
    for name, offset in offsets.items():
        expected = FULL_CONTRACTS[name]
        window = 0x60 if name == "DBREG_RESUME" else 0x20
        if offset + window > size:
            raise ValueError(f"{name} window falls outside text image")
        checked[name] = check_sequence(
            disassemble(path, offset, window), offset, expected,
            allow_plain_ret=name == "PIVOT_ADD_RSP28_RET")
    missing = sorted(FULL_CONTRACTS.keys() - offsets.keys())
    return {"firmware_label": firmware, "text_sha256": sha256_file(path),
            "text_size": size, "checked": checked, "missing": missing,
            "coverage_complete": not missing,
            "all_contracts_match": not missing and all(
                item["contract_match"] for item in checked.values()),
            "scope": "bounded entry instruction shapes; no runtime, basic-block, or full-chain proof"}


def inspect(path, firmware, pivot_offset, dbreg_offset,
            iret_offset, ret_tramp_offset):
    if not path.is_file():
        raise ValueError("text image must be a regular file")
    size = path.stat().st_size
    windows = {"pivot": (pivot_offset, 8), "dbreg_resume": (dbreg_offset, 0x60),
               "iret": (iret_offset, 4), "ret_tramp": (ret_tramp_offset, 2)}
    if any(offset < 0 or offset + length > size
           for offset, length in windows.values()):
        raise ValueError("gadget window falls outside text image")
    pivot = check_sequence(disassemble(path, pivot_offset, 8), pivot_offset,
                           PIVOT, allow_plain_ret=True)
    dbreg = check_sequence(disassemble(path, dbreg_offset, 0x60),
                           dbreg_offset, DBREG)
    iret = check_sequence(disassemble(path, iret_offset, 4),
                          iret_offset, IRET)
    ret_tramp = check_sequence(disassemble(path, ret_tramp_offset, 2),
                               ret_tramp_offset, RET_TRAMP)
    return {"firmware_label": firmware, "text_sha256": sha256_file(path),
            "text_size": size, "pivot": pivot, "dbreg_resume": dbreg,
            "iret": iret, "ret_tramp": ret_tramp,
            "all_contracts_match": all(item["contract_match"] for item in
                                       (pivot, dbreg, iret, ret_tramp)),
            "scope": "bounded instruction-shape check; no runtime or full-chain proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", required=True, type=Path,
                        help="raw kernel text image; never copied into this repo")
    parser.add_argument("--firmware", required=True, help="provenance label only")
    parser.add_argument("--offsets", type=Path,
                        help="JSON manifest for all or selected gadget offsets")
    parser.add_argument("--pivot-offset", type=lambda x: int(x, 0))
    parser.add_argument("--dbreg-offset", type=lambda x: int(x, 0))
    parser.add_argument("--iret-offset", type=lambda x: int(x, 0))
    parser.add_argument("--ret-tramp-offset",
                        type=lambda x: int(x, 0))
    args = parser.parse_args()
    try:
        if args.offsets:
            if any(value is not None for value in (args.pivot_offset,
                   args.dbreg_offset, args.iret_offset,
                   args.ret_tramp_offset)):
                raise ValueError("--offsets cannot be combined with individual offsets")
            result = inspect_manifest(args.text, args.firmware,
                                      parse_offset_manifest(args.offsets,
                                                            args.firmware))
        else:
            if any(value is None for value in (args.pivot_offset,
                   args.dbreg_offset, args.iret_offset,
                   args.ret_tramp_offset)):
                raise ValueError("four individual offsets are required without --offsets")
            result = inspect(args.text, args.firmware, args.pivot_offset,
                             args.dbreg_offset, args.iret_offset,
                             args.ret_tramp_offset)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0 if result["all_contracts_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
