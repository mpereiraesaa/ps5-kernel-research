#!/usr/bin/env python3
"""Check the one-trap source layout against public Kstuff trapframe offsets.

This is a source-geometry check. It cannot validate FW 12.02 instruction
bytes, scratch ownership, register preservation, or exception delivery.
"""

import argparse
import ast
import json
import re
from pathlib import Path


def expression(value: str, known: dict[str, int]) -> int:
    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name):
            return known[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return evaluate(node.left) + evaluate(node.right)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            return evaluate(node.left) - evaluate(node.right)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return evaluate(node.left) * evaluate(node.right)
        raise ValueError(f"unsupported expression: {value}")

    return evaluate(ast.parse(value, mode="eval").body)


def parse_definitions(raw: str, kind: str) -> dict[str, int]:
    values = {}
    if kind == "c":
        entries = re.findall(r"^\s*([A-Z][A-Z_0-9]+)\s*=\s*([^,]+),", raw, re.M)
    else:
        entries = re.findall(r"^%define\s+(iret_[a-z]+)\s+([^\n;]+)", raw, re.M)
    for name, value in entries:
        values[name] = expression(value.strip(), values)
    return values


def check(source: str, structs: str) -> dict:
    c = parse_definitions(source, "c")
    k = parse_definitions(structs, "nasm")
    errors = []
    required = ("CPU_COUNT", "SLOT_SIZE", "SCRATCH_SIZE", "FRAME_OFF",
                "HW_FRAME_OFF", "IRET_FRAME_OFF", "CHAIN1_OFF",
                "AFTER_COPY_OFF", "CHAIN2_OFF", "MARKER_SRC_OFF",
                "MARKER_DST_OFF", "REGS_RDI", "REGS_RSI", "REGS_RCX",
                "REGS_RIP", "REGS_CS", "REGS_RFLAGS", "REGS_RSP", "REGS_SS")
    for name in required:
        if name not in c:
            errors.append(f"missing source constant {name}")
    for name in ("iret_rdi", "iret_rsi", "iret_rcx", "iret_rip",
                 "iret_cs", "iret_eflags", "iret_rsp", "iret_ss"):
        if name not in k:
            errors.append(f"missing public trapframe constant {name}")
    if errors:
        return {"geometry_valid": False, "errors": errors}

    for own, public in (("REGS_RDI", "iret_rdi"),
                        ("REGS_RSI", "iret_rsi"),
                        ("REGS_RCX", "iret_rcx"),
                        ("REGS_RIP", "iret_rip"),
                        ("REGS_CS", "iret_cs"),
                        ("REGS_RFLAGS", "iret_eflags"),
                        ("REGS_RSP", "iret_rsp"),
                        ("REGS_SS", "iret_ss")):
        if c[own] != k[public]:
            errors.append(f"{own}={c[own]:#x} differs from {public}={k[public]:#x}")
    if c["SCRATCH_SIZE"] != c["CPU_COUNT"] * c["SLOT_SIZE"]:
        errors.append("scratch size does not cover all CPU slots")
    if c["HW_FRAME_OFF"] != c["FRAME_OFF"] - 0x28:
        errors.append("hardware frame is not at IST top minus 0x28")
    if c["IRET_FRAME_OFF"] != c["HW_FRAME_OFF"] + 0xe8:
        errors.append("add_rsp_iret does not land at staged iret frame")
    if c["CHAIN1_OFF"] + k["iret_ss"] + 8 != c["AFTER_COPY_OFF"]:
        errors.append("first register frame does not end at copy continuation")
    if c["AFTER_COPY_OFF"] + 16 != c["CHAIN2_OFF"]:
        errors.append("copy pop/ret does not enter second register frame")

    intervals = [
        ("hardware_frame", c["HW_FRAME_OFF"], c["FRAME_OFF"]),
        ("entry_iret", c["IRET_FRAME_OFF"], c["IRET_FRAME_OFF"] + 40),
        ("register_frame_1", c["CHAIN1_OFF"], c["AFTER_COPY_OFF"]),
        ("copy_pop_ret", c["AFTER_COPY_OFF"], c["CHAIN2_OFF"]),
        ("register_frame_2", c["CHAIN2_OFF"], c["CHAIN2_OFF"] + k["iret_ss"] + 8),
        ("marker_source", c["MARKER_SRC_OFF"], c["MARKER_SRC_OFF"] + 8),
        ("marker_destination", c["MARKER_DST_OFF"], c["MARKER_DST_OFF"] + 8),
    ]
    for name, start, end in intervals:
        if not 0 <= start < end <= c["SLOT_SIZE"]:
            errors.append(f"{name} is outside one CPU slot")
    for index, (name, start, end) in enumerate(intervals):
        for other, a, b in intervals[index + 1:]:
            if start < b and a < end:
                errors.append(f"{name} overlaps {other}")

    # The source has one canary expression in the staging loop and another in
    # the observer's comparison loop. Report uniqueness without assuming it.
    canary_pattern = (r"canary\s*=\s*(0x[0-9a-fA-F]+)ULL\s*([|+])\s*"
                      r"\(\(uint64_t\)cpu\s*<<\s*8\)\s*([|+])\s*"
                      r"\(uint64_t\)(?:word|i)")
    formulas = re.findall(canary_pattern, source, re.S)
    expected_formulas = 2 if "observer_worker" in source else 1
    if len(formulas) != expected_formulas or len(set(formulas)) != 1:
        errors.append("canary expression missing or inconsistent")
        unique_canaries = None
        distinct_canaries = None
        collisions = []
    else:
        base, cpu_op, word_op = formulas[0]
        values = {}
        collisions = []
        for cpu in range(c["CPU_COUNT"]):
            for word in range(5):
                value = int(base, 16)
                value = value | (cpu << 8) if cpu_op == "|" else value + (cpu << 8)
                value = value | word if word_op == "|" else value + word
                if value in values and len(collisions) < 5:
                    collisions.append({"first": values[value], "again": [cpu, word]})
                values.setdefault(value, [cpu, word])
        unique_canaries = len(values) == c["CPU_COUNT"] * 5
        distinct_canaries = len(values)

    return {"geometry_valid": not errors, "errors": errors,
            "cpu_count": c["CPU_COUNT"], "slot_size": c["SLOT_SIZE"],
            "scratch_size": c["SCRATCH_SIZE"],
            "intervals": [{"name": name, "start": start, "end": end}
                          for name, start, end in intervals],
            "unique_canaries": unique_canaries,
            "distinct_canaries": distinct_canaries,
            "canary_collision_examples": collisions,
            "scope": "source geometry only; no 12.02 instruction or runtime validation"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local fullchain C source")
    parser.add_argument("structs", type=Path, help="public Kstuff structs.inc")
    args = parser.parse_args()
    result = check(args.source.read_text(), args.structs.read_text())
    print(json.dumps(result, indent=2))
    if not result["geometry_valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
