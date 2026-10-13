#!/usr/bin/env python3
"""Check proposed KH2 address intervals before any console experiment.

This checks geometry only. It cannot establish kernel-data ownership, firmware
instruction bytes, whether the writes occur, or whether #DB is delivered.
"""

import argparse
import json
from pathlib import Path

LIMIT = 1 << 64


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"invalid integer: {value!r}")
    result = int(value, 0) if isinstance(value, str) else value
    if not 0 <= result < LIMIT:
        raise ValueError(f"address/size outside uint64: {value!r}")
    return result


def span(name, base, size):
    start, length = number(base), number(size)
    if not length or start + length > LIMIT:
        raise ValueError(f"empty or overflowing span: {name}")
    return name, start, start + length


def region(name, value):
    return span(name, value["base"], value["size"])


def intersects(a, b):
    return a[1] < b[2] and b[1] < a[2]


def inside(a, b):
    return b[1] <= a[1] and a[2] <= b[2]


def check(plan):
    errors = []
    slots = plan["cpu_slots"]
    base, size, count = (number(slots[key]) for key in ("base", "size", "count"))
    if count != 16:
        raise ValueError(f"expected 16 CPU landing slots, got {count}")
    if not size or base + count * size > LIMIT:
        raise ValueError("empty or overflowing CPU landing array")
    landings = [span(f"cpu[{i}]", base + i * size, size) for i in range(count)]
    b1 = {name: region(name, plan["b1"][name])
          for name in ("image", "big", "journal")}
    reserved = [region(f"reserved:{item['name']}", item)
                for item in plan.get("reserved", [])]
    gate = region("gate", plan["gate"])
    if gate[2] - gate[1] != 16:
        errors.append("gate must contain two qwords")
    if gate[1] % 8:
        errors.append("unaligned gate")
    ist = [span(f"ist[{i}]", address, 8)
           for i, address in enumerate(plan["ist_qwords"])]
    if len(ist) != 16:
        errors.append(f"expected 16 IST qwords, got {len(ist)}")

    for name, values in (("frame_slots", plan["frame_slots"]),
                         ("context_qwords", plan["context_qwords"]),
                         ("journal_qwords", plan["journal_qwords"])):
        expected = {"frame_slots": 2, "context_qwords": 4,
                    "journal_qwords": 5}[name]
        if len(values) != expected:
            errors.append(f"expected {expected} {name}, got {len(values)}")
    frames = [span(f"frame[{i}]", address, 0x28)
              for i, address in enumerate(plan["frame_slots"])]
    context = [span(f"context[{i}]", address, 8)
               for i, address in enumerate(plan["context_qwords"])]
    journal = [span(f"journal_word[{i}]", address, 8)
               for i, address in enumerate(plan["journal_qwords"])]
    for item in ist + frames + context + journal:
        if item[1] % 8:
            errors.append(f"unaligned {item[0]}")
    for item in frames + context:
        if not inside(item, b1["image"]):
            errors.append(f"{item[0]} outside B1 image")
    for item in journal:
        if not inside(item, b1["journal"]):
            errors.append(f"{item[0]} outside B1 journal")

    # A reserved region may intentionally contain a B1 part. It must not
    # overlay any per-CPU landing slot in this disjoint-layout contract.
    physical = landings + list(b1.values()) + [gate] + ist
    for i, item in enumerate(physical):
        for other in physical[i + 1:]:
            if intersects(item, other):
                errors.append(f"{item[0]} overlaps {other[0]}")
    for item in reserved:
        for landing in landings:
            if intersects(item, landing):
                errors.append(f"{item[0]} overlaps {landing[0]}")
    fields = frames + context + journal
    for i, item in enumerate(fields):
        for other in fields[i + 1:]:
            if intersects(item, other):
                errors.append(f"{item[0]} overlaps {other[0]}")
    return {"geometry_valid": not errors, "errors": errors,
            "ownership_verified": False,
            "scope": "interval geometry only; no FW 12.02 byte or runtime proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="JSON candidate address plan")
    args = parser.parse_args()
    try:
        result = check(json.loads(args.plan.read_text()))
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(f"invalid plan: {exc}")
    print(json.dumps(result, indent=2))
    if not result["geometry_valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
