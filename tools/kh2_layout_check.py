#!/usr/bin/env python3
"""Check proposed KH2 address intervals before any console experiment.

This checks geometry only. It cannot establish kernel-data ownership, firmware
instruction bytes, whether the writes occur, or whether #DB is delivered.
"""

import argparse
import hashlib
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
    kdata_base = number(plan["kdata_base"])
    entries = plan["landings"]
    cpus = [number(item["cpu"]) for item in entries]
    if sorted(cpus) != list(range(16)):
        raise ValueError("landings must name each CPU 0..15 exactly once")
    landings = {cpu: region(f"cpu[{cpu}]", item)
                for cpu, item in zip(cpus, entries)}
    selected_cpu = number(plan["selected_cpu"])
    if selected_cpu not in landings:
        raise ValueError("selected_cpu must name a landing")
    selected = landings[selected_cpu]
    b1 = {name: region(name, plan["b1"][name])
          for name in ("image", "big", "journal")}
    reserved = [region(f"reserved:{item['name']}", item)
                for item in plan.get("reserved", [])]
    gate = region("gate", plan["gate"])
    if gate[2] - gate[1] != 16:
        errors.append("gate must contain two qwords")
    if gate[1] % 8:
        errors.append("unaligned gate")
    if gate[1] != kdata_base + 0x2e88300 + 16:
        errors.append("vector-1 gate differs from 12.02 IDT address")
    ist = [span(f"ist[{i}]", address, 8)
           for i, address in enumerate(plan["ist_qwords"])]
    if len(ist) != 16:
        errors.append(f"expected 16 IST qwords, got {len(ist)}")
    tss = plan["tss"]
    tss_base, stride, ist_index = (number(tss[key]) for key in
                                   ("base", "stride", "ist_index"))
    if tss_base != kdata_base + 0x2e8afe0:
        errors.append("TSS base differs from 12.02 offset")
    if stride != 0x68 or ist_index != 6:
        errors.append("12.02 KH2 expects TSS stride 0x68 and IST6")
    for cpu, actual in enumerate(ist):
        expected = tss_base + cpu * stride + 0x24 + 8 * (ist_index - 1)
        if actual[1] != expected:
            errors.append(f"ist[{cpu}] differs from TSS/IST6 address")
    targets = {}
    for phase in ("arm", "dispatch"):
        values = plan["ist_targets"][phase]
        if len(values) != 16:
            raise ValueError(f"expected 16 {phase} IST targets, got {len(values)}")
        targets[phase] = [number(value) for value in values]
        for cpu, top in enumerate(targets[phase]):
            if top % 8 or top < 0x28 or not inside(
                    ("hardware_frame", top - 0x28, top), landings[cpu]):
                errors.append(f"{phase} IST target outside cpu[{cpu}] landing")
    if targets["arm"][selected_cpu] != number(plan["frame_slots"][0]) + 0x28:
        errors.append("selected arm IST target differs from F1 top")
    if targets["dispatch"][selected_cpu] != number(plan["frame_slots"][1]) + 0x28:
        errors.append("selected dispatch IST target differs from F2 top")
    for cpu in range(16):
        if cpu != selected_cpu and targets["arm"][cpu] != targets["dispatch"][cpu]:
            errors.append(f"cpu[{cpu}] IST target changes without an A2 readback")

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
    # FreeBSD's packed TSS places IST6 at +0x4c; its qword address need not
    # be aligned, even though the stack top stored there is aligned.
    for item in frames + context + journal:
        if item[1] % 8:
            errors.append(f"unaligned {item[0]}")
    for item in frames + context:
        if not inside(item, b1["image"]):
            errors.append(f"{item[0]} outside B1 image")
    if not inside(selected, b1["image"]):
        errors.append("selected CPU landing outside B1 image")
    for item in frames:
        if not inside(item, selected):
            errors.append(f"{item[0]} outside selected CPU landing")
    for item in journal:
        if not inside(item, b1["journal"]):
            errors.append(f"{item[0]} outside B1 journal")

    # The selected landing must live in the B1 image so both frame slots can
    # be reached through its IST6. All other physical overlaps are rejected.
    physical = list(landings.values()) + list(b1.values()) + [gate] + ist
    for i, item in enumerate(physical):
        for other in physical[i + 1:]:
            if {item[0], other[0]} == {selected[0], "image"}:
                continue
            if intersects(item, other):
                errors.append(f"{item[0]} overlaps {other[0]}")
    for item in reserved:
        for cpu, landing in landings.items():
            if intersects(item, landing):
                if cpu != selected_cpu or not inside(landing, item):
                    errors.append(f"{item[0]} overlaps {landing[0]}")
    fields = frames + context + journal
    for i, item in enumerate(fields):
        for other in fields[i + 1:]:
            if intersects(item, other):
                errors.append(f"{item[0]} overlaps {other[0]}")
    return {"geometry_valid": not errors, "errors": errors,
            "expected_b2_ist_image_sha": (hashlib.sha256(b"".join(
                value.to_bytes(8, "little") for value in targets["arm"])).hexdigest()
                if not errors else None),
            "expected_a2_ist_image_sha": (hashlib.sha256(b"".join(
                value.to_bytes(8, "little") for value in targets["dispatch"])).hexdigest()
                if not errors else None),
            "selected_a2_ist_expected": (
                hex(targets["dispatch"][selected_cpu]) if not errors else None),
            "ownership_verified": False,
            "scope": "interval geometry only; no FW 12.02 byte or runtime proof"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="JSON candidate address plan")
    args = parser.parse_args()
    try:
        result = check(json.loads(args.plan.read_text()))
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        parser.error(f"invalid plan: {exc}")
    print(json.dumps(result, indent=2))
    if not result["geometry_valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
