#!/usr/bin/env python3
"""Check proposed KH2 address intervals and optional retained log fields.

This checks geometry and reported source-plan consistency only. It cannot
establish kernel-data ownership, firmware instruction bytes, whether writes
occurred, or whether #DB was delivered.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

from khook_trace_classify import RECORD, classify

LIMIT = 1 << 64


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"invalid integer: {value!r}")
    result = int(value, 0) if isinstance(value, str) else value
    if not 0 <= result < LIMIT:
        raise ValueError(f"address/size outside uint64: {value!r}")
    return result


def sha256_text(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    return value.lower()


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
    for item in frames + context:
        if not inside(item, selected):
            errors.append(f"{item[0]} outside selected CPU landing")
    for cpu, landing in landings.items():
        if not inside(landing, b1["image"]):
            errors.append(f"cpu[{cpu}] outside B1 image")
    for item in journal:
        if not inside(item, b1["journal"]):
            errors.append(f"{item[0]} outside B1 journal")

    # B1 image staging/readback must cover every CPU landing that the shared
    # gate can select. Other physical overlaps are rejected.
    physical = list(landings.values()) + list(b1.values()) + [gate] + ist
    for i, item in enumerate(physical):
        for other in physical[i + 1:]:
            if item[0].startswith("cpu[") and other[0] == "image" and inside(item, other):
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


def locate_write_error(plan, error):
    """Map a reported failed B1/B2 write address to the candidate plan."""
    address = number(error["addr"])
    stage, region = error["stage"], error["region"]
    location = {"seq": error["seq"], "stage": stage, "region": region,
                "addr": error["addr"], "plan_match": False}
    if stage == "B1" and region in plan["b1"]:
        part = plan["b1"][region]
        base, size = number(part["base"]), number(part["size"])
        if base <= address < base + size:
            location.update(plan_match=True, offset=hex(address - base))
    elif stage == "B2" and region == "gate":
        base = number(plan["gate"]["base"])
        if address in (base, base + 8):
            location.update(plan_match=True, word=(address - base) // 8)
    elif stage == "B2" and region == "ist6":
        for cpu, item in enumerate(plan["ist_qwords"]):
            if address == number(item):
                location.update(plan_match=True, cpu=cpu)
                break
    elif stage == "B2" and region == "context":
        for index, item in enumerate(plan["context_qwords"]):
            if address == number(item):
                location.update(plan_match=True,
                                context=("rbp", "rip", "rsp", "dr7")[index])
                break
    return location


def compare_log(plan, raw, manifest=None, geometry=None):
    """Compare only classifier-accepted, unambiguous KH2 report fields."""
    geometry = check(plan) if geometry is None else geometry
    if not geometry["geometry_valid"]:
        raise ValueError("cannot compare a log with an invalid layout")
    if manifest is not None and not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    build_sha = sha256_text(plan.get("build_sha"), "build_sha")
    part_sha = {part: sha256_text(plan["b1"][part].get("image_sha"),
                                 f"b1.{part}.image_sha")
                for part in ("image", "big", "journal")}
    classification = classify(raw, manifest)
    records = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        match = RECORD.match(line)
        if match:
            seq, _, payload = match.groups()
            records.setdefault(int(seq), []).append(dict(
                token.split("=", 1) for token in payload.split()
                if token.count("=") == 1))

    expected = {
        "B0": {
            "cpu": number(plan["selected_cpu"]),
            "build_sha": build_sha,
            "f1_slot": number(plan["frame_slots"][0]),
            "f2_slot": number(plan["frame_slots"][1]),
        },
        "B2": {
            "ist_count": 16,
            "ist_image_sha": geometry["expected_b2_ist_image_sha"],
            "ist6_actual": number(plan["ist_targets"]["arm"][number(plan["selected_cpu"])]),
        },
        "A2": {
            "ist_count": 16,
            "ist_before_sha": geometry["expected_b2_ist_image_sha"],
            "ist_image_sha": geometry["expected_a2_ist_image_sha"],
            "ist_actual": number(plan["ist_targets"]["dispatch"][number(plan["selected_cpu"])]),
            "armed_addr": number(plan["journal_qwords"][4]),
        },
    }
    for part in ("image", "big", "journal"):
        expected[f"B1.{part}"] = {
            "addr": number(plan["b1"][part]["base"]),
            "bytes": number(plan["b1"][part]["size"]),
            "image_sha": part_sha[part],
        }
    expected["B1.image"].update(zip(
        ("rbp_addr", "rip_addr", "rsp_addr", "dr7_addr"),
        map(number, plan["context_qwords"])))
    expected["B1.journal"].update(zip(
        ("a1p_addr", "a1r_addr", "d1s_addr", "d1o_addr"),
        map(number, plan["journal_qwords"][:4])))

    accepted = {stage: seq for stage, seq in classification["observed"].items()
                if stage in ("B0", "B2", "A2")}
    accepted.update({f"B1.{part}": seq for part, seq in
                     classification["b1_parts"].items()})
    write_error_locations = [locate_write_error(plan, error)
                             for error in classification["capture_errors"]
                             if error["operation"] == "write"]
    mismatches = []
    comparison_errors = []
    compared_fields = []
    if classification["integrity"] == "mismatch":
        comparison_errors.append("manifest SHA-256 differs from supplied log")
    else:
        for stage, seq in accepted.items():
            matches = records.get(seq, [])
            if len(matches) != 1:
                comparison_errors.append(f"{stage}: ambiguous or missing raw sequence {seq}")
                continue
            fields = matches[0]
            if (fields.get("stage") != stage.split(".")[0] or
                    (stage.startswith("B1.") and fields.get("part") != stage.split(".")[1])):
                comparison_errors.append(f"{stage}: raw sequence {seq} names another stage")
                continue
            for key, wanted in expected[stage].items():
                value = fields.get(key)
                try:
                    actual = (value.lower() if key.endswith("sha") else
                              int(value, 10 if key in ("cpu", "bytes", "ist_count") else 16))
                except (AttributeError, TypeError, ValueError):
                    comparison_errors.append(f"{stage}.{key}: accepted field cannot be read")
                    continue
                compared_fields.append(f"{stage}.{key}")
                if actual != wanted:
                    mismatches.append({"field": f"{stage}.{key}",
                                       "expected": wanted if isinstance(wanted, str) else hex(wanted),
                                       "observed": value, "seq": seq})
    if comparison_errors:
        status = "comparison_error"
    elif mismatches:
        status = "mismatch"
    elif classification["rejected"] or classification["capture_errors"] or classification["causal_order_conflict"]:
        status = "classifier_rejected_or_capture_error"
    elif not compared_fields:
        status = "no_comparable_records"
    elif any(stage not in accepted for stage in expected):
        status = "partial_observed_fields_match"
    else:
        status = "observed_fields_match"
    return {
        "comparison_status": status,
        "compared_fields": compared_fields,
        "missing_layout_records": [stage for stage in expected if stage not in accepted],
        "mismatches": mismatches,
        "comparison_errors": comparison_errors,
        "classifier_rejected": classification["rejected"],
        "capture_errors": classification["capture_errors"],
        "write_error_locations": write_error_locations,
        "causal_order_conflict": classification["causal_order_conflict"],
        "transport": classification["transport"],
        "integrity": classification["integrity"],
        "scope": "accepted log fields versus source plan; no 12.02 ownership or execution proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="JSON candidate address plan")
    parser.add_argument("--log", type=Path, help="retained ps5log/1 KH2 run")
    parser.add_argument("--manifest", type=Path, help="optional same-run ps5log/1 manifest")
    args = parser.parse_args()
    if args.manifest and not args.log:
        parser.error("--manifest requires --log")
    try:
        plan = json.loads(args.plan.read_text())
        result = check(plan)
        if args.log and result["geometry_valid"]:
            manifest = json.loads(args.manifest.read_text()) if args.manifest else None
            result["log_comparison"] = compare_log(plan, args.log.read_bytes(), manifest, result)
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        parser.error(f"invalid plan: {exc}")
    print(json.dumps(result, indent=2))
    if not result["geometry_valid"] or (args.log and
            result["log_comparison"]["comparison_status"] in
            ("comparison_error", "mismatch", "classifier_rejected_or_capture_error",
             "no_comparable_records")):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
