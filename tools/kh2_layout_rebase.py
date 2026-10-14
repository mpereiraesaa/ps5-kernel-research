#!/usr/bin/env python3
"""Rebase a zero-based KH2 geometry template for a selected CPU.

This transforms addresses and CPU ownership only. It does not establish
runtime scratch ownership, staged bytes, kernel instructions, or #DB delivery.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from kh2_layout_check import LIMIT, check, number


def _has_staged_hash(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("_sha") or key == "sha256" or _has_staged_hash(item):
                return True
    elif isinstance(value, list):
        return any(_has_staged_hash(item) for item in value)
    return False


def rebase(template, selected_cpu, kdata_base):
    """Return a checked copy; the selected physical landing stays in place."""
    base = number(kdata_base)
    cpu = number(selected_cpu)
    if cpu >= 16:
        raise ValueError("selected CPU must be 0..15")
    if not base or base % 0x1000 or base >> 47 != 0x1ffff:
        raise ValueError("kdata base must be a page-aligned kernel address")
    if number(template["kdata_base"]) != 0:
        raise ValueError("template kdata_base must be zero to avoid double rebasing")
    if _has_staged_hash(template):
        raise ValueError("template contains build or staged-byte hashes that rebasing would stale")
    original = check(template)
    if not original["geometry_valid"]:
        raise ValueError(f"template geometry invalid: {original['errors']}")

    plan = copy.deepcopy(template)
    old_cpu = number(plan["selected_cpu"])
    landings = {number(item["cpu"]): item for item in plan["landings"]}
    if cpu != old_cpu:
        for field in ("base", "size"):
            landings[old_cpu][field], landings[cpu][field] = (
                landings[cpu][field], landings[old_cpu][field])
        for phase in ("arm", "dispatch"):
            targets = plan["ist_targets"][phase]
            targets[old_cpu], targets[cpu] = targets[cpu], targets[old_cpu]
    plan["selected_cpu"] = cpu

    def shifted(value):
        address = number(value)
        if address > LIMIT - 1 - base:
            raise ValueError("rebased address exceeds uint64")
        return hex(base + address)

    for landing in plan["landings"]:
        landing["base"] = shifted(landing["base"])
    for part in plan["b1"].values():
        part["base"] = shifted(part["base"])
    for item in plan.get("reserved", []):
        item["base"] = shifted(item["base"])
    plan["gate"]["base"] = shifted(plan["gate"]["base"])
    plan["tss"]["base"] = shifted(plan["tss"]["base"])
    for field in ("ist_qwords", "frame_slots", "context_qwords",
                  "journal_qwords"):
        plan[field] = [shifted(value) for value in plan[field]]
    for phase in ("arm", "dispatch"):
        plan["ist_targets"][phase] = [
            shifted(value) for value in plan["ist_targets"][phase]]
    plan["kdata_base"] = hex(base)
    plan["coordinates"] = (
        "absolute addresses from operator-supplied kdata base; "
        "geometry only, no runtime ownership or instruction-byte proof")
    result = check(plan)
    if not result["geometry_valid"]:
        raise ValueError(f"rebased geometry invalid: {result['errors']}")
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--selected-cpu", required=True, type=int)
    parser.add_argument("--kdata-base", required=True)
    args = parser.parse_args()
    try:
        data = args.template.read_bytes()
        plan = rebase(json.loads(data), args.selected_cpu, args.kdata_base)
    except (KeyError, TypeError, ValueError) as error:
        parser.error(str(error))
    plan["source_template_sha256"] = hashlib.sha256(data).hexdigest()
    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
