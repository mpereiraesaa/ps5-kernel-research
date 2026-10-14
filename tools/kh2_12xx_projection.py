#!/usr/bin/env python3
"""Compare public 11.60/12.70 gadget-to-Kstuff anchors for FW 12.02.

This produces address-only candidates. It does not read kernel text or prove
that an instruction sequence, frame, or breakpoint works on FW 12.02.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

if __package__:
    from .kh2_anchor_projection import load_kstuff
    from .kh2_gadget_contract import FULL_CONTRACTS
else:
    from kh2_anchor_projection import load_kstuff
    from kh2_gadget_contract import FULL_CONTRACTS


DONORS = ("11_60", "12_70")
DATA_ANCHORS = {"IDT_ARRAY": "idt", "COMMON_TSS": "tss_array",
                "PMAP_STORE": "kernel_pmap_store"}
MAP_ROW = re.compile(r"^\s*(0x[0-9a-fA-F]+|0)\s*,\s*//\s*"
                     r"((?:KERNEL_SYM_|KERNEL_GADGET_)?[A-Z][A-Z0-9_]*)",
                     re.MULTILINE)


def load_map(path, suffix, kind):
    source = path.read_text()
    match = re.search(rf"g_{kind}_map_{suffix}\s*\[\s*\]\s*=\s*\{{([^}}]*)\}}",
                      source, re.DOTALL)
    if not match:
        raise ValueError(f"missing {kind} map for {suffix} in {path}")
    values = {}
    prefix = "KERNEL_GADGET_" if kind == "gadget" else "KERNEL_SYM_"
    for offset, name in MAP_ROW.findall(match.group(1)):
        if name.startswith(prefix):
            name = name[len(prefix):]
        if name in values:
            raise ValueError(f"duplicate {kind} name {name} in {path}")
        values[name] = int(offset, 0)
    if not values:
        raise ValueError(f"empty {kind} map in {path}")
    return values


def coordinate_gap(symbols, kstuff):
    gaps = {}
    for symbol, anchor in DATA_ANCHORS.items():
        if symbol not in symbols or anchor not in kstuff:
            raise ValueError(f"missing data anchor {symbol}/{anchor}")
        gaps[symbol] = symbols[symbol] - kstuff[anchor]
    if len(set(gaps.values())) != 1 or next(iter(gaps.values())) <= 0:
        raise ValueError(f"inconsistent text/data gaps: {gaps}")
    return next(iter(gaps.values()))


def project(kstuff, symbols, gadgets, target_gap, max_distance):
    gaps = {fw: coordinate_gap(symbols[fw], kstuff[fw]) for fw in DONORS}
    if coordinate_gap(symbols["12_70"], kstuff["12_02"]) != target_gap:
        raise ValueError("12.70 and 12.02 data anchors do not agree")
    if target_gap <= 0 or max_distance < 0:
        raise ValueError("target gap must be positive and distance nonnegative")
    if any(set(gadgets[fw]) != set(FULL_CONTRACTS) for fw in DONORS):
        raise ValueError("donor gadget maps must match the 21 known names")
    common_anchors = set.intersection(*(set(kstuff[fw]) for fw in (*DONORS, "12_02")))
    selected, unresolved, excluded = {}, {}, []
    for name in sorted(gadgets["11_60"]):
        if any(gadgets[fw][name] == 0 for fw in DONORS):
            excluded.append(name)
            continue
        stable = []
        for anchor in sorted(common_anchors):
            if any(kstuff[fw][anchor] >= 0 for fw in (*DONORS, "12_02")):
                continue
            deltas = {
                gadgets[fw][name] - (gaps[fw] + kstuff[fw][anchor])
                for fw in DONORS
            }
            if len(deltas) != 1:
                continue
            delta = deltas.pop()
            candidate = target_gap + kstuff["12_02"][anchor] + delta
            if candidate < 0:
                continue
            stable.append((abs(delta), anchor, delta, candidate))
        stable.sort()
        local = [row for row in stable if row[0] <= max_distance]
        if local and len({row[3] for row in local}) == 1:
            selected[name] = {
                "candidate_offset": f"0x{local[0][3]:x}",
                "local_relations": [
                    {"anchor": row[1], "delta": f"{row[2]:+#x}"}
                    for row in local
                ],
                "other_stable_relations": [
                    {"anchor": row[1], "delta": f"{row[2]:+#x}",
                     "candidate_offset": f"0x{row[3]:x}"}
                    for row in stable if row[0] > max_distance
                ],
            }
        else:
            unresolved[name] = {
                "reason": "conflicting local projections" if local else
                          "no shared local relation",
                "local_projections": [
                    {"anchor": row[1], "candidate_offset": f"0x{row[3]:x}"}
                    for row in local
                ],
            }
    return {
        "donor_coordinate_gaps": {fw: f"0x{gaps[fw]:x}" for fw in DONORS},
        "target_coordinate_gap": f"0x{target_gap:x}",
        "max_local_distance": f"0x{max_distance:x}",
        "selected_address_candidates": selected,
        "unresolved_nonzero_gadgets": unresolved,
        "excluded_zero_donor_gadgets": excluded,
        "warning": "Address-only projections; no FW 12.02 text bytes or execution validated.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kstuff-dir", required=True, type=Path)
    parser.add_argument("--byepervisor-1160", required=True, type=Path)
    parser.add_argument("--byepervisor-1270", required=True, type=Path)
    parser.add_argument("--target-gap", default=0xd50000, type=lambda s: int(s, 0))
    parser.add_argument("--max-local-distance", default=0x4000,
                        type=lambda s: int(s, 0))
    args = parser.parse_args()
    paths = {
        "11_60": (args.kstuff_dir / "11_60.h", args.byepervisor_1160),
        "12_02": (args.kstuff_dir / "12_02.h",),
        "12_70": (args.kstuff_dir / "12_70.h", args.byepervisor_1270),
    }
    kstuff = {fw: load_kstuff(family[0], fw) for fw, family in paths.items()}
    symbols = {fw: load_map(paths[fw][1], fw.replace("_", ""), "sym") for fw in DONORS}
    gadgets = {fw: load_map(paths[fw][1], fw.replace("_", ""), "gadget")
               for fw in DONORS}
    result = project(kstuff, symbols, gadgets, args.target_gap, args.max_local_distance)
    result["header_sha256"] = {
        f"{fw}_{kind}": hashlib.sha256(path.read_bytes()).hexdigest()
        for fw, family in paths.items()
        for kind, path in zip(("kstuff", "byepervisor"), family)
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
