#!/usr/bin/env python3
"""Project address-only KH2 candidates from stable public anchor relations.

This reads offset headers, never kernel images. A projection is not an
instruction-byte check or evidence that a 12.02 gadget executes.
"""

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path


DONORS = ("13_00", "13_20", "13_60")
DEF_RE = re.compile(r"^DEF\((\w+),\s*([^)]*)\)", re.MULTILINE)
GADGET_RE = re.compile(
    r"0x([0-9a-fA-F]+)\s*,\s*//\s*KERNEL_GADGET_(\w+)"
)


def _integer_expression(node, known):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.Name):
        return known[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_integer_expression(node.operand, known)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _integer_expression(node.left, known) + _integer_expression(node.right, known)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
        return _integer_expression(node.left, known) - _integer_expression(node.right, known)
    raise ValueError("unsupported offset expression")


def load_kstuff(path, expected_firmware=None):
    source = path.read_text()
    if expected_firmware is not None:
        code = expected_firmware.replace("_", "")
        if not re.search(rf"^START_FW\({code}\)", source, re.MULTILINE):
            raise ValueError(f"Kstuff firmware label mismatch in {path}")
    values = {}
    for name, expression in DEF_RE.findall(source):
        if name in values:
            raise ValueError(f"duplicate Kstuff name {name} in {path}")
        values[name] = _integer_expression(ast.parse(expression, mode="eval").body, values)
    if "doreti_iret" not in values:
        raise ValueError(f"missing doreti_iret in {path}")
    return values


def load_gadgets(path, expected_firmware=None):
    source = path.read_text()
    code = expected_firmware.replace("_", "") if expected_firmware else r"\d+"
    match = re.search(rf"g_gadget_map_{code}\s*\[\s*\]\s*=\s*\{{([^}}]*)\}}", source, re.DOTALL)
    if not match:
        raise ValueError(f"missing gadget map in {path}")
    values = {}
    for offset, name in GADGET_RE.findall(match.group(1)):
        if name in values:
            raise ValueError(f"duplicate gadget {name} in {path}")
        values[name] = int(offset, 16)
    if "IRETQ" not in values:
        raise ValueError(f"missing IRETQ in {path}")
    return values


def project(kstuff, gadgets, target_gap, max_local_distance):
    donor_names = set.intersection(*(set(gadgets[fw]) for fw in DONORS))
    if any(set(gadgets[fw]) != donor_names for fw in DONORS):
        raise ValueError("donor gadget name sets differ")
    common_anchors = set.intersection(*(set(kstuff[fw]) for fw in (*DONORS, "12_02")))
    gaps = {
        fw: gadgets[fw]["IRETQ"] - kstuff[fw]["doreti_iret"]
        for fw in DONORS
    }
    selected, remote, unresolved = {}, {}, []
    for gadget in sorted(donor_names):
        stable = []
        for anchor in sorted(common_anchors):
            if any(kstuff[fw][anchor] >= 0 for fw in DONORS) or kstuff["12_02"][anchor] >= 0:
                continue
            deltas = {
                gadgets[fw][gadget] - (gaps[fw] + kstuff[fw][anchor])
                for fw in DONORS
            }
            if len(deltas) == 1:
                delta = deltas.pop()
                candidate = target_gap + kstuff["12_02"][anchor] + delta
                if candidate < 0:
                    continue
                stable.append({
                    "anchor": anchor,
                    "delta": delta,
                    "distance": abs(delta),
                    "candidate_offset": candidate,
                })
        stable.sort(key=lambda row: (row["distance"], row["anchor"]))
        local = [row for row in stable if row["distance"] <= max_local_distance]
        if local and len({row["candidate_offset"] for row in local}) == 1:
            selected[gadget] = {
                "candidate_offset": f"0x{local[0]['candidate_offset']:x}",
                "relations": [
                    {"anchor": row["anchor"], "delta": f"{row['delta']:+#x}"}
                    for row in local
                ],
            }
        elif stable:
            remote[gadget] = {
                "nearest_anchor": stable[0]["anchor"],
                "distance": f"0x{stable[0]['distance']:x}",
                "reason": "conflicting local projections" if local else "outside local distance",
            }
            if local:
                remote[gadget]["local_projections"] = [
                    {
                        "anchor": row["anchor"],
                        "delta": f"{row['delta']:+#x}",
                        "candidate_offset": f"0x{row['candidate_offset']:x}",
                    }
                    for row in local
                ]
        else:
            unresolved.append(gadget)
    return {
        "donor_coordinate_gaps": {fw: f"0x{gap:x}" for fw, gap in gaps.items()},
        "target_coordinate_gap": f"0x{target_gap:x}",
        "max_local_distance": f"0x{max_local_distance:x}",
        "selected_address_candidates": selected,
        "stable_but_remote_or_conflicting": remote,
        "no_stable_anchor_relation": unresolved,
        "warning": "Address-only projections; no 12.02 text bytes or execution validated.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kstuff-dir", required=True, type=Path)
    parser.add_argument("--byepervisor-dir", required=True, type=Path)
    parser.add_argument("--target-gap", required=True, type=lambda s: int(s, 0))
    parser.add_argument("--max-local-distance", default=0x4000,
                        type=lambda s: int(s, 0))
    args = parser.parse_args()
    if args.target_gap <= 0 or args.max_local_distance < 0:
        parser.error("target gap must be positive and local distance nonnegative")
    paths = {
        fw: (args.kstuff_dir / f"{fw}.h", args.byepervisor_dir / f"{fw}.h")
        for fw in DONORS
    }
    paths["12_02"] = (args.kstuff_dir / "12_02.h",)
    kstuff = {fw: load_kstuff(path[0], fw) for fw, path in paths.items()}
    gadgets = {fw: load_gadgets(paths[fw][1], fw) for fw in DONORS}
    if any(len(gadgets[fw]) != 21 for fw in DONORS):
        parser.error("each donor must contain all 21 published gadget names")
    result = project(kstuff, gadgets, args.target_gap, args.max_local_distance)
    result["header_sha256"] = {
        f"{fw}_{kind}": hashlib.sha256(path.read_bytes()).hexdigest()
        for fw, family in paths.items()
        for kind, path in zip(("kstuff", "byepervisor"), family)
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
