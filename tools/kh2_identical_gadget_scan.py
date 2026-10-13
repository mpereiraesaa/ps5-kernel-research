#!/usr/bin/env python3
"""Find byte-identical gadget candidates using an external verified donor.

No donor or target bytes are written to disk or printed. A hit is a candidate
instruction entry, not proof that it belongs to executable code or a valid
chain. Both images and their provenance remain outside this notes repo.
"""

import argparse
import json
from pathlib import Path

import kh2_gadget_contract as contracts


def find_matches(image, signature, limit):
    """Return the count and first limit offsets, including overlapping hits."""
    count = 0
    first = []
    position = 0
    while True:
        hit = image.find(signature, position)
        if hit < 0:
            break
        count += 1
        if len(first) < limit:
            first.append(hit)
        position = hit + 1
    return count, first


def signature_for(donor, path, name, offset):
    expected = contracts.FULL_CONTRACTS[name]
    length = 0x80 if name == "DBREG_RESUME" else 0x40
    instructions = contracts.disassemble(path, offset, length)
    match = contracts.check_sequence(
        instructions, offset, expected,
        allow_plain_ret=name == "PIVOT_ADD_RSP28_RET")
    if not match["contract_match"]:
        raise ValueError(f"donor entry shape mismatch: {name}")
    if len(instructions) <= len(expected):
        raise ValueError(f"cannot bound donor entry end: {name}")
    end = instructions[len(expected)][0]
    if end <= offset or end > len(donor):
        raise ValueError(f"invalid donor entry extent: {name}")
    return donor[offset:end]


def scan(donor_path, target_path, offsets, target_firmware, limit):
    if not donor_path.is_file() or not target_path.is_file():
        raise ValueError("donor and target must be regular files")
    if set(offsets) != set(contracts.FULL_CONTRACTS):
        raise ValueError("donor manifest must cover all 21 gadget names")
    donor = donor_path.read_bytes()
    target = target_path.read_bytes()
    donor_sha = contracts.sha256_file(donor_path)
    target_sha = contracts.sha256_file(target_path)
    same_image = donor_sha == target_sha
    results = {}
    for name, offset in offsets.items():
        if offset < 0 or offset >= len(donor):
            raise ValueError(f"donor offset outside image: {name}")
        signature = signature_for(donor, donor_path, name, offset)
        count, first = find_matches(target, signature, limit)
        results[name] = {
            "donor_offset": hex(offset),
            "signature_length": len(signature),
            "candidate_count": count,
            "first_offsets": [hex(value) for value in first],
            "first_offsets_truncated": count > len(first),
            "donor_offset_found_in_same_image":
                (target.find(signature, offset) == offset) if same_image else None,
        }
    return {
        "donor_sha256": donor_sha,
        "target_sha256": target_sha,
        "target_firmware_label": target_firmware,
        "same_image": same_image,
        "gadgets": results,
        "scope": "byte-identical candidate search; no instruction-boundary, code-region, runtime, or chain proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donor", required=True, type=Path)
    parser.add_argument("--donor-firmware", required=True)
    parser.add_argument("--donor-offsets", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--target-firmware", required=True)
    parser.add_argument("--first", type=int, default=32,
                        help="maximum reported offsets per gadget (1..1000)")
    args = parser.parse_args()
    if not 1 <= args.first <= 1000:
        parser.error("--first must be from 1 to 1000")
    try:
        offsets = contracts.parse_offset_manifest(args.donor_offsets,
                                                   args.donor_firmware)
        result = scan(args.donor, args.target, offsets,
                      args.target_firmware, args.first)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 1 if result["same_image"] and not all(
        gadget["donor_offset_found_in_same_image"]
        for gadget in result["gadgets"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
