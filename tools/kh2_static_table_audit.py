#!/usr/bin/env python3
"""Find paired data-pointer rows across held 13.60 and 12.02 images.

The donor seed is a data-file offset, not a gadget address. Each row has
seven interleaved text pointers and six metadata pointers. Identical
metadata within each firmware and a matching pair gap identify row
homology; this does not transfer interior instructions between functions.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path


TEXT_REL = (-0x50, -0x40, -0x30, -0x20, -0x10, 0, 0x10)
META_REL = (-0x48, -0x38, -0x28, -0x18, -0x8, 0x8)


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("table row outside data image")
    return struct.unpack_from("<Q", data, offset)[0]


def _row(data: bytes, origin: int, text_base: int, text_limit: int):
    pointers = [_u64(data, origin + rel) for rel in TEXT_REL]
    if not all(text_base <= pointer < text_base + text_limit
               for pointer in pointers):
        return None
    metadata = tuple(_u64(data, origin + rel) for rel in META_REL)
    return {
        "origin": origin,
        "text_offsets": tuple(pointer - text_base for pointer in pointers),
        "metadata": metadata,
    }


def donor_pair(data: bytes, seed: int, text_base: int, text_limit: int):
    first_meta = _u64(data, seed + META_REL[0]).to_bytes(8, "little")
    rows = []
    start = 0
    while (hit := data.find(first_meta, start)) >= 0:
        origin = hit - META_REL[0]
        if origin % 8 == 0 and origin >= 0x50 and origin + 0x18 <= len(data):
            row = _row(data, origin, text_base, text_limit)
            if row and row["metadata"] == tuple(
                    _u64(data, seed + rel) for rel in META_REL):
                rows.append(row)
        start = hit + 1
    rows.sort(key=lambda row: row["origin"])
    if len(rows) != 2 or not any(row["origin"] == seed for row in rows):
        raise ValueError("donor seed did not identify exactly two rows")
    return rows


def target_pairs(data: bytes, text_base: int, text_limit: int,
                 row_gap: int):
    candidates = {}
    for origin in range(0x50, len(data) - 0x18, 8):
        first = _u64(data, origin)
        second = _u64(data, origin + 0x10)
        if not (text_base <= first < text_base + text_limit and
                second == first + 0x20):
            continue
        row = _row(data, origin, text_base, text_limit)
        if row:
            candidates[origin] = row
    pairs = []
    for origin, row in candidates.items():
        next_row = candidates.get(origin + row_gap)
        if next_row and row["metadata"] == next_row["metadata"]:
            pairs.append((row, next_row))
    return pairs


def audit(data_1202: bytes, data_1360: bytes, seed_1360: int,
          text_base_1202: int, text_base_1360: int,
          text_limit_1202: int = 0xD50000,
          text_limit_1360: int = 0xCC0000) -> dict:
    donor = donor_pair(data_1360, seed_1360,
                       text_base_1360, text_limit_1360)
    gap = donor[1]["origin"] - donor[0]["origin"]
    matches = target_pairs(data_1202, text_base_1202, text_limit_1202, gap)
    if len(matches) != 1:
        raise ValueError(f"expected one matching 12.02 row pair, got {len(matches)}")
    target = matches[0]
    def public(row):
        return {"data_offset": f"0x{row['origin']:x}",
                "text_offsets": [f"0x{offset:x}" for offset in row["text_offsets"]]}
    return {
        "donor_rows": [public(row) for row in donor],
        "target_rows": [public(row) for row in target],
        "row_gap": f"0x{gap:x}",
        "scope": "data-table homology only; no containing-function or interior-gadget transfer",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-1202", type=Path, required=True)
    parser.add_argument("--data-1360", type=Path, required=True)
    parser.add_argument("--donor-seed", type=lambda s: int(s, 0),
                        default=0x1C6718)
    parser.add_argument("--text-base-1202", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--text-base-1360", type=lambda s: int(s, 0), required=True)
    args = parser.parse_args()
    try:
        target = args.data_1202.read_bytes()
        donor = args.data_1360.read_bytes()
        result = audit(target, donor, args.donor_seed,
                       args.text_base_1202, args.text_base_1360)
        result["input_sha256"] = {
            "data_1202": hashlib.sha256(target).hexdigest(),
            "data_1360": hashlib.sha256(donor).hexdigest(),
        }
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
