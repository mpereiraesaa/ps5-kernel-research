#!/usr/bin/env python3
"""Locate public 13.60 gadget pointers in held donor kdata without emitting bytes.

An exact text pointer in a data dump may be payload staging, so classify its
location against Byepervisor's published data cave and big-chain placement.
This does not infer a 12.02 instruction address or establish cave ownership.
"""

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path


DONOR_GAP = 0xCC0000
DATA_CAVE_TEXT_OFFSET = 0x2D39000
SCRATCH_BIG = 0x4000
BIG_CHAIN_OFFSET = 0x3A00
PREFIX = (
    (0x00, "MOV_RAX_RSI"),
    (0x08, "POP_RCX"),
    (0x18, "ST_RCX_RAX"),
    (0x20, "POP_RCX"),
    (0x30, "ST_RCX_RDX"),
)


def audit(data: bytes, offsets: dict[str, str], text_base: int,
          gap: int = DONOR_GAP,
          cave_text_offset: int = DATA_CAVE_TEXT_OFFSET,
          scratch_size: int = SCRATCH_BIG) -> dict:
    if text_base < 0 or gap <= 0 or cave_text_offset < gap or scratch_size <= 0:
        raise ValueError("invalid text base, gap, cave offset, or scratch size")
    cave = cave_text_offset - gap
    if cave + scratch_size > len(data):
        raise ValueError("published scratch span exceeds data image")
    targets = {}
    for name, raw in offsets.items():
        offset = int(raw, 0)
        if not 0 <= offset < gap:
            raise ValueError(f"{name} outside donor text range")
        pointer = text_base + offset
        if pointer >= 1 << 64 or pointer in targets:
            raise ValueError("invalid or duplicate gadget pointer")
        targets[pointer] = name

    pages = Counter()
    names = Counter()
    cave_hits = outside_hits = 0
    for index, (pointer,) in enumerate(struct.iter_unpack(
            "<Q", data[:len(data) // 8 * 8])):
        name = targets.get(pointer)
        if name is None:
            continue
        place = index * 8
        pages[place & ~0xfff] += 1
        names[name] += 1
        if cave <= place < cave + scratch_size:
            cave_hits += 1
        else:
            outside_hits += 1

    prefix = []
    for displacement, name in PREFIX:
        place = cave + BIG_CHAIN_OFFSET + displacement
        expected = text_base + int(offsets[name], 0)
        prefix.append(place + 8 <= len(data) and
                      struct.unpack_from("<Q", data, place)[0] == expected)

    return {
        "cave_data_offset": f"0x{cave:x}",
        "published_scratch_size": f"0x{scratch_size:x}",
        "big_chain_data_offset": f"0x{cave + BIG_CHAIN_OFFSET:x}",
        "exact_aligned_hits": cave_hits + outside_hits,
        "inside_published_scratch": cave_hits,
        "outside_published_scratch": outside_hits,
        "hits_by_page": {f"0x{page:x}": count
                         for page, count in sorted(pages.items())},
        "hits_by_gadget": dict(sorted(names.items())),
        "big_chain_prefix_matches": all(prefix),
        "big_chain_prefix_checks": len(prefix),
        "scope": "exact aligned public gadget pointers in donor kdata only; no native-table or 12.02 gadget claim",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-1360", required=True, type=Path)
    parser.add_argument("--offsets", required=True, type=Path)
    parser.add_argument("--text-base-1360", required=True,
                        type=lambda s: int(s, 0))
    args = parser.parse_args()
    try:
        manifest_bytes = args.offsets.read_bytes()
        manifest = json.loads(manifest_bytes)
        if manifest.get("firmware") != "13.60" or len(manifest.get("offsets", {})) != 21:
            raise ValueError("expected complete public 13.60 gadget manifest")
        data = args.data_1360.read_bytes()
        result = audit(data, manifest["offsets"], args.text_base_1360)
        result["input_sha256"] = {
            "data_1360": hashlib.sha256(data).hexdigest(),
            "offsets": hashlib.sha256(manifest_bytes).hexdigest(),
        }
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
