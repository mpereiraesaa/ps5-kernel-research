#!/usr/bin/env python3
"""Audit paired sy_call anchors and 13.60 data references near getuid body.

The inputs are data images held outside this notes repository and the public
13.60 gadget-offset manifest. This reports address relationships only; a
nearby pointer would not establish a shared containing function or 12.02
instruction bytes.
"""

import argparse
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path


ENTRY_COUNT = 0x2DF
SYSENT_STRIDE = 0x30
SY_CALL_OFFSET = 8
TABLE_1202 = 0x1AF4D0
TABLE_1360 = 0x1B6E50
GETUID_BODY_1360 = 0x2A8D60
GETUID_HOOK_DELTA = 0xE
REPORTED_HITS = 32


def _entry_offsets(data: bytes, table: int, text_base: int,
                   text_limit: int) -> list[int]:
    end = table + (ENTRY_COUNT - 1) * SYSENT_STRIDE + SY_CALL_OFFSET + 8
    if table < 0 or end > len(data):
        raise ValueError("sysent table exceeds data image")
    result = []
    for number in range(ENTRY_COUNT):
        pointer = struct.unpack_from(
            "<Q", data, table + number * SYSENT_STRIDE + SY_CALL_OFFSET)[0]
        offset = pointer - text_base
        if not 0 <= offset < text_limit:
            raise ValueError(f"sysent[{number}].sy_call outside text range")
        result.append(offset)
    return result


def _body_pointer_refs(data: bytes, text_base: int, body_offset: int,
                       radius: int) -> dict:
    body = text_base + body_offset
    hook = body + GETUID_HOOK_DELTA
    if not 0 <= body < 1 << 64 or not 0 <= hook < 1 << 64:
        raise ValueError("donor body pointer outside uint64")
    near = []
    aligned = data[:len(data) // 8 * 8]
    for index, (pointer,) in enumerate(struct.iter_unpack("<Q", aligned)):
        if body - radius <= pointer <= body + radius:
            near.append((index * 8, pointer - text_base))

    def exact(value):
        needle = struct.pack("<Q", value)
        result, start = [], 0
        while (found := data.find(needle, start)) >= 0:
            result.append(found)
            start = found + 1
        return result

    body_hits, hook_hits = exact(body), exact(hook)
    return {
        "body_offset": f"0x{body_offset:x}",
        "hook_offset": f"0x{body_offset + GETUID_HOOK_DELTA:x}",
        "window_radius": f"0x{radius:x}",
        "aligned_near_count": len(near),
        "aligned_near_hits": [
            {"data_offset": f"0x{place:x}", "text_offset": f"0x{target:x}"}
            for place, target in near[:REPORTED_HITS]
        ],
        "exact_body_count": len(body_hits),
        "exact_body_offsets": [f"0x{place:x}" for place in body_hits[:REPORTED_HITS]],
        "exact_hook_count": len(hook_hits),
        "exact_hook_offsets": [f"0x{place:x}" for place in hook_hits[:REPORTED_HITS]],
        "scope": "donor data qwords and exact byte patterns only; no 12.02 body projection",
    }


def audit(data_1202: bytes, data_1360: bytes, offsets: dict[str, str],
          text_base_1202: int, text_base_1360: int,
          max_local_distance: int = 0x4000,
          text_limit_1202: int = 0xD50000,
          text_limit_1360: int = 0xCC0000,
          donor_body_offset: int = GETUID_BODY_1360) -> dict:
    if max_local_distance < 0 or text_limit_1202 <= 0 or text_limit_1360 <= 0:
        raise ValueError("distance and text limits must be nonnegative/positive")
    if not 0 <= donor_body_offset or donor_body_offset + GETUID_HOOK_DELTA >= text_limit_1360:
        raise ValueError("donor getuid body outside text range")
    target = _entry_offsets(data_1202, TABLE_1202,
                            text_base_1202, text_limit_1202)
    donor = _entry_offsets(data_1360, TABLE_1360,
                           text_base_1360, text_limit_1360)
    deltas = Counter(target[n] - donor[n] for n in range(ENTRY_COUNT))
    rows = {}
    for name, raw_offset in sorted(offsets.items()):
        try:
            gadget = int(raw_offset, 0)
        except (TypeError, ValueError) as error:
            raise ValueError(f"invalid gadget offset for {name}") from error
        if not 0 <= gadget < text_limit_1360:
            raise ValueError(f"{name} outside donor text range")
        distance = min(abs(gadget - entry) for entry in donor)
        nearest = [n for n, entry in enumerate(donor)
                   if abs(gadget - entry) == distance]
        rows[name] = {
            "donor_offset": f"0x{gadget:x}",
            "nearest_distance": f"0x{distance:x}",
            "nearest_syscall_numbers": nearest,
            "inside_local_window": distance <= max_local_distance,
        }
    local = [name for name, row in rows.items()
             if row["inside_local_window"]]
    return {
        "paired_syscalls": ENTRY_COUNT,
        "sy_call_delta_histogram": {
            f"{delta:+#x}": count for delta, count in sorted(deltas.items())
        },
        "max_local_distance": f"0x{max_local_distance:x}",
        "local_gadget_names": local,
        "gadget_distances": rows,
        "donor_getuid_body_data_refs": _body_pointer_refs(
            data_1360, text_base_1360, donor_body_offset,
            max_local_distance),
        "scope": "sy_call proximity and donor data-pointer scan only; not a function boundary, gadget offset projection, or 12.02 byte check",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-1202", type=Path, required=True)
    parser.add_argument("--data-1360", type=Path, required=True)
    parser.add_argument("--offsets", type=Path, required=True)
    parser.add_argument("--text-base-1202", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--text-base-1360", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--max-local-distance", type=lambda s: int(s, 0),
                        default=0x4000)
    args = parser.parse_args()
    try:
        manifest = json.loads(args.offsets.read_text())
        if manifest.get("firmware") != "13.60" or len(manifest.get("offsets", {})) != 21:
            raise ValueError("expected the complete public 13.60 gadget manifest")
        data_1202 = args.data_1202.read_bytes()
        data_1360 = args.data_1360.read_bytes()
        result = audit(data_1202, data_1360, manifest["offsets"],
                       args.text_base_1202, args.text_base_1360,
                       args.max_local_distance)
        result["input_sha256"] = {
            "data_1202": hashlib.sha256(data_1202).hexdigest(),
            "data_1360": hashlib.sha256(data_1360).hexdigest(),
            "offsets": hashlib.sha256(args.offsets.read_bytes()).hexdigest(),
        }
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
