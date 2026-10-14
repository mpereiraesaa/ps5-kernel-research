#!/usr/bin/env python3
"""Find aligned rel32 jump entries to CLI bodies in a supplied text image.

This is a donor-calibrated candidate filter, not a symbol resolver. It does
not identify a 12.02 AP init vector without independent same-firmware
evidence, and never prints instruction bytes.
"""

import argparse
import hashlib
import json
from pathlib import Path

from sysent_trampoline_map import follow_rel32_jump


def scan(text: bytes, max_results: int = 16) -> dict:
    if max_results < 1:
        raise ValueError("max_results must be positive")
    count = 0
    first = []
    for entry in range(0, len(text) - 4, 8):
        if text[entry] != 0xe9:
            continue
        try:
            target = follow_rel32_jump(text, entry)
        except ValueError:
            continue
        if text[target] != 0xfa:
            continue
        count += 1
        if len(first) < max_results:
            first.append({"entry_offset": hex(entry),
                          "target_offset": hex(target)})
    return {"candidate_count": count, "candidates": first,
            "candidates_truncated": count > len(first),
            "scope": "8-byte-aligned E9 rel32 entries to CLI; neither uniqueness nor AP identity follows"}


def inspect_known(text: bytes, offset: int) -> dict:
    if offset % 8:
        raise ValueError("known vector is not 8-byte aligned")
    if offset < 0 or offset + 5 > len(text):
        raise ValueError("known vector outside text image")
    if text[offset] != 0xe9:
        raise ValueError("known vector is not a direct rel32 jump")
    target = follow_rel32_jump(text, offset)
    if text[target] != 0xfa:
        raise ValueError("known vector target does not start with CLI")
    return {"entry_offset": hex(offset), "target_offset": hex(target),
            "direct_rel32_to_cli": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--text", required=True, type=Path)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--known-vector-offset", type=lambda s: int(s, 0))
    parser.add_argument("--max-results", type=int, default=16)
    args = parser.parse_args()
    try:
        text = args.text.read_bytes()
        result = scan(text, args.max_results)
        result.update({"firmware_label": args.firmware,
                       "text_sha256": hashlib.sha256(text).hexdigest(),
                       "known_vector": (inspect_known(text, args.known_vector_offset)
                                        if args.known_vector_offset is not None
                                        else None)})
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
