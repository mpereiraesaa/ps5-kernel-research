#!/usr/bin/env python3
"""Resolve a syscall table entry through a text jump when text is available.

Inputs remain local and are never copied into the research-notes repository.
With only a data dump, this reports the sy_call entry and leaves its target
unresolved. The 12.02 table offset is in the checked-in Kstuff header;
the 13.60 table offset comes from the local donor dump audit in doc 16.
"""

import argparse
import json
import struct
from pathlib import Path


SYSENT_STRIDE = 0x30
SY_CALL_OFF = 8
GETUID_NUMBER = 24
TABLE_1202 = 0x1AF4D0
TABLE_1360 = 0x1B6E50


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise ValueError(f"qword outside data image at {offset:#x}")
    return struct.unpack_from("<Q", data, offset)[0]


def sy_call_neighbors(data: bytes, table_offset: int, text_base: int,
                      text_size: int) -> dict[int, int]:
    entries = {}
    for number in (GETUID_NUMBER - 1, GETUID_NUMBER, GETUID_NUMBER + 1):
        pointer = _u64(data, table_offset + number * SYSENT_STRIDE + SY_CALL_OFF)
        offset = pointer - text_base
        if not 0 <= offset < text_size:
            raise ValueError(f"sysent[{number}].sy_call outside supplied text range")
        entries[number] = offset
    if (entries[23] - entries[24], entries[25] - entries[24]) != (0x38, 0x8):
        raise ValueError("getuid neighboring sy_call spacing differs from donor")
    return entries


def follow_rel32_jump(text: bytes, entry: int) -> int:
    if not 0 <= entry <= len(text) - 5:
        raise ValueError("jump entry outside text image")
    if text[entry] != 0xE9:
        raise ValueError("sy_call entry is not a direct rel32 jump")
    displacement = struct.unpack_from("<i", text, entry + 1)[0]
    target = entry + 5 + displacement
    if not 0 <= target < len(text):
        raise ValueError("jump target outside text image")
    return target


def analyze(data_1202: bytes, data_1360: bytes, text_1360: bytes,
            text_base_1202: int, text_base_1360: int,
            text_1202: bytes | None = None) -> dict:
    entries_1360 = sy_call_neighbors(data_1360, TABLE_1360,
                                     text_base_1360, len(text_1360))
    target_1360 = follow_rel32_jump(text_1360, entries_1360[GETUID_NUMBER])
    # The data-only 12.02 image cannot establish whether this entry jumps,
    # or where it transfers if it does.
    # The kdata-minus-ktext distance bounds pre-data addresses in this dump;
    # it is not a claim about the executable text's actual size. An optional
    # text image supplies the direct bound needed for instruction inspection.
    text_size_1202 = len(text_1202) if text_1202 is not None else 0xD50000
    entries_1202 = sy_call_neighbors(data_1202, TABLE_1202,
                                     text_base_1202, text_size_1202)
    target_1202 = (follow_rel32_jump(text_1202, entries_1202[GETUID_NUMBER])
                   if text_1202 is not None else None)
    return {
        "syscall": "getuid",
        "syscall_number": GETUID_NUMBER,
        "sysent_stride": SYSENT_STRIDE,
        "sy_call_field_offset": SY_CALL_OFF,
        "fw_1360": {"sy_call_text_offset": entries_1360[GETUID_NUMBER],
                    "rel32_target_text_offset": target_1360,
                    "neighbor_offsets": entries_1360},
        "fw_1202": {"sy_call_text_offset": entries_1202[GETUID_NUMBER],
                    "rel32_target_text_offset": target_1202,
                    "neighbor_offsets": entries_1202},
        "sy_call_offset_delta_1202_minus_1360": (
            entries_1202[GETUID_NUMBER] - entries_1360[GETUID_NUMBER]),
        "scope": "data identifies sy_call entries; only same-firmware text resolves a rel32 jump target",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-1202", type=Path, required=True)
    parser.add_argument("--data-1360", type=Path, required=True)
    parser.add_argument("--text-1360", type=Path, required=True)
    parser.add_argument("--text-1202", type=Path,
                        help="optional future 12.02 text image; never required to report the entry")
    parser.add_argument("--text-base-1202", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--text-base-1360", type=lambda s: int(s, 0), required=True)
    args = parser.parse_args()
    try:
        result = analyze(args.data_1202.read_bytes(), args.data_1360.read_bytes(),
                         args.text_1360.read_bytes(), args.text_base_1202,
                         args.text_base_1360,
                         args.text_1202.read_bytes() if args.text_1202 else None)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
