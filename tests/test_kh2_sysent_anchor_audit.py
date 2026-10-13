"""Synthetic bounds and pairing checks for the syscall anchor audit."""

import importlib.util
import struct
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "kh2_sysent_anchor_audit",
    Path(__file__).resolve().parents[1] / "tools/kh2_sysent_anchor_audit.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def paired_tables():
    target = bytearray(module.TABLE_1202 + module.ENTRY_COUNT * module.SYSENT_STRIDE)
    donor = bytearray(module.TABLE_1360 + module.ENTRY_COUNT * module.SYSENT_STRIDE)
    for number in range(module.ENTRY_COUNT):
        donor_offset = 0x1000 + number * 8
        for image, table, base, offset in (
            (target, module.TABLE_1202, 0x200000, donor_offset + 0x20),
            (donor, module.TABLE_1360, 0x100000, donor_offset),
        ):
            struct.pack_into("<Q", image,
                             table + number * module.SYSENT_STRIDE + 8,
                             base + offset)
    return target, donor


class SysentAnchorAuditTests(unittest.TestCase):
    def test_pairs_entries_but_only_near_donor_gadget_is_local(self):
        target, donor = paired_tables()
        result = module.audit(target, donor,
                              {"NEAR": "0x1002", "FAR": "0x4000"},
                              0x200000, 0x100000, max_local_distance=0x10,
                              text_limit_1202=0x10000,
                              text_limit_1360=0x10000)
        self.assertEqual(result["paired_syscalls"], 735)
        self.assertEqual(result["sy_call_delta_histogram"], {"+0x20": 735})
        self.assertEqual(result["local_gadget_names"], ["NEAR"])
        self.assertEqual(result["gadget_distances"]["NEAR"]["nearest_syscall_numbers"], [0])
        self.assertEqual(result["gadget_distances"]["FAR"]["nearest_syscall_numbers"], [734])

    def test_out_of_range_pair_rejects_entire_audit(self):
        target, donor = paired_tables()
        struct.pack_into("<Q", target,
                         module.TABLE_1202 + 24 * module.SYSENT_STRIDE + 8,
                         0x1234)
        with self.assertRaisesRegex(ValueError, r"sysent\[24\].*outside"):
            module.audit(target, donor, {"NEAR": "0x1002"},
                         0x200000, 0x100000,
                         text_limit_1202=0x10000,
                         text_limit_1360=0x10000)


if __name__ == "__main__":
    unittest.main()
