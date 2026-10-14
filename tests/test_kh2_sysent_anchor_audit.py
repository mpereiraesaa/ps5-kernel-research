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
                              text_limit_1360=0x10000,
                              donor_body_offset=0x8000)
        self.assertEqual(result["paired_syscalls"], 735)
        self.assertEqual(result["sy_call_delta_histogram"], {"+0x20": 735})
        self.assertEqual(result["local_gadget_names"], ["NEAR"])
        self.assertEqual(result["gadget_distances"]["NEAR"]["nearest_syscall_numbers"], [0])
        self.assertEqual(result["gadget_distances"]["FAR"]["nearest_syscall_numbers"], [734])
        self.assertEqual(result["donor_getuid_body_data_refs"]["aligned_near_count"], 0)

    def test_body_reference_scan_counts_aligned_near_and_unaligned_exact(self):
        target, donor = paired_tables()
        body = 0x100000 + 0x8000
        struct.pack_into("<Q", donor, 0x100, body)
        struct.pack_into("<Q", donor, 0x108, body + module.GETUID_HOOK_DELTA)
        struct.pack_into("<Q", donor, 0x110, body + 0x20)
        struct.pack_into("<Q", donor, 0x123, body)
        result = module.audit(target, donor, {"NEAR": "0x1002"},
                              0x200000, 0x100000, max_local_distance=0x40,
                              text_limit_1202=0x10000,
                              text_limit_1360=0x10000,
                              donor_body_offset=0x8000)
        refs = result["donor_getuid_body_data_refs"]
        self.assertEqual(refs["aligned_near_count"], 3)
        self.assertEqual(refs["aligned_near_hits"], [
            {"data_offset": "0x100", "text_offset": "0x8000"},
            {"data_offset": "0x108", "text_offset": "0x800e"},
            {"data_offset": "0x110", "text_offset": "0x8020"},
        ])
        self.assertEqual(refs["exact_body_count"], 2)
        self.assertEqual(refs["exact_body_offsets"], ["0x100", "0x123"])
        self.assertEqual(refs["exact_hook_count"], 1)
        self.assertEqual(refs["exact_hook_offsets"], ["0x108"])

    def test_out_of_range_pair_rejects_entire_audit(self):
        target, donor = paired_tables()
        struct.pack_into("<Q", target,
                         module.TABLE_1202 + 24 * module.SYSENT_STRIDE + 8,
                         0x1234)
        with self.assertRaisesRegex(ValueError, r"sysent\[24\].*outside"):
            module.audit(target, donor, {"NEAR": "0x1002"},
                         0x200000, 0x100000,
                         text_limit_1202=0x10000,
                         text_limit_1360=0x10000,
                         donor_body_offset=0x8000)

    def test_rejects_body_hook_outside_donor_range(self):
        target, donor = paired_tables()
        with self.assertRaisesRegex(ValueError, "donor getuid body"):
            module.audit(target, donor, {}, 0x200000, 0x100000,
                         text_limit_1360=0x10000,
                         donor_body_offset=0xfff2)


if __name__ == "__main__":
    unittest.main()
