"""Synthetic homology and ambiguity checks for paired pointer rows."""

import importlib.util
import struct
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "kh2_static_table_audit",
    Path(__file__).resolve().parents[1] / "tools/kh2_static_table_audit.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def place_row(data, origin, text_base, metadata_base, variant):
    for index, rel in enumerate(module.TEXT_REL):
        offset = (0x1000 + variant * 0x200 + index * 0x20)
        if rel == 0:
            offset = 0x1600 + variant * 0x200
        if rel == 0x10:
            offset = 0x1620 + variant * 0x200
        struct.pack_into("<Q", data, origin + rel, text_base + offset)
    for index, rel in enumerate(module.META_REL):
        struct.pack_into("<Q", data, origin + rel, metadata_base + index * 8)


class StaticTableAuditTests(unittest.TestCase):
    def setUp(self):
        self.donor = bytearray(0x600)
        self.target = bytearray(0x600)
        for row_index, origin in enumerate((0x100, 0x200)):
            place_row(self.donor, origin, 0x100000, 0x300000, row_index)
        for row_index, origin in enumerate((0x180, 0x280)):
            place_row(self.target, origin, 0x200000, 0x400000, row_index)

    def test_unique_paired_rows_preserve_order_without_projecting_gadget(self):
        result = module.audit(self.target, self.donor, 0x100,
                              0x200000, 0x100000,
                              text_limit_1202=0x10000,
                              text_limit_1360=0x10000)
        self.assertEqual(result["row_gap"], "0x100")
        self.assertEqual([r["data_offset"] for r in result["donor_rows"]],
                         ["0x100", "0x200"])
        self.assertEqual([r["data_offset"] for r in result["target_rows"]],
                         ["0x180", "0x280"])
        self.assertIn("no containing-function", result["scope"])

    def test_ambiguous_target_pair_is_rejected(self):
        place_row(self.target, 0x380, 0x200000, 0x400000, 2)
        with self.assertRaisesRegex(ValueError, "expected one matching"):
            module.audit(self.target, self.donor, 0x100,
                         0x200000, 0x100000,
                         text_limit_1202=0x10000,
                         text_limit_1360=0x10000)


if __name__ == "__main__":
    unittest.main()
