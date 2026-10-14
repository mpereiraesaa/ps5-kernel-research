"""Synthetic provenance checks for exact donor gadget pointers."""

import importlib.util
import struct
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "kh2_donor_gadget_pointer_audit",
    Path(__file__).resolve().parents[1] /
    "tools/kh2_donor_gadget_pointer_audit.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class DonorGadgetPointerAuditTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(0x6000)
        self.base = 0x100000
        self.offsets = {
            "MOV_RAX_RSI": "0x10", "POP_RCX": "0x20",
            "ST_RCX_RAX": "0x30", "ST_RCX_RDX": "0x40",
            "OUTSIDE": "0x50",
        }
        for displacement, name in module.PREFIX:
            struct.pack_into("<Q", self.data, 0x4a00 + displacement,
                             self.base + int(self.offsets[name], 0))

    def audit(self):
        return module.audit(self.data, self.offsets, self.base,
                            gap=0x1000, cave_text_offset=0x2000)

    def test_chain_prefix_and_cave_are_distinct_from_outside_hit(self):
        struct.pack_into("<Q", self.data, 0x180, self.base + 0x50)
        result = self.audit()
        self.assertTrue(result["big_chain_prefix_matches"])
        self.assertEqual(result["cave_data_offset"], "0x1000")
        self.assertEqual(result["big_chain_data_offset"], "0x4a00")
        self.assertEqual(result["exact_aligned_hits"], 6)
        self.assertEqual(result["inside_published_scratch"], 5)
        self.assertEqual(result["outside_published_scratch"], 1)
        self.assertEqual(result["hits_by_page"], {"0x0": 1, "0x4000": 5})

    def test_missing_prefix_and_unaligned_pointer_do_not_pass(self):
        struct.pack_into("<Q", self.data, 0x4a30, 0)
        struct.pack_into("<Q", self.data, 0x183, self.base + 0x50)
        result = self.audit()
        self.assertFalse(result["big_chain_prefix_matches"])
        self.assertEqual(result["exact_aligned_hits"], 4)
        self.assertEqual(result["outside_published_scratch"], 0)

    def test_short_image_rejects_published_scratch_span(self):
        with self.assertRaisesRegex(ValueError, "scratch span"):
            module.audit(bytes(0x2000), self.offsets, self.base,
                         gap=0x1000, cave_text_offset=0x2000)


if __name__ == "__main__":
    unittest.main()
