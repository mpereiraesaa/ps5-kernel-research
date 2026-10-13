"""Synthetic checks for the offline sy_call entry resolver."""

import importlib.util
import struct
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "sysent_trampoline_map",
    Path(__file__).resolve().parents[1] / "tools/sysent_trampoline_map.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class SysentTrampolineMapTests(unittest.TestCase):
    def test_neighbors_identify_entry_without_claiming_body(self):
        data = bytearray(0x800)
        base, table = 0x100000, 0x100
        for number, offset in ((23, 0x238), (24, 0x200), (25, 0x208)):
            struct.pack_into("<Q", data,
                             table + number * module.SYSENT_STRIDE + 8,
                             base + offset)
        self.assertEqual(module.sy_call_neighbors(data, table, base, 0x300),
                         {23: 0x238, 24: 0x200, 25: 0x208})

    def test_follow_rel32_jump(self):
        text = bytearray(0x80)
        text[0x10] = 0xE9
        struct.pack_into("<i", text, 0x11, 0x60 - (0x10 + 5))
        self.assertEqual(module.follow_rel32_jump(text, 0x10), 0x60)

    def test_reject_non_jump_entry(self):
        with self.assertRaisesRegex(ValueError, "not a direct rel32 jump"):
            module.follow_rel32_jump(bytes(0x80), 0x10)

    def test_reject_neighbor_drift(self):
        data = bytearray(0x800)
        base, table = 0x100000, 0x100
        for number, offset in ((23, 0x238), (24, 0x200), (25, 0x209)):
            struct.pack_into("<Q", data,
                             table + number * module.SYSENT_STRIDE + 8,
                             base + offset)
        with self.assertRaisesRegex(ValueError, "spacing differs"):
            module.sy_call_neighbors(data, table, base, 0x300)


if __name__ == "__main__":
    unittest.main()
