"""Synthetic checks for the AP-vector candidate filter."""

import importlib.util
import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "kh2_ap_vector_scan", ROOT / "tools/kh2_ap_vector_scan.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def put_jump(image: bytearray, entry: int, target: int) -> None:
    image[entry] = 0xe9
    struct.pack_into("<i", image, entry + 1, target - entry - 5)


class ApVectorScanTests(unittest.TestCase):
    def test_keeps_ambiguous_candidates_and_rejects_false_shapes(self):
        image = bytearray(0x100)
        for entry, target in ((0x20, 0x80), (0x40, 0xa0), (0x31, 0xc0)):
            put_jump(image, entry, target)
            image[target] = 0xfa
        put_jump(image, 0x60, 0x200)
        result = module.scan(bytes(image), max_results=1)
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["candidates"], [
            {"entry_offset": "0x20", "target_offset": "0x80"}])
        self.assertTrue(result["candidates_truncated"])
        self.assertEqual(module.inspect_known(bytes(image), 0x40)[
            "target_offset"], "0xa0")
        with self.assertRaisesRegex(ValueError, "aligned"):
            module.inspect_known(bytes(image), 0x31)
        with self.assertRaisesRegex(ValueError, "outside text"):
            module.inspect_known(bytes(image), 0x60)

    def test_known_entry_needs_cli_target(self):
        image = bytearray(0x80)
        put_jump(image, 0x18, 0x50)
        with self.assertRaisesRegex(ValueError, "CLI"):
            module.inspect_known(bytes(image), 0x18)
        with self.assertRaisesRegex(ValueError, "direct rel32"):
            module.inspect_known(bytes(image), 0x20)
        with self.assertRaisesRegex(ValueError, "positive"):
            module.scan(bytes(image), max_results=0)


if __name__ == "__main__":
    unittest.main()
