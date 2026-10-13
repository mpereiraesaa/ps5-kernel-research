"""Synthetic checks for bytewise gadget candidate search."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location(
    "kh2_identical_gadget_scan",
    ROOT / "tools/kh2_identical_gadget_scan.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class IdenticalGadgetScanTests(unittest.TestCase):
    def test_finds_entries_at_any_byte_and_counts_overlaps(self):
        count, first = module.find_matches(b"\x00\x58\xc3\x00\x58\xc3",
                                           b"\x58\xc3", 1)
        self.assertEqual(count, 2)
        self.assertEqual(first, [1])
        count, first = module.find_matches(b"\x90\x90\x90", b"\x90\x90", 2)
        self.assertEqual((count, first), (2, [0, 1]))

    def test_derives_only_bounded_instruction_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "synthetic.bin"
            image.write_bytes(b"\x00\x58\xc3\x90" + b"\x00" * 0x40)
            signature = module.signature_for(image.read_bytes(), image,
                                             "POP_RAX", 1)
            self.assertEqual(signature, b"\x58\xc3")
            with self.assertRaisesRegex(ValueError, "shape mismatch"):
                module.signature_for(image.read_bytes(), image,
                                     "POP_RCX", 1)


if __name__ == "__main__":
    unittest.main()
