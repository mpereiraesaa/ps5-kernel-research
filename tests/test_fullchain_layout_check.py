import unittest
from pathlib import Path

from tools.fullchain_layout_check import check_offsets


ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / "r0gdb/prosper0gdb/offsets/12_02.h").read_text()


class FullchainOffsetAuditTests(unittest.TestCase):
    def test_public_1202_bindings_expose_copy_gadget_typo(self):
        source = """enum {
          IDT_OFF = 0x2e88300,
          TSS_OFF = 0x2e8afe0,
          ADD_RSP_IRET_OFF = 0x2b3626,
          POP_ALL_IRET_OFF = 0x2b35ce,
          REP_MOVSB_POP_RBP_RET_OFF = 0x2efbba,
          DORETI_IRET_OFF = 0x2b362d,
        };"""
        wrong = check_offsets(source, HEADER, 0xd50000)
        self.assertFalse(wrong["offsets_valid"])
        self.assertEqual(len(wrong["errors"]), 1)
        self.assertIn("REP_MOVSB_POP_RBP_RET_OFF", wrong["errors"][0])
        self.assertIn("expected 0x2efdba", wrong["errors"][0])
        corrected = check_offsets(source.replace("0x2efbba", "0x2efdba"),
                                  HEADER, 0xd50000)
        self.assertTrue(corrected["offsets_valid"], corrected["errors"])
        self.assertEqual(len(corrected["checks"]), 6)

    def test_fw_and_gap_are_explicit_inputs(self):
        with self.assertRaisesRegex(ValueError, "FW 12.02"):
            check_offsets("", HEADER.replace("START_FW(1202)", "START_FW(1360)"),
                          0xd50000)
        with self.assertRaisesRegex(ValueError, "positive ktext gap"):
            check_offsets("", HEADER, 0)


if __name__ == "__main__":
    unittest.main()
