import unittest
from pathlib import Path

from tools.fullchain_layout_check import check, check_offsets


ROOT = Path(__file__).resolve().parents[1]
HEADER = (ROOT / "r0gdb/prosper0gdb/offsets/12_02.h").read_text()
STRUCTS = """%define iret_rdi 0
%define iret_rsi 8
%define iret_rcx 24
%define iret_rip 232
%define iret_cs (iret_rip+8)
%define iret_eflags (iret_rip+16)
%define iret_rsp (iret_rip+24)
%define iret_ss (iret_rip+32)
"""
GEOMETRY = """enum {
  CPU_COUNT = 16,
  SLOT_SIZE = 0x500,
  SCRATCH_SIZE = CPU_COUNT * SLOT_SIZE,
  FRAME_OFF = 0x80,
  HW_FRAME_OFF = FRAME_OFF - 0x28,
  IRET_FRAME_OFF = FRAME_OFF + 0xc0,
  CHAIN1_OFF = 0x180,
  AFTER_COPY_OFF = 0x290,
  CHAIN2_OFF = 0x2a0,
  MARKER_SRC_OFF = 0x400,
  MARKER_DST_OFF = 0x408,
  REGS_RDI = 0,
  REGS_RSI = 8,
  REGS_RCX = 24,
  REGS_RIP = 232,
  REGS_CS = 240,
  REGS_RFLAGS = 248,
  REGS_RSP = 256,
  REGS_SS = 264,
};
uint64_t canary = 0x4a524652414d4500ULL {op} ((uint64_t)cpu << 8)
                  {op} (uint64_t)word;
"""


class FullchainOffsetAuditTests(unittest.TestCase):
    def test_canary_collision_fails_geometry_gate(self):
        historical = check(GEOMETRY.replace("{op}", "|"), STRUCTS)
        self.assertFalse(historical["geometry_valid"])
        self.assertFalse(historical["unique_canaries"])
        self.assertEqual(historical["distinct_canaries"], 20)
        self.assertIn("20 distinct values for 80", historical["errors"][0])

        corrected = check(GEOMETRY.replace("{op}", "+"), STRUCTS)
        self.assertTrue(corrected["geometry_valid"], corrected["errors"])
        self.assertTrue(corrected["unique_canaries"])
        self.assertEqual(corrected["distinct_canaries"], 80)

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
