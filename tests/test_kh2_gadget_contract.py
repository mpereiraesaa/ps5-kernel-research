"""Synthetic checks for the offline KH2 instruction-contract verifier."""

import importlib.util
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "kh2_gadget_contract",
    Path(__file__).resolve().parents[1] / "tools/kh2_gadget_contract.py",
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class GadgetContractTests(unittest.TestCase):
    def test_parses_instruction_only_output_and_accepts_pivot(self):
        output = """Disassembly of section .data:
0000000000000100 <.data+0x100>:
 100:\tadd    rsp,0x28
 104:\trepz ret
 106:\tnop
"""
        instructions = module.parse_instructions(output)
        result = module.check_sequence(instructions, 0x100, module.PIVOT,
                                       allow_plain_ret=True)
        self.assertTrue(result["contract_match"])
        self.assertEqual(len(instructions), 3)

    def test_rejects_shifted_entry_and_stack_delta(self):
        instructions = [(0x101, "add rsp,0x28"), (0x105, "ret")]
        shifted = module.check_sequence(instructions, 0x100,
                                        module.PIVOT, True)
        self.assertFalse(shifted["contract_match"])
        self.assertEqual(shifted["first_mismatch_index"], 0)
        instructions[0] = (0x100, "add rsp,0x30")
        result = module.check_sequence(instructions, 0x100,
                                       module.PIVOT, True)
        self.assertEqual(result["first_mismatch_index"], 0)
        self.assertFalse(result["contract_match"])

    def test_rejects_changed_debug_register_restore(self):
        instructions = [(0x200 + index, line)
                        for index, line in enumerate(module.DBREG)]
        self.assertTrue(module.check_sequence(
            instructions, 0x200, module.DBREG)["contract_match"])
        instructions[10] = (0x20a, "mov dr6,rax")
        result = module.check_sequence(instructions, 0x200, module.DBREG)
        self.assertEqual(result["first_mismatch_index"], 10)
        self.assertFalse(result["contract_match"])


if __name__ == "__main__":
    unittest.main()
