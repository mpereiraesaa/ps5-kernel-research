"""Synthetic checks for the offline KH2 instruction-contract verifier."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_distinguishes_iret_from_plain_return(self):
        iret = module.check_sequence([(0x300, "iretq")],
                                     0x300, module.IRET)
        ret = module.check_sequence([(0x400, "ret")],
                                    0x400, module.RET_TRAMP)
        self.assertTrue(iret["contract_match"])
        self.assertTrue(ret["contract_match"])
        self.assertFalse(module.check_sequence(
            [(0x300, "ret")], 0x300, module.IRET)["contract_match"])

    def test_full_contracts_cover_13_60_header_names(self):
        manifest = Path(__file__).resolve().parents[1] / \
            "examples/kh2_gadget_offsets_1360.json"
        offsets = module.parse_offset_manifest(manifest)
        self.assertEqual(set(offsets), set(module.FULL_CONTRACTS))
        self.assertEqual(len(offsets), 21)

    def test_rex_pop_and_nop_aliases_do_not_hide_wrong_following_ret(self):
        pop = module.check_sequence(
            [(0x100, "rex.RXB pop r8"), (0x102, "ret")],
            0x100, module.FULL_CONTRACTS["POP_R8"])
        rep = module.check_sequence(
            [(0x200, "rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]"),
             (0x202, "xchg ax,ax"), (0x204, "repz ret")],
            0x200, module.FULL_CONTRACTS["REP_MOVSB"])
        wrong = module.check_sequence(
            [(0x100, "rex.RXB pop r8"), (0x102, "jmp 0x200")],
            0x100, module.FULL_CONTRACTS["POP_R8"])
        self.assertTrue(pop["contract_match"])
        self.assertTrue(rep["contract_match"])
        self.assertEqual(wrong["first_mismatch_index"], 1)

    def test_partial_manifest_reports_missing_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "text.bin"
            image.write_bytes(b"\x00" * 0x100)
            manifest = root / "offsets.json"
            manifest.write_text(json.dumps({"firmware": "synthetic",
                                            "offsets": {"IRETQ": "0x10"}}))
            with patch.object(module, "disassemble", return_value=[(0x10, "iretq")]):
                result = module.inspect_manifest(
                    image, "synthetic", module.parse_offset_manifest(manifest))
            self.assertTrue(result["checked"]["IRETQ"]["contract_match"])
            self.assertFalse(result["coverage_complete"])
            self.assertFalse(result["all_contracts_match"])
            self.assertIn("POP_RSP", result["missing"])

    def test_rejects_unknown_and_invalid_manifest_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "offsets.json"
            for offsets in ({"GUESSED": "0x10"}, {"POP_RSP": -1},
                            {"POP_RSP": True}):
                manifest.write_text(json.dumps({"firmware": "synthetic",
                                                "offsets": offsets}))
                with self.assertRaises(ValueError):
                    module.parse_offset_manifest(manifest)

    def test_rejects_manifest_identity_mixups(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "offsets.json"
            manifest.write_text('{"firmware":"13.60","offsets":{"IRETQ":"0x10",'
                                '"IRETQ":"0x20"}}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                module.parse_offset_manifest(manifest)
            manifest.write_text(json.dumps({"firmware": "13.60",
                                            "offsets": {"IRETQ": "0x10"}}))
            with self.assertRaisesRegex(ValueError, "does not match"):
                module.parse_offset_manifest(manifest, "12.02")


if __name__ == "__main__":
    unittest.main()
