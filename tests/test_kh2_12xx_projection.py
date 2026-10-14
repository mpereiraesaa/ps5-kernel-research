import tempfile
import unittest
from pathlib import Path

from tools.kh2_12xx_projection import coordinate_gap, load_map, project
from tools.kh2_gadget_contract import FULL_CONTRACTS


class TwelveFamilyProjectionTests(unittest.TestCase):
    def test_parses_both_comment_styles_and_rejects_wrong_map(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "offsets.h"
            path.write_text(
                "uint64_t g_sym_map_1160[] = {\n"
                "  0x300, // KERNEL_SYM_IDT_ARRAY\n"
                "};\n"
                "uint64_t g_gadget_map_1160[] = {\n"
                "  0x88, // PIVOT_ADD_RSP28_RET\n"
                "  0, // POP_R8 does not exist\n"
                "};\n"
            )
            self.assertEqual(load_map(path, "1160", "sym")["IDT_ARRAY"], 0x300)
            self.assertEqual(load_map(path, "1160", "gadget")["POP_R8"], 0)
            with self.assertRaisesRegex(ValueError, "missing gadget map"):
                load_map(path, "1270", "gadget")
            path.write_text("uint64_t g_gadget_map_1270[] = {\n"
                            "  0x88, // KERNEL_GADGET_PIVOT_ADD_RSP28_RET\n"
                            "  0x89, // KERNEL_GADGET_PIVOT_ADD_RSP28_RET\n};\n")
            with self.assertRaisesRegex(ValueError, "duplicate gadget"):
                load_map(path, "1270", "gadget")

    def test_data_anchors_must_agree(self):
        symbols = {"IDT_ARRAY": 0x300, "COMMON_TSS": 0x400,
                   "PMAP_STORE": 0x500}
        offsets = {"idt": 0x200, "tss_array": 0x300,
                   "kernel_pmap_store": 0x400}
        self.assertEqual(coordinate_gap(symbols, offsets), 0x100)
        symbols["COMMON_TSS"] += 1
        with self.assertRaisesRegex(ValueError, "inconsistent text/data gaps"):
            coordinate_gap(symbols, offsets)

    def test_projects_only_unanimous_nearby_nonzero_gadgets(self):
        data = {"idt": 0x200, "tss_array": 0x300,
                "kernel_pmap_store": 0x400}
        kstuff = {
            "11_60": {**data, "cpu_switch": -0x50, "other": -0x40},
            "12_70": {**data, "cpu_switch": -0x70, "other": -0x60},
            "12_02": {**data, "cpu_switch": -0x60, "other": -0x50},
        }
        names = list(FULL_CONTRACTS)
        gadgets = {fw: dict.fromkeys(names, 0) for fw in ("11_60", "12_70")}
        gadgets["11_60"].update(PIVOT_ADD_RSP28_RET=0xa0, DBREG_RESUME=0xb8)
        gadgets["12_70"].update(PIVOT_ADD_RSP28_RET=0xa0, DBREG_RESUME=0xb8)
        symbols = {
            "11_60": {"IDT_ARRAY": 0x300, "COMMON_TSS": 0x400,
                      "PMAP_STORE": 0x500},
            "12_70": {"IDT_ARRAY": 0x320, "COMMON_TSS": 0x420,
                      "PMAP_STORE": 0x520},
        }
        result = project(kstuff, symbols, gadgets, 0x120, 0x20)
        self.assertEqual(result["selected_address_candidates"]["PIVOT_ADD_RSP28_RET"]
                         ["candidate_offset"], "0xb0")
        self.assertEqual(result["selected_address_candidates"]["DBREG_RESUME"]
                         ["candidate_offset"], "0xc8")
        self.assertEqual(len(result["excluded_zero_donor_gadgets"]), 19)
        kstuff["12_02"]["other"] = -0x48
        result = project(kstuff, symbols, gadgets, 0x120, 0x20)
        self.assertEqual(result["unresolved_nonzero_gadgets"]["PIVOT_ADD_RSP28_RET"]
                         ["reason"], "conflicting local projections")
        symbols["12_70"]["IDT_ARRAY"] += 1
        with self.assertRaisesRegex(ValueError, "inconsistent text/data gaps"):
            project(kstuff, symbols, gadgets, 0x120, 0x20)
        symbols["12_70"]["IDT_ARRAY"] -= 1
        gadgets["12_70"]["UNKNOWN"] = gadgets["12_70"].pop("CLD")
        with self.assertRaisesRegex(ValueError, "21 known names"):
            project(kstuff, symbols, gadgets, 0x120, 0x20)


if __name__ == "__main__":
    unittest.main()
