import tempfile
import unittest
from pathlib import Path

from tools.kh2_anchor_projection import load_gadgets, load_kstuff, project


class AnchorProjectionTests(unittest.TestCase):
    def test_headers_parse_symbolic_offsets_and_reject_executable_expression(self):
        with tempfile.TemporaryDirectory() as temp:
            header = Path(temp) / "offsets.h"
            header.write_text("DEF(doreti_iret, -0x100)\nDEF(near, doreti_iret + 0x10)\n")
            self.assertEqual(load_kstuff(header)["near"], -0xf0)
            header.write_text("DEF(doreti_iret, __import__('os').system('false'))\n")
            with self.assertRaises((ValueError, SyntaxError)):
                load_kstuff(header)
            header.write_text(
                "uint64_t g_gadget_map_1[] = {\n"
                "  0x1100, // KERNEL_GADGET_IRETQ\n"
                "  0x1130, // KERNEL_GADGET_PIVOT\n"
                "};\n"
            )
            self.assertEqual(load_gadgets(header)["PIVOT"], 0x1130)
            with self.assertRaisesRegex(ValueError, "firmware label mismatch"):
                load_kstuff(header, "12_02")
            with self.assertRaisesRegex(ValueError, "missing gadget map"):
                load_gadgets(header, "13_60")

    def test_requires_all_donors_and_reports_conflicting_target_regions(self):
        kstuff = {
            "13_00": {"doreti_iret": -0x100, "near": -0xe0, "other": -0x200},
            "13_20": {"doreti_iret": -0x100, "near": -0xe0, "other": -0x200},
            "13_60": {"doreti_iret": -0x100, "near": -0xe0, "other": -0x200},
            "12_02": {"doreti_iret": -0x200, "near": -0x1e0, "other": -0x280},
        }
        gadgets = {
            fw: {"IRETQ": 0x1100, "PIVOT": 0x1130, "MOVED": 0x1800}
            for fw in ("13_00", "13_20", "13_60")
        }
        result = project(kstuff, gadgets, 0x2000, 0x40)
        self.assertEqual(result["selected_address_candidates"]["PIVOT"]["candidate_offset"],
                         "0x1e30")
        self.assertEqual(result["selected_address_candidates"]["IRETQ"]["candidate_offset"],
                         "0x1e00")
        self.assertEqual(result["stable_but_remote_or_conflicting"]["MOVED"]["reason"],
                         "outside local distance")
        gadgets["13_20"]["PIVOT"] += 1
        result = project(kstuff, gadgets, 0x2000, 0x40)
        self.assertIn("PIVOT", result["no_stable_anchor_relation"])

    def test_reports_local_conflict_instead_of_selecting_a_projection(self):
        kstuff = {
            fw: {"doreti_iret": -0x100, "a": -0xe0, "b": -0xc0}
            for fw in ("13_00", "13_20", "13_60")
        }
        kstuff["12_02"] = {"doreti_iret": -0x100, "a": -0xe0, "b": -0xb0}
        gadgets = {
            fw: {"IRETQ": 0x1100, "PIVOT": 0x1120}
            for fw in ("13_00", "13_20", "13_60")
        }
        result = project(kstuff, gadgets, 0x2000, 0x40)
        self.assertNotIn("PIVOT", result["selected_address_candidates"])
        conflict = result["stable_but_remote_or_conflicting"]["PIVOT"]
        self.assertEqual(conflict["reason"], "conflicting local projections")
        self.assertEqual(
            {row["candidate_offset"] for row in conflict["local_projections"]},
            {"0x1f20", "0x1f30"},
        )


if __name__ == "__main__":
    unittest.main()
