import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from kh2_layout_check import check  # noqa: E402


def candidate():
    return {
        "cpu_slots": {"base": "0x10000", "size": "0x500", "count": 16},
        "b1": {
            "image": {"base": "0x20000", "size": "0x500"},
            "big": {"base": "0x23a00", "size": "0x600"},
            "journal": {"base": "0x25000", "size": "0x100"},
        },
        "reserved": [{"name": "reference_image", "base": "0x20000",
                      "size": "0x4000"}],
        "gate": {"base": "0x30000", "size": 16},
        "ist_qwords": [hex(0x31000 + 8 * i) for i in range(16)],
        "frame_slots": ["0x20018", "0x20218"],
        "context_qwords": [hex(0x20300 + 8 * i) for i in range(4)],
        "journal_qwords": [hex(0x25000 + 8 * i) for i in range(5)],
    }


class LayoutCheck(unittest.TestCase):
    def test_disjoint_synthetic_plan_is_geometry_only(self):
        result = check(candidate())
        self.assertTrue(result["geometry_valid"], result["errors"])
        self.assertFalse(result["ownership_verified"])

    def test_pr97_shared_base_collides_with_reference_reservation_and_writes(self):
        plan = candidate()
        plan["b1"]["image"]["base"] = "0x10000"
        plan["b1"]["big"]["base"] = "0x13a00"
        plan["reserved"][0]["base"] = "0x10000"
        plan["frame_slots"] = ["0x10018", "0x10218"]
        plan["context_qwords"] = [hex(0x10300 + 8 * i) for i in range(4)]
        errors = check(plan)["errors"]
        self.assertIn("cpu[0] overlaps image", errors)
        self.assertIn("cpu[11] overlaps big", errors)
        self.assertIn("reserved:reference_image overlaps cpu[12]", errors)

    def test_crossing_and_out_of_span_fields_are_rejected(self):
        plan = candidate()
        plan["b1"]["journal"]["base"] = "0x204f8"
        plan["journal_qwords"][0] = "0x205f8"
        plan["context_qwords"][0] = "0x20500"
        errors = check(plan)["errors"]
        self.assertIn("image overlaps journal", errors)
        self.assertIn("context[0] outside B1 image", errors)
        self.assertIn("journal_word[0] outside B1 journal", errors)

    def test_address_wrap_is_rejected(self):
        plan = copy.deepcopy(candidate())
        plan["gate"]["base"] = "0xfffffffffffffff8"
        with self.assertRaisesRegex(ValueError, "overflowing span"):
            check(plan)


if __name__ == "__main__":
    unittest.main()
