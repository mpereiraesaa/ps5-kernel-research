import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "examples/kh2_layout_1202_zero_span_candidate.json"
sys.path.insert(0, str(ROOT / "tools"))
from kh2_layout_check import check, number  # noqa: E402
from kh2_layout_rebase import rebase  # noqa: E402


class LayoutRebase(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(TEMPLATE.read_text())
        self.base = 0xffffffff972d0000

    def test_selected_cpu_9_keeps_special_physical_landing(self):
        source = copy.deepcopy(self.template)
        plan = rebase(self.template, 9, self.base)
        landings = {number(item["cpu"]): number(item["base"])
                    for item in plan["landings"]}
        self.assertEqual(plan["selected_cpu"], 9)
        self.assertEqual(landings[9], self.base + 0x2099000)
        self.assertEqual(landings[0], self.base + 0x2096d00)
        self.assertEqual(number(plan["ist_targets"]["arm"][9]),
                         self.base + 0x2099040)
        self.assertEqual(number(plan["ist_targets"]["dispatch"][9]),
                         self.base + 0x2099240)
        self.assertEqual(number(plan["frame_slots"][0]),
                         self.base + 0x2099018)
        self.assertEqual(number(plan["gate"]["base"]),
                         self.base + 0x2e88310)
        result = check(plan)
        self.assertTrue(result["geometry_valid"], result["errors"])
        self.assertFalse(result["ownership_verified"])
        self.assertEqual(self.template, source)

    def test_all_selected_cpus_have_valid_geometry(self):
        for cpu in range(16):
            with self.subTest(cpu=cpu):
                plan = rebase(self.template, cpu, self.base)
                self.assertTrue(check(plan)["geometry_valid"])

    def test_rejects_double_rebase_stale_hash_and_overflow(self):
        plan = rebase(self.template, 9, self.base)
        with self.assertRaisesRegex(ValueError, "must be zero"):
            rebase(plan, 0, self.base)
        with self.assertRaisesRegex(ValueError, "page-aligned kernel"):
            rebase(self.template, 9, 0)
        staged = copy.deepcopy(self.template)
        staged["b1"]["image"]["image_sha"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "staged-byte hashes"):
            rebase(staged, 9, self.base)
        with self.assertRaisesRegex(ValueError, "exceeds uint64"):
            rebase(self.template, 9, 0xfffffffffffff000)

    def test_cli_records_template_digest(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/kh2_layout_rebase.py"),
             str(TEMPLATE), "--selected-cpu", "9", "--kdata-base",
             hex(self.base)], capture_output=True, text=True, check=True)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["source_template_sha256"],
                         hashlib.sha256(TEMPLATE.read_bytes()).hexdigest())
        self.assertTrue(check(plan)["geometry_valid"])


if __name__ == "__main__":
    unittest.main()
