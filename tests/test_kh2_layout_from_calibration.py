import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
from kh2_layout_check import check, number  # noqa: E402
from kh2_layout_from_calibration import create_plan  # noqa: E402
from kh2_r0_calibration_check import base_from_gate_bracket  # noqa: E402
from test_kh2_r0_calibration_check import (  # noqa: E402
    BASE, BUILD, CPU, EXIT, GATE, START, trace,
)

TEMPLATE = ROOT / "examples/kh2_layout_1202_zero_span_candidate.json"


def evidence(raw):
    return ({"sha256": hashlib.sha256(raw).hexdigest(),
             "clean": True, "gaps": []}, START + "\n" + EXIT + "\n")


class LayoutFromCalibration(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(TEMPLATE.read_text())
        self.raw = trace()
        self.manifest, self.stdout = evidence(self.raw)

    def test_complete_capture_selects_its_own_cpu_and_derived_base(self):
        self.assertEqual(base_from_gate_bracket(self.raw), BASE)
        plan = create_plan(self.template, self.raw, self.manifest,
                           self.stdout, BUILD)
        self.assertEqual(plan["selected_cpu"], CPU)
        self.assertEqual(number(plan["kdata_base"]), BASE)
        self.assertEqual(number(plan["gate"]["base"]), GATE)
        selected = next(item for item in plan["landings"]
                        if item["cpu"] == CPU)
        self.assertEqual(number(selected["base"]), BASE + 0x2099000)
        self.assertTrue(check(plan)["geometry_valid"])
        self.assertFalse(check(plan)["ownership_verified"])
        self.assertIn("not independent", plan["calibration"]["base_source"])

    def test_rejects_manifest_stdout_and_readback_mismatch(self):
        wrong_manifest = dict(self.manifest, gaps=[3])
        with self.assertRaisesRegex(ValueError, "R0 capture incomplete"):
            create_plan(self.template, self.raw, wrong_manifest,
                        self.stdout, BUILD)
        with self.assertRaisesRegex(ValueError, "R0 capture incomplete"):
            create_plan(self.template, self.raw, self.manifest,
                        self.stdout.replace(EXIT, EXIT.replace("0x123abc", "0x888")),
                        BUILD)
        changed = self.raw.replace(b"gate_lo=0x1 gate_hi=0x2 ist6=0x3",
                                   b"gate_lo=0x4 gate_hi=0x2 ist6=0x3", 1)
        changed_manifest, changed_stdout = evidence(changed)
        with self.assertRaisesRegex(ValueError, "worker R0 values differ"):
            create_plan(self.template, changed, changed_manifest,
                        changed_stdout, BUILD)

    def test_rejects_missing_or_duplicate_gate_begin(self):
        begin = next(line for line in self.raw.splitlines()
                     if b"region=gate" in line and b"state=begin" in line)
        without = b"\n".join(line for line in self.raw.splitlines()
                             if line != begin) + b"\n"
        with self.assertRaisesRegex(ValueError, "exactly one"):
            base_from_gate_bracket(without)
        duplicated = self.raw + begin + b"\n"
        with self.assertRaisesRegex(ValueError, "exactly one"):
            base_from_gate_bracket(duplicated)

    def test_cli_pins_capture_hashes_without_raw_logs_in_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.log").write_bytes(self.raw)
            manifest_bytes = json.dumps(self.manifest).encode()
            (root / "run.json").write_bytes(manifest_bytes)
            stdout_bytes = self.stdout.encode()
            (root / "elfldr.txt").write_bytes(stdout_bytes)
            completed = subprocess.run([
                sys.executable, str(ROOT / "tools/kh2_layout_from_calibration.py"),
                str(TEMPLATE), "--log", str(root / "run.log"),
                "--manifest", str(root / "run.json"),
                "--stdout", str(root / "elfldr.txt"), "--build-sha", BUILD,
            ], capture_output=True, text=True, check=True)
            plan = json.loads(completed.stdout)
            self.assertEqual(plan["calibration"]["log_sha256"],
                             hashlib.sha256(self.raw).hexdigest())
            self.assertEqual(plan["calibration"]["manifest_sha256"],
                             hashlib.sha256(manifest_bytes).hexdigest())
            self.assertEqual(plan["calibration"]["stdout_sha256"],
                             hashlib.sha256(stdout_bytes).hexdigest())
            self.assertNotIn("0x123abc", completed.stdout)
            self.assertTrue(check(plan)["geometry_valid"])


if __name__ == "__main__":
    unittest.main()
