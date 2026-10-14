import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from kh2_r0_calibration_check import inspect


BUILD = "a" * 64
EXIT = f"[KH2R0] exit rc=0 build={BUILD}; affinity restored"
BASE = 0xffffffff80000000
CPU = 2
GATE = BASE + 0x2e88310
IST6 = BASE + 0x2e8afe0 + CPU * 0x68 + 0x4c


def trace():
    payloads = [
        f"KH2C stage=MAIN_BASELINE fw=12.02 cpu={CPU} build_sha={BUILD} "
        "gate_lo=0x1 gate_hi=0x2 ist6=0x3",
        f"KH2R stage=R0 cpu={CPU} region=gate addr=0x{GATE:x} bytes=16 state=begin",
        f"KH2R stage=R0 cpu={CPU} region=gate addr=0x{GATE:x} bytes=16 state=done",
        f"KH2R stage=R0 cpu={CPU} region=ist6 addr=0x{IST6:x} bytes=8 state=begin",
        f"KH2R stage=R0 cpu={CPU} region=ist6 addr=0x{IST6:x} bytes=8 state=done",
        f"KH2 stage=R0 source=observer cpu={CPU} verified=1 observer_cpu=3 "
        f"build_sha={BUILD} gate_lo=0x1 gate_hi=0x2 ist6=0x3 pipe_ready=1 idle=1",
    ]
    lines = ["HELLO ps5log/1 title=KH2R01202 app=kh2-r0-calibration boot=0x1"]
    lines += [f"{i}\t{i*1000}\tMARK\t{payload}"
              for i, payload in enumerate(payloads, 1)]
    lines.append("BYE seq=7 reason=done")
    return ("\n".join(lines) + "\n").encode()


def verified(raw, **manifest_changes):
    manifest = {"sha256": hashlib.sha256(raw).hexdigest(),
                "clean": True, "gaps": []}
    manifest.update(manifest_changes)
    return inspect(raw, manifest, EXIT + "\n", BASE, BUILD)


class R0CalibrationCheck(unittest.TestCase):
    def test_complete_retained_trace_requires_all_three_evidence_channels(self):
        raw = trace()
        result = verified(raw)
        self.assertEqual(result["status"], "retained_calibration_complete")
        self.assertEqual(result["confirmed_prefix"],
                         ["main baseline", "gate begin", "gate done",
                          "ist6 begin", "ist6 done", "R0"])
        self.assertEqual(result["cpu"], CPU)
        self.assertEqual(result["observer_cpu"], 3)
        self.assertEqual(inspect(raw, None, EXIT, BASE, BUILD)["status"],
                         "partial_evidence")
        self.assertEqual(inspect(raw, {"sha256": hashlib.sha256(raw).hexdigest(),
                                       "clean": True, "gaps": []}, None,
                                 BASE, BUILD)["status"], "partial_evidence")

    def test_missing_ist_done_stops_prefix_even_with_r0_and_clean_close(self):
        lines = trace().splitlines()
        raw = b"\n".join(line for line in lines if b"region=ist6" not in line or
                         b"state=done" not in line) + b"\n"
        result = verified(raw)
        self.assertEqual(result["status"], "invalid_or_error")
        self.assertEqual(result["next_missing"], "ist6 done")

    def test_wrong_location_and_build_cannot_pass(self):
        raw = trace().replace(f"addr=0x{IST6:x}".encode(),
                              f"addr=0x{IST6+8:x}".encode())
        self.assertEqual(verified(raw)["next_missing"], "ist6 begin")
        wrong_build = trace().replace(f"build_sha={BUILD}".encode(),
                                      f"build_sha={'b'*64}".encode())
        self.assertTrue(verified(wrong_build)["issues"])
        wrong_main_word = trace().replace(b"gate_lo=0x1 gate_hi=0x2 ist6=0x3",
                                          b"gate_lo=0x4 gate_hi=0x2 ist6=0x3", 1)
        result = verified(wrong_main_word)
        self.assertIn("worker R0 values differ from main baseline", result["issues"])
        self.assertEqual(result["next_missing"], "R0")
        no_main = b"\n".join(line for line in trace().splitlines()
                             if b"KH2C stage=MAIN_BASELINE" not in line) + b"\n"
        self.assertEqual(verified(no_main)["next_missing"], "main baseline")

    def test_capture_error_manifest_gap_and_missing_exit_are_distinct(self):
        raw = trace()
        self.assertIn("manifest", verified(raw, gaps=[2])["issues"][0])
        missing_exit = inspect(raw, {"sha256": hashlib.sha256(raw).hexdigest(),
                                     "clean": True, "gaps": []},
                               "[KH2R0] native R0 read complete\n", BASE, BUILD)
        self.assertEqual(missing_exit["return_marker"], "missing_clean_exit")
        stale_build_stdout = inspect(raw, {"sha256": hashlib.sha256(raw).hexdigest(),
                                           "clean": True, "gaps": []},
                                     EXIT.replace(BUILD, "b" * 64), BASE, BUILD)
        self.assertEqual(stale_build_stdout["return_marker"], "missing_clean_exit")
        error = raw.replace(b"BYE seq=7 reason=done\n",
                            b"7\t7000\tERR\tKH2E stage=R0 cpu=2 operation=finish "
                            b"region=pipe addr=0x0 code=-2\nBYE seq=8 reason=done\n")
        self.assertTrue(any("KH2E" in issue for issue in verified(error)["issues"]))

    def test_cli_requires_same_run_manifest_and_final_stdout(self):
        raw = trace()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.log").write_bytes(raw)
            (root / "run.json").write_text(json.dumps({
                "sha256": hashlib.sha256(raw).hexdigest(),
                "clean": True, "gaps": []}))
            (root / "elfldr.txt").write_text(EXIT + "\n")
            script = Path(__file__).resolve().parents[1] / "tools" / \
                "kh2_r0_calibration_check.py"
            command = [sys.executable, str(script), str(root / "run.log"),
                       "--kdata-base", hex(BASE), "--build-sha", BUILD,
                       "--manifest", str(root / "run.json")]
            partial = subprocess.run(command, capture_output=True, text=True,
                                     check=False)
            self.assertEqual(partial.returncode, 1)
            self.assertEqual(json.loads(partial.stdout)["status"], "partial_evidence")
            complete = subprocess.run(command + ["--stdout", str(root / "elfldr.txt")],
                                      capture_output=True, text=True, check=False)
            self.assertEqual(complete.returncode, 0, complete.stderr)
            self.assertEqual(json.loads(complete.stdout)["status"],
                             "retained_calibration_complete")


if __name__ == "__main__":
    unittest.main()
