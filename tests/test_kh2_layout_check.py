import json
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from kh2_layout_check import check  # noqa: E402
from kh2_layout_check import compare_log  # noqa: E402
from test_khook_trace_classify import record  # noqa: E402


def candidate():
    path = Path(__file__).resolve().parents[1] / "examples/kh2_layout_synthetic.json"
    return json.loads(path.read_text())


def planned_log(plan, *, b2_sha=None, image_addr="0x20000", through="A2"):
    hashes = check(plan)
    arm = hashes["expected_b2_ist_image_sha"]
    dispatch = hashes["expected_a2_ist_image_sha"]
    payloads = [
        record("B0", cpu="0", f1_slot="0x20018", f2_slot="0x20218"),
        record("B1", cpu="0", part="image", addr=image_addr, bytes="1280",
               rbp_addr="0x20300", rip_addr="0x20308", rsp_addr="0x20310",
               dr7_addr="0x20318"),
        record("B1", cpu="0", part="big", addr="0x23a00", bytes="1536"),
        record("B1", cpu="0", part="journal", addr="0x25000", bytes="256",
               a1p_addr="0x25000", a1r_addr="0x25008", d1s_addr="0x25010",
               d1o_addr="0x25018"),
        record("B2", cpu="0", ist_image_sha=b2_sha or arm,
               ist_readback_sha=b2_sha or arm,
               ist6_actual="0x20040", ist6_expected="0x20040"),
        record("A2", cpu="0", ist_before_sha=b2_sha or arm,
               ist_image_sha=dispatch, ist_readback_sha=dispatch,
               ist_actual="0x20240", ist_expected="0x20240",
               armed_addr="0x25020"),
    ]
    if through == "B1":
        payloads = payloads[:4]
    return "".join(f"{i}\t{i * 1000}\tMARK\t{payload}\n"
                   for i, payload in enumerate(payloads, 1)).encode()


class LayoutCheck(unittest.TestCase):
    def test_retained_report_matches_plan_but_does_not_verify_ownership(self):
        plan = candidate()
        result = compare_log(plan, planned_log(plan))
        self.assertEqual(result["comparison_status"], "observed_fields_match")
        self.assertEqual(result["missing_layout_records"], [])
        self.assertIn("B2.ist_image_sha", result["compared_fields"])
        self.assertIn("A2.ist_image_sha", result["compared_fields"])
        self.assertEqual(result["transport"], "unknown")

    def test_partial_log_is_a_coverage_gap_and_mismatch_is_located(self):
        plan = candidate()
        partial = compare_log(plan, planned_log(plan, through="B1"))
        self.assertEqual(partial["comparison_status"], "partial_observed_fields_match")
        self.assertEqual(partial["missing_layout_records"], ["B2", "A2"])
        changed_image = compare_log(plan, planned_log(plan, image_addr="0x1fff8"))
        self.assertEqual(changed_image["comparison_status"], "mismatch")
        self.assertEqual(changed_image["mismatches"][0]["field"], "B1.image.addr")
        changed = compare_log(plan, planned_log(plan, b2_sha="f" * 64))
        self.assertEqual(changed["comparison_status"], "mismatch")
        self.assertEqual([item["field"] for item in changed["mismatches"]],
                         ["B2.ist_image_sha", "A2.ist_before_sha"])

    def test_mismatched_manifest_does_not_compare_fields(self):
        plan = candidate()
        result = compare_log(plan, planned_log(plan),
                             {"sha256": "0" * 64, "clean": True, "gaps": []})
        self.assertEqual(result["comparison_status"], "comparison_error")
        self.assertEqual(result["compared_fields"], [])
        self.assertEqual(result["integrity"], "mismatch")

    def test_ambiguous_sequence_cannot_be_joined_to_plan(self):
        plan = candidate()
        raw = planned_log(plan)
        duplicate = raw.splitlines(keepends=True)[0]
        result = compare_log(plan, raw + duplicate)
        self.assertEqual(result["comparison_status"], "comparison_error")
        self.assertIn("B0: ambiguous", result["comparison_errors"][0])

    def test_cli_partial_log_succeeds_and_source_mismatch_fails(self):
        plan_path = Path(__file__).resolve().parents[1] / "examples/kh2_layout_synthetic.json"
        checker = Path(__file__).resolve().parents[1] / "tools/kh2_layout_check.py"
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "run.log"
            log_path.write_bytes(planned_log(candidate(), through="B1"))
            command = [sys.executable, str(checker), str(plan_path),
                       "--log", str(log_path)]
            partial = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(partial.returncode, 0, partial.stderr)
            self.assertEqual(json.loads(partial.stdout)["log_comparison"]["comparison_status"],
                             "partial_observed_fields_match")
            log_path.write_bytes(planned_log(candidate(), image_addr="0x1fff8"))
            mismatch = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(mismatch.returncode, 1, mismatch.stderr)
            self.assertEqual(json.loads(mismatch.stdout)["log_comparison"]["mismatches"][0]["field"],
                             "B1.image.addr")

    def test_disjoint_synthetic_plan_is_geometry_only(self):
        result = check(candidate())
        self.assertTrue(result["geometry_valid"], result["errors"])
        self.assertFalse(result["ownership_verified"])
        self.assertEqual(result["selected_a2_ist_expected"], "0x20240")
        self.assertEqual(int(candidate()["ist_qwords"][0], 16) % 8, 4)
        arm = [int(value, 16) for value in candidate()["ist_targets"]["arm"]]
        dispatch = [int(value, 16) for value in candidate()["ist_targets"]["dispatch"]]
        self.assertEqual(result["expected_b2_ist_image_sha"],
                         hashlib.sha256(struct.pack("<16Q", *arm)).hexdigest())
        self.assertEqual(result["expected_a2_ist_image_sha"],
                         hashlib.sha256(struct.pack("<16Q", *dispatch)).hexdigest())

    def test_pr97_shared_base_collides_with_reference_reservation_and_writes(self):
        plan = candidate()
        for item in plan["landings"]:
            item["base"] = hex(0x10000 + item["cpu"] * 0x500)
        plan["b1"]["image"]["base"] = "0x10000"
        plan["b1"]["big"]["base"] = "0x13a00"
        plan["reserved"][0]["base"] = "0x10000"
        plan["frame_slots"] = ["0x10018", "0x10218"]
        plan["context_qwords"] = [hex(0x10300 + 8 * i) for i in range(4)]
        for cpu in range(16):
            plan["ist_targets"]["arm"][cpu] = hex(0x10000 + cpu * 0x500 + 0x28)
            plan["ist_targets"]["dispatch"][cpu] = plan["ist_targets"]["arm"][cpu]
        plan["ist_targets"]["arm"][0] = "0x10040"
        plan["ist_targets"]["dispatch"][0] = "0x10240"
        errors = check(plan)["errors"]
        self.assertNotIn("cpu[0] overlaps image", errors)
        self.assertIn("cpu[11] overlaps big", errors)
        self.assertIn("reserved:reference_image overlaps cpu[12]", errors)

    def test_selected_landing_must_contain_both_frames_inside_image(self):
        plan = candidate()
        plan["landings"][0]["size"] = "0x200"
        errors = check(plan)["errors"]
        self.assertIn("frame[1] outside selected CPU landing", errors)
        plan["landings"][0]["base"] = "0x26000"
        errors = check(plan)["errors"]
        self.assertIn("selected CPU landing outside B1 image", errors)

    def test_ist_target_must_route_into_its_cpu_landing_in_both_phases(self):
        plan = candidate()
        plan["ist_targets"]["arm"][7] = plan["ist_targets"]["arm"][8]
        plan["ist_targets"]["dispatch"][0] = "0x20248"
        plan["ist_targets"]["dispatch"][9] = "0x12830"
        result = check(plan)
        errors = result["errors"]
        self.assertIn("arm IST target outside cpu[7] landing", errors)
        self.assertIn("selected dispatch IST target differs from F2 top", errors)
        self.assertIn("cpu[9] IST target changes without an A2 readback", errors)
        self.assertIsNone(result["expected_b2_ist_image_sha"])
        self.assertIsNone(result["expected_a2_ist_image_sha"])

    def test_ist_qword_addresses_follow_12_02_tss_geometry(self):
        plan = candidate()
        plan["ist_qwords"][7] = "0x2e8b2fc"
        self.assertIn("ist[7] differs from TSS/IST6 address", check(plan)["errors"])
        plan = candidate()
        plan["kdata_base"] = "0x1000"
        errors = check(plan)["errors"]
        self.assertIn("vector-1 gate differs from 12.02 IDT address", errors)
        self.assertIn("TSS base differs from 12.02 offset", errors)

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
        plan = candidate()
        plan["gate"]["base"] = "0xfffffffffffffff8"
        with self.assertRaisesRegex(ValueError, "overflowing span"):
            check(plan)


if __name__ == "__main__":
    unittest.main()
