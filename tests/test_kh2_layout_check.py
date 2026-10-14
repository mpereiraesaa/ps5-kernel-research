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
from kh2_layout_check import locate_write_error  # noqa: E402
from test_khook_trace_classify import record  # noqa: E402


def candidate():
    path = Path(__file__).resolve().parents[1] / "examples/kh2_layout_synthetic.json"
    return json.loads(path.read_text())


def zero_span_candidate():
    path = Path(__file__).resolve().parents[1] / "examples/kh2_layout_1202_zero_span_candidate.json"
    return json.loads(path.read_text())


def planned_log(plan, *, b0_sha=None, b1_big_sha=None, b2_sha=None,
                image_addr="0x1b500", through="A2",
                b2_gate_lo="0x333", b2_gate_hi="0x444"):
    hashes = check(plan)
    arm = hashes["expected_b2_ist_image_sha"]
    dispatch = hashes["expected_a2_ist_image_sha"]
    payloads = [
        record("B0", cpu="0", build_sha=b0_sha or "a" * 64,
               f1_slot="0x20018", f2_slot="0x20218"),
        record("B1", cpu="0", part="image", addr=image_addr, bytes="20480",
               rbp_addr="0x20300", rip_addr="0x20308", rsp_addr="0x20310",
               dr7_addr="0x20318"),
        record("B1", cpu="0", part="big", addr="0x23a00", bytes="1536",
               image_sha=b1_big_sha or "c" * 64,
               readback_sha=b1_big_sha or "c" * 64),
        record("B1", cpu="0", part="journal", addr="0x25000", bytes="256",
               a1p_addr="0x25000", a1r_addr="0x25008", d1s_addr="0x25010",
               d1o_addr="0x25018"),
        record("B2", cpu="0", ist_image_sha=b2_sha or arm,
               ist_readback_sha=b2_sha or arm,
               gate_lo=b2_gate_lo, expected_lo=b2_gate_lo,
               gate_hi=b2_gate_hi, expected_hi=b2_gate_hi,
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
    def test_optional_pivot_gate_comparison_detects_wrong_descriptor(self):
        plan = candidate()
        target = 0xffffffff8876c2de
        ordinary = compare_log(plan, planned_log(plan), b2_target=target)
        self.assertEqual(ordinary["comparison_status"], "mismatch")
        self.assertEqual(ordinary["mismatches"][0]["field"], "B2.pivot_gate")
        self.assertEqual(ordinary["b2_pivot_gate_comparison"]["status"],
                         "different")
        matched = compare_log(plan, planned_log(
            plan, b2_gate_lo="0x88768e060020c2de",
            b2_gate_hi="0xffffffff"), b2_target=target)
        self.assertEqual(matched["comparison_status"], "partial_address_evidence")
        self.assertEqual(matched["b2_pivot_gate_comparison"]["status"], "equal")

    def test_retained_report_matches_plan_but_does_not_verify_ownership(self):
        plan = candidate()
        result = compare_log(plan, planned_log(plan))
        self.assertEqual(result["comparison_status"], "partial_address_evidence")
        self.assertEqual(result["missing_layout_records"], [])
        self.assertFalse(result["address_bracket_coverage"]["complete"])
        self.assertIn("B0.scratch address/size absent from plan",
                      result["address_bracket_coverage"]["unplanned_regions"])
        self.assertTrue(result["address_bracket_coverage"]["missing_reads"])
        self.assertTrue(result["address_bracket_coverage"]["missing_writes"])
        self.assertIn("B2.ist_image_sha", result["compared_fields"])
        self.assertIn("A2.ist_image_sha", result["compared_fields"])
        self.assertEqual(result["transport"], "unknown")

    def test_partial_log_is_a_coverage_gap_and_mismatch_is_located(self):
        plan = candidate()
        partial = compare_log(plan, planned_log(plan, through="B1"))
        self.assertEqual(partial["comparison_status"], "partial_observed_fields_match")
        self.assertEqual(partial["missing_layout_records"], ["B2", "A2"])
        changed_image = compare_log(plan, planned_log(plan, image_addr="0x1b4f8"))
        self.assertEqual(changed_image["comparison_status"], "mismatch")
        self.assertEqual(changed_image["mismatches"][0]["field"], "B1.image.addr")
        changed = compare_log(plan, planned_log(plan, b2_sha="f" * 64))
        self.assertEqual(changed["comparison_status"], "mismatch")
        self.assertEqual([item["field"] for item in changed["mismatches"]],
                         ["B2.ist_image_sha", "A2.ist_before_sha"])

    def test_build_and_staged_image_hash_mismatch_survive_internal_classification(self):
        plan = candidate()
        result = compare_log(plan, planned_log(plan, b0_sha="f" * 64,
                                               b1_big_sha="e" * 64))
        self.assertEqual(result["comparison_status"], "mismatch")
        self.assertEqual([item["field"] for item in result["mismatches"]],
                         ["B0.build_sha", "B1.big.image_sha"])

    def test_log_join_requires_declared_build_and_staged_hashes(self):
        plan = candidate()
        del plan["build_sha"]
        with self.assertRaisesRegex(ValueError, "build_sha"):
            compare_log(plan, planned_log(candidate()))
        plan = candidate()
        del plan["b1"]["journal"]["image_sha"]
        with self.assertRaisesRegex(ValueError, "b1.journal.image_sha"):
            compare_log(plan, planned_log(candidate()))

    def test_mismatched_manifest_does_not_compare_fields(self):
        plan = candidate()
        result = compare_log(plan, planned_log(plan),
                             {"sha256": "0" * 64, "clean": True, "gaps": []})
        self.assertEqual(result["comparison_status"], "comparison_error")
        self.assertEqual(result["compared_fields"], [])
        self.assertEqual(result["integrity"], "mismatch")

    def test_failed_write_address_identifies_b1_chunk_and_ist_cpu(self):
        plan = candidate()
        raw = planned_log(plan, through="B1")
        raw += ("5\t5000\tERR\tKH2E stage=B1 cpu=0 operation=write "
                "region=image addr=0x1ba00\n"
                "6\t6000\tERR\tKH2E stage=B2 cpu=0 operation=write "
                f"region=ist6 addr={plan['ist_qwords'][7]}\n").encode()
        result = compare_log(plan, raw)
        self.assertEqual(result["comparison_status"],
                         "classifier_rejected_or_capture_error")
        self.assertEqual(result["write_error_locations"], [
            {"seq": 5, "stage": "B1", "region": "image", "addr": "0x1ba00",
             "plan_match": True, "offset": "0x500", "landing_cpu": 2},
            {"seq": 6, "stage": "B2", "region": "ist6",
             "addr": plan["ist_qwords"][7], "plan_match": True, "cpu": 7},
        ])

    def test_open_write_bracket_maps_landing_without_claiming_b1(self):
        plan = candidate()
        raw = planned_log(plan, through="B1").splitlines(keepends=True)[0]
        raw += ("2\t2000\tMARK\tKH2W stage=B1 cpu=0 region=image "
                "addr=0x1ba00 bytes=1280 state=begin\n").encode()
        result = compare_log(plan, raw)
        self.assertEqual(result["comparison_status"],
                         "classifier_rejected_or_capture_error")
        self.assertEqual(result["open_write_locations"], [
            {"seq": 2, "stage": "B1", "region": "image", "addr": "0x1ba00",
             "plan_match": True, "offset": "0x500", "landing_cpu": 2,
             "bytes": 1280, "result": "open"},
        ])
        self.assertIn("B1.image", result["missing_layout_records"])
        crossing = {"seq": 3, "stage": "B1", "region": "image",
                    "addr": "0x1b9f0", "bytes": 32}
        self.assertNotIn("landing_cpu", locate_write_error(plan, crossing))

    def test_open_read_bracket_maps_frame_without_claiming_b2(self):
        plan = candidate()
        raw = planned_log(plan, through="B1")
        raw += ("5\t5000\tMARK\tKH2R stage=B2 cpu=0 region=frame "
                "addr=0x20018 bytes=40 state=begin\n").encode()
        result = compare_log(plan, raw)
        self.assertEqual(result["comparison_status"],
                         "classifier_rejected_or_capture_error")
        self.assertEqual(result["open_read_locations"], [
            {"seq": 5, "stage": "B2", "region": "frame", "addr": "0x20018",
             "plan_match": True, "frame": 1, "offset": "0x0",
             "bytes": 40, "result": "open"},
        ])
        self.assertIn("B2", result["missing_layout_records"])

    def test_observer_handoff_reads_map_to_selected_plan_fields(self):
        plan = candidate()
        attempt = {"seq": 7, "stage": "R1", "region": "gate",
                   "addr": plan["gate"]["base"], "bytes": 16}
        self.assertEqual(locate_write_error(plan, attempt)["gate_words"], 2)
        attempt.update(region="f1", addr=plan["frame_slots"][0], bytes=40)
        self.assertEqual(locate_write_error(plan, attempt)["frame"], 1)
        attempt.update(stage="R2", region="D1O",
                       addr=plan["journal_qwords"][3], bytes=8)
        self.assertEqual(locate_write_error(plan, attempt)["journal"], "D1O")
        attempt["addr"] = plan["journal_qwords"][2]
        self.assertFalse(locate_write_error(plan, attempt)["plan_match"])

    def test_gate_and_context_write_error_addresses_use_plan_fields(self):
        plan = candidate()
        base = {"seq": 5, "stage": "B2", "region": "gate", "addr": "0x2e88310"}
        self.assertEqual(locate_write_error(plan, base)["word"], 0)
        self.assertEqual(locate_write_error(plan, {**base, "addr": "0x2e88318",
                                                        "bytes": 8})["word"], 1)
        context = {**base, "region": "context", "addr": "0x20308"}
        self.assertEqual(locate_write_error(plan, context)["context"], "rip")
        context["addr"] = "0x20320"
        self.assertFalse(locate_write_error(plan, context)["plan_match"])

    def test_late_write_error_addresses_use_dispatch_and_restore_fields(self):
        plan = candidate()
        error = {"seq": 9, "stage": "A2", "region": "ist6",
                 "addr": plan["ist_qwords"][0]}
        self.assertEqual(locate_write_error(plan, error)["cpu"], 0)
        error["addr"] = plan["ist_qwords"][7]
        self.assertFalse(locate_write_error(plan, error)["plan_match"])
        self.assertEqual(locate_write_error(plan, error, access="read")["cpu"], 7)
        error.update(region="armed", addr=plan["journal_qwords"][4])
        self.assertTrue(locate_write_error(plan, error)["plan_match"])
        error.update(stage="D2", region="image", addr="0x1ba00")
        self.assertEqual(locate_write_error(plan, error)["landing_cpu"], 2)
        error.update(region="gate", addr=plan["gate"]["base"])
        self.assertEqual(locate_write_error(plan, error)["word"], 0)
        error.update(region="ist6", addr=plan["ist_qwords"][7])
        self.assertEqual(locate_write_error(plan, error)["cpu"], 7)
        error.update(region="scratch", addr="0x30000")
        self.assertFalse(locate_write_error(plan, error)["plan_match"])
        plan["scratch"] = {"base": "0x30000", "size": "0x100"}
        self.assertEqual(locate_write_error(plan, error)["offset"], "0x0")

    def test_retained_bracket_outside_plan_fails_log_join(self):
        plan = candidate()
        def bracket(address):
            return (f"7\t7000\tMARK\tKH2R stage=B2 cpu=0 region=gate "
                    f"addr={address} bytes=16 state=begin\n"
                    f"8\t8000\tMARK\tKH2R stage=B2 cpu=0 region=gate "
                    f"addr={address} bytes=16 state=done\n").encode()

        without = compare_log(plan, planned_log(plan))
        correct = compare_log(plan, planned_log(plan) +
                              bracket(plan["gate"]["base"]))
        self.assertEqual(correct["comparison_status"], "partial_address_evidence")
        self.assertEqual(correct["read_attempt_locations"][0]["plan_match"], True)
        def missing_read_count(result):
            return sum(item["count"] for item in
                       result["address_bracket_coverage"]["missing_reads"])
        self.assertEqual(missing_read_count(without) - missing_read_count(correct), 1)

        wrong = compare_log(plan, planned_log(plan) + bracket("0x2e88410"))
        self.assertEqual(wrong["comparison_status"], "mismatch")
        self.assertEqual(wrong["mismatches"][0]["field"], "KH2R.B2.gate.addr")
        self.assertFalse(wrong["read_attempt_locations"][0]["plan_match"])

        wrong_write = (
            b"7\t7000\tMARK\tKH2W stage=B2 cpu=0 region=gate "
            b"addr=0x2e88410 bytes=8 state=begin\n"
            b"8\t8000\tMARK\tKH2W stage=B2 cpu=0 region=gate "
            b"addr=0x2e88410 bytes=8 state=done\n"
        )
        wrong = compare_log(plan, planned_log(plan) + wrong_write)
        self.assertEqual(wrong["comparison_status"], "mismatch")
        self.assertEqual(wrong["mismatches"][0]["field"], "KH2W.B2.gate.addr")

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
            log_path.write_bytes(planned_log(candidate(), image_addr="0x1b4f8"))
            mismatch = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(mismatch.returncode, 1, mismatch.stderr)
            self.assertEqual(json.loads(mismatch.stdout)["log_comparison"]["mismatches"][0]["field"],
                             "B1.image.addr")
            log_path.write_bytes(planned_log(candidate()))
            no_brackets = subprocess.run(command, capture_output=True,
                                         text=True, check=False)
            self.assertEqual(no_brackets.returncode, 1, no_brackets.stderr)
            self.assertEqual(json.loads(no_brackets.stdout)["log_comparison"]
                             ["comparison_status"], "partial_address_evidence")
            pivot = subprocess.run(command + ["--b2-pivot-ktext-base",
                                           "0xffffffff884c0000"],
                                   capture_output=True, text=True, check=False)
            self.assertEqual(pivot.returncode, 1, pivot.stderr)
            self.assertEqual(json.loads(pivot.stdout)["log_comparison"]["mismatches"][0]["field"],
                             "B2.pivot_gate")

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

    def test_dump_zero_span_candidate_covers_all_landings_without_claiming_ownership(self):
        plan = zero_span_candidate()
        result = check(plan)
        self.assertTrue(result["geometry_valid"], result["errors"])
        self.assertFalse(result["ownership_verified"])
        image = plan["b1"]["image"]
        self.assertEqual((int(image["base"], 16), int(image["size"], 16)),
                         (0x2094500, 0x5000))
        self.assertEqual(int(plan["reserved"][0]["base"], 16), 0x2099000)
        with self.assertRaisesRegex(ValueError, "build_sha"):
            compare_log(plan, b"")

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

    def test_every_cpu_landing_and_selected_context_must_be_staged_in_image(self):
        plan = candidate()
        plan["landings"][7]["base"] = "0x26000"
        plan["context_qwords"][0] = "0x1fb80"
        errors = check(plan)["errors"]
        self.assertIn("cpu[7] outside B1 image", errors)
        self.assertIn("context[0] outside selected CPU landing", errors)

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
