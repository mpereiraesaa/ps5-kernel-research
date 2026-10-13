import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from khook_trace_classify import (  # noqa: E402
    STAGES, SOURCES, classify, classify_kstuff_fullchain,
)


def record(stage, **overrides):
    common = {"cpu": "3", "verified": "1"}
    raw = {
        "B0": {"fw": "12.02", "build_sha": "a" * 64,
               "scratch_sha": "d" * 64,
               "gate_lo": "0x111", "gate_hi": "0x222", "ist6": "0x900",
               "f1_slot": "0x118", "f2_slot": "0x318"},
        "B2": {"gate_lo": "0x333", "expected_lo": "0x333",
               "gate_hi": "0x444", "expected_hi": "0x444",
               "ist_count": "16", "ist_matched": "16",
               "ist_image_sha": "b" * 64, "ist_readback_sha": "b" * 64,
               "ist6_actual": "0x140", "ist6_expected": "0x140",
               "rbp_actual": "0x100", "rbp_expected": "0x100",
               "rip_actual": "0x200", "rip_expected": "0x200",
               "rsp_actual": "0x300", "rsp_expected": "0x300",
               "dr7_actual": "0x403", "dr7_expected": "0x403",
               **{f"f1_can{i}": hex(i + 1) for i in range(5)},
               **{f"f2_can{i}": hex(i + 11) for i in range(5)}},
        "F1": {"slot": "0x118", "rip": "0x1234", "cs": "0x43",
               "flags": "0x202", "rsp": "0x5678", "ss": "0x3b",
               **{f"can{i}": hex(i + 1) for i in range(5)}},
        "F2": {"slot": "0x318", "rip": "0x4321", "cs": "0x43",
               "flags": "0x202", "rsp": "0x8765", "ss": "0x3b",
               **{f"can{i}": hex(i + 11) for i in range(5)}},
        "A2": {"ist_actual": "0x340", "ist_expected": "0x340",
               "armed_actual": "0x55", "armed_expected": "0x55"},
        "D2": {"returned": "1", "gate_restored": "1",
               "scratch_restored": "1", "ist_restored": "16",
               "gate_lo": "0x111", "gate_hi": "0x222", "ist6": "0x900",
               "scratch_readback_sha": "d" * 64},
    }
    if stage == "B1":
        part = overrides.get("part", "image")
        geometry = {"image": ("0x100", "1280"),
                    "big": ("0x1000", "1536"),
                    "journal": ("0x700", "256")}
        addr, length = geometry[part]
        raw[stage] = {"part": part, "addr": addr, "bytes": length,
                      "image_sha": "c" * 64, "readback_sha": "c" * 64}
        if part == "journal":
            for name, address in (("a1p", "0x700"), ("a1r", "0x708"),
                                  ("d1s", "0x710"), ("d1o", "0x718")):
                raw[stage][f"{name}_addr"] = address
                raw[stage][f"{name}_before"] = "0x0"
    if stage in ("A1P", "A1R", "D1S", "D1O"):
        addr = {"A1P": "0x700", "A1R": "0x708",
                "D1S": "0x710", "D1O": "0x718"}[stage]
        raw[stage] = {"addr": addr, "before": "0x0",
                      "after": "0x55", "expected": "0x55"}
    fields = {"stage": stage, "source": SOURCES[stage], **common,
              **raw.get(stage, {}), **overrides}
    return "KH2 " + " ".join(f"{key}={value}" for key, value in fields.items())


def run(*stages, clean=False, gaps=None):
    payloads = []
    for stage in stages:
        if stage == "B1":
            payloads.extend(record(stage, part=part)
                            for part in ("image", "big", "journal"))
        else:
            payloads.append(record(stage))
    lines = [f"{i}\t{i * 1000}\tMARK\t{payload}\n"
             for i, payload in enumerate(payloads, 1)]
    raw = ("HELLO ps5log/1 title=TEST app=khook boot=0x1\n" +
           "".join(lines) +
           (f"BYE seq={len(payloads)} reason=complete\n" if clean else "")).encode()
    manifest = {"clean": clean, "gaps": [] if gaps is None else gaps,
                "sha256": hashlib.sha256(raw).hexdigest()}
    return classify(raw, manifest)


class ClassifierTests(unittest.TestCase):
    def test_pretrigger_only_does_not_claim_db_failed(self):
        result = run("B0", "B1", "B2")
        self.assertEqual(result["first_missing_direct_evidence"], "F1")
        self.assertEqual(result["transport"], "incomplete")
        self.assertIn("not proof", result["interpretation"])


class FullchainTests(unittest.TestCase):
    LIVE_STAGE = b"[K1] fw=12.02 cpu=3 frames=16 handler=+0x2b3626\n"
    PC_STAGE = (b"HELLO ps5log/1 title=TEST app=fullchain boot=0x1\n"
                b"1\t1000\tMARK\tstaged frames=16 cpu=3 "
                b"chain=popall-copy-popall-doreti\n")
    AUDIT_CHANGED = (
        b"[KA1] gate_target=+0x2b3626 gate_ist=4 native=NO "
        b"staged_ist4=16 scratch_nonzero=100\n"
        b"[KA1] cpu=3 ist4=0xffff800000000080 STAGED marker=NO\n"
        b"[KA2] cpu=3 hw_frame=CHANGED rip=0x1234 cs=0x43 "
        b"flags=0x202 rsp=0x5678 ss=0x3b\n"
        b"[KA2] staged=16 changed_hw_frames=1 marked=0\n"
    )
    FC1 = (
        b"2\t2000\tMARK\tFC1 seq=1 phase=READY fw=12.02 "
        b"build=prearmed-v1 trigger_cpu=3 observer_cpu=7\n"
        b"3\t3000\tMARK\tFC1 seq=2 phase=GATE_VERIFIED cpu=3 "
        b"gate_lo=0x111 gate_hi=0x222 expected_lo=0x111 "
        b"expected_hi=0x222 ist4_matched=16 first_bad_cpu=-1 "
        b"first_bad_ist=0x0\n"
    )

    def test_prepatch_marker_does_not_prove_gate_patch(self):
        result = classify_kstuff_fullchain(self.LIVE_STAGE, pc=self.PC_STAGE)
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")
        self.assertEqual(result["pc_transport"], "unknown")

    def test_setup_only_completion_is_not_a_failed_live_trigger(self):
        pc = self.PC_STAGE + (
            b"2\t2000\tMARK\tsetup-only full_frames=16 "
            b"patch-readback=YES restored=YES no_db=1\n"
            b"BYE seq=2 reason=setup-only_complete\n")
        result = classify_kstuff_fullchain(
            b"", pc=pc, pc_same_run_verified=True)
        self.assertEqual(result["boundary"], "setup_only_completed_no_db_triggered")

    def test_changed_frame_without_marker_narrows_but_does_not_prove_delivery(self):
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, self.AUDIT_CHANGED, same_attempt_verified=True)
        self.assertEqual(result["signals"]["audit_frame"], "changed")
        self.assertEqual(result["signals"]["audit_marker"], "no")
        self.assertEqual(result["boundary"],
                         "frame_changed_copy_marker_or_later_unproven")
        self.assertIn("does not establish", result["caveat"])

    def test_marker_without_return_bounds_later_chain(self):
        audit = self.AUDIT_CHANGED.replace(b"marker=NO", b"marker=WRITTEN")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, audit, same_attempt_verified=True)
        self.assertEqual(result["boundary"],
                         "copy_marker_seen_return_or_transport_unproven")

    def test_return_mismatch_and_pc_only_return_are_distinct(self):
        live = self.LIVE_STAGE + (
            b"[K1r] shared #DB gate and all IST4 slots restored\n"
            b"[K2] returned after INT1; cpu=3 frame=MISMATCH marker=MATCH\n")
        result = classify_kstuff_fullchain(live)
        self.assertEqual(result["boundary"],
                         "returned_but_frame_or_marker_check_failed")
        pc = self.PC_STAGE + (
            b"2\t2000\tMARK\treturned after INT1 cpu=3 frame=MATCH "
            b"marker=MATCH restored=YES\nBYE seq=2 reason=complete\n")
        manifest = {"sha256": hashlib.sha256(pc).hexdigest(),
                    "clean": True, "gaps": []}
        result = classify_kstuff_fullchain(self.LIVE_STAGE, pc=pc,
                                           manifest=manifest,
                                           pc_same_run_verified=True)
        self.assertEqual(result["boundary"], "one_trap_return_and_checks_passed")
        self.assertEqual(result["pc_transport"], "complete")
        result = classify_kstuff_fullchain(self.LIVE_STAGE, pc=pc,
                                           manifest=manifest)
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")

    def test_post_recovery_audit_cannot_negate_a_missing_return(self):
        audit = (b"[KA1] gate_target=+0x3188b0 gate_ist=4 native=YES "
                 b"staged_ist4=0 scratch_nonzero=0\n"
                 b"[KA2] staged=0 changed_hw_frames=0 marked=0\n")
        result = classify_kstuff_fullchain(self.LIVE_STAGE, audit)
        self.assertIsNone(result["signals"]["audit_frame"])
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")

    def test_unlinked_audit_does_not_advance_boundary(self):
        result = classify_kstuff_fullchain(self.LIVE_STAGE, self.AUDIT_CHANGED)
        self.assertEqual(result["signals"]["audit_frame"], "changed")
        self.assertFalse(result["signals"]["audit_same_attempt_verified"])
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")

    def test_nonselected_cpu_activity_is_surfaced(self):
        audit = self.AUDIT_CHANGED.replace(
            b"[KA2] staged=16 changed_hw_frames=1 marked=0\n",
            b"[KA1] cpu=7 ist4=0xffff800000002380 STAGED marker=WRITTEN\n"
            b"[KA2] cpu=7 hw_frame=CHANGED rip=0x7777 cs=0x20 "
            b"flags=0x2 rsp=0x8888 ss=0\n"
            b"[KA2] staged=16 changed_hw_frames=2 marked=1\n")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, audit, same_attempt_verified=True)
        self.assertEqual(result["signals"]["audit_nonselected_cpus"], [7])
        self.assertTrue(result["nonselected_cpu_activity_requires_review"])

    def test_prearmed_gate_record_advances_only_when_linked(self):
        pc = self.PC_STAGE + self.FC1
        unlinked = classify_kstuff_fullchain(self.LIVE_STAGE, pc=pc)
        self.assertEqual(unlinked["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")
        linked = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=pc, pc_same_run_verified=True)
        self.assertEqual(linked["boundary"],
                         "gate_and_ist_staged_delivery_or_later_unproven")
        self.assertTrue(linked["signals"]["fc1"]["gate_verified"])
        with_audit = classify_kstuff_fullchain(
            self.LIVE_STAGE, self.AUDIT_CHANGED, pc=pc,
            same_attempt_verified=True, pc_same_run_verified=True)
        self.assertEqual(with_audit["boundary"],
                         "frame_changed_copy_marker_or_later_unproven")

    def test_prearmed_cpu_identity_conflict_blocks_progress_claim(self):
        pc = self.PC_STAGE + self.FC1.replace(
            b"trigger_cpu=3", b"trigger_cpu=4")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=pc, pc_same_run_verified=True)
        self.assertTrue(result["signals"]["cpu_identity_conflict"])
        self.assertEqual(result["boundary"], "conflicting_probe_cpu_records")

    def test_prearmed_frame_and_marker_narrow_boundary(self):
        frame = (b"4\t4000\tMARK\tFC1 seq=3 phase=FRAME cpu=3 "
                 b"rip=0x123 cs=0x43 flags=0x202 rsp=0x456 ss=0x3b\n")
        pc = self.PC_STAGE + self.FC1 + frame
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=pc, pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "frame_changed_copy_marker_or_later_unproven")
        marker = (b"5\t5000\tMARK\tFC1 seq=4 phase=MARKER cpu=3 "
                  b"value=0x4b53545546464348\n")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=pc + marker, pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "copy_marker_seen_return_or_transport_unproven")
        self.assertEqual(result["signals"]["fc1"]["records"][-1]["fields"]["value"],
                         "0x4b53545546464348")

    def test_prearmed_v2_targeted_sample_requires_selected_cpu(self):
        v2 = self.FC1.replace(b"prearmed-v1", b"prearmed-v2")
        targeted = (b"4\t4000\tMARK\tFC1 seq=3 phase=FRAME cpu=3 "
                    b"sample=targeted rip=0x123 cs=0x43 flags=0x202 "
                    b"rsp=0x456 ss=0x3b\n")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + v2 + targeted,
            pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "frame_changed_copy_marker_or_later_unproven")
        wrong_cpu = targeted.replace(b"cpu=3", b"cpu=7")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + v2 + wrong_cpu,
            pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "gate_and_ist_staged_delivery_or_later_unproven")
        self.assertIn("invalid FC1 sample mode or targeted CPU",
                      result["signals"]["fc1"]["issues"])
        no_mode = targeted.replace(b"sample=targeted ", b"")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + v2 + no_mode,
            pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "gate_and_ist_staged_delivery_or_later_unproven")

    def test_prearmed_gate_mismatch_and_nonselected_frame(self):
        bad_gate = self.FC1.replace(b"gate_lo=0x111", b"gate_lo=0x112")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + bad_gate,
            pc_same_run_verified=True)
        self.assertFalse(result["signals"]["fc1"]["gate_verified"])
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")
        frame = (b"4\t4000\tMARK\tFC1 seq=3 phase=FRAME cpu=7 "
                 b"rip=0x123 cs=0x20 flags=0x2 rsp=0x456 ss=0x0\n")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + self.FC1 + frame,
            pc_same_run_verified=True)
        self.assertTrue(result["nonselected_cpu_activity_requires_review"])

    def test_prearmed_error_reports_bound_patch_handoff(self):
        error_gate = self.FC1.replace(
            b"MARK\tFC1 seq=2 phase=GATE_VERIFIED",
            b"ERR\tFC1 seq=2 phase=GATE_VERIFIED").replace(
                b"gate_lo=0x111", b"gate_lo=0x112")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + error_gate,
            pc_same_run_verified=True)
        self.assertTrue(result["signals"]["fc1"]["gate_mismatch"])
        self.assertEqual(result["boundary"],
                         "observer_gate_or_ist_mismatch_after_main_readback")
        ready = self.FC1.splitlines(keepends=True)[0]
        read_fail = b"3\t3000\tERR\tFC1 seq=2 phase=READ_FAIL\n"
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + ready + read_fail,
            pc_same_run_verified=True)
        self.assertTrue(result["signals"]["fc1"]["read_fail_before_gate_report"])
        self.assertEqual(result["boundary"],
                         "observer_read_failed_after_main_patch_phase")

    def test_prearmed_rejects_out_of_order_frame(self):
        frame = (b"3\t3000\tMARK\tFC1 seq=2 phase=FRAME cpu=3 "
                 b"rip=0x123 cs=0x43 flags=0x202 rsp=0x456 ss=0x3b\n")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE,
            pc=self.PC_STAGE + self.FC1.splitlines(keepends=True)[0] + frame,
            pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")
        self.assertIn("frame or marker without preceding verified gate",
                      result["signals"]["fc1"]["issues"])

    def test_prearmed_marker_without_frame_is_flagged(self):
        marker = (b"4\t4000\tMARK\tFC1 seq=3 phase=MARKER cpu=3 "
                  b"value=0x4b53545546464348\n")
        result = classify_kstuff_fullchain(
            self.LIVE_STAGE, pc=self.PC_STAGE + self.FC1 + marker,
            pc_same_run_verified=True)
        self.assertEqual(result["boundary"],
                         "copy_marker_seen_return_or_transport_unproven")
        self.assertTrue(any("marker seen without matching frame" in issue
                            for issue in result["signals"]["fc1"]["issues"]))

    def test_prearmed_return_observer_failure_is_not_success(self):
        live = self.LIVE_STAGE + (
            b"[K2] returned after INT1; cpu=3 frame=MATCH marker=MATCH "
            b"observer=FAIL saved_rip=0x123\n")
        result = classify_kstuff_fullchain(live)
        self.assertEqual(result["boundary"],
                         "returned_but_observer_failed")


class OtherClassifierTests(unittest.TestCase):
    def test_later_record_with_missing_frame_is_coverage_gap(self):
        result = run("B0", "B1", "B2", "A2", clean=True)
        self.assertEqual(result["first_missing_direct_evidence"], "F1")
        self.assertEqual(result["later_direct_evidence"], ["A2"])
        self.assertFalse(result["out_of_order"])

    def test_full_diagnostic_does_not_prove_ap(self):
        result = run(*STAGES, clean=True)
        self.assertIsNone(result["first_missing_direct_evidence"])
        self.assertEqual(result["transport"], "complete")
        self.assertIn("AP phase unassessed", result["interpretation"])

    def test_reversed_or_wrong_source_record_is_flagged(self):
        result = run("B0", "B2", "B1", clean=True)
        self.assertTrue(result["out_of_order"])
        self.assertTrue(result["causal_order_conflict"])
        raw = ("1\t1\tMARK\t" + record("F1", source="user") + "\n").encode()
        result = classify(raw)
        self.assertNotIn("F1", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"], "wrong source")

    def test_delayed_frame_report_is_not_execution_order_conflict(self):
        result = run("B0", "B1", "B2", "A1P", "F1", clean=True)
        self.assertTrue(result["out_of_order"])
        self.assertFalse(result["causal_order_conflict"])
        self.assertIn("asynchronous sampling", result["interpretation"])
        self.assertEqual(result["first_missing_direct_evidence"], "A1R")

    def test_manifest_hash_or_sequence_gap_degrades_transport(self):
        result = run("B0", clean=True, gaps=[{"expected": 2, "got": 3}])
        self.assertEqual(result["transport"], "incomplete")
        raw = ("1\t1\tMARK\t" + record("B0") + "\n").encode()
        result = classify(raw, {"clean": True, "gaps": [], "sha256": "0" * 64})
        self.assertEqual(result["integrity"], "mismatch")
        self.assertEqual(result["transport"], "incomplete")

    def test_kh1_bare_assertion_and_incomplete_b1_are_not_milestones(self):
        old = b"1\t1\tMARK\tKH1 stage=F1 source=frame verified=1\n"
        result = classify(old)
        self.assertEqual(result["observed"], {})
        self.assertIn("KH1 lacks required raw evidence", result["rejected"][0]["reason"])
        partial = ("1\t1\tMARK\t" + record("B0") + "\n" +
                   "2\t2\tMARK\t" + record("B1") + "\n").encode()
        result = classify(partial)
        self.assertNotIn("B1", result["observed"])
        self.assertEqual(len(result["b1_missing_parts"]), 2)

    def test_unchanged_frame_and_wrong_journal_value_are_rejected(self):
        same = record("F1", rip="0x1", cs="0x2", flags="0x3",
                      rsp="0x4", ss="0x5")
        payloads = [record("B0"), record("B1", part="journal"),
                    record("B2"), same, record("A1P", after="0x56")]
        raw = "".join(f"{i}\t{i}\tMARK\t{value}\n"
                      for i, value in enumerate(payloads, 1)).encode()
        result = classify(raw)
        self.assertEqual(result["observed"], {"B0": 1, "B2": 3})
        self.assertIn("frame canary unchanged", result["rejected"][0]["reason"])
        self.assertIn("journal transition not verified", result["rejected"][1]["reason"])

    def test_cross_stage_readbacks_and_disjoint_evidence(self):
        lines = [record("B0"), record("B1"),
                 record("B1", part="big", addr="0x140"),
                 record("B2", gate_lo="0x111", expected_lo="0x111",
                        gate_hi="0x222", expected_hi="0x222"),
                 record("B1", part="journal"),
                 record("A1P"), record("A1R", addr="0x700"),
                 record("D2", scratch_readback_sha="e" * 64)]
        raw = "".join(f"{i}\t{i}\tMARK\t{value}\n"
                      for i, value in enumerate(lines, 1)).encode()
        result = classify(raw)
        self.assertEqual(result["observed"], {"B0": 1, "A1P": 6})
        reasons = [entry["reason"] for entry in result["rejected"]]
        self.assertIn("image parts overlap", reasons)
        self.assertIn("gate equals native B0 baseline", reasons)
        self.assertIn("journal baseline differs from B1 preseed", reasons)
        self.assertIn("restoration readback differs from B0", reasons)

    def test_gate_and_restoration_require_native_baseline(self):
        raw = ("1\t1\tMARK\t" + record("B2") + "\n" +
               "2\t2\tMARK\t" + record("D2") + "\n").encode()
        result = classify(raw)
        self.assertEqual(result["observed"], {})
        self.assertEqual(result["first_missing_direct_evidence"], "B0")
        self.assertTrue(all("B0 baseline missing" in item["reason"]
                            for item in result["rejected"]))

    def test_final_pretrigger_context_must_be_read_back(self):
        cases = [record("B2", rip_actual="0x0", rip_expected="0x0"),
                 record("B2", dr7_actual="0x0", dr7_expected="0x0"),
                 record("B2", rsp_actual="0x301")]
        for value in cases:
            with self.subTest(value=value):
                raw = ("1\t1\tMARK\t" + record("B0") + "\n" +
                       "2\t2\tMARK\t" + value + "\n").encode()
                result = classify(raw)
                self.assertNotIn("B2", result["observed"])
                self.assertEqual(result["first_missing_direct_evidence"], "B1")
                self.assertEqual(len(result["rejected"]), 1)

    def test_selected_ist_must_point_at_each_planned_frame(self):
        for value in (record("B2", ist6_actual="0x900", ist6_expected="0x900"),
                      record("B2", ist6_actual="0x148", ist6_expected="0x148")):
            with self.subTest(value=value):
                raw = ("1\t1\tMARK\t" + record("B0") + "\n" +
                       "2\t2\tMARK\t" + value + "\n").encode()
                result = classify(raw)
                self.assertNotIn("B2", result["observed"])
                self.assertEqual(result["rejected"][0]["reason"],
                                 "selected IST6 does not point to first frame")

        raw = ("1\t1\tMARK\t" + record("B0") + "\n" +
               "2\t2\tMARK\t" + record("A2", ist_actual="0x348",
                                           ist_expected="0x348") + "\n").encode()
        result = classify(raw)
        self.assertNotIn("A2", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"],
                         "selected IST6 does not point to dispatch frame")

    def test_arm_return_ist_requires_baseline(self):
        raw = ("1\t1\tMARK\t" + record("A2") + "\n").encode()
        result = classify(raw)
        self.assertNotIn("A2", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"],
                         "B0 baseline missing for dispatch IST")

    def test_frame_and_journal_changes_require_earlier_samples(self):
        payloads = [record("B0"), record("B1", part="journal"),
                    record("B2"), record("F1", can0="0xff"),
                    record("A1P", before="0x9")]
        raw = "".join(f"{i}\t{i}\tMARK\t{value}\n"
                      for i, value in enumerate(payloads, 1)).encode()
        result = classify(raw)
        self.assertNotIn("F1", result["observed"])
        self.assertNotIn("A1P", result["observed"])
        reasons = [entry["reason"] for entry in result["rejected"]]
        self.assertIn("frame canaries differ from B2 pretrigger readback", reasons)
        self.assertIn("journal baseline differs from B1 preseed", reasons)

    def test_b2_rejects_duplicate_canaries_and_unstaged_journal(self):
        raw = ("1\t1\tMARK\t" + record("B0") + "\n" +
               "2\t2\tMARK\t" + record("B2", f2_can0="0x1") + "\n" +
               "3\t3\tMARK\t" + record("B1", part="journal",
                                        a1p_addr="0x900") + "\n").encode()
        result = classify(raw)
        self.assertNotIn("B2", result["observed"])
        self.assertNotIn("journal", result["b1_parts"])
        self.assertEqual([item["reason"] for item in result["rejected"]],
                         ["pretrigger frame canaries not distinct",
                          "journal word outside staged region"])

    def test_frame_slots_must_fit_the_staged_image(self):
        raw = ("1\t1\tMARK\t" + record("B0") + "\n" +
               "2\t2\tMARK\t" + record("B1", addr="0x200") + "\n").encode()
        result = classify(raw)
        self.assertEqual(result["rejected"][0]["reason"],
                         "frame slot outside staged image")
        raw = ("1\t1\tMARK\t" +
               record("B0", f2_slot="0x120") + "\n").encode()
        result = classify(raw)
        self.assertEqual(result["rejected"][0]["reason"],
                         "frame slots overlap or are unaligned")

    def test_kh2_record_fits_console_logger_line(self):
        import re
        for value in (record("B2"), record("B1", part="journal")):
            worst = re.sub(r"0x[0-9a-f]+", "0xffffffffffffffff", value)
            self.assertLess(len(worst.encode()) + 30, 1024)

    def test_duplicate_or_malformed_kh2_fields_are_rejected(self):
        for suffix in (" cpu=4", " extra=one=two", " stray"):
            with self.subTest(suffix=suffix):
                raw = ("1\t1\tMARK\t" + record("B0") + suffix + "\n").encode()
                result = classify(raw)
                self.assertEqual(result["observed"], {})
                self.assertEqual(result["rejected"][0]["reason"],
                                 "malformed or duplicate KH2 field")


if __name__ == "__main__":
    unittest.main()
