import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from khook_trace_classify import (  # noqa: E402
    STAGES, SOURCES, classify, classify_kstuff_fullchain,
)


def run(*stages, clean=False, gaps=None):
    lines = [f"{i}\t{i * 1000}\tMARK\tKH1 stage={stage} "
             f"source={SOURCES[stage]} verified=1\n"
             for i, stage in enumerate(stages, 1)]
    raw = ("HELLO ps5log/1 title=TEST app=khook boot=0x1\n" +
           "".join(lines) +
           (f"BYE seq={len(stages)} reason=complete\n" if clean else "")).encode()
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

    def test_prepatch_marker_does_not_prove_gate_patch(self):
        result = classify_kstuff_fullchain(self.LIVE_STAGE, pc=self.PC_STAGE)
        self.assertEqual(result["boundary"],
                         "prepatch_staging_seen_gate_patch_or_later_unproven")
        self.assertEqual(result["pc_transport"], "unknown")

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
        result = run("B1", "B0", clean=True)
        self.assertTrue(result["out_of_order"])
        raw = b"1\t1\tMARK\tKH1 stage=F1 source=user verified=1\n"
        result = classify(raw)
        self.assertNotIn("F1", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"], "wrong source")

    def test_manifest_hash_or_sequence_gap_degrades_transport(self):
        result = run("B0", clean=True, gaps=[{"expected": 2, "got": 3}])
        self.assertEqual(result["transport"], "incomplete")
        raw = b"1\t1\tMARK\tKH1 stage=B0 source=user verified=1\n"
        result = classify(raw, {"clean": True, "gaps": [], "sha256": "0" * 64})
        self.assertEqual(result["integrity"], "mismatch")
        self.assertEqual(result["transport"], "incomplete")


if __name__ == "__main__":
    unittest.main()
