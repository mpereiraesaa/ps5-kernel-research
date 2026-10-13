import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from khook_trace_classify import STAGES, SOURCES, classify  # noqa: E402


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
