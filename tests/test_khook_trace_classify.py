import hashlib
import json
import subprocess
import sys
import tempfile
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
        "R0": {"observer_cpu": "7", "build_sha": "a" * 64,
               "gate_lo": "0x111", "gate_hi": "0x222", "ist6": "0x900",
               "pipe_ready": "1", "idle": "1"},
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
        "R1": {"observer_cpu": "7", "gate_lo": "0x333",
               "gate_hi": "0x444", "ist6": "0x140",
               "f1_slot": "0x118", "f2_slot": "0x318",
               **{f"f1_can{i}": hex(i + 1) for i in range(5)},
               **{f"f2_can{i}": hex(i + 11) for i in range(5)},
               **{f"{name}_addr": address
                  for name, address in (("a1p", "0x700"), ("a1r", "0x708"),
                                        ("d1s", "0x710"), ("d1o", "0x718"))},
               **{f"{name}_before": "0x0"
                  for name in ("a1p", "a1r", "d1s", "d1o")}},
        "F1": {"slot": "0x118", "rip": "0x1234", "cs": "0x43",
               "flags": "0x202", "rsp": "0x5678", "ss": "0x3b",
               **{f"can{i}": hex(i + 1) for i in range(5)}},
        "F2": {"slot": "0x318", "rip": "0x4321", "cs": "0x43",
               "flags": "0x202", "rsp": "0x8765", "ss": "0x3b",
               **{f"can{i}": hex(i + 11) for i in range(5)}},
        "A2": {"ist_count": "16", "ist_matched": "16",
               "ist_before_sha": "b" * 64,
               "ist_image_sha": "c" * 64,
               "ist_readback_sha": "c" * 64,
               "first_bad_cpu": "16", "first_bad_ist": "0x0",
               "ist_actual": "0x340", "ist_expected": "0x340",
               "armed_addr": "0x6a0",
               "armed_actual": "0x55", "armed_expected": "0x55"},
        "Q1": {"observer_cpu": "7", "reason": "arm_return",
               "idle": "1", "inflight": "0", "samples": "1"},
        "R2": {"observer_cpu": "7", "gate_lo": "0x333",
               "gate_hi": "0x444", "ist6": "0x340", "f2_slot": "0x318",
               **{f"f2_can{i}": hex(i + 11) for i in range(5)},
               "d1s_addr": "0x710", "d1s_before": "0x0",
               "d1o_addr": "0x718", "d1o_before": "0x0"},
        "D2": {"returned": "1", "gate_restored": "1",
               "scratch_restored": "1", "ist_restored": "16",
               "gate_lo": "0x111", "gate_hi": "0x222", "ist6": "0x900",
               "scratch_readback_sha": "d" * 64,
               "image_restored_sha": "e" * 64,
               "big_restored_sha": "f" * 64,
               "journal_restored_sha": "0" * 64},
        "Q2": {"observer_cpu": "7", "reason": "syscall_return",
               "idle": "1", "inflight": "0", "samples": "1"},
    }
    if stage == "B1":
        part = overrides.get("part", "image")
        geometry = {"image": ("0x100", "1280"),
                    "big": ("0x1000", "1536"),
                    "journal": ("0x600", "512")}
        addr, length = geometry[part]
        raw[stage] = {"part": part, "addr": addr, "bytes": length,
                      "before_sha": {"image": "e" * 64,
                                     "big": "f" * 64,
                                     "journal": "0" * 64}[part],
                      "image_sha": "c" * 64, "readback_sha": "c" * 64}
        if part == "image":
            raw[stage].update({"rbp_addr": "0x400", "rip_addr": "0x408",
                               "rsp_addr": "0x410", "dr7_addr": "0x418"})
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


def run(*stages, clean=False, gaps=None, f2_target=None):
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
    return classify(raw, manifest, f2_target)


def classify_records(*payloads, b2_target=None):
    raw = "".join(f"{i}\t{i * 1000}\tMARK\t{value}\n"
                  for i, value in enumerate(payloads, 1)).encode()
    return classify(raw, b2_target=b2_target)


class ClassifierTests(unittest.TestCase):
    def test_worker_lifecycle_errors_are_not_milestones(self):
        raw = ("1\t1000\tERR\tKH2E stage=R0 cpu=3 operation=prepare "
               "region=pipe addr=0x0 code=-3\n"
               "2\t2000\tERR\tKH2E stage=Q2 cpu=3 operation=finish "
               "region=pipe addr=0x0 code=-2\n").encode()
        result = classify(raw)
        self.assertEqual(result["observed"], {})
        self.assertEqual([item["code"] for item in result["capture_errors"]],
                         [-3, -2])
        self.assertEqual(result["rejected"], [])
        invalid = ("1\t1000\tERR\tKH2E stage=R1 cpu=3 operation=prepare "
                   "region=pipe addr=0x0 code=0\n").encode()
        self.assertEqual(classify(invalid)["rejected"][0]["reason"],
                         "malformed KH2E capture error")

    def test_optional_b2_gate_comparison_keeps_mismatched_readback(self):
        target = 0xffffffff8876c2de
        gate = {"gate_lo": "0x88768e060020c2de",
                "expected_lo": "0x88768e060020c2de",
                "gate_hi": "0xffffffff", "expected_hi": "0xffffffff"}
        equal = classify_records(record("B0"), record("B2", **gate),
                                 b2_target=target)
        self.assertIn("B2", equal["observed"])
        self.assertEqual(equal["b2_pivot_gate_comparison"]["status"], "equal")
        self.assertEqual(equal["b2_pivot_gate_comparison"]["observed_target"],
                         hex(target))
        self.assertEqual(equal["b2_pivot_gate_comparison"]["observed_ist"], 6)
        self.assertEqual(equal["b2_pivot_gate_comparison"]["observed_selector"],
                         "0x20")
        wrong = {**gate, "gate_lo": "0x88768e060020c2df",
                 "expected_lo": "0x88768e060020c2df"}
        different = classify_records(record("B0"), record("B2", **wrong),
                                     b2_target=target)
        self.assertIn("B2", different["observed"])
        self.assertEqual(different["b2_pivot_gate_comparison"]["status"],
                         "different")
        self.assertEqual(different["b2_pivot_gate_comparison"]["observed_target"],
                         "0xffffffff8876c2df")
        wrong_ist = {**gate, "gate_lo": "0x88768e070020c2de",
                     "expected_lo": "0x88768e070020c2de"}
        ist_result = classify_records(record("B0"), record("B2", **wrong_ist),
                                      b2_target=target)
        self.assertEqual(ist_result["b2_pivot_gate_comparison"]["status"],
                         "different")
        self.assertEqual(ist_result["b2_pivot_gate_comparison"]["observed_target"],
                         hex(target))
        self.assertEqual(ist_result["b2_pivot_gate_comparison"]["observed_ist"],
                         7)
        missing = classify_records(record("B0"), b2_target=target)
        self.assertEqual(missing["b2_pivot_gate_comparison"]["status"],
                         "no_accepted_b2")
        self.assertNotIn("b2_pivot_gate_comparison",
                         classify_records(record("B0"), record("B2", **gate)))
        with self.assertRaisesRegex(ValueError, "canonical kernel"):
            classify_records(record("B0"), b2_target=0x1000)

    def test_gate_write_brackets_accept_qwords_and_reject_16_bytes(self):
        records = [
            "KH2W stage=B2 cpu=3 region=gate addr=0x508 bytes=8 state=begin",
            "KH2W stage=B2 cpu=3 region=gate addr=0x508 bytes=8 state=done",
            "KH2W stage=B2 cpu=3 region=gate addr=0x500 bytes=8 state=begin",
            "KH2W stage=B2 cpu=3 region=gate addr=0x500 bytes=8 state=done",
            "KH2W stage=D2 cpu=3 region=gate addr=0x508 bytes=8 state=begin",
            "KH2W stage=D2 cpu=3 region=gate addr=0x508 bytes=8 state=done",
            "KH2W stage=D2 cpu=3 region=gate addr=0x500 bytes=8 state=begin",
            "KH2W stage=D2 cpu=3 region=gate addr=0x500 bytes=8 state=done",
        ]
        accepted = classify_records(*records)
        self.assertEqual([item["addr"] for item in accepted["write_attempts"]],
                         ["0x508", "0x500", "0x508", "0x500"])
        self.assertEqual(accepted["rejected"], [])
        combined = classify_records(
            "KH2W stage=B2 cpu=3 region=gate addr=0x500 bytes=16 state=begin",
            "KH2W stage=D2 cpu=3 region=gate addr=0x500 bytes=16 state=begin")
        self.assertEqual(len(combined["rejected"]), 2)

    def test_cli_f2_entry_base_is_added_and_restricted_to_khook(self):
        payloads = (record("B0"), record("B2"),
                    record("F2", rip="0x3140a0"))
        raw = "".join(f"{i}\t{i * 1000}\tMARK\t{payload}\n"
                      for i, payload in enumerate(payloads, 1))
        script = Path(__file__).resolve().parents[1] / "tools" / "khook_trace_classify.py"
        with tempfile.TemporaryDirectory() as temp_dir:
            log = Path(temp_dir) / "trace.log"
            log.write_text(raw)
            command = [sys.executable, str(script), str(log),
                       "--f2-entry-ktext-base", "0x1000"]
            completed = subprocess.run(command, capture_output=True, text=True,
                                       check=True)
            comparison = json.loads(completed.stdout)["f2_entry_rip_comparison"]
            self.assertEqual(comparison["expected"], "0x3140a0")
            self.assertEqual(comparison["status"], "equal")
            pivot_command = command + ["--b2-pivot-ktext-base",
                                       "0xffffffff884c0000"]
            pivot = subprocess.run(pivot_command, capture_output=True,
                                   text=True, check=True)
            pivot_result = json.loads(pivot.stdout)["b2_pivot_gate_comparison"]
            self.assertEqual(pivot_result["expected_target"],
                             "0xffffffff8876c2de")
            self.assertEqual(pivot_result["status"], "different")
            legacy = subprocess.run(command + ["--mode", "kstuff-fullchain"],
                                    capture_output=True, text=True)
            self.assertEqual(legacy.returncode, 2)
            self.assertIn("requires --mode khook", legacy.stderr)

    def test_optional_f2_entry_comparison_preserves_frame_evidence(self):
        equal = run("B0", "B2", "F2", f2_target=0x4321)
        self.assertIn("F2", equal["observed"])
        self.assertEqual(equal["f2_entry_rip_comparison"]["status"], "equal")
        different = run("B0", "B2", "F2", f2_target=0x3130a0)
        self.assertIn("F2", different["observed"])
        self.assertEqual(different["f2_entry_rip_comparison"], {
            "expected": "0x3130a0", "observed": "0x4321",
            "status": "different",
            "scope": "address equality only; DR0/DR7 and syscall dispatch unverified",
        })
        missing = run("B0", "B2", f2_target=0x4321)
        self.assertEqual(missing["f2_entry_rip_comparison"]["status"],
                         "no_accepted_f2")
        self.assertIsNone(missing["f2_entry_rip_comparison"]["observed"])
        self.assertNotIn("f2_entry_rip_comparison", run("B0", "B2", "F2"))
        with self.assertRaisesRegex(ValueError, "outside 64-bit"):
            run("B0", f2_target=-1)

    def test_read_brackets_expose_unresolved_callback_without_claiming_b0(self):
        begin = ("1\t1000\tMARK\tKH2R stage=B0 cpu=3 region=gate "
                 "addr=0x500 bytes=16 state=begin\n")
        result = classify(begin.encode())
        self.assertEqual(result["first_missing_direct_evidence"], "B0")
        self.assertEqual(result["open_read_attempts"][0]["addr"], "0x500")
        self.assertEqual(result["observed"], {})
        done = ("2\t2000\tMARK\tKH2R stage=B0 cpu=3 region=gate "
                "addr=0x500 bytes=16 state=done\n")
        completed = classify((begin + done).encode())
        self.assertEqual(completed["open_read_attempts"], [])
        self.assertEqual(completed["last_read_attempt"]["result"], "done")
        failed = classify((begin + "2\t2000\tERR\tKH2E stage=B0 cpu=3 "
                           "operation=read region=gate addr=0x500\n").encode())
        self.assertEqual(failed["read_attempts"][0]["result"], "error")
        orphan = classify(done.encode())
        self.assertIn("KH2R done without begin",
                      [item["reason"] for item in orphan["rejected"]])

    def test_observer_handoff_read_bracket_keeps_r1_unverified(self):
        begin = ("1\t1000\tMARK\tKH2R stage=R1 cpu=3 region=f1 "
                 "addr=0x118 bytes=40 state=begin\n")
        result = classify(begin.encode())
        self.assertEqual(result["observed"], {})
        self.assertEqual(result["first_missing_direct_evidence"], "B0")
        self.assertEqual(result["open_read_attempts"][0]["stage"], "R1")
        self.assertEqual(result["open_read_attempts"][0]["region"], "f1")
        failed = classify((begin + "2\t2000\tERR\tKH2E stage=R1 cpu=3 "
                           "operation=read region=f1 addr=0x118\n").encode())
        self.assertEqual(failed["read_attempts"][0]["result"], "error")
        invalid = classify(begin.replace("region=f1", "region=scratch").encode())
        self.assertIn("malformed KH2R read bracket",
                      [item["reason"] for item in invalid["rejected"]])

    def test_write_brackets_expose_open_callback_without_claiming_execution(self):
        prefix = f"1\t1000\tMARK\t{record('B0')}\n"
        begin = ("2\t2000\tMARK\tKH2W stage=B1 cpu=3 region=image "
                 "addr=0x100 bytes=1280 state=begin\n")
        open_result = classify((prefix + begin).encode())
        self.assertEqual(open_result["observed"], {"B0": 1})
        self.assertEqual(open_result["first_missing_direct_evidence"], "B1")
        self.assertEqual(open_result["open_write_attempts"][0]["addr"], "0x100")
        self.assertEqual(open_result["last_write_attempt"]["result"], "open")
        done = ("3\t3000\tMARK\tKH2W stage=B1 cpu=3 region=image "
                "addr=0x100 bytes=1280 state=done\n")
        completed = classify((prefix + begin + done).encode())
        self.assertEqual(completed["open_write_attempts"], [])
        self.assertEqual(completed["last_write_attempt"]["result"], "done")
        failed = classify((prefix + begin +
                           "3\t3000\tERR\tKH2E stage=B1 cpu=3 "
                           "operation=write region=image addr=0x100\n").encode())
        self.assertEqual(failed["write_attempts"][0]["result"], "error")
        self.assertEqual(failed["open_write_attempts"], [])
        orphan = classify((prefix + done).encode())
        self.assertIn("KH2W done without begin",
                      [item["reason"] for item in orphan["rejected"]])

    def test_write_errors_are_retained_without_forging_milestones(self):
        raw = (f"1\t1000\tMARK\t{record('B0')}\n"
               "2\t2000\tERR\tKH2E stage=B1 cpu=3 operation=write "
               "region=image addr=0x600\n"
               "3\t3000\tERR\tKH2E stage=B2 cpu=3 operation=write "
               "region=ist6 addr=0x804\n"
               "4\t4000\tERR\tKH2E stage=A2 cpu=3 operation=write "
               "region=armed addr=0x6a0\n"
               "5\t5000\tERR\tKH2E stage=D2 cpu=3 operation=write "
               "region=journal addr=0x600\n").encode()
        result = classify(raw)
        self.assertEqual([item["operation"] for item in result["capture_errors"]],
                         ["write"] * 4)
        self.assertEqual(result["observed"], {"B0": 1})
        self.assertEqual(result["first_missing_direct_evidence"], "B1")
        invalid = classify(raw + b"6\t6000\tERR\tKH2E stage=F1 cpu=3 "
                           b"operation=write region=ist6 addr=0x804\n")
        self.assertIn("malformed KH2E capture error",
                      [item["reason"] for item in invalid["rejected"]])

    def test_pretrigger_only_does_not_claim_db_failed(self):
        result = run("B0", "B1", "R0", "B2", "R1")
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
        result = run("B0", "B1", "R0", "B2", "R1", "Q1", "A2", clean=True)
        self.assertEqual(result["first_missing_direct_evidence"], "F1")
        self.assertEqual(result["later_direct_evidence"], ["Q1", "A2"])
        self.assertFalse(result["out_of_order"])

    def test_full_diagnostic_does_not_prove_ap(self):
        result = run(*STAGES, clean=True)
        self.assertIsNone(result["first_missing_direct_evidence"])
        self.assertTrue(result["handoff_record_set_complete"])
        self.assertEqual(result["transport"], "complete")
        self.assertIn("AP phase unassessed", result["interpretation"])

    def test_missing_quiesce_remains_visible_with_later_readback(self):
        result = run("B0", "B1", "R0", "B2", "R1", "A2")
        self.assertIn("Q1", result["missing_direct_evidence"])
        self.assertIn("Q1", result["handoff_records_missing"])
        self.assertFalse(result["handoff_record_set_complete"])
        self.assertIn("A2", result["observed"])

    def test_missing_prepatch_worker_record_is_coverage_gap(self):
        result = run("B0", "B1", "B2", "F1")
        self.assertEqual(result["first_missing_direct_evidence"], "R0")
        self.assertIn("F1", result["later_direct_evidence"])
        self.assertIn("R0", result["handoff_records_missing"])
        self.assertFalse(result["handoff_record_set_complete"])

    def test_capture_read_error_identifies_gap_without_claiming_execution(self):
        payloads = [record("B0"), *(record("B1", part=part)
                    for part in ("image", "big", "journal")), record("R0"),
                    record("B2")]
        raw = "".join(f"{index}\t{index * 1000}\tMARK\t{value}\n"
                      for index, value in enumerate(payloads, 1))
        raw += ("7\t7000\tERR\tKH2E stage=R1 cpu=3 operation=read "
                "region=f1 addr=0x118\n")
        result = classify(raw.encode())
        self.assertEqual(result["first_missing_direct_evidence"], "R1")
        self.assertEqual(result["first_capture_error"],
                         {"seq": 7, "stage": "R1", "cpu": 3,
                          "operation": "read", "region": "f1",
                          "addr": "0x118"})
        self.assertNotIn("R1", result["observed"])
        self.assertEqual(result["rejected"], [])

    def test_d2_requires_restoration_of_all_three_b1_spans(self):
        staged = [record("B0"), *(record("B1", part=part)
                  for part in ("image", "big", "journal")), record("B2")]
        result = classify_records(*staged,
                                  record("D2", scratch_readback_sha="e" * 64))
        self.assertEqual(result["rejected"][0]["reason"],
                         "restoration readback differs from B0")
        result = classify_records(*staged,
                                  record("D2", journal_restored_sha="1" * 64))
        self.assertEqual(result["rejected"][0]["reason"],
                         "journal restoration differs from B1 prewrite")
        self.assertNotIn("D2", result["observed"])

    def test_d2_requires_accepted_b2_ist_count(self):
        staged = [record("B0"), *(record("B1", part=part)
                  for part in ("image", "big", "journal"))]
        missing = classify_records(*staged, record("D2"))
        self.assertNotIn("D2", missing["observed"])
        self.assertEqual(missing["rejected"][0]["reason"],
                         "B2 IST count missing for restoration comparison")
        self.assertEqual(missing["rejected"][0]["stage"], "D2")
        mismatch = classify_records(*staged, record("B2"),
                                    record("D2", ist_restored="15"))
        self.assertNotIn("D2", mismatch["observed"])
        self.assertEqual(mismatch["rejected"][0]["reason"],
                         "IST restoration count differs")
        accepted = classify_records(*staged, record("B2"), record("D2"))
        self.assertIn("D2", accepted["observed"])

    def test_b1_hash_error_is_not_a_staging_record(self):
        raw = ("1\t1000\tMARK\t" + record("B0") + "\n" +
               "2\t2000\tERR\tKH2E stage=B1 cpu=3 operation=hash "
               "region=big addr=0x1000\n").encode()
        result = classify(raw)
        self.assertEqual(result["first_missing_direct_evidence"], "B1")
        self.assertEqual(result["capture_errors"][0]["operation"], "hash")
        self.assertNotIn("B1", result["observed"])

    def test_context_and_armed_writes_must_fit_restored_b1_spans(self):
        for changed, reason in (({"rbp_addr": "0x600"},
                                 "pretrigger rbp address outside context area"),
                                ({"rip_addr": "0x400"},
                                 "pretrigger context addresses reused")):
            result = classify_records(record("B0"),
                                      record("B1", part="image", **changed))
            self.assertEqual(result["rejected"][0]["reason"], reason)
            self.assertNotIn("B1", result["observed"])
        staged = [record("B0"), *(record("B1", part=part)
                  for part in ("image", "big", "journal")), record("B2")]
        for address in ("0x800", "0x700"):
            result = classify_records(*staged, record("A2", armed_addr=address))
            self.assertEqual(result["rejected"][0]["reason"],
                             "armed state outside journal free word")
            self.assertNotIn("A2", result["observed"])
        result = classify_records(record("B0"), record("A2"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "B1 journal missing for armed-state geometry")

    def test_handoff_records_require_linked_raw_readbacks(self):
        staged = [record("B0"), *(record("B1", part=part)
                    for part in ("image", "big", "journal"))]
        result = classify_records(*staged, record("R0", observer_cpu="3"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "invalid or selected observer CPU")
        result = classify_records(*staged, record("R0", gate_lo="0x333"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "idle observer native state differs from B0")

        prior = [*staged, record("R0"), record("B2")]
        result = classify_records(*prior, record("R1", f1_can0="0xff"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "first observer canaries differ from B2")

        prior += [record("R1")]
        result = classify_records(*prior, record("Q1", inflight="1"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "first observer quiescence not verified")

        prior += [record("Q1"), record("A2")]
        result = classify_records(*prior, record("R2", d1s_before="0x1"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "dispatch journal changed before second trigger")

        prior += [record("R2")]
        result = classify_records(*prior, record("Q2", idle="0"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "second observer quiescence not verified")

    def test_late_quiesce_conflicts_with_main_a2_order(self):
        result = run("B0", "B1", "R0", "B2", "R1", "A2", "Q1")
        self.assertTrue(result["causal_order_conflict"])
        self.assertFalse(result["handoff_record_set_complete"])

    def test_reversed_or_wrong_source_record_is_flagged(self):
        result = run("B0", "B2", "B1", clean=True)
        self.assertTrue(result["out_of_order"])
        self.assertTrue(result["causal_order_conflict"])
        raw = ("1\t1\tMARK\t" + record("F1", source="user") + "\n").encode()
        result = classify(raw)
        self.assertNotIn("F1", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"], "wrong source")

    def test_delayed_frame_report_is_not_execution_order_conflict(self):
        result = run("B0", "B1", "R0", "B2", "R1", "A1P", "F1", clean=True)
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
        self.assertIn("B1 span baselines missing for restoration", reasons)

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

        result = classify_records(
            record("B0"), *(record("B1", part=part)
                            for part in ("image", "big", "journal")),
            record("B2"),
            record("A2", ist_actual="0x348", ist_expected="0x348"))
        self.assertNotIn("A2", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"],
                         "selected IST6 does not point to dispatch frame")

    def test_arm_return_ist_requires_baseline(self):
        raw = ("1\t1\tMARK\t" + record("A2") + "\n").encode()
        result = classify(raw)
        self.assertNotIn("A2", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"],
                         "B0 baseline missing for dispatch IST")

    def test_a2_all_cpu_ist_readback_catches_other_cpu_drift(self):
        staged = [record("B0"), *(record("B1", part=part)
                  for part in ("image", "big", "journal")), record("B2")]
        result = classify_records(*staged, record(
            "A2", ist_matched="15", first_bad_cpu="7",
            first_bad_ist="0xdeadbeef", ist_readback_sha="d" * 64))
        self.assertNotIn("A2", result["observed"])
        self.assertEqual(result["rejected"][0]["reason"],
                         "A2 IST image mismatch first_bad_cpu=7 "
                         "first_bad_ist=0xdeadbeef")
        result = classify_records(*staged, record("A2", ist_before_sha="d" * 64))
        self.assertEqual(result["rejected"][0]["reason"],
                         "A2 arm IST baseline differs from B2 image")
        result = classify_records(record("B0"), record(
            "B2", ist_count="1", ist_matched="1"))
        self.assertEqual(result["rejected"][0]["reason"],
                         "IST readback count differs")

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
        for value in (record("B2"), record("A2"), record("B1", part="journal"),
                      record("R1"), record("R2")):
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
