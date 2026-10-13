#!/usr/bin/env python3
"""Classify direct khook milestone records without inferring missing execution.

The input is a ps5log/1 run file. KH1 records are emitted only after a
separate observer has validated the named frame/journal evidence; this tool
checks their order and transport integrity, not the underlying kernel bytes.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


STAGES = ("B0", "B1", "B2", "F1", "A1", "A2", "F2", "D1", "D2")
SOURCES = {
    "B0": "user", "B1": "user", "B2": "user", "F1": "frame",
    "A1": "journal", "A2": "user", "F2": "frame", "D1": "journal",
    "D2": "user",
}
RECORD = re.compile(r"^(\d+)\t(\d+)\tMARK\tKH1 stage=(\w+) source=(\w+) verified=1(?:\s|$)")


def classify(raw: bytes, manifest: dict | None = None) -> dict:
    seen = {}
    rejected = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        match = RECORD.match(line)
        if not match:
            continue
        seq, _, stage, source = match.groups()
        if source != SOURCES.get(stage):
            rejected.append({"seq": int(seq), "stage": stage, "reason": "wrong source"})
            continue
        if stage in seen:
            rejected.append({"seq": int(seq), "stage": stage, "reason": "duplicate"})
            continue
        seen[stage] = int(seq)

    ordered = sorted(seen, key=seen.get)
    # Compare the two orderings directly; a skipped stage is a coverage gap,
    # whereas a reversed pair is an inconsistency.
    out_of_order = ordered != sorted(ordered, key=STAGES.index)
    first_missing = next((stage for stage in STAGES if stage not in seen), None)
    later = (list(stage for stage in STAGES[STAGES.index(first_missing) + 1:]
                  if stage in seen) if first_missing else [])

    transport = "unknown"
    integrity = "unknown"
    if manifest is not None:
        integrity = ("match" if manifest.get("sha256") == hashlib.sha256(raw).hexdigest()
                     else "mismatch")
        transport = ("complete" if manifest.get("clean") is True and
                     manifest.get("gaps") == [] and integrity == "match"
                     else "incomplete")

    if out_of_order:
        interpretation = "record order contradicts the proposed milestone order"
    elif first_missing is None:
        interpretation = "all diagnostic milestones directly recorded; AP phase unassessed"
    else:
        interpretation = ("earliest missing direct evidence is not proof "
                          "that the stage did not execute")

    return {
        "observed": seen,
        "first_missing_direct_evidence": first_missing,
        "later_direct_evidence": later,
        "out_of_order": out_of_order,
        "rejected": rejected,
        "integrity": integrity,
        "transport": transport,
        "interpretation": interpretation,
    }


def _transport(raw: bytes | None, manifest: dict | None) -> str:
    if raw is None or manifest is None:
        return "unknown"
    if (manifest.get("sha256") == hashlib.sha256(raw).hexdigest()
            and manifest.get("clean") is True and manifest.get("gaps") == []):
        return "complete"
    return "incomplete"


def classify_kstuff_fullchain(live: bytes, audit: bytes | None = None,
                             pc: bytes | None = None,
                             manifest: dict | None = None,
                             same_attempt_verified: bool = False,
                             pc_same_run_verified: bool = False) -> dict:
    """Classify the current Kstuff-style one-ICEBP probe's actual records.

    The audit only reports changed canaries when the IST4 slot is still
    staged. No audit, or a post-recovery audit, cannot exclude delivery.
    """
    live_text = live.decode("utf-8", errors="replace")
    pc_text = pc.decode("utf-8", errors="replace") if pc is not None else ""
    audit_text = audit.decode("utf-8", errors="replace") if audit else ""

    stage = re.search(r"\[K1\] fw=12\.02 cpu=(\d+) frames=16\b", live_text)
    returned = re.search(
        r"\[K2\] returned after INT1; cpu=(\d+) frame=(MATCH|MISMATCH) "
        r"marker=(MATCH|MISMATCH)\b", live_text)
    pc_stage = re.search(
        r"^\d+\t\d+\tMARK\tstaged frames=16 cpu=(\d+) "
        r"chain=popall-copy-popall-doreti\b", pc_text, re.M)
    pc_return = re.search(
        r"^\d+\t\d+\t(?:MARK|WARN)\treturned after INT1 cpu=(\d+) "
        r"frame=(MATCH|MISMATCH) marker=(MATCH|MISMATCH) restored=YES\b",
        pc_text, re.M)
    restored = "[K1r] shared #DB gate and all IST4 slots restored" in live_text

    cpu = int(stage.group(1)) if stage else (
        int(pc_stage.group(1)) if pc_stage and pc_same_run_verified else None)
    audit_header = re.search(
        r"\[KA1\] gate_target=\+0x([0-9a-fA-F]+) gate_ist=(\d+) "
        r"native=(YES|NO) staged_ist4=(\d+) scratch_nonzero=(\d+)",
        audit_text)
    audit_summary = re.search(
        r"\[KA2\] staged=(\d+) changed_hw_frames=(\d+) marked=(\d+)",
        audit_text)
    frame = None
    marker = None
    if cpu is not None and audit_header and audit_summary:
        cpu_line = re.search(
            rf"\[KA1\] cpu={cpu} ist4=0x[0-9a-fA-F]+(?: STAGED)? "
            r"marker=(WRITTEN|NO)\b", audit_text)
        changed_line = re.search(rf"\[KA2\] cpu={cpu} hw_frame=CHANGED\b", audit_text)
        if cpu_line:
            marker = cpu_line.group(1).lower()
            if changed_line:
                frame = "changed"
            elif f"[KA1] cpu={cpu} ist4=" in audit_text and " STAGED " in cpu_line.group(0):
                frame = "canary_unchanged"

    signals = {
        "cpu": cpu,
        "staged_stdout": bool(stage),
        "staged_pc": bool(pc_stage),
        "pc_same_run_verified": pc_same_run_verified,
        "gate_and_ist_restored_stdout": restored,
        "return_stdout": bool(returned),
        "return_pc": bool(pc_return),
        "return_frame": returned.group(2) if returned else None,
        "return_marker": returned.group(3) if returned else None,
        "audit_gate_offset": (f"0x{audit_header.group(1)}" if audit_header else None),
        "audit_native_gate": (audit_header.group(3) == "YES" if audit_header else None),
        "audit_staged_ist4": (int(audit_header.group(4)) if audit_header else None),
        "audit_frame": frame,
        "audit_marker": marker,
        "audit_same_attempt_verified": same_attempt_verified,
    }
    return_record = returned or (pc_return if pc_same_run_verified else None)
    return_frame = returned.group(2) if returned else (
        pc_return.group(2) if pc_return and pc_same_run_verified else None)
    return_marker = returned.group(3) if returned else (
        pc_return.group(3) if pc_return and pc_same_run_verified else None)
    signals["return_frame"] = return_frame
    signals["return_marker"] = return_marker
    if returned and pc_return and pc_same_run_verified and returned.groups() != pc_return.groups():
        boundary = "conflicting_return_records"
    elif return_record:
        boundary = ("one_trap_return_and_checks_passed" if
                    return_frame == return_marker == "MATCH"
                    else "returned_but_frame_or_marker_check_failed")
    elif same_attempt_verified and marker == "written" and frame == "canary_unchanged":
        boundary = "audit_conflict_marker_without_changed_frame"
    elif same_attempt_verified and marker == "written" and frame == "changed":
        boundary = "copy_marker_seen_return_or_transport_unproven"
    elif same_attempt_verified and frame == "changed":
        boundary = "frame_changed_copy_marker_or_later_unproven"
    elif (same_attempt_verified and audit_header and
          audit_header.group(1).lower() == "2b3626" and
          int(audit_header.group(4)) == 16):
        boundary = "gate_and_ist_staged_delivery_or_later_unproven"
    elif stage or (pc_stage and pc_same_run_verified):
        boundary = "prepatch_staging_seen_gate_patch_or_later_unproven"
    else:
        boundary = "no_probe_staging_evidence"
    return {
        "signals": signals,
        "boundary": boundary,
        "pc_transport": _transport(pc, manifest),
        "caveat": ("Audit and PC-log evidence advance the boundary only with "
                   "explicit same-attempt assertions. A changed audit frame "
                   "supports delivery "
                   "at the staged slot; it does not establish a valid #DB frame. "
                   "Missing or post-recovery evidence cannot prove that a stage "
                   "did not execute."),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path,
                        help="ps5logd .log, or elfldr stdout in kstuff-fullchain mode")
    parser.add_argument("--mode", choices=("khook", "kstuff-fullchain"),
                        default="khook")
    parser.add_argument("--audit", type=Path,
                        help="separate read-only [KA] audit output, if available")
    parser.add_argument("--pc-log", type=Path,
                        help="ps5logd .log for kstuff-fullchain mode")
    parser.add_argument("--audit-same-attempt", action="store_true",
                        help="assert audit and live logs belong to one attempt, before recovery")
    parser.add_argument("--pc-same-run", action="store_true",
                        help="assert PC log and elfldr stdout belong to the same run")
    parser.add_argument("--manifest", type=Path, help="matching ps5logd .json file")
    args = parser.parse_args()
    raw = args.log.read_bytes()
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    if args.mode == "kstuff-fullchain":
        result = classify_kstuff_fullchain(
            raw, args.audit.read_bytes() if args.audit else None,
            args.pc_log.read_bytes() if args.pc_log else None, manifest,
            args.audit_same_attempt, args.pc_same_run)
    else:
        if args.audit or args.pc_log or args.audit_same_attempt or args.pc_same_run:
            parser.error("fullchain-only options require --mode kstuff-fullchain")
        result = classify(raw, manifest)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
