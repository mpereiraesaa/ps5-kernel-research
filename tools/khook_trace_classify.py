#!/usr/bin/env python3
"""Classify raw khook milestones without inferring missing execution.

The input is a ps5log/1 run file. Proposed KH2 records carry the observer's
raw frame, journal, and readback fields. This tool checks internal consistency,
order, and transport integrity, not the underlying kernel bytes.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


STAGES = ("B0", "B1", "B2", "F1", "A1P", "A1R", "A2", "F2",
          "D1S", "D1O", "D2")
B1_PARTS = ("arm", "dispatch", "handler", "frame", "journal")
SOURCES = {
    "B0": "user", "B1": "user", "B2": "user", "F1": "frame",
    "A1P": "journal", "A1R": "journal", "A2": "user",
    "F2": "frame", "D1S": "journal", "D1O": "journal", "D2": "user",
}
RECORD = re.compile(r"^(\d+)\t(\d+)\tMARK\tKH2\s+(.+)$")
HEX = re.compile(r"0x[0-9a-fA-F]+\Z")
SHA = re.compile(r"[0-9a-fA-F]{64}\Z")


def _raw_fields(stage: str, fields: dict[str, str], baseline: dict | None,
                ist_count: int | None) -> tuple[str | None, int | None]:
    def number(key: str) -> int:
        value = fields.get(key, "")
        if not HEX.fullmatch(value):
            raise ValueError(f"missing or invalid {key}")
        return int(value, 16)

    def sha(key: str) -> str:
        value = fields.get(key, "")
        if not SHA.fullmatch(value):
            raise ValueError(f"missing or invalid {key}")
        return value.lower()

    try:
        cpu = int(fields.get("cpu", ""))
        if not 0 <= cpu < 16:
            raise ValueError("invalid CPU")
        if baseline and cpu != baseline["cpu"]:
            raise ValueError("CPU differs from B0")
        if fields.get("verified") != "1":
            raise ValueError("verified=1 absent")
        if stage == "B0":
            if fields.get("fw") != "12.02":
                raise ValueError("wrong or missing firmware")
            sha("build_sha")
            sha("scratch_sha")
            number("gate_lo")
            number("gate_hi")
            number("ist6")
            if number("f1_slot") == number("f2_slot"):
                raise ValueError("frame slots are identical")
        elif stage == "B1":
            if fields.get("part") not in B1_PARTS:
                raise ValueError("missing or unknown image part")
            number("addr")
            if int(fields.get("bytes", "0")) <= 0:
                raise ValueError("image part has no bytes")
            if sha("image_sha") != sha("readback_sha"):
                raise ValueError("image/readback hash mismatch")
        elif stage == "B2":
            if (number("gate_lo") != number("expected_lo") or
                    number("gate_hi") != number("expected_hi")):
                raise ValueError("gate readback differs")
            if baseline and (number("gate_lo"), number("gate_hi")) == (
                    baseline["gate_lo"], baseline["gate_hi"]):
                raise ValueError("gate equals native B0 baseline")
            count = int(fields.get("ist_count", "0"))
            if not 1 <= count <= 16 or int(fields.get("ist_matched", "-1")) != count:
                raise ValueError("IST readback count differs")
            if sha("ist_image_sha") != sha("ist_readback_sha"):
                raise ValueError("IST readback hash mismatch")
            return None, count
        elif stage in ("F1", "F2"):
            if baseline is None:
                raise ValueError("B0 baseline missing for frame address")
            expected_slot = baseline["f1_slot" if stage == "F1" else "f2_slot"]
            if number("slot") != expected_slot:
                raise ValueError("frame slot differs from B0")
            actual = [number(key) for key in ("rip", "cs", "flags", "rsp", "ss")]
            preseed = [number(f"can{i}") for i in range(5)]
            if actual == preseed:
                raise ValueError("frame canary unchanged")
        elif stage in ("A1P", "A1R", "D1S", "D1O"):
            number("addr")
            before, after, expected = (number(key) for key in
                                       ("before", "after", "expected"))
            if before == after or after != expected:
                raise ValueError("journal transition not verified")
        elif stage == "A2":
            if (number("ist_actual") != number("ist_expected") or
                    number("armed_actual") != number("armed_expected")):
                raise ValueError("arm-return readback differs")
            if number("armed_actual") == 0:
                raise ValueError("arm-return state is zero")
        elif stage == "D2":
            if fields.get("returned") != "1" or fields.get("gate_restored") != "1" or (
                    fields.get("scratch_restored") != "1"):
                raise ValueError("return or restoration absent")
            restored = int(fields.get("ist_restored", "0"))
            if restored < 1 or (ist_count is not None and restored != ist_count):
                raise ValueError("IST restoration count differs")
            if baseline and ((number("gate_lo"), number("gate_hi"),
                              number("ist6"), sha("scratch_readback_sha")) !=
                             (baseline["gate_lo"], baseline["gate_hi"],
                              baseline["ist6"], baseline["scratch_sha"])):
                raise ValueError("restoration readback differs from B0")
    except (TypeError, ValueError) as error:
        return str(error), None
    return None, None


def classify(raw: bytes, manifest: dict | None = None) -> dict:
    seen = {}
    rejected = []
    b1_parts = {}
    b1_regions = []
    baseline = None
    ist_count = None
    journal_addrs = set()
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if "\tMARK\tKH1 " in line:
            rejected.append({"reason": "KH1 lacks required raw evidence"})
            continue
        match = RECORD.match(line)
        if not match:
            continue
        seq, _, payload = match.groups()
        fields = dict(re.findall(r"\b(\w+)=([^\s]+)", payload))
        stage, source = fields.get("stage"), fields.get("source")
        if source != SOURCES.get(stage):
            rejected.append({"seq": int(seq), "stage": stage, "reason": "wrong source"})
            continue
        if stage in seen or (stage == "B1" and fields.get("part") in b1_parts):
            rejected.append({"seq": int(seq), "stage": stage, "reason": "duplicate"})
            continue
        reason, count = _raw_fields(stage, fields, baseline, ist_count)
        if reason:
            rejected.append({"seq": int(seq), "stage": stage, "reason": reason})
            continue
        if stage == "B1":
            start = int(fields["addr"], 16)
            end = start + int(fields["bytes"])
            if any(start < old_end and old_start < end for old_start, old_end
                   in b1_regions):
                rejected.append({"seq": int(seq), "stage": stage,
                                 "reason": "image parts overlap"})
                continue
            b1_regions.append((start, end))
        if stage in ("A1P", "A1R", "D1S", "D1O"):
            address = int(fields["addr"], 16)
            if address in journal_addrs:
                rejected.append({"seq": int(seq), "stage": stage,
                                 "reason": "journal address reused"})
                continue
            journal_addrs.add(address)
        if stage == "B0":
            baseline = {"cpu": int(fields["cpu"]),
                        "gate_lo": int(fields["gate_lo"], 16),
                        "gate_hi": int(fields["gate_hi"], 16),
                        "ist6": int(fields["ist6"], 16),
                        "scratch_sha": fields["scratch_sha"].lower(),
                        "f1_slot": int(fields["f1_slot"], 16),
                        "f2_slot": int(fields["f2_slot"], 16)}
        if stage == "B2":
            ist_count = count
        if stage == "B1":
            b1_parts[fields["part"]] = int(seq)
            if len(b1_parts) == len(B1_PARTS):
                seen[stage] = int(seq)
        else:
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
        "b1_parts": b1_parts,
        "b1_missing_parts": [part for part in B1_PARTS if part not in b1_parts],
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


def _fc1_records(pc_text: str) -> dict:
    """Keep raw pre-armed observer reports and reject broken local ordering."""
    records = []
    issues = []
    last_seq = 0
    for line in pc_text.splitlines():
        parts = line.split("\t", 3)
        if len(parts) != 4 or not parts[3].startswith("FC1 "):
            continue
        fields = dict(re.findall(r"\b(\w+)=([^\s]+)", parts[3]))
        try:
            seq = int(fields["seq"])
            phase = fields["phase"]
        except (KeyError, ValueError):
            issues.append("malformed FC1 header")
            continue
        if seq != last_seq + 1:
            issues.append(f"FC1 sequence expected {last_seq + 1}, got {seq}")
        last_seq = seq
        records.append({"seq": seq, "level": parts[2], "phase": phase,
                        "fields": fields})

    ready = next((r for r in records if r["phase"] == "READY"
                  and r["level"] == "MARK"), None)
    gate_reports = [r for r in records if r["phase"] == "GATE_VERIFIED"]
    gate_report = gate_reports[0] if len(gate_reports) == 1 else None
    gate = None
    gate_mismatch = False
    if sum(r["phase"] == "READY" for r in records) > 1:
        issues.append("duplicate READY")
        ready = None
    if len(gate_reports) > 1:
        issues.append("duplicate GATE_VERIFIED")
    if gate_report:
        fields = gate_report["fields"]
        gate_cpu_matches = (ready is not None and
                            fields.get("cpu") ==
                            ready["fields"].get("trigger_cpu"))
        complete = (gate_cpu_matches and
                    all(re.fullmatch(r"0x[0-9a-fA-F]+", fields.get(k, ""))
                        for k in ("gate_lo", "gate_hi", "expected_lo",
                                  "expected_hi", "first_bad_ist")) and
                    fields.get("ist4_matched", "").isdigit() and
                    re.fullmatch(r"-?\d+", fields.get("first_bad_cpu", "")))
        if not complete or not ready or gate_report["seq"] <= ready["seq"]:
            issues.append("malformed or out-of-order GATE_VERIFIED")
        else:
            matched = (fields["gate_lo"] == fields["expected_lo"] and
                       fields["gate_hi"] == fields["expected_hi"] and
                       fields["ist4_matched"] == "16" and
                       fields["first_bad_cpu"] == "-1")
            if gate_report["level"] == "MARK" and matched:
                gate = gate_report
            elif gate_report["level"] == "ERR" and not matched:
                gate_mismatch = True
            else:
                issues.append("GATE_VERIFIED level and values disagree")
    read_fail = [r for r in records if r["phase"] == "READ_FAIL"
                 and r["level"] == "ERR"]
    read_fail_before_gate = bool(ready and not gate_report and any(
        r["seq"] > ready["seq"] for r in read_fail))

    def valid_sample(record):
        fields = record["fields"]
        sample = fields.get("sample")
        version = ready["fields"].get("build") if ready else None
        if sample is None:
            if version == "prearmed-v2":
                issues.append("prearmed-v2 frame or marker lacks sample mode")
                return False
            return True
        if sample not in ("targeted", "sweep") or (
                sample == "targeted" and ready and
                fields.get("cpu") != ready["fields"].get("trigger_cpu")):
            issues.append("invalid FC1 sample mode or targeted CPU")
            return False
        return True

    frames = [r for r in records if r["phase"] == "FRAME"
              and r["level"] == "MARK"
              and all(re.fullmatch(r"0x[0-9a-fA-F]+", r["fields"].get(k, ""))
                      for k in ("rip", "cs", "flags", "rsp", "ss"))
              and valid_sample(r)]
    markers = [r for r in records if r["phase"] == "MARKER"
               and r["level"] == "MARK"
               and r["fields"].get("value") == "0x4b53545546464348"
               and valid_sample(r)]
    if any(r["phase"] in ("FRAME", "MARKER") and
           (not gate or r["seq"] <= gate["seq"]) for r in records):
        issues.append("frame or marker without preceding verified gate")
        frames = []
        markers = []
    def cpu_set(selected):
        cpus = set()
        for record in selected:
            try:
                cpu = int(record["fields"]["cpu"])
                if not 0 <= cpu < 16:
                    raise ValueError
                cpus.add(cpu)
            except (KeyError, ValueError):
                issues.append(f"invalid CPU in FC1 {record['phase']}")
        return sorted(cpus)

    frame_cpus = cpu_set(frames)
    marker_cpus = cpu_set(markers)
    if markers and any(r["fields"].get("cpu") not in
                       {str(cpu) for cpu in frame_cpus} for r in markers):
        issues.append("marker seen without matching frame report; inspect raw snapshot")

    return {"records": records, "issues": issues,
            "ready": bool(ready), "gate_verified": bool(gate),
            "gate_mismatch": gate_mismatch,
            "read_fail_before_gate_report": read_fail_before_gate,
            "read_fail": bool(read_fail),
            "trigger_cpu": (int(ready["fields"]["trigger_cpu"])
                            if ready and ready["fields"].get("trigger_cpu", "").isdigit()
                            else None),
            "frame_cpus": frame_cpus, "marker_cpus": marker_cpus}


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
    fc1 = _fc1_records(pc_text)

    stage = re.search(r"\[K1\] fw=12\.02 cpu=(\d+) frames=16\b", live_text)
    returned = re.search(
        r"\[K2\] returned after INT1; cpu=(\d+) frame=(MATCH|MISMATCH) "
        r"marker=(MATCH|MISMATCH)(?: observer=(OK|FAIL))?\b", live_text)
    pc_stage = re.search(
        r"^\d+\t\d+\tMARK\tstaged frames=16 cpu=(\d+) "
        r"chain=popall-copy-popall-doreti\b", pc_text, re.M)
    pc_return = re.search(
        r"^\d+\t\d+\t(?:MARK|WARN)\treturned after INT1 cpu=(\d+) "
        r"frame=(MATCH|MISMATCH) marker=(MATCH|MISMATCH) "
        r"(?:observer=(OK|FAIL) )?restored=YES\b",
        pc_text, re.M)
    setup_stdout = ("[K2] full frames/IST4 and shared gate read back; "
                    "originals restored; no #DB" in live_text)
    setup_pc = bool(re.search(
        r"^\d+\t\d+\tMARK\tsetup-only full_frames=16 "
        r"patch-readback=YES restored=YES no_db=1\b", pc_text, re.M))
    restored = "[K1r] shared #DB gate and all IST4 slots restored" in live_text

    cpu = int(stage.group(1)) if stage else (
        int(pc_stage.group(1)) if pc_stage and pc_same_run_verified else (
            fc1["trigger_cpu"] if pc_same_run_verified else None))
    named_cpus = ([int(stage.group(1))] if stage else [])
    if pc_same_run_verified:
        if pc_stage:
            named_cpus.append(int(pc_stage.group(1)))
        if fc1["trigger_cpu"] is not None:
            named_cpus.append(fc1["trigger_cpu"])
    cpu_identity_conflict = len(set(named_cpus)) > 1
    audit_header = re.search(
        r"\[KA1\] gate_target=\+0x([0-9a-fA-F]+) gate_ist=(\d+) "
        r"native=(YES|NO) staged_ist4=(\d+) scratch_nonzero=(\d+)",
        audit_text)
    audit_summary = re.search(
        r"\[KA2\] staged=(\d+) changed_hw_frames=(\d+) marked=(\d+)",
        audit_text)
    changed_cpus = sorted({int(value) for value in re.findall(
        r"\[KA2\] cpu=(\d+) hw_frame=CHANGED\b", audit_text)})
    marked_cpus = sorted({int(value) for value in re.findall(
        r"\[KA1\] cpu=(\d+) ist4=0x[0-9a-fA-F]+(?: STAGED)? "
        r"marker=WRITTEN\b", audit_text)})
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
        "cpu_identity_conflict": cpu_identity_conflict,
        "staged_stdout": bool(stage),
        "staged_pc": bool(pc_stage),
        "pc_same_run_verified": pc_same_run_verified,
        "gate_and_ist_restored_stdout": restored,
        "return_stdout": bool(returned),
        "return_pc": bool(pc_return),
        "setup_only_stdout": setup_stdout,
        "setup_only_pc": setup_pc,
        "return_frame": returned.group(2) if returned else None,
        "return_marker": returned.group(3) if returned else None,
        "audit_gate_offset": (f"0x{audit_header.group(1)}" if audit_header else None),
        "audit_native_gate": (audit_header.group(3) == "YES" if audit_header else None),
        "audit_staged_ist4": (int(audit_header.group(4)) if audit_header else None),
        "audit_frame": frame,
        "audit_marker": marker,
        "audit_same_attempt_verified": same_attempt_verified,
        "audit_changed_cpus": changed_cpus if audit_summary else [],
        "audit_marked_cpus": marked_cpus if audit_summary else [],
        "audit_nonselected_cpus": (
            sorted((set(changed_cpus) | set(marked_cpus)) - {cpu})
            if audit_summary and cpu is not None else []),
        "fc1": fc1,
    }
    return_record = returned or (pc_return if pc_same_run_verified else None)
    return_frame = returned.group(2) if returned else (
        pc_return.group(2) if pc_return and pc_same_run_verified else None)
    return_marker = returned.group(3) if returned else (
        pc_return.group(3) if pc_return and pc_same_run_verified else None)
    signals["return_frame"] = return_frame
    signals["return_marker"] = return_marker
    if cpu_identity_conflict:
        boundary = "conflicting_probe_cpu_records"
    elif setup_stdout or (setup_pc and pc_same_run_verified):
        boundary = "setup_only_completed_no_db_triggered"
    elif returned and pc_return and pc_same_run_verified and returned.groups() != pc_return.groups():
        boundary = "conflicting_return_records"
    elif return_record:
        boundary = ("one_trap_return_and_checks_passed" if
                    return_frame == return_marker == "MATCH" and
                    not (returned and returned.group(4) == "FAIL") and
                    not (pc_return and pc_same_run_verified and
                         pc_return.group(4) == "FAIL")
                    else ("returned_but_observer_failed" if
                          return_frame == return_marker == "MATCH" else
                          "returned_but_frame_or_marker_check_failed"))
    elif same_attempt_verified and marker == "written" and frame == "canary_unchanged":
        boundary = "audit_conflict_marker_without_changed_frame"
    elif (pc_same_run_verified and cpu is not None and
          cpu in fc1["marker_cpus"]) or (
          same_attempt_verified and marker == "written" and frame == "changed"):
        boundary = "copy_marker_seen_return_or_transport_unproven"
    elif (pc_same_run_verified and cpu is not None and
          cpu in fc1["frame_cpus"]) or (same_attempt_verified and frame == "changed"):
        boundary = "frame_changed_copy_marker_or_later_unproven"
    elif pc_same_run_verified and fc1["gate_mismatch"]:
        boundary = "observer_gate_or_ist_mismatch_after_main_readback"
    elif pc_same_run_verified and fc1["read_fail_before_gate_report"]:
        boundary = "observer_read_failed_after_main_patch_phase"
    elif (pc_same_run_verified and fc1["gate_verified"]) or (
          same_attempt_verified and audit_header and
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
        "nonselected_cpu_activity_requires_review": bool(
            (same_attempt_verified and signals["audit_nonselected_cpus"]) or
            (pc_same_run_verified and cpu is not None and
             (set(fc1["frame_cpus"] + fc1["marker_cpus"]) - {cpu}))),
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
