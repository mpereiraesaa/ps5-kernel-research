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


STAGES = ("B0", "B1", "R0", "B2", "R1", "F1", "A1P", "A1R",
          "Q1", "A2", "R2", "F2", "D1S", "D1O", "Q2", "D2")
B1_PARTS = ("image", "big", "journal")
JOURNAL_STAGES = ("A1P", "A1R", "D1S", "D1O")
CONTROL_STAGES = ("B0", "B1", "R0", "B2", "R1", "Q1", "A2",
                  "R2", "Q2", "D2")
HANDOFF_STAGES = ("R0", "R1", "Q1", "R2", "Q2")
FRAME_BYTES = 0x28
GETUID_ENTRY_1202 = 0x3130A0
PIVOT_1202_CANDIDATE = 0x2AC2DE
SOURCES = {
    "B0": "user", "B1": "user", "B2": "user", "F1": "frame",
    "A1P": "journal", "A1R": "journal", "A2": "user",
    "F2": "frame", "D1S": "journal", "D1O": "journal", "D2": "user",
    "R0": "observer", "R1": "observer", "Q1": "observer",
    "R2": "observer", "Q2": "observer",
}
RECORD = re.compile(r"^(\d+)\t(\d+)\tMARK\tKH2\s+(.+)$")
CAPTURE_ERROR = re.compile(r"^(\d+)\t(\d+)\tERR\tKH2E\s+(.+)$")
WRITE_BRACKET = re.compile(r"^(\d+)\t(\d+)\tMARK\tKH2W\s+(.+)$")
READ_BRACKET = re.compile(r"^(\d+)\t(\d+)\tMARK\tKH2R\s+(.+)$")
HEX = re.compile(r"0x[0-9a-fA-F]+\Z")
SHA = re.compile(r"[0-9a-fA-F]{64}\Z")
WRITE_REGIONS = {
    "B1": {"image", "big", "journal"},
    "B2": {"gate", "ist6", "context"},
    "A2": {"ist6", "armed"},
    "D2": {"gate", "ist6", "image", "big", "journal", "scratch"},
}
READ_REGIONS = {
    "B0": {"gate", "ist6", "scratch"},
    "B1": {"image", "big", "journal"},
    "B2": {"gate", "ist6", "context", "frame"},
    "A2": {"ist6", "armed"},
    "D2": {"gate", "ist6", "scratch", "image", "big", "journal"},
    "R0": {"gate", "ist6"},
    "R1": {"gate", "ist6", "f1", "f2", "A1P", "A1R", "D1S", "D1O"},
    "R2": {"gate", "ist6", "f2", "D1S", "D1O"},
}


def _raw_fields(stage: str, fields: dict[str, str], baseline: dict | None,
                ist_count: int | None, frame_preseed: dict | None,
                journal_preseed: dict | None, state: dict,
                seen: dict) -> tuple[str | None, int | None]:
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
            f1_slot, f2_slot = number("f1_slot"), number("f2_slot")
            if f1_slot % 8 or f2_slot % 8 or (
                    f1_slot < f2_slot + FRAME_BYTES and
                    f2_slot < f1_slot + FRAME_BYTES):
                raise ValueError("frame slots overlap or are unaligned")
        elif stage == "B1":
            if baseline is None:
                raise ValueError("B0 baseline missing for image layout")
            if fields.get("part") not in B1_PARTS:
                raise ValueError("missing or unknown image part")
            number("addr")
            sha("before_sha")
            if int(fields.get("bytes", "0")) <= 0:
                raise ValueError("image part has no bytes")
            if sha("image_sha") != sha("readback_sha"):
                raise ValueError("image/readback hash mismatch")
            if fields["part"] == "image":
                start, end = number("addr"), number("addr") + int(fields["bytes"])
                if any(slot < start or slot + FRAME_BYTES > end for slot in
                       (baseline["f1_slot"], baseline["f2_slot"])):
                    raise ValueError("frame slot outside staged image")
                context_addresses = []
                for name in ("rbp", "rip", "rsp", "dr7"):
                    address = number(f"{name}_addr")
                    if (address % 8 or address < start or address + 8 > end or
                            any(address < baseline[slot] + FRAME_BYTES and
                                baseline[slot] < address + 8
                                for slot in ("f1_slot", "f2_slot"))):
                        raise ValueError(f"pretrigger {name} address outside context area")
                    context_addresses.append(address)
                if len(set(context_addresses)) != len(context_addresses):
                    raise ValueError("pretrigger context addresses reused")
            if fields["part"] == "journal":
                start, end = number("addr"), number("addr") + int(fields["bytes"])
                addresses = []
                for name in JOURNAL_STAGES:
                    address = number(f"{name.lower()}_addr")
                    number(f"{name.lower()}_before")
                    if address < start or address + 8 > end or address % 8:
                        raise ValueError("journal word outside staged region")
                    addresses.append(address)
                if len(set(addresses)) != len(addresses):
                    raise ValueError("journal preseed addresses reused")
        elif stage == "R0":
            if baseline is None or "B1" not in seen:
                raise ValueError("B0/B1 missing before idle observer READY")
            observer_cpu = int(fields.get("observer_cpu", "-1"))
            if not 0 <= observer_cpu < 16 or observer_cpu == cpu:
                raise ValueError("invalid or selected observer CPU")
            if sha("build_sha") != baseline["build_sha"]:
                raise ValueError("observer build differs from B0")
            if (number("gate_lo"), number("gate_hi"), number("ist6")) != (
                    baseline["gate_lo"], baseline["gate_hi"],
                    baseline["ist6"]):
                raise ValueError("idle observer native state differs from B0")
            if fields.get("pipe_ready") != "1" or fields.get("idle") != "1":
                raise ValueError("observer pipe or idle state absent")
        elif stage == "B2":
            if baseline is None:
                raise ValueError("B0 baseline missing for gate comparison")
            if (number("gate_lo") != number("expected_lo") or
                    number("gate_hi") != number("expected_hi")):
                raise ValueError("gate readback differs")
            if (number("gate_lo"), number("gate_hi")) == (
                    baseline["gate_lo"], baseline["gate_hi"]):
                raise ValueError("gate equals native B0 baseline")
            count = int(fields.get("ist_count", "0"))
            if count != 16 or int(fields.get("ist_matched", "-1")) != count:
                raise ValueError("IST readback count differs")
            if sha("ist_image_sha") != sha("ist_readback_sha"):
                raise ValueError("IST readback hash mismatch")
            arm_ist = baseline["f1_slot"] + FRAME_BYTES
            if (number("ist6_actual") != number("ist6_expected") or
                    number("ist6_actual") != arm_ist or
                    arm_ist == baseline["ist6"]):
                raise ValueError("selected IST6 does not point to first frame")
            for name in ("rbp", "rip", "rsp", "dr7"):
                if number(f"{name}_actual") != number(f"{name}_expected"):
                    raise ValueError(f"pretrigger {name} readback differs")
            if number("rip_actual") == 0 or number("rsp_actual") == 0:
                raise ValueError("pretrigger return target or stack is zero")
            if number("dr7_actual") != 0x403:
                raise ValueError("pretrigger DR7 differs from reference arm value")
            canaries = [number(f"{frame}_can{i}")
                        for frame in ("f1", "f2") for i in range(5)]
            if len(set(canaries)) != len(canaries):
                raise ValueError("pretrigger frame canaries not distinct")
            return None, count
        elif stage == "R1":
            if "R0" not in seen or state.get("pretrigger") is None or (
                    journal_preseed is None or frame_preseed is None):
                raise ValueError("R0/B1/B2 missing before first observer sample")
            if int(fields.get("observer_cpu", "-1")) != state["observer_cpu"]:
                raise ValueError("observer CPU differs from R0")
            pretrigger = state["pretrigger"]
            if any(number(key) != pretrigger[key] for key in
                   ("gate_lo", "gate_hi", "ist6")):
                raise ValueError("first observer gate or IST differs from B2")
            if (number("f1_slot") != baseline["f1_slot"] or
                    number("f2_slot") != baseline["f2_slot"]):
                raise ValueError("first observer frame slot differs from B0")
            for frame in ("F1", "F2"):
                if [number(f"{frame.lower()}_can{i}") for i in range(5)] != (
                        frame_preseed[frame]):
                    raise ValueError("first observer canaries differ from B2")
            for name, (address, before) in journal_preseed.items():
                if (number(f"{name.lower()}_addr"),
                        number(f"{name.lower()}_before")) != (address, before):
                    raise ValueError("first observer journal differs from B1")
        elif stage in ("F1", "F2"):
            if baseline is None:
                raise ValueError("B0 baseline missing for frame address")
            if frame_preseed is None:
                raise ValueError("B2 pretrigger frame canaries missing")
            expected_slot = baseline["f1_slot" if stage == "F1" else "f2_slot"]
            if number("slot") != expected_slot:
                raise ValueError("frame slot differs from B0")
            actual = [number(key) for key in ("rip", "cs", "flags", "rsp", "ss")]
            preseed = [number(f"can{i}") for i in range(5)]
            if preseed != frame_preseed[stage]:
                raise ValueError("frame canaries differ from B2 pretrigger readback")
            if actual == preseed:
                raise ValueError("frame canary unchanged")
        elif stage in JOURNAL_STAGES:
            if journal_preseed is None:
                raise ValueError("B1 journal preseed missing")
            address = number("addr")
            before, after, expected = (number(key) for key in
                                       ("before", "after", "expected"))
            if (address, before) != journal_preseed[stage]:
                raise ValueError("journal baseline differs from B1 preseed")
            if before == after or after != expected:
                raise ValueError("journal transition not verified")
        elif stage == "A2":
            if baseline is None:
                raise ValueError("B0 baseline missing for dispatch IST")
            journal_region = state.get("b1_regions", {}).get("journal")
            if journal_region is None:
                raise ValueError("B1 journal missing for armed-state geometry")
            if "B2" not in seen or ist_count is None:
                raise ValueError("B2 arm IST image missing for A2 comparison")
            armed_addr = number("armed_addr")
            if (armed_addr % 8 or armed_addr < journal_region[0] or
                    armed_addr + 8 > journal_region[1] or
                    (journal_preseed is not None and any(
                        armed_addr == address for address, _ in
                        journal_preseed.values()))):
                raise ValueError("armed state outside journal free word")
            if sha("ist_before_sha") != state["pretrigger"]["ist_image_sha"]:
                raise ValueError("A2 arm IST baseline differs from B2 image")
            a2_count = int(fields.get("ist_count", ""))
            matched = int(fields.get("ist_matched", ""))
            first_bad_cpu = int(fields.get("first_bad_cpu", ""))
            first_bad_ist = number("first_bad_ist")
            if a2_count != ist_count:
                raise ValueError("A2 IST count differs from B2")
            if (matched != a2_count or
                    sha("ist_image_sha") != sha("ist_readback_sha") or
                    first_bad_cpu != 16 or first_bad_ist != 0):
                raise ValueError(
                    f"A2 IST image mismatch first_bad_cpu={first_bad_cpu} "
                    f"first_bad_ist={first_bad_ist:#x}")
            if (number("ist_actual") != number("ist_expected") or
                    number("armed_actual") != number("armed_expected")):
                raise ValueError("arm-return readback differs")
            dispatch_ist = baseline["f2_slot"] + FRAME_BYTES
            if (number("ist_actual") != dispatch_ist or
                    dispatch_ist == baseline["ist6"]):
                raise ValueError("selected IST6 does not point to dispatch frame")
            if number("armed_actual") == 0:
                raise ValueError("arm-return state is zero")
        elif stage == "Q1":
            if "R1" not in seen:
                raise ValueError("first observer READY missing before quiesce")
            if int(fields.get("observer_cpu", "-1")) != state["observer_cpu"]:
                raise ValueError("observer CPU differs from R0")
            if (fields.get("reason") != "arm_return" or
                    fields.get("idle") != "1" or
                    fields.get("inflight") != "0" or
                    int(fields.get("samples", "0")) < 1):
                raise ValueError("first observer quiescence not verified")
        elif stage == "R2":
            if "Q1" not in seen or "A2" not in seen or (
                    state.get("pretrigger") is None or
                    journal_preseed is None or frame_preseed is None):
                raise ValueError("Q1/A2 missing before second observer sample")
            if int(fields.get("observer_cpu", "-1")) != state["observer_cpu"]:
                raise ValueError("observer CPU differs from R0")
            pretrigger = state["pretrigger"]
            if (number("gate_lo") != pretrigger["gate_lo"] or
                    number("gate_hi") != pretrigger["gate_hi"] or
                    number("ist6") != state["arm_return_ist"]):
                raise ValueError("second observer gate or IST differs")
            if number("f2_slot") != baseline["f2_slot"] or (
                    [number(f"f2_can{i}") for i in range(5)] !=
                    frame_preseed["F2"]):
                raise ValueError("second observer frame differs from B2")
            for name in ("D1S", "D1O"):
                address, before = journal_preseed[name]
                if (number(f"{name.lower()}_addr"),
                        number(f"{name.lower()}_before")) != (address, before):
                    raise ValueError("dispatch journal changed before second trigger")
        elif stage == "Q2":
            if "R2" not in seen:
                raise ValueError("second observer READY missing before quiesce")
            if int(fields.get("observer_cpu", "-1")) != state["observer_cpu"]:
                raise ValueError("observer CPU differs from R0")
            if (fields.get("reason") != "syscall_return" or
                    fields.get("idle") != "1" or
                    fields.get("inflight") != "0" or
                    int(fields.get("samples", "0")) < 1):
                raise ValueError("second observer quiescence not verified")
        elif stage == "D2":
            if baseline is None:
                raise ValueError("B0 baseline missing for restoration comparison")
            if set(state.get("b1_before", {})) != set(B1_PARTS):
                raise ValueError("B1 span baselines missing for restoration")
            if ist_count is None:
                raise ValueError("B2 IST count missing for restoration comparison")
            if fields.get("returned") != "1" or fields.get("gate_restored") != "1" or (
                    fields.get("scratch_restored") != "1"):
                raise ValueError("return or restoration absent")
            restored = int(fields.get("ist_restored", "0"))
            if restored != ist_count:
                raise ValueError("IST restoration count differs")
            if ((number("gate_lo"), number("gate_hi"),
                 number("ist6"), sha("scratch_readback_sha")) !=
                (baseline["gate_lo"], baseline["gate_hi"],
                 baseline["ist6"], baseline["scratch_sha"])):
                raise ValueError("restoration readback differs from B0")
            for part in B1_PARTS:
                if sha(f"{part}_restored_sha") != state["b1_before"][part]:
                    raise ValueError(f"{part} restoration differs from B1 prewrite")
    except (TypeError, ValueError) as error:
        return str(error), None
    return None, None


def _pivot_gate_words(target: int) -> tuple[int, int]:
    lo = ((target & 0xffff) | (0x20 << 16) | (6 << 32) |
          (0xe << 40) | (1 << 47) | (((target >> 16) & 0xffff) << 48))
    hi = (target >> 32) & 0xffffffff
    return lo, hi


def _gate_target(lo: int, hi: int) -> int:
    return ((lo & 0xffff) | (((lo >> 48) & 0xffff) << 16) |
            ((hi & 0xffffffff) << 32))


def classify(raw: bytes, manifest: dict | None = None,
             f2_target: int | None = None,
             b2_target: int | None = None) -> dict:
    if f2_target is not None and not 0 <= f2_target <= 0xffffffffffffffff:
        raise ValueError("F2 target outside 64-bit address range")
    if b2_target is not None and not (
            0 <= b2_target <= 0xffffffffffffffff and
            b2_target >> 47 == 0x1ffff):
        raise ValueError("B2 pivot target outside canonical kernel range")
    seen = {}
    rejected = []
    capture_errors = []
    write_attempts = []
    pending_writes = {}
    read_attempts = []
    pending_reads = {}
    b1_parts = {}
    b1_regions = []
    baseline = None
    ist_count = None
    frame_preseed = None
    journal_preseed = None
    state = {}
    f2_rip = None
    b2_gate = None
    for line in raw.decode("utf-8", errors="replace").splitlines():
        read_match = READ_BRACKET.match(line)
        if read_match:
            seq, _, payload = read_match.groups()
            tokens = payload.split()
            pairs = [token.split("=", 1) for token in tokens]
            fields = dict(pairs) if all(len(pair) == 2 for pair in pairs) else {}
            try:
                stage, region = fields["stage"], fields["region"]
                cpu, length = int(fields["cpu"]), int(fields["bytes"])
                address, bracket_state = fields["addr"], fields["state"]
                if (set(fields) != {"stage", "cpu", "region", "addr", "bytes", "state"}
                        or len(fields) != len(pairs) or
                        region not in READ_REGIONS.get(stage, set()) or
                        not 0 <= cpu < 16 or
                        (baseline is not None and cpu != baseline["cpu"]) or
                        not HEX.fullmatch(address) or
                        not 0 < length <= 0x500 or
                        bracket_state not in ("begin", "done")):
                    raise ValueError
            except (KeyError, ValueError):
                rejected.append({"seq": int(seq),
                                 "reason": "malformed KH2R read bracket"})
            else:
                key = stage, cpu, region, int(address, 16), length
                if bracket_state == "begin":
                    if key in pending_reads:
                        rejected.append({"seq": int(seq),
                                         "reason": "duplicate KH2R begin"})
                    else:
                        attempt = {"seq": int(seq), "stage": stage, "cpu": cpu,
                                   "region": region, "addr": address,
                                   "bytes": length, "result": "open"}
                        read_attempts.append(attempt)
                        pending_reads[key] = attempt
                elif key not in pending_reads:
                    rejected.append({"seq": int(seq),
                                     "reason": "KH2R done without begin"})
                else:
                    attempt = pending_reads.pop(key)
                    attempt.update(result="done", end_seq=int(seq))
            continue
        bracket_match = WRITE_BRACKET.match(line)
        if bracket_match:
            seq, _, payload = bracket_match.groups()
            tokens = payload.split()
            pairs = [token.split("=", 1) for token in tokens]
            fields = dict(pairs) if all(len(pair) == 2 for pair in pairs) else {}
            try:
                stage, region = fields["stage"], fields["region"]
                cpu, length = int(fields["cpu"]), int(fields["bytes"])
                address, bracket_state = fields["addr"], fields["state"]
                if (set(fields) != {"stage", "cpu", "region", "addr", "bytes", "state"}
                        or len(fields) != len(pairs) or
                        region not in WRITE_REGIONS.get(stage, set()) or
                        not 0 <= cpu < 16 or
                        (baseline is not None and cpu != baseline["cpu"]) or
                        not HEX.fullmatch(address) or
                        not 0 < length <= 0x500 or
                        (stage == "A2" and length != 8) or
                        (stage == "B2" and length != 8) or
                        (stage == "D2" and region in ("gate", "ist6") and
                         length != 8) or
                        bracket_state not in ("begin", "done")):
                    raise ValueError
            except (KeyError, ValueError):
                rejected.append({"seq": int(seq),
                                 "reason": "malformed KH2W write bracket"})
            else:
                key = stage, cpu, region, int(address, 16), length
                if bracket_state == "begin":
                    if key in pending_writes:
                        rejected.append({"seq": int(seq),
                                         "reason": "duplicate KH2W begin"})
                    else:
                        attempt = {"seq": int(seq), "stage": stage, "cpu": cpu,
                                   "region": region, "addr": address,
                                   "bytes": length, "result": "open"}
                        write_attempts.append(attempt)
                        pending_writes[key] = attempt
                elif key not in pending_writes:
                    rejected.append({"seq": int(seq),
                                     "reason": "KH2W done without begin"})
                else:
                    attempt = pending_writes.pop(key)
                    attempt.update(result="done", end_seq=int(seq))
            continue
        error_match = CAPTURE_ERROR.match(line)
        if error_match:
            seq, _, payload = error_match.groups()
            tokens = payload.split()
            pairs = [token.split("=", 1) for token in tokens]
            fields = dict(pairs) if all(len(pair) == 2 for pair in pairs) else {}
            try:
                stage = fields["stage"]
                cpu = int(fields["cpu"])
                address = fields["addr"]
                region = fields["region"]
                operation = fields.get("operation")
                if (len(fields) != len(pairs) or stage not in STAGES or
                        operation not in ("read", "hash", "write",
                                          "prepare", "finish") or
                        (operation == "write" and stage not in
                         ("B1", "B2", "A2", "D2")) or
                        not 0 <= cpu < 16 or
                        (baseline is not None and cpu != baseline["cpu"]) or
                        not HEX.fullmatch(address) or
                        not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", region)):
                    raise ValueError
                if operation in ("prepare", "finish"):
                    if (set(fields) != {"stage", "cpu", "operation", "region",
                                        "addr", "code"} or
                            region != "pipe" or int(address, 16) != 0 or
                            int(fields["code"]) == 0 or
                            (operation == "prepare" and stage != "R0") or
                            (operation == "finish" and stage not in ("R0", "Q2"))):
                        raise ValueError
            except (KeyError, ValueError):
                rejected.append({"seq": int(seq),
                                 "reason": "malformed KH2E capture error"})
            else:
                error = {"seq": int(seq), "stage": stage,
                         "cpu": cpu, "operation": operation,
                         "region": region, "addr": address}
                if operation in ("prepare", "finish"):
                    error["code"] = int(fields["code"])
                capture_errors.append(error)
                if operation == "write":
                    matching = [key for key in pending_writes
                                if key[:3] == (stage, cpu, region) and
                                key[3] == int(address, 16)]
                    if len(matching) == 1:
                        attempt = pending_writes.pop(matching[0])
                        attempt.update(result="error", end_seq=int(seq))
                elif operation == "read":
                    matching = [key for key in pending_reads
                                if key[:3] == (stage, cpu, region) and
                                key[3] == int(address, 16)]
                    if len(matching) == 1:
                        attempt = pending_reads.pop(matching[0])
                        attempt.update(result="error", end_seq=int(seq))
            continue
        if "\tMARK\tKH1 " in line:
            rejected.append({"reason": "KH1 lacks required raw evidence"})
            continue
        match = RECORD.match(line)
        if not match:
            continue
        seq, _, payload = match.groups()
        fields = {}
        malformed = False
        for token in payload.split():
            pair = re.fullmatch(r"([A-Za-z_]\w*)=([^\s=]+)", token)
            if pair is None or pair.group(1) in fields:
                malformed = True
                break
            fields[pair.group(1)] = pair.group(2)
        if malformed:
            rejected.append({"seq": int(seq), "reason": "malformed or duplicate KH2 field"})
            continue
        stage, source = fields.get("stage"), fields.get("source")
        if source != SOURCES.get(stage):
            rejected.append({"seq": int(seq), "stage": stage, "reason": "wrong source"})
            continue
        if stage in seen or (stage == "B1" and fields.get("part") in b1_parts):
            rejected.append({"seq": int(seq), "stage": stage, "reason": "duplicate"})
            continue
        reason, count = _raw_fields(stage, fields, baseline, ist_count,
                                    frame_preseed, journal_preseed, state, seen)
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
        if stage == "B0":
            baseline = {"cpu": int(fields["cpu"]),
                        "build_sha": fields["build_sha"].lower(),
                        "gate_lo": int(fields["gate_lo"], 16),
                        "gate_hi": int(fields["gate_hi"], 16),
                        "ist6": int(fields["ist6"], 16),
                        "scratch_sha": fields["scratch_sha"].lower(),
                        "f1_slot": int(fields["f1_slot"], 16),
                        "f2_slot": int(fields["f2_slot"], 16)}
        if stage == "B2":
            ist_count = count
            frame_preseed = {name.upper(): [int(fields[f"{name}_can{i}"], 16)
                                            for i in range(5)]
                             for name in ("f1", "f2")}
            state["pretrigger"] = {
                "gate_lo": int(fields["gate_lo"], 16),
                "gate_hi": int(fields["gate_hi"], 16),
                "ist6": int(fields["ist6_actual"], 16),
                "ist_image_sha": fields["ist_image_sha"].lower(),
            }
        if stage == "R0":
            state["observer_cpu"] = int(fields["observer_cpu"])
        if stage == "A2":
            state["arm_return_ist"] = int(fields["ist_actual"], 16)
        if stage == "B1":
            b1_parts[fields["part"]] = int(seq)
            state.setdefault("b1_before", {})[fields["part"]] = (
                fields["before_sha"].lower())
            state.setdefault("b1_regions", {})[fields["part"]] = (
                int(fields["addr"], 16),
                int(fields["addr"], 16) + int(fields["bytes"]))
            if fields["part"] == "journal":
                journal_preseed = {
                    name: (int(fields[f"{name.lower()}_addr"], 16),
                           int(fields[f"{name.lower()}_before"], 16))
                    for name in JOURNAL_STAGES}
            if len(b1_parts) == len(B1_PARTS):
                seen[stage] = int(seq)
        else:
            seen[stage] = int(seq)
            if stage == "F2":
                f2_rip = int(fields["rip"], 16)
            if stage == "B2":
                b2_gate = (int(fields["gate_lo"], 16),
                           int(fields["gate_hi"], 16))

    ordered = sorted(seen, key=seen.get)
    # Observer reports can arrive later than the corresponding kernel write.
    # User and handshaken observer control reports support a causal order
    # check. A skipped stage remains a coverage gap, not a failed stage.
    out_of_order = ordered != sorted(ordered, key=STAGES.index)
    control_order = [stage for stage in ordered if stage in CONTROL_STAGES]
    causal_order_conflict = control_order != sorted(
        control_order, key=CONTROL_STAGES.index)
    missing = [stage for stage in STAGES if stage not in seen]
    first_missing = missing[0] if missing else None
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

    if causal_order_conflict:
        interpretation = "handshaken control records contradict the required stage order"
    elif out_of_order:
        interpretation = ("observer report order differs from phase order; "
                          "asynchronous sampling does not prove execution-order reversal")
    elif first_missing is None:
        interpretation = "all diagnostic milestones directly recorded; AP phase unassessed"
    else:
        interpretation = ("earliest missing direct evidence is not proof "
                          "that the stage did not execute")

    result = {
        "observed": seen,
        "b1_parts": b1_parts,
        "b1_missing_parts": [part for part in B1_PARTS if part not in b1_parts],
        "first_missing_direct_evidence": first_missing,
        "missing_direct_evidence": missing,
        "later_direct_evidence": later,
        "handoff_records_missing": [stage for stage in HANDOFF_STAGES
                                    if stage not in seen],
        "handoff_record_set_complete": (
            all(stage in seen for stage in HANDOFF_STAGES)
            and not causal_order_conflict),
        "capture_errors": capture_errors,
        "first_capture_error": capture_errors[0] if capture_errors else None,
        "write_attempts": write_attempts,
        "open_write_attempts": [attempt for attempt in write_attempts
                                if attempt["result"] == "open"],
        "last_write_attempt": write_attempts[-1] if write_attempts else None,
        "read_attempts": read_attempts,
        "open_read_attempts": [attempt for attempt in read_attempts
                               if attempt["result"] == "open"],
        "last_read_attempt": read_attempts[-1] if read_attempts else None,
        "out_of_order": out_of_order,
        "causal_order_conflict": causal_order_conflict,
        "rejected": rejected,
        "integrity": integrity,
        "transport": transport,
        "interpretation": interpretation,
    }
    if f2_target is not None:
        result["f2_entry_rip_comparison"] = {
            "expected": f"0x{f2_target:x}",
            "observed": None if f2_rip is None else f"0x{f2_rip:x}",
            "status": ("no_accepted_f2" if f2_rip is None else
                       "equal" if f2_rip == f2_target else "different"),
            "scope": "address equality only; DR0/DR7 and syscall dispatch unverified",
        }
    if b2_target is not None:
        expected_lo, expected_hi = _pivot_gate_words(b2_target)
        observed_lo, observed_hi = b2_gate if b2_gate is not None else (None, None)
        result["b2_pivot_gate_comparison"] = {
            "expected_target": f"0x{b2_target:x}",
            "observed_target": (None if b2_gate is None else
                                f"0x{_gate_target(observed_lo, observed_hi):x}"),
            "expected_lo": f"0x{expected_lo:x}",
            "expected_hi": f"0x{expected_hi:x}",
            "observed_lo": None if observed_lo is None else f"0x{observed_lo:x}",
            "observed_hi": None if observed_hi is None else f"0x{observed_hi:x}",
            "observed_selector": (None if observed_lo is None else
                                  f"0x{(observed_lo >> 16) & 0xffff:x}"),
            "observed_ist": (None if observed_lo is None else
                             (observed_lo >> 32) & 7),
            "observed_type": (None if observed_lo is None else
                              (observed_lo >> 40) & 0xf),
            "observed_dpl": (None if observed_lo is None else
                             (observed_lo >> 45) & 3),
            "observed_present": (None if observed_lo is None else
                                 (observed_lo >> 47) & 1),
            "status": ("no_accepted_b2" if b2_gate is None else
                       "equal" if b2_gate == (expected_lo, expected_hi)
                       else "different"),
            "scope": "descriptor equality only; 12.02 pivot bytes unverified",
        }
    return result


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
    parser.add_argument("--f2-entry-ktext-base", type=lambda value: int(value, 0),
                        help="same-run FW 12.02 text base; compare accepted F2 RIP "
                             "with base+0x3130a0 without asserting delivery")
    parser.add_argument("--b2-pivot-ktext-base", type=lambda value: int(value, 0),
                        help="same-run FW 12.02 text base; compare accepted B2 "
                             "gate with candidate pivot base+0x2ac2de")
    args = parser.parse_args()
    raw = args.log.read_bytes()
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    if args.mode == "kstuff-fullchain":
        if (args.f2_entry_ktext_base is not None or
                args.b2_pivot_ktext_base is not None):
            parser.error("F2/B2 comparison requires --mode khook")
        result = classify_kstuff_fullchain(
            raw, args.audit.read_bytes() if args.audit else None,
            args.pc_log.read_bytes() if args.pc_log else None, manifest,
            args.audit_same_attempt, args.pc_same_run)
    else:
        if args.audit or args.pc_log or args.audit_same_attempt or args.pc_same_run:
            parser.error("fullchain-only options require --mode kstuff-fullchain")
        f2_target = None
        if args.f2_entry_ktext_base is not None:
            if not 0 <= args.f2_entry_ktext_base <= (
                    0xffffffffffffffff - GETUID_ENTRY_1202):
                parser.error("F2 entry text base outside 64-bit address range")
            f2_target = args.f2_entry_ktext_base + GETUID_ENTRY_1202
        b2_target = None
        if args.b2_pivot_ktext_base is not None:
            if not 0 <= args.b2_pivot_ktext_base <= (
                    0xffffffffffffffff - PIVOT_1202_CANDIDATE):
                parser.error("B2 pivot text base outside 64-bit address range")
            b2_target = args.b2_pivot_ktext_base + PIVOT_1202_CANDIDATE
            if b2_target >> 47 != 0x1ffff:
                parser.error("B2 pivot target outside canonical kernel range")
        result = classify(raw, manifest, f2_target, b2_target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
