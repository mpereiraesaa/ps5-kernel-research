#!/usr/bin/env python3
"""Join a standalone KH2 R0 calibration log, manifest, and elfldr stdout.

This checks retained reports and build identity, not kernel ownership or
whether an exception was delivered. The R0-only ELF has no B0/B1 records.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


HEX = re.compile(r"0x[0-9a-fA-F]+\Z")
SHA = re.compile(r"[0-9a-fA-F]{64}\Z")
PHASES = ("main baseline", "gate begin", "gate done", "ist6 begin",
          "ist6 done", "R0")


def fields(payload):
    pairs = [token.split("=", 1) for token in payload.split()]
    if not pairs or any(len(pair) != 2 or not pair[0] or not pair[1]
                        for pair in pairs) or len({p[0] for p in pairs}) != len(pairs):
        raise ValueError("malformed or duplicate field")
    return dict(pairs)


def decimal(value, low, high):
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError("invalid decimal field")
    result = int(value)
    if not low <= result <= high:
        raise ValueError("decimal field outside range")
    return result


def address(value):
    if not HEX.fullmatch(value):
        raise ValueError("invalid hex address")
    result = int(value, 16)
    if result >= 1 << 64:
        raise ValueError("hex value outside uint64")
    return result


def inspect(raw, manifest, stdout, kdata_base, build_sha):
    if not 0 <= kdata_base < 1 << 64 or not SHA.fullmatch(build_sha):
        raise ValueError("invalid kdata base or build SHA-256")
    issues, events = [], []
    lines = raw.decode("utf-8", errors="replace").splitlines()
    hello = [line for line in lines if line.startswith("HELLO ps5log/1 ")]
    if len(hello) != 1 or not all(token in hello[0].split() for token in
                                     ("title=KH2R01202", "app=kh2-r0-calibration")):
        issues.append("missing or wrong KH2 R0 ps5log/1 HELLO")
    last_seq = 0
    for line in lines:
        parts = line.split("\t", 3)
        if len(parts) != 4:
            if "\tKH2" in line:
                issues.append("malformed KH2 transport line")
            continue
        if not parts[3].startswith("KH2"):
            continue
        try:
            seq = decimal(parts[0], 1, 1 << 63)
            if seq <= last_seq:
                raise ValueError("non-increasing KH2 sequence")
            last_seq = seq
            level, payload = parts[2], parts[3]
            kind, text = payload.split(" ", 1)
            data = fields(text)
            if kind == "KH2C" and level == "MARK":
                if set(data) != {"stage", "fw", "cpu", "build_sha", "gate_lo",
                                 "gate_hi", "ist6"} or \
                        data["stage"] != "MAIN_BASELINE" or \
                        data["fw"] != "12.02" or \
                        data["build_sha"].lower() != build_sha.lower():
                    raise ValueError("main baseline firmware or build mismatch")
                events.append({"phase": "main baseline", "seq": seq,
                               "cpu": decimal(data["cpu"], 0, 15),
                               "gate_lo": address(data["gate_lo"]),
                               "gate_hi": address(data["gate_hi"]),
                               "ist6": address(data["ist6"])})
            elif kind == "KH2R" and level == "MARK":
                if set(data) != {"stage", "cpu", "region", "addr", "bytes", "state"}:
                    raise ValueError("invalid read bracket fields")
                if data["stage"] != "R0" or data["region"] not in ("gate", "ist6") \
                        or data["state"] not in ("begin", "done"):
                    raise ValueError("unexpected read bracket")
                cpu = decimal(data["cpu"], 0, 15)
                length = decimal(data["bytes"], 1, 0x500)
                events.append({"phase": f'{data["region"]} {data["state"]}',
                               "seq": seq, "cpu": cpu, "addr": address(data["addr"]),
                               "bytes": length})
            elif kind == "KH2" and level == "MARK":
                required = {"stage", "source", "cpu", "verified", "observer_cpu",
                            "build_sha", "gate_lo", "gate_hi", "ist6",
                            "pipe_ready", "idle"}
                if set(data) != required or data["stage"] != "R0" or \
                        data["source"] != "observer" or data["verified"] != "1":
                    raise ValueError("unexpected or malformed KH2 milestone")
                cpu = decimal(data["cpu"], 0, 15)
                observer = decimal(data["observer_cpu"], 0, 15)
                if observer == cpu or data["build_sha"].lower() != build_sha.lower() or \
                        data["pipe_ready"] != "1" or data["idle"] != "1":
                    raise ValueError("R0 CPU, build, or readiness mismatch")
                events.append({"phase": "R0", "seq": seq, "cpu": cpu,
                               "observer_cpu": observer,
                               "gate_lo": address(data["gate_lo"]),
                               "gate_hi": address(data["gate_hi"]),
                               "ist6": address(data["ist6"])})
            elif kind == "KH2E" and level == "ERR":
                issues.append(f"KH2E at sequence {seq}: {text}")
            else:
                raise ValueError("unexpected KH2 record or write bracket")
        except ValueError as exc:
            issues.append(f"KH2 record at {parts[0]}: {exc}")

    cpu = next((event["cpu"] for event in events), None)
    expected = []
    if cpu is not None:
        gate = kdata_base + 0x2e88310
        ist6 = kdata_base + 0x2e8afe0 + cpu * 0x68 + 0x4c
        if gate + 16 > 1 << 64 or ist6 + 8 > 1 << 64:
            raise ValueError("derived gate or IST6 address overflows uint64")
        expected = [
            {"phase": "main baseline"},
            {"phase": "gate begin", "addr": gate, "bytes": 16},
            {"phase": "gate done", "addr": gate, "bytes": 16},
            {"phase": "ist6 begin", "addr": ist6, "bytes": 8},
            {"phase": "ist6 done", "addr": ist6, "bytes": 8},
            {"phase": "R0"},
        ]
    baseline = next((event for event in events
                     if event["phase"] == "main baseline"), None)
    worker_r0 = next((event for event in events if event["phase"] == "R0"), None)
    if baseline and expected:
        expected[-1].update({key: baseline[key]
                             for key in ("gate_lo", "gate_hi", "ist6")})
    prefix = 0
    for index, event in enumerate(events):
        if index >= len(expected) or any(event.get(key) != value for key, value in
                                         expected[index].items()) or event["cpu"] != cpu:
            issues.append(f"unexpected address/order at KH2 sequence {event['seq']}")
            break
        prefix += 1
    if len(events) > len(expected):
        issues.append("extra R0 calibration records")
    if baseline and worker_r0 and any(
            baseline[key] != worker_r0[key] for key in ("gate_lo", "gate_hi", "ist6")):
        issues.append("worker R0 values differ from main baseline")
    transport = "unknown"
    if manifest is not None:
        transport = ("complete" if manifest.get("sha256") == hashlib.sha256(raw).hexdigest()
                     and manifest.get("clean") is True and manifest.get("gaps") == []
                     else "incomplete")
        if transport != "complete":
            issues.append("manifest digest, clean close, or sequence gaps failed")
    exit_marker = f"[KH2R0] exit rc=0 build={build_sha.lower()}; affinity restored"
    return_state = "not_supplied" if stdout is None else (
        "reported_clean" if exit_marker in stdout.splitlines() else "missing_clean_exit")
    if stdout is not None and return_state != "reported_clean":
        issues.append("final affinity-restored stdout marker absent")
    complete = prefix == len(PHASES) and not issues and transport == "complete" \
        and return_state == "reported_clean"
    return {
        "status": "retained_calibration_complete" if complete else
                  "invalid_or_error" if issues else "partial_evidence",
        "confirmed_prefix": list(PHASES[:prefix]),
        "next_missing": PHASES[prefix] if prefix < len(PHASES) else None,
        "issues": issues,
        "transport": transport,
        "return_marker": return_state,
        "cpu": cpu,
        "observer_cpu": next((e["observer_cpu"] for e in events if e["phase"] == "R0"), None),
        "scope": "reported reads/worker return only; no kernel ownership or #DB proof",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="retained KH2 R0 ps5log/1 run")
    parser.add_argument("--manifest", type=Path, help="same-run ps5logd JSON manifest")
    parser.add_argument("--stdout", type=Path, help="same-attempt elfldr stdout capture")
    parser.add_argument("--kdata-base", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--build-sha", required=True, help="source-list build tag")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text()) if args.manifest else None
        result = inspect(args.log.read_bytes(), manifest,
                         args.stdout.read_text() if args.stdout else None,
                         args.kdata_base, args.build_sha)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    if result["status"] != "retained_calibration_complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
