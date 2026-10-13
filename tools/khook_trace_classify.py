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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="verbatim ps5logd .log file")
    parser.add_argument("--manifest", type=Path, help="matching ps5logd .json file")
    args = parser.parse_args()
    raw = args.log.read_bytes()
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    print(json.dumps(classify(raw, manifest), indent=2))


if __name__ == "__main__":
    main()
