#!/usr/bin/env python3
"""Bind a KH2 geometry candidate to one complete R0 calibration capture.

The gate bracket supplies a derived base, not an independent base read.
The output remains an offline geometry candidate without ownership or #DB proof.
"""

import argparse
import hashlib
import json
from pathlib import Path

from kh2_layout_rebase import rebase
from kh2_r0_calibration_check import base_from_gate_bracket, inspect


def create_plan(template, raw, manifest, stdout, build_sha):
    base = base_from_gate_bracket(raw)
    result = inspect(raw, manifest, stdout, base, build_sha)
    if result["status"] != "retained_calibration_complete":
        raise ValueError("R0 capture incomplete or mismatched: " +
                         "; ".join(result["issues"] or
                                   [str(result["next_missing"])]))
    plan = rebase(template, result["cpu"], base)
    plan["calibration"] = {
        "status": result["status"],
        "log_sha256": hashlib.sha256(raw).hexdigest(),
        "build_sha": build_sha.lower(),
        "base_source": "main gate begin address minus published 12.02 IDT offset; not independent",
        "scope": "same-attempt reported R0 values and geometry only; no ownership or #DB proof",
    }
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("template", type=Path)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--build-sha", required=True,
                        help="source/header input-list build tag, not ELF SHA-256")
    args = parser.parse_args()
    try:
        template_bytes = args.template.read_bytes()
        log_bytes = args.log.read_bytes()
        manifest_bytes = args.manifest.read_bytes()
        stdout_bytes = args.stdout.read_bytes()
        plan = create_plan(json.loads(template_bytes), log_bytes,
                           json.loads(manifest_bytes),
                           stdout_bytes.decode("utf-8"), args.build_sha)
    except (OSError, KeyError, TypeError, ValueError, AttributeError) as error:
        parser.error(str(error))
    plan["source_template_sha256"] = hashlib.sha256(template_bytes).hexdigest()
    plan["calibration"]["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    plan["calibration"]["stdout_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()
    print(json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
