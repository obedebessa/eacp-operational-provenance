#!/usr/bin/env python3
"""Verify a future hardening archive against independently selected run identity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eacp_hardening.attestation import AttestationPolicy, verify_archive
from eacp_hardening.common import HardeningError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-ref", default="refs/heads/main")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, default=1)
    parser.add_argument("--trusted-root", type=Path)
    args = parser.parse_args()
    try:
        policy = AttestationPolicy(args.repository, args.source_sha, args.source_ref,
                                   args.run_id, args.run_attempt)
        result = verify_archive(args.archive, args.bundle, policy, trusted_root=args.trusted_root)
    except HardeningError as exc:
        print(f"Attestation rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
