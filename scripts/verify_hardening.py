#!/usr/bin/env python3
"""Verify candidate metadata and byte preservation of the frozen 1.3 release.

Does not replace or weaken the historical verifier. That verifier stays unchanged
and must be run in the immutable v1.3.0 checkout, not over added candidate files.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVED_COMMIT = "537799bd2b292ce6e78004de22f4ab6df1b4feda"
DOCUMENTATION_BASELINE = "e1ee51f050d7bf6e31dbee68560dd781e9b75985"
# This already-existing commit published the standalone Profile DOI. It predates
# the hardening work; do not classify its documented metadata changes as new
# scientific changes or silently permit further edits to those files.
PREEXISTING_DOI_UPDATES = {
    "EVIDENCE_BRIEF_v1.3.md", "EXPERT_REVIEW_REQUEST_v1.3.md", "MANIFEST-v1.3.0.sha256",
    "RELEASE_NOTES_v1.3.0.md", "REVIEWER_GUIDE_v1.3.md", "index.html", "paper/README.md",
}
PRESENTATION_CHANGES = {
    "README.md", "CITATION.cff", "pyproject.toml", "tests/test_repository_contract.py",
    ".github/workflows/reproduce-small.yml",
}
REQUIRED = (
    "eacp_hardening/common.py", "eacp_hardening/trust.py", "eacp_hardening/privacy.py",
    "eacp_hardening/store.py", "eacp_hardening/integrity.py", "eacp_hardening/attestation.py",
    "eacp_hardening/cli.py", "eacp_hardening/campaign.py", ".github/workflows/eacp-hardening-v1.4.yml",
    "scripts/reprocess_frozen_privacy_v1_4.py", "scripts/reproduce_hardening_v1_4.py",
    "scripts/evaluate_pilot_v1_4.py", "docs/v1.4/README.md", "docs/v1.4/REVIEWER_PACKET.md",
    "docs/v1.4/TRUST_MODEL.md", "docs/v1.4/EXTERNAL_VALIDATION.md", "docs/v1.4/PILOT_PROTOCOL.json",
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.PIPE).strip()


def verify() -> dict:
    errors = []
    for name in REQUIRED:
        if not (ROOT / name).is_file():
            errors.append(f"missing candidate file: {name}")
    metadata = (ROOT / "pyproject.toml").read_text()
    citation = (ROOT / "CITATION.cff").read_text()
    if 'version = "1.4.0rc1"' not in metadata or 'hardening = ["cryptography==50.0.1"]' not in metadata:
        errors.append("candidate package version/dependency mismatch")
    if "version: 1.4.0-rc1" not in citation or any(line.startswith("doi:") for line in citation.splitlines()):
        errors.append("candidate citation must identify its version without claiming an archival DOI")
    try:
        archived = git("rev-parse", "v1.3.0^{commit}")
        if archived != ARCHIVED_COMMIT:
            errors.append("historical v1.3.0 tag no longer identifies the expected frozen commit")
        original_files = set(git("ls-tree", "-r", "--name-only", ARCHIVED_COMMIT).splitlines())
        changed = set(git("diff", "--name-only", ARCHIVED_COMMIT, "--").splitlines())
        unexpected = sorted((changed & original_files) - PRESENTATION_CHANGES - PREEXISTING_DOI_UPDATES)
        since_baseline = set(git("diff", "--name-only", DOCUMENTATION_BASELINE, "--").splitlines())
        unexpected = sorted(set(unexpected) | ((since_baseline & original_files) - PRESENTATION_CHANGES))
        errors.extend("historical file modified: " + name for name in unexpected)
        preserved = len(original_files - PRESENTATION_CHANGES - PREEXISTING_DOI_UPDATES - set(unexpected))
    except (OSError, subprocess.CalledProcessError):
        errors.append("git history is required to verify the independent historical source pin")
        preserved = 0
    return {"candidate": "1.4.0-rc1", "archived_source": ARCHIVED_COMMIT,
            "preexisting_documentation_baseline": DOCUMENTATION_BASELINE,
            "historical_files_preserved": preserved, "errors": errors,
            "publication_status": "unpublished candidate",
            "external_replication": "not established", "organizational_pilot": "not performed"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="reject premature promotion of this candidate")
    args = parser.parse_args()
    report = verify()
    if args.release:
        report["errors"].append("unpublished candidate: no final 1.4 archival record or live attestation has been verified")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
