#!/usr/bin/env python3
"""Verify 1.4 metadata and byte preservation of historical evidence.

Does not replace or weaken the historical verifier. That verifier stays unchanged
and must be run in the immutable v1.3.0 checkout, not over added candidate files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVED_COMMIT = "537799bd2b292ce6e78004de22f4ab6df1b4feda"
DOCUMENTATION_BASELINE = "e1ee51f050d7bf6e31dbee68560dd781e9b75985"
SIGNED_SOURCE = "0bcb038fef930faff3ef19f661bf995f97d605d8"
VERSION = "1.4.0"
DOI = "10.5281/zenodo.22326718"
MANIFEST = "MANIFEST-v1.4.0.sha256"
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
    if 'version = "1.4.0"' not in metadata or 'hardening = ["cryptography==50.0.1"]' not in metadata:
        errors.append("package version/dependency mismatch")
    if "version: 1.4.0\n" not in citation or f'doi: "{DOI}"\n' not in citation:
        errors.append("software citation must identify the exact 1.4 version and reserved DOI")
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
    return {"version": VERSION, "archived_source": ARCHIVED_COMMIT,
            "preexisting_documentation_baseline": DOCUMENTATION_BASELINE,
            "historical_files_preserved": preserved, "errors": errors,
            "publication_status": "not checked by this local verifier; consult the Zenodo record",
            "doi": DOI, "external_replication": "not authenticated by this verifier",
            "organizational_pilot": "not performed"}


def release_errors() -> list[str]:
    """Fail closed on source/tag/manifest/evidence drift; never infer publication."""
    errors = []
    try:
        if git("status", "--porcelain"):
            errors.append("release checkout must be clean")
        if git("cat-file", "-t", "refs/tags/v1.4.0") != "tag":
            errors.append("v1.4.0 must be an annotated tag")
        if git("rev-parse", "v1.4.0^{commit}") != git("rev-parse", "HEAD"):
            errors.append("v1.4.0 tag must identify HEAD")
        names = git("ls-tree", "-r", "--name-only", SIGNED_SOURCE, "--", "eacp_hardening").splitlines()
        current = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "eacp_hardening").glob("*.py"))
        if sorted(names) != current:
            errors.append("implementation module set differs from the signed source")
        for name in names:
            expected = subprocess.check_output(["git", "show", f"{SIGNED_SOURCE}:{name}"], cwd=ROOT)
            if name == "eacp_hardening/__init__.py":
                expected = expected.replace(b'__version__ = "1.4.0rc1"', b'__version__ = "1.4.0"')
            if (ROOT / name).read_bytes() != expected:
                errors.append(f"implementation changed beyond version metadata: {name}")
        baseline = "01c81d50c9142a3166eb793fc9c3c35adf2c223d"
        changed_evidence = git("diff", "--name-only", baseline, "--", "results/hardening-v1.4")
        if changed_evidence:
            errors.append("retained hardening evidence changed")
        tar = ROOT / "results/hardening-v1.4/live-signing-33945266470/artifact-33945266470/eacp-hardening-v1.4.tar.gz"
        if hashlib.sha256(tar.read_bytes()).hexdigest() != "b4ee08dc32eb56e568ccc93ba45459642f3844427adab0bd8c044153b5ac3bea":
            errors.append("live signed TAR digest mismatch")
        check = subprocess.run([sys.executable, str(ROOT / "scripts/generate_manifest.py"),
                                "--manifest", MANIFEST, "--check"], cwd=ROOT, capture_output=True, text=True)
        if check.returncode:
            errors.append("final release manifest mismatch or missing")
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"release prerequisite missing or unreadable: {type(exc).__name__}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true", help="verify local archival readiness, not online publication")
    args = parser.parse_args()
    report = verify()
    if args.release:
        report["errors"].extend(release_errors())
        report["release_readiness"] = "passed" if not report["errors"] else "failed"
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
