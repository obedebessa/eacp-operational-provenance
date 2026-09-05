#!/usr/bin/env python3
"""Package a clean candidate and historical tag for review without publishing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_COMMIT = "537799bd2b292ce6e78004de22f4ab6df1b4feda"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def package(destination: Path) -> dict:
    if git("status", "--porcelain"):
        raise ValueError("freeze a clean source/results commit before making the review package")
    if git("rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("complete the local Git history before packaging; shallow bundles are not transferable")
    if git("rev-parse", "v1.3.0^{commit}") != HISTORICAL_COMMIT:
        raise ValueError("historical tag pin changed")
    destination = destination.resolve()
    archive = destination.parent / (destination.name + ".zip")
    checksum_file = Path(str(archive) + ".sha256")
    if any(path.exists() for path in (destination, archive, checksum_file)):
        raise ValueError("destination, archive and checksum must not already exist")
    source_commit = git("rev-parse", "HEAD")
    branch = git("symbolic-ref", "HEAD")
    if not branch.startswith("refs/heads/"):
        raise ValueError("a named candidate branch is required")
    destination.mkdir(parents=True)
    bundle = destination / "EACP_1.4.0-rc1_source.bundle"
    subprocess.run(["git", "bundle", "create", str(bundle), branch, "refs/tags/v1.3.0"], cwd=ROOT, check=True)
    subprocess.run(["git", "bundle", "verify", str(bundle)], cwd=ROOT, check=True, capture_output=True)
    # Verifying inside the producer repository can hide missing Git objects.
    # Require a standalone clone and verify the delivered bytes before archiving.
    with tempfile.TemporaryDirectory(prefix="eacp-package-transfer-") as temporary:
        checkout = Path(temporary) / "checkout"
        subprocess.run(["git", "clone", "--quiet", "--branch", branch.removeprefix("refs/heads/"),
                        str(bundle), str(checkout)], check=True, capture_output=True)
        for ref, expected in (("HEAD", source_commit), ("v1.3.0^{commit}", HISTORICAL_COMMIT)):
            actual = subprocess.check_output(["git", "rev-parse", ref], cwd=checkout, text=True).strip()
            if actual != expected:
                raise ValueError("transferred Git identity does not match the pinned source")
        for command in (["scripts/verify_hardening.py"],
                        ["scripts/generate_manifest.py", "--manifest", "MANIFEST-v1.4.0-rc1.sha256", "--check"]):
            subprocess.run([sys.executable, "-B", *command], cwd=checkout, check=True, capture_output=True)
    metadata = {"schema": "eacp.local-review-package/1", "version": "1.4.0-rc1",
                "source_commit": source_commit, "branch": branch, "historical_commit": HISTORICAL_COMMIT,
                "published": False, "external_reproduction_claimed": False, "organizational_pilot_claimed": False,
                "publication_scope": "final archival release, not GitHub source availability",
                "local_transfer_clone_verified": True}
    (destination / "PACKAGE.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    (destination / "REVIEWER_PACKET.md").write_text((ROOT / "docs/v1.4/REVIEWER_PACKET.md").read_text())
    short_branch = branch.removeprefix("refs/heads/")
    (destination / "START_HERE.md").write_text(f"""# EACP 1.4.0-rc1 - local review package

This package contains a complete Git bundle, including the historical v1.3.0 tag.
It is an engineering candidate, not a final archival release or a replacement for
the published 1.3 PDFs/DOIs. PACKAGE.json's published flag refers to a final
archival release, not source availability on GitHub.
No production readiness, independent execution or organizational pilot is claimed.
The producer verified a fresh local clone, pinned commits and its file manifest;
this transfer check is not independent reproduction by an external reviewer.

## Open the exact source

```sh
git clone --branch {short_branch} EACP_1.4.0-rc1_source.bundle eacp-review
cd eacp-review
git checkout --detach {source_commit}
git rev-parse HEAD
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[hardening]'
.venv/bin/python scripts/verify_hardening.py
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python scripts/reproduce_hardening_v1_4.py --output reproduction-output/reviewer-new
```

Read `docs/v1.4/README.md`, `docs/v1.4/REVIEWER_PACKET.md` and
`results/hardening-v1.4/VERIFICATION.md`. Review source and logs before executing.
The reproduction runner is not a sandbox. Python3.11+, Git and GitHubCLI are the
documented prerequisites; existing bundle verification is not a new live run.

Candidate package commit: `{source_commit}`.
Historical release: `{HISTORICAL_COMMIT}` (tag `v1.3.0`).
Per-run code identity and source hashes are inside the retained reports; the
results-only package commit may postdate the measured code commit.

SHA256SUMS checks transfer integrity only. Obtain the expected package checksum
and source commit from the sender through your agreed channel; the package cannot
authenticate itself. No reviewer statement or signed third-party letter is in
this package, and no correspondence has been sent automatically.
""")
    files = sorted(path for path in destination.iterdir() if path.is_file())
    (destination / "SHA256SUMS").write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in files))
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(destination.iterdir()):
            output.write(path, arcname=destination.name + "/" + path.name)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    with checksum_file.open("x") as output:
        output.write(checksum + "  " + archive.name + "\n")
    return {**metadata, "archive": str(archive), "archive_sha256": checksum}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.output_directory), indent=2, sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "not_packaged", "reason": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
