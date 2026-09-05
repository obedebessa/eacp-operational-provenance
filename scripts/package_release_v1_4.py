#!/usr/bin/env python3
"""Create a verified final distribution; does not upload or claim publication."""
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


def run(*args, cwd=ROOT):
    return subprocess.check_output(list(args), cwd=cwd, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package(destination: Path, receipts: Path) -> dict:
    destination = destination.resolve()
    receipts = receipts.resolve()
    archive = destination.with_suffix(".zip")
    if destination.exists() or archive.exists():
        raise ValueError("destination already exists; preserve it and choose a fresh destination")
    if not receipts.is_dir() or not (receipts / "verification.json").is_file():
        raise ValueError("complete final verification receipts are required")
    checks = json.loads((receipts / "verification.json").read_text())
    commit = run("git", "rev-parse", "HEAD")
    if checks.get("source_commit") != commit or checks.get("status") != "passed":
        raise ValueError("verification receipts do not match this passing final source")
    run(sys.executable, "-B", "scripts/verify_hardening.py", "--release")
    destination.mkdir(parents=True)
    bundle = destination / "eacp-v1.4.0.bundle"
    run("git", "bundle", "create", str(bundle), "refs/tags/v1.4.0", "refs/tags/v1.3.0")
    # Verify in a new repository, not only against objects already on the producer.
    with tempfile.TemporaryDirectory(prefix="eacp-final-transfer-") as temporary:
        clone = Path(temporary) / "checkout"
        run("git", "clone", "--quiet", "--branch", "v1.4.0", str(bundle), str(clone))
        if run("git", "rev-parse", "HEAD", cwd=clone) != commit:
            raise ValueError("transferred source commit mismatch")
        run(sys.executable, "-B", "scripts/verify_hardening.py", "--release", cwd=clone)
        source_zip = Path(temporary) / "source.zip"
        run("git", "archive", "--format=zip", "-o", str(source_zip), "HEAD")
        with zipfile.ZipFile(source_zip) as source:
            for name in source.namelist():
                if Path(name).is_absolute() or ".." in Path(name).parts:
                    raise ValueError("unsafe source archive path")
            source.extractall(destination / "source")
    import shutil
    shutil.copytree(receipts, destination / "verification")
    metadata = {
        "version": "1.4.0", "source_commit": commit,
        "source_tree": run("git", "rev-parse", "HEAD^{tree}"),
        "tag": "v1.4.0", "tag_object": run("git", "rev-parse", "refs/tags/v1.4.0"),
        "doi": "10.5281/zenodo.22326718",
        "doi_status_at_source_freeze": "reserved; public record establishes publication",
        "bundle_sha256": digest(bundle), "fresh_bundle_clone_verified": True,
        "organizational_pilot_performed": False, "human_executor_identity_authenticated": False,
        "verification_operator": "author-directed AI-assisted local execution",
        "final_zip_has_new_attestation": False,
    }
    (destination / "RELEASE.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    (destination / "START_HERE.md").write_text(f"""# EACP software 1.4.0

Archival software edition; the paper and normative Profile remain version 1.3.
See source/RELEASE_NOTES_v1.4.0.md for scope and the retained measurements.
DOI 10.5281/zenodo.22326718 was reserved at freeze. Consult Zenodo for status.
No field pilot, production certification, SLSA L3 or authenticated independent
human review is claimed. Private executor materials are not in this deposit.

## Verify transfer, then reproduce

Review source before execution. This package is not a sandbox.
Obtain the expected ZIP checksum through a trusted channel. SHA256SUMS inside
this package checks consistency, not authenticity.

```sh
shasum -a 256 -c SHA256SUMS
git clone --branch v1.4.0 eacp-v1.4.0.bundle eacp-review
cd eacp-review
git checkout --detach {commit}
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[hardening]'
.venv/bin/python scripts/verify_hardening.py --release
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python scripts/reproduce_hardening_v1_4.py --output reproduction-output/new-execution
```

Prerequisites: Python 3.11+, Git and a trusted GitHub CLI for retained attestation
verification. The source/ directory is a convenient export; use the Git bundle
for the historical identity checks and reproduction runner.

Final commit: {commit}
RELEASE.json records the annotated tag object and source tree.
verification/ contains author-directed AI-assisted final checks, not an external
execution. Old results and failed attempts remain unchanged in source/results/.
The live signature covers only the retained TAR from run 33945266470, not this
ZIP or this final commit. Licensing is file-scoped: source/LICENSES/README.md.
""")
    files = sorted(p for p in destination.rglob("*") if p.is_file())
    (destination / "SHA256SUMS").write_text("".join(
        digest(p) + "  " + p.relative_to(destination).as_posix() + "\n" for p in files))
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for p in sorted(destination.rglob("*")):
            if p.is_file():
                output.write(p, destination.name + "/" + p.relative_to(destination).as_posix())
    with zipfile.ZipFile(archive) as check:
        if check.testzip() is not None:
            raise ValueError("ZIP CRC verification failed")
        prefix = destination.name + "/"
        for line in check.read(prefix + "SHA256SUMS").decode().splitlines():
            expected, name = line.split("  ", 1)
            if hashlib.sha256(check.read(prefix + name)).hexdigest() != expected:
                raise ValueError("final ZIP checksum verification failed")
    checksum = digest(archive)
    archive.with_suffix(".zip.sha256").write_text(checksum + "  " + archive.name + "\n")
    return {**metadata, "zip": str(archive), "zip_sha256": checksum, "bytes": archive.stat().st_size}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--verification-directory", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.output_directory, args.verification_directory), indent=2))
