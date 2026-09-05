#!/usr/bin/env python3
"""Freeze a clean candidate into a full-history bundle + byte-checked review ZIP."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_path(destination):
    # Append; with_suffix would silently drop the last dotted version component.
    return Path(str(destination) + '.zip')


def package(destination, verification):
    archive = archive_path(destination)
    sidecar = Path(str(archive) + '.sha256')
    if any(p.exists() or p.is_symlink() for p in (destination, archive, sidecar)):
        raise ValueError('refusing to replace any existing candidate output')
    subprocess.run([sys.executable, str(ROOT / 'scripts/verify_candidate_v1_5.py'), '--freeze'], cwd=ROOT, check=True)
    if not (verification / 'FINAL_SUMMARY.json').is_file():
        raise ValueError('final execution receipts required before packaging')
    summary = json.loads((verification / 'FINAL_SUMMARY.json').read_text())
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
    if summary.get('source_commit') != commit or summary.get('required_checks_passed') is not True:
        raise ValueError('final verification does not match this commit or required checks')
    destination.mkdir(parents=False, exist_ok=False)
    bundle = destination / 'eacp-1.5.0rc1.bundle'
    subprocess.run(['git', 'bundle', 'create', str(bundle), 'HEAD', 'refs/tags/v1.4.0', 'refs/tags/v1.3.0'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='eacp-candidate-clone-') as d:
        clone = Path(d) / 'source'
        subprocess.run(['git', 'clone', str(bundle), str(clone)], check=True, capture_output=True)
        subprocess.run(['git', 'checkout', '--detach', commit], cwd=clone, check=True, capture_output=True)
        subprocess.run([sys.executable, 'scripts/verify_candidate_v1_5.py', '--freeze'], cwd=clone, check=True)
        names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=clone).decode().split('\0')
        for name in filter(None, names):
            source = clone / name
            if source.is_symlink() or not source.is_file():
                raise ValueError('unsupported source member')
            target = destination / 'source' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    for source in verification.rglob('*'):
        if source.is_symlink():
            raise ValueError('verification symlink is forbidden')
    shutil.copytree(verification, destination / 'verification')
    metadata = dict(software='1.5.0rc1', profile='1.3', paper='1.3', protocol='operability/1', commit=commit,
                    tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT).decode().strip(),
                    bundle_sha256=sha(bundle), doi=None, publication='NOT_PUBLISHED', new_live_attestation=False,
                    operator='author-directed AI-assisted', external_human_review=False)
    (destination / 'CANDIDATE.json').write_text(json.dumps(metadata, indent=2))
    (destination / 'START_HERE.md').write_text(f'''# EACP software 1.5.0rc1 review candidate

Exact commit: {commit}. Profile/paper 1.3 and historical negative cohorts are preserved.
No new DOI, live signature, independent human review or organizational pilot is claimed.
Read source/docs/v1.5/README.md and EVIDENCE_MATRIX.md before running code.
verification/FINAL_SUMMARY.json distinguishes checks and limitations; raw logs and
failed development invocations remain separate, not pooled into success rates.

Obtain this ZIP's expected SHA-256 via a trusted channel, then verify SHA256SUMS.
An internal checksum checks consistency, not authenticity. No enclosed script is
automatically executed by an evidence import; review source before reproduction.

```
shasum -a 256 -c SHA256SUMS
git clone eacp-1.5.0rc1.bundle eacp-review
cd eacp-review
git checkout --detach {commit}
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.2.1
.venv/bin/python -m pip install .
.venv/bin/python scripts/verify_candidate_v1_5.py --freeze
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -I -m eacp_hardening demo --output-directory /tmp/eacp-review-demo-new
```

The historical reviewer target ecfd42d4 and software 1.4.0 are recoverable from
the Git bundle. Use each historical verifier in its own immutable checkout.
Reviewer conclusions are intentionally blank in the evidence matrix. Licensing
is file-scoped; see source/LICENSES/README.md. This is a candidate for review,
not a guarantee that criticism is impossible or a production certification.
''')
    members = sorted(p for p in destination.rglob('*') if p.is_file())
    if sum(p.stat().st_size for p in members) > 256 * 1024 * 1024:
        raise ValueError('review package exceeds byte budget')
    (destination / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.relative_to(destination).as_posix() + '\n' for p in members))
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(destination.rglob('*')):
            if p.is_file():
                z.write(p, destination.name + '/' + p.relative_to(destination).as_posix())
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None:
            raise ValueError('review ZIP CRC failure')
        prefix = destination.name + '/'
        manifest = z.read(prefix + 'SHA256SUMS').decode().splitlines()
        expected_names = {prefix + 'SHA256SUMS'}
        for line in manifest:
            expected, name = line.split('  ', 1)
            expected_names.add(prefix + name)
            if hashlib.sha256(z.read(prefix + name)).hexdigest() != expected:
                raise ValueError('review ZIP checksum failure')
        if set(z.namelist()) != expected_names or len(z.namelist()) != len(expected_names):
            raise ValueError('review ZIP member set mismatch')
    sidecar.write_text(sha(archive) + '  ' + archive.name + '\n')
    return dict(metadata, zip=str(archive), sha256=sha(archive), bytes=archive.stat().st_size, members=len(expected_names))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--output-directory', type=Path, required=True)
    p.add_argument('--verification-directory', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(package(args.output_directory, args.verification_directory), indent=2))
