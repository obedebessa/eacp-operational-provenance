#!/usr/bin/env python3
"""Build a privacy-screened source snapshot and labeled receipt derivatives.

No Git history, private policy, old input manifest, or identifying executor
declaration is copied into the delivery. Original submissions remain untouched.
The external policy belongs outside the repository. Signed binary artifacts are
never modified: unexplained privacy findings abort publication.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MEASURED = 'e2807efc14209e42ba5ac82f5aa8d44599d22c43'
MAX_INPUT = 256 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def project(data, policy):
    """Only text is redacted; callers must scan all opaque members separately."""
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return data
    for entry in sorted(policy.get('replacements', []), key=lambda x: -len(x['from'])):
        original, replacement = entry['from'], entry['to']
        if not original:
            raise ValueError('empty private replacement')
        variants = {unicodedata.normalize(form, original) for form in ('NFC', 'NFD')}
        variants |= {urllib.parse.quote(v, safe='/') for v in list(variants)}
        variants |= {json.dumps(v, ensure_ascii=True)[1:-1] for v in list(variants)}
        for value in sorted(variants, key=len, reverse=True):
            if entry.get('word', False):
                text = re.sub(r'(?<!\w)' + re.escape(value) + r'(?!\w)',
                              lambda _: replacement, text)
            else:
                text = text.replace(value, replacement)
    return text.encode('utf-8')


def checked_members(path):
    """Read only safe regular members; do not execute content or extract paths."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > 10000 or sum(i.file_size for i in infos) > MAX_INPUT:
            raise ValueError('input ZIP resource limit')
        if len({i.filename for i in infos}) != len(infos) or archive.testzip():
            raise ValueError('input ZIP duplicate member or CRC failure')
        roots = set()
        for item in infos:
            name = PurePosixPath(item.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in item.filename:
                raise ValueError('unsafe input ZIP member')
            if ((item.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('input ZIP symlink')
            if item.filename.startswith('__MACOSX/') or item.filename.startswith('__MACOSX'):
                continue
            if not item.is_dir():
                roots.add(name.parts[0])
        if len(roots) != 1:
            raise ValueError('input ZIP must contain one package directory')
        prefix = next(iter(roots)) + '/'
        return {i.filename[len(prefix):]: archive.read(i) for i in infos
                if i.filename.startswith(prefix) and not i.is_dir()
                and not PurePosixPath(i.filename).name.startswith('._')}


def protected_evidence(name, data):
    """Do not rewrite compressed artifacts or cryptographic envelopes as text."""
    if name.endswith(('.zip', '.whl', '.tar.gz', '.tgz', '.pdf', '.bundle')):
        return True
    return any(marker in data for marker in
               (b'"dsseEnvelope"', b'"verificationResult"', b'"signedEntryTimestamp"',
                b'"predicateType"', b'"signatures"', b'"signature"'))


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def build(destination, verification, external_zip, crypto_zip, policy_path, delivery_verification=None):
    archive_path = Path(str(destination) + '.zip')
    sidecar = Path(str(archive_path) + '.sha256')
    if any(p.exists() or p.is_symlink() for p in (destination, archive_path, sidecar)):
        raise ValueError('refusing to overwrite a prior delivery')
    policy = json.loads(policy_path.read_text())
    if policy_path.resolve().is_relative_to(ROOT):
        raise ValueError('private policy must be outside the repository')
    check = subprocess.run([sys.executable, 'scripts/verify_candidate_v1_5.py', '--freeze'],
                           cwd=ROOT, capture_output=True, text=True)
    if check.returncode:
        raise ValueError('candidate freeze gate failed; inspect privately before packaging')
    gate = json.loads(check.stdout)
    if not (gate.get('runtime_byte_equivalent') is True and gate.get('profile_byte_equivalent') is True):
        raise ValueError('runtime differs from the supplied execution reference')
    author = json.loads((verification / 'FINAL_SUMMARY.json').read_text())
    if author.get('source_commit') != MEASURED or author.get('required_checks_passed') is not True:
        raise ValueError('author receipts do not match original measured candidate')
    external, crypto = checked_members(external_zip), checked_members(crypto_zip)
    if 'SUMMARY_updated.md' not in crypto:
        raise ValueError('latest supplied summary missing')
    env = json.loads(external['00-environment.json'])
    if env.get('head') != MEASURED:
        raise ValueError('external execution reference mismatch')
    for name in ('01-historical-1.3-offline-test.rc',
                 '03-gh-attestation-verify-historical-1.3.rc', '04-hardening-suite.rc'):
        if crypto[name].strip() != b'0':
            raise ValueError('historical follow-up result is not successful')
    destination.mkdir(parents=False, exist_ok=False)
    changes, omissions = [], []

    def copy(relative, data, origin, redaction=True):
        target = destination / relative
        if target.exists():
            raise ValueError('duplicate delivery output')
        target.parent.mkdir(parents=True, exist_ok=True)
        result = project(data, policy) if redaction and not protected_evidence(relative, data) else data
        target.write_bytes(result)
        if result != data:
            changes.append(dict(path=relative, origin=origin, original_sha256=digest(data),
                                distributed_sha256=digest(result), status='PRIVACY_DERIVATIVE'))

    for name in git('ls-files').splitlines():
        source = ROOT / name
        if source.is_symlink() or not source.is_file():
            raise ValueError('unsupported tracked member')
        # Source bytes already passed their source/ledger gate. Never silently
        # patch source, PDFs or cryptographic objects during packaging.
        copy('source/' + name, source.read_bytes(), 'delivery-source', redaction=False)
    for source in sorted(verification.rglob('*')):
        if source.is_symlink():
            raise ValueError('author receipt symlink')
        if not source.is_file():
            continue
        relative = source.relative_to(verification).as_posix()
        if source.suffix in {'.bundle', '.pyc'} or '__pycache__' in source.parts:
            omissions.append(dict(origin='author', path=relative, reason='history/cache excluded'))
            continue
        copy('verification/author/' + relative, source.read_bytes(), 'author-run')
    for name, data in sorted(external.items()):
        if name in {'SHA256SUMS', 'EXECUTOR.md', 'SUMMARY.md'} or name.startswith('demo/private/'):
            omissions.append(dict(origin='external', path=name, original_sha256=digest(data),
                                  reason='superseded manifest/summary, identifying declaration, or synthetic private store'))
            continue
        copy('verification/external/' + name, data, 'external-submission')
    copy('verification/external/SUMMARY.md', crypto['SUMMARY_updated.md'], 'latest-supplied-summary')
    for name, data in sorted(crypto.items()):
        if name in {'SHA256SUMS', 'SUMMARY_updated.md'}:
            continue
        copy('verification/historical-crypto/' + name, data, 'historical-crypto-addendum')
    if delivery_verification:
        for source in sorted(delivery_verification.rglob('*')):
            if source.is_symlink():
                raise ValueError('delivery verification symlink')
            if source.is_file():
                copy('verification/delivery/' + source.relative_to(delivery_verification).as_posix(),
                     source.read_bytes(), 'current-delivery-checks')
    copy('verification/external/EXECUTION_SCOPE.md',
         (ROOT / 'docs/v1.5/EXTERNAL_EXECUTION.md').read_bytes(), 'maintainer-scope-record', False)
    metadata = dict(format='eacp.privacy-review-delivery/1', software='1.5.0rc1',
                    profile='1.3', paper='1.3', source_commit=git('rev-parse', 'HEAD'),
                    source_tree=git('rev-parse', 'HEAD^{tree}'), execution_reference=MEASURED,
                    execution_reference_runtime_matches=True, includes_git_history=False,
                    new_live_signature=False, doi=None, independent_expert_approval=False,
                    executor='External Executor E1 (identity held separately)',
                    attribution='supplied execution, not identity authenticated by the package',
                    input_external_zip_sha256=digest(external_zip.read_bytes()),
                    input_crypto_zip_sha256=digest(crypto_zip.read_bytes()))
    write_json(destination / 'CANDIDATE.json', metadata)
    write_json(destination / 'REDACTION_LEDGER.json',
               dict(format='eacp.delivery-privacy-projection/1', files=changes, omitted=omissions,
                    originals='retained separately; not included in screened delivery',
                    scientific_claim='none added by redaction'))
    copy('START_HERE.md', (ROOT / 'START_HERE.md').read_bytes(), 'review-card', False)
    # Links in the source card are relative to the source snapshot.
    card = (destination / 'START_HERE.md').read_text()
    card = card.replace('(docs/', '(source/docs/').replace('(RELEASE_NOTES_', '(source/RELEASE_NOTES_')
    (destination / 'START_HERE.md').write_text(card + '\n\nSee REPRODUCE.md for copy-ready delivery commands.\n')
    (destination / 'REPRODUCE.md').write_text('''# Review snapshot and original execution

Verify the externally supplied ZIP digest first, then run from this directory:

```sh
shasum -a 256 -c SHA256SUMS
cd source
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.2.1
.venv/bin/python -m pip install .
.venv/bin/python -m pip check
.venv/bin/python -m unittest discover -s tests/hardening -v
.venv/bin/python -O -m unittest discover -s tests/operability -v
.venv/bin/python -m unittest discover -s spec/tests -v
.venv/bin/python -m unittest discover -s experiments/github_actions/tests -v
.venv/bin/python -m unittest discover -s experiments/correlation_robustness -v
.venv/bin/python -m unittest discover -s experiments/index_ablation -v
.venv/bin/python -I -m eacp_hardening demo --output-directory /tmp/eacp-review-demo-new
.venv/bin/python scripts/mutate_v1_5.py --output /tmp/eacp-review-mutants-new
```

On Linux, `sha256sum -c SHA256SUMS` is equivalent. Use new output directories.
GitHub CLI must be installed to execute the real historical signature test;
record a missing CLI as a skip, never a pass. Install platform venv support if
`ensurepip` is unavailable. Do not use customer data, production secrets or a
letter of intent as collection authorization.

This source snapshot excludes Git history. Do not run the Git-preservation gate,
full repository-contract suite or original campaign in it and report their
missing-history failures as runtime defects. To repeat the original complete
276-test/campaign procedure, obtain a full official checkout at the execution
reference recorded in CANDIDATE.json. That checkout contains historical metadata
outside this privacy-screened delivery. The current source is a later packaging
commit with unchanged runtime and Profile bytes, not a claim E1 tested new
packaging/privacy utilities. The author/external logs retain their actual commits.

The first external run had one skip; the historical-crypto follow-up passed it.
Repeated suites are not new unique tests. The latest supplied summary is
verification/external/SUMMARY.md. Machine-generated operator fields are preserved
as emitted and do not identify a person. See verification/external/EXECUTION_SCOPE.md for attribution.

Historical manifests apply to their original checkouts. Only this delivery's
SHA256SUMS binds its redacted files. A checksum establishes byte consistency,
not authenticity, source truth or independent human approval. Historical signed
TARs remain byte-identical and never cover this whole ZIP.
''')
    # Inspect both expanded contents and final archive/member names. A clean
    # directory scan alone does not check the enclosing output basename.
    def inspect_public(target):
        with tempfile.TemporaryDirectory(prefix='eacp-private-scan-policy-') as temporary:
            scan_policy = Path(temporary) / 'policy.json'
            write_json(scan_policy, {key: policy.get(key, []) for key in ('deny_literals', 'allow_emails')})
            scan = subprocess.run([sys.executable, str(ROOT / 'scripts/privacy_scan_v1_5.py'),
                                   str(target), '--policy', str(scan_policy)], capture_output=True, text=True)
        if scan.returncode:
            raise ValueError('privacy scan rejected delivery; inspect local staging, do not share')
        return json.loads(scan.stdout)

    write_json(destination / 'PRIVACY_SCAN.json', inspect_public(destination))
    members = sorted(p for p in destination.rglob('*') if p.is_file())
    (destination / 'SHA256SUMS').write_text(''.join(digest(p.read_bytes()) + '  ' +
        p.relative_to(destination).as_posix() + '\n' for p in members))
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(destination.rglob('*')):
            if path.is_file():
                info = zipfile.ZipInfo(destination.name + '/' + path.relative_to(destination).as_posix(),
                                       date_time=(2026, 9, 5, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes())
    with zipfile.ZipFile(archive_path) as archive:
        prefix = destination.name + '/'
        expected = {prefix + 'SHA256SUMS'}
        for line in archive.read(prefix + 'SHA256SUMS').decode().splitlines():
            sha, name = line.split('  ', 1)
            expected.add(prefix + name)
            if digest(archive.read(prefix + name)) != sha:
                raise ValueError('delivery checksum failure')
        if archive.testzip() or set(archive.namelist()) != expected or len(archive.namelist()) != len(expected):
            raise ValueError('delivery membership/CRC failure')
    inspect_public(archive_path)
    sidecar.write_text(digest(archive_path.read_bytes()) + '  ' + archive_path.name + '\n')
    return dict(metadata, archive=archive_path.name, sha256=digest(archive_path.read_bytes()),
                bytes=archive_path.stat().st_size, members=len(expected), redacted_files=len(changes))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--author-verification', type=Path, required=True)
    parser.add_argument('--external-zip', type=Path, required=True)
    parser.add_argument('--crypto-zip', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--delivery-verification', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output_directory, args.author_verification, args.external_zip,
                           args.crypto_zip, args.policy, args.delivery_verification), indent=2))
