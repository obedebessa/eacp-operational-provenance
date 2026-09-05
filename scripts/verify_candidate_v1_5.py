#!/usr/bin/env python3
"""Candidate identity/history checks; never declares publication or external review."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BASE = '5067a26ad008db3bc4b4a5554e52c60239142735'
HISTORICAL_1_3 = '537799bd2b292ce6e78004de22f4ab6df1b4feda'
ALLOWED = {'CITATION.cff', 'README.md', 'pyproject.toml', 'tests/test_repository_contract.py',
           '.github/workflows/reproduce-small.yml', 'eacp_hardening/__init__.py',
           'eacp_hardening/common.py', 'eacp_hardening/store.py', 'eacp_hardening/cli.py'}
EXECUTION_REFERENCE = 'e2807efc14209e42ba5ac82f5aa8d44599d22c43'
PRIVACY_LEDGERS = ('docs/v1.5/PRIVACY_REDACTIONS.json',
                   'docs/v1.5/PDF_PRIVACY_REDACTIONS.json')
REVIEWER_DOCUMENTS = {'docs/v1.4/REVIEWER_PACKET.md', 'docs/v1.5/README.md'}
PAPER_PDFS = {'paper/EACP_preprint.pdf',
              'paper/Cross_Plane_Operational_Provenance_Preprint_v1.3.0.pdf'}
SHA256 = re.compile(r'[0-9a-f]{64}')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT,
                                   stderr=subprocess.PIPE).decode().strip()


def git_blob(reference, name):
    return subprocess.check_output(['git', 'show', reference + ':' + name],
                                   cwd=ROOT, stderr=subprocess.PIPE)


def safe_relative_path(name):
    if not isinstance(name, str) or not name or any(ord(c) < 32 for c in name):
        return False
    path = PurePosixPath(name)
    return (not path.is_absolute() and path.as_posix() == name
            and not any(part in ('.', '..') for part in path.parts)
            and '\\' not in name and ':' not in name)


def eligible_redaction(name, ledger):
    if not safe_relative_path(name):
        return False
    if ledger.endswith('/PDF_PRIVACY_REDACTIONS.json'):
        return name in PAPER_PDFS
    if name in REVIEWER_DOCUMENTS:
        return True
    path = PurePosixPath(name)
    # Signed archives and their attestation/verification inputs are immutable.
    return (name.startswith('results/hardening-v1.4/')
            and path.suffix in {'.json', '.txt', '.md'}
            and not any(part == 'inputs' or part.startswith(('attestation', 'artifact-'))
                        for part in path.parts))


def regular_local_file(name):
    path = ROOT / name
    return (path.is_file()
            and not any((ROOT / Path(*PurePosixPath(name).parts[:i])).is_symlink()
                        for i in range(1, len(PurePosixPath(name).parts) + 1)))


def privacy_redactions():
    """Grant narrow exceptions only after checking original and derivative bytes."""
    accepted, seen, errors = set(), set(), []
    for ledger in PRIVACY_LEDGERS:
        try:
            if not regular_local_file(ledger):
                raise ValueError('missing or non-regular ledger')
            data = json.loads((ROOT / ledger).read_text())
            if (not isinstance(data, dict) or data.get('format') != 'eacp.privacy-redactions/1'
                    or data.get('original_commit') != EXECUTION_REFERENCE
                    or not isinstance(data.get('files'), list)):
                raise ValueError('invalid ledger format or execution reference')
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append('invalid privacy ledger ' + ledger + ': ' + str(exc))
            continue
        for entry in data['files']:
            if not isinstance(entry, dict) or not eligible_redaction(entry.get('path'), ledger):
                errors.append('ineligible privacy redaction in ' + ledger)
                continue
            name = entry['path']
            if name in seen:
                errors.append('duplicate privacy redaction: ' + name)
                continue
            seen.add(name)
            if (any(not isinstance(entry.get(key), str) or not SHA256.fullmatch(entry[key])
                    for key in ('original_sha256', 'redacted_sha256'))
                    or not isinstance(entry.get('reason'), str) or not entry['reason'].strip()):
                errors.append('invalid privacy redaction hashes or reason: ' + name)
                continue
            try:
                if not regular_local_file(name):
                    raise ValueError('missing or non-regular derivative')
                mode = git('ls-tree', EXECUTION_REFERENCE, '--', name).split(' ', 1)[0]
                if mode not in {'100644', '100755'}:
                    raise ValueError('original is not a regular Git blob')
                original = hashlib.sha256(git_blob(EXECUTION_REFERENCE, name)).hexdigest()
                current = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                if original != entry['original_sha256']:
                    raise ValueError('original hash mismatch')
                if current != entry['redacted_sha256']:
                    raise ValueError('current derivative hash mismatch')
                if original == current:
                    raise ValueError('redaction entry has unchanged bytes')
            except (OSError, subprocess.CalledProcessError, ValueError) as exc:
                errors.append('invalid privacy redaction ' + name + ': ' + str(exc))
                continue
            accepted.add(name)
    return accepted, errors


def execution_equivalence():
    """Compare runtime and Profile bytes to the candidate that was executed."""
    report = {}
    for label, directory in (('runtime', 'eacp_hardening'), ('profile', 'spec')):
        original = set(git('ls-tree', '-r', '--name-only', EXECUTION_REFERENCE,
                           '--', directory).splitlines())
        current = {path.relative_to(ROOT).as_posix() for path in (ROOT / directory).rglob('*')
                   if (path.is_file() or path.is_symlink())
                   and '__pycache__' not in path.parts and path.suffix != '.pyc'}
        changed = original ^ current
        for name in original & current:
            if not regular_local_file(name) or (ROOT / name).read_bytes() != git_blob(EXECUTION_REFERENCE, name):
                changed.add(name)
        report[label + '_byte_equivalent'] = bool(original) and not changed
        report[label + '_files_compared'] = len(original)
        report[label + '_changed_paths'] = sorted(changed)
    return report


def verify(require_clean=False):
    errors = []
    original, changed, redacted = set(), set(), set()
    head, status = None, None
    equivalence = {'runtime_byte_equivalent': False, 'profile_byte_equivalent': False}
    try:
        if git('rev-parse', 'v1.4.0^{commit}') != BASE:
            errors.append('historical 1.4 tag changed')
        if git('rev-parse', 'v1.3.0^{commit}') != HISTORICAL_1_3:
            errors.append('historical 1.3 tag changed')
        if git('rev-parse', EXECUTION_REFERENCE + '^{commit}') != EXECUTION_REFERENCE:
            errors.append('execution reference changed')
        original = set(git('ls-tree', '-r', '--name-only', BASE).splitlines())
        changed = set(git('diff', '--name-only', BASE, '--').splitlines())
        redacted, ledger_errors = privacy_redactions()
        errors.extend(ledger_errors)
        errors.extend('unapproved historical change: ' + n
                      for n in sorted((original & changed) - ALLOWED - redacted))
        equivalence = execution_equivalence()
        for label in ('runtime', 'profile'):
            if not equivalence[label + '_byte_equivalent']:
                errors.append(label + ' differs from the executed candidate')
        if 'version = "1.5.0rc1"' not in (ROOT / 'pyproject.toml').read_text():
            errors.append('candidate package version mismatch')
        cff = (ROOT / 'CITATION.cff').read_text()
        if 'version: 1.5.0rc1\n' not in cff or any(line.startswith('doi:') for line in cff.splitlines()):
            errors.append('candidate must not borrow an archived version DOI')
        status = git('status', '--short')
        head = git('rev-parse', 'HEAD')
        if require_clean and status:
            errors.append('candidate freeze requires a clean checkout')
    except (OSError, subprocess.CalledProcessError):
        errors.append('required candidate source or full Git history unavailable; no snapshot fallback')
    return {'software': '1.5.0rc1', 'profile': '1.3', 'paper': '1.3', 'protocol': 'operability/1',
            'head': head, 'historical_1_4': BASE, 'working_tree_status': status,
            'execution_reference': EXECUTION_REFERENCE, **equivalence,
            'historical_files_byte_preserved': len(original - changed),
            'historical_files_redacted_derivatives': len(original & changed & redacted),
            'redacted_derivative_files': len(redacted),
            'changed_historical_paths': sorted(original & changed), 'errors': errors,
            'doi': None, 'publication': 'NOT_PUBLISHED', 'new_live_signature': 'NOT_PERFORMED',
            'external_review': 'NOT_ESTABLISHED', 'organizational_pilot': 'NOT_PERFORMED'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    result = verify(args.freeze)
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result['errors']))
