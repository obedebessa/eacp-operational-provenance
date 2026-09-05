#!/usr/bin/env python3
"""Candidate identity/history checks; never declares publication or external review."""
import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = '5067a26ad008db3bc4b4a5554e52c60239142735'
ALLOWED = {'CITATION.cff', 'README.md', 'pyproject.toml', 'tests/test_repository_contract.py',
           '.github/workflows/reproduce-small.yml', 'eacp_hardening/__init__.py',
           'eacp_hardening/common.py', 'eacp_hardening/store.py', 'eacp_hardening/cli.py'}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def verify(require_clean=False):
    errors = []
    if git('rev-parse', 'v1.4.0^{commit}') != BASE:
        errors.append('historical 1.4 tag changed')
    if git('rev-parse', 'v1.3.0^{commit}') != '537799bd2b292ce6e78004de22f4ab6df1b4feda':
        errors.append('historical 1.3 tag changed')
    original = set(git('ls-tree', '-r', '--name-only', BASE).splitlines())
    changed = set(git('diff', '--name-only', BASE, '--').splitlines())
    errors.extend('unapproved historical change: ' + n for n in sorted((original & changed) - ALLOWED))
    if 'version = "1.5.0rc1"' not in (ROOT / 'pyproject.toml').read_text():
        errors.append('candidate package version mismatch')
    cff = (ROOT / 'CITATION.cff').read_text()
    if 'version: 1.5.0rc1\n' not in cff or any(line.startswith('doi:') for line in cff.splitlines()):
        errors.append('candidate must not borrow an archived version DOI')
    status = git('status', '--short')
    if require_clean and status:
        errors.append('candidate freeze requires a clean checkout')
    return {'software': '1.5.0rc1', 'profile': '1.3', 'paper': '1.3', 'protocol': 'operability/1',
            'head': git('rev-parse', 'HEAD'), 'historical_1_4': BASE, 'working_tree_status': status,
            'historical_files_byte_preserved': len(original - changed),
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
