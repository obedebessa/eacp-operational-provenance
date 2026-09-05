#!/usr/bin/env python3
"""Inventory actual wheel, RECORD hashes, source equivalence and narrow canaries.

Not a comprehensive secret/vulnerability scanner. Never imports archive code.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {'github_token': rb'ghp_[A-Za-z0-9]{36}', 'aws_access_key': rb'AKIA[A-Z0-9]{16}',
            'private_key_pem': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'}


def audit(path):
    errors, files, signals = [], {}, []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any(Path(n).is_absolute() or '..' in Path(n).parts for n in names):
            raise ValueError('ambiguous or unsafe wheel membership')
        if sum(i.file_size for i in archive.infolist()) > 16 * 1024 * 1024:
            raise ValueError('wheel resource limit exceeded')
        if archive.testzip() is not None:
            errors.append('ZIP CRC failure')
        record = next(n for n in names if n.endswith('.dist-info/RECORD'))
        rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
        if {r[0] for r in rows} != set(names) or len(rows) != len(names):
            errors.append('wheel RECORD membership mismatch')
        for name, expected, length in rows:
            data = archive.read(name)
            files[name] = hashlib.sha256(data).hexdigest()
            if name != record:
                actual = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
                if expected != actual or int(length) != len(data):
                    errors.append('wheel RECORD hash/size mismatch: ' + name)
            if name.startswith('eacp_hardening/') and name.endswith('.py'):
                if not (ROOT / name).is_file() or (ROOT / name).read_bytes() != data:
                    errors.append('runtime wheel/source mismatch: ' + name)
            for label, pattern in PATTERNS.items():
                if re.search(pattern, data):
                    signals.append({'file': name, 'kind': label, 'value': 'suppressed'})
        source_profile = ROOT / 'spec/tools/eacp_profile.py'
        if archive.read('eacp_profile/eacp_profile.py') != source_profile.read_bytes():
            errors.append('installed Profile differs from frozen reference bytes')
        expected_runtime = {'eacp_hardening/' + p.name for p in (ROOT / 'eacp_hardening').glob('*.py')}
        actual_runtime = {n for n in names if n.startswith('eacp_hardening/') and n.endswith('.py')}
        if expected_runtime != actual_runtime:
            errors.append('runtime module set incomplete')
    return {'format': 'eacp.distribution-audit/1', 'wheel_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'files': files, 'errors': errors, 'narrow_secret_signals': signals,
            'scope': 'actual project wheel only; three token/PEM patterns, not exhaustive secret detection',
            'licensing': 'runtime Apache-2.0; paper/data not in wheel; full repository is file-scoped',
            'external_human_review': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('wheel', type=Path)
    report = audit(p.parse_args().wheel)
    print(json.dumps(report, indent=2))
    raise SystemExit(bool(report['errors'] or report['narrow_secret_signals']))
