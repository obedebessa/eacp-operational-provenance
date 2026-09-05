#!/usr/bin/env python3
"""Read-only code inventory and bounded synthetic before/after boundary probes."""
import hashlib
import importlib.metadata
import json
import platform
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eacp_hardening.common import HardeningError, strict_json
from eacp_hardening.store import EvidenceStore


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def inventory():
    names = git('ls-files').splitlines()
    hashes = {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
              for n in names if (ROOT / n).is_file()}
    probes = {}
    try:
        strict_json('[' * 200 + '0' + ']' * 200)
        probes['json_depth_200_rejected'] = False
    except HardeningError:
        probes['json_depth_200_rejected'] = True
    with tempfile.TemporaryDirectory(prefix='eacp-boundary-probe-') as temp:
        target = Path(temp) / 'loose.sqlite'
        target.touch(mode=0o600)
        target.chmod(0o666)
        try:
            with EvidenceStore(target, b'1' * 32):
                probes['world_readable_database_rejected'] = False
        except HardeningError:
            probes['world_readable_database_rejected'] = True
        target.chmod(0o600)
        link = Path(temp) / 'link.sqlite'
        link.symlink_to(target)
        try:
            with EvidenceStore(link, b'1' * 32):
                probes['symlink_database_rejected'] = False
        except (HardeningError, OSError):
            probes['symlink_database_rejected'] = True
    return {'format': 'eacp.upgrade-inventory/1', 'head': git('rev-parse', 'HEAD'),
            'status': git('status', '--short'), 'reviewed_commit': git('rev-parse', 'ecfd42d4f54d2d91d18fcdddf676d822001b79f9'),
            'frozen_1_4': git('rev-parse', 'v1.4.0^{commit}'),
            'changes_since_review': git('log', '--oneline', 'ecfd42d..HEAD').splitlines(),
            'files_sha256': hashes, 'python': sys.version, 'platform': platform.platform(),
            'sqlite': sqlite3.sqlite_version,
            'installed_distributions': sorted((d.metadata['Name'], d.version) for d in importlib.metadata.distributions()),
            'cli_help': subprocess.check_output([sys.executable, '-m', 'eacp_hardening', '--help'], cwd=ROOT).decode(),
            'boundary_probes': probes, 'probe_scope': 'isolated synthetic files; no customer data or remote mutations'}


if __name__ == '__main__':
    print(json.dumps(inventory(), indent=2, sort_keys=True))
