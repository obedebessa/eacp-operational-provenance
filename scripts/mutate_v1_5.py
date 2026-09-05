#!/usr/bin/env python3
"""Three actual code mutations in disposable copies, with assertion-only kills."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTANTS = [
    ('scope', 'spec/tools/eacp_profile.py',
     'if scope is not None and (key[2], key[3]) != scope:', 'if False:',
     'test_operations.ProfileInvariantTests.test_R03_scope_mutation_sentinel'),
    ('authorization', 'eacp_hardening/common.py',
     'if principal.tenant_id != tenant_id or not principal.roles.intersection(roles):', 'if False:',
     'test_operations.BoundaryTests.test_A02_authorization_mutation_sentinel'),
    ('digest', 'eacp_hardening/integrity.py',
     'if not hmac.compare_digest(digest(material), checkpoint["material_sha256"]):', 'if False:',
     'test_operations.OperationsTests.test_X05_digest_mutation_sentinel'),
]


def run(output):
    output.mkdir(parents=False, exist_ok=False)
    results = []
    for name, path, before, after, test in MUTANTS:
        with tempfile.TemporaryDirectory(prefix='eacp-disposable-mutant-') as d:
            copy = Path(d)
            for directory in ('eacp_hardening', 'spec/tools', 'tests/operability'):
                shutil.copytree(ROOT / directory, copy / directory, ignore=shutil.ignore_patterns('__pycache__'))
            target = copy / path
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError('mutation anchor no longer unique: ' + name)
            # Generated disposable mutant, never edits the working repository.
            target.write_text(original.replace(before, after))
            # Also shadow an already-installed Profile package. Otherwise a
            # wheel in the operator environment could bypass the mutated source.
            shutil.copytree(copy / 'spec/tools', copy / 'eacp_profile')
            command = [sys.executable, '-c',
                       "import sys,unittest;sys.path.insert(0,'tests/operability');"
                       "r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromName(sys.argv[1]));"
                       "sys.exit(not r.wasSuccessful())", test]
            result = subprocess.run(command, cwd=copy, capture_output=True, timeout=30)
            (output / (name + '.stdout')).write_bytes(result.stdout)
            (output / (name + '.stderr')).write_bytes(result.stderr)
            text = result.stderr.decode(errors='replace')
            killed = (result.returncode == 1 and 'AssertionError' in text and 'FAIL:' in text
                      and 'ERROR:' not in text and 'Ran 1 test' in text)
            results.append(dict(mutant=name, target=path, replacement=after, original=before, command=command,
                                source_sha256=hashlib.sha256(original.encode()).hexdigest(),
                                mutation_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                                returncode=result.returncode, status='killed_by_assertion' if killed else 'NOT_KILLED_AS_REQUIRED'))
    report = {'format': 'eacp.actual-mutations/1', 'results': results,
              'scope': 'three specified code mutations only; not exhaustive mutation coverage'}
    (output / 'summary.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return all(r['status'] == 'killed_by_assertion' for r in results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(not run(parser.parse_args().output))
