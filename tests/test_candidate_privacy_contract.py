"""Privacy exceptions must bind both revisions without bypassing provenance.

All mutations use a tiny disposable Git repository with synthetic content.
"""
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('candidate_privacy_verifier',
                                            ROOT / 'scripts/verify_candidate_v1_5.py')
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CandidatePrivacyContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='eacp-privacy-gate-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'source'
        self.root.mkdir()
        self._git('init', '--quiet')
        self._git('config', 'user.name', 'EACP test fixture')
        self._git('config', 'user.email', 'fixture@example.invalid')
        self._git('config', 'commit.gpgsign', 'false')
        self._git('config', 'core.autocrlf', 'false')
        self.path = 'results/hardening-v1.4/reproduction/summary.json'
        self.original = b'{"directory":"/private/local-workspace", "passed":7}\n'
        self.derivative = b'{"directory":"/workspace/eacp", "passed":7}\n'
        files = {
            self.path: self.original,
            'pyproject.toml': b'version = "1.5.0rc1"\n',
            'CITATION.cff': b'version: 1.5.0rc1\n',
            'eacp_hardening/__init__.py': b'__version__ = "1.5.0rc1"\n',
            'spec/tools/eacp_profile.py': b'PROFILE = "1.3"\n',
            'spec/schema/core.json': b'{"type":"object"}\n',
        }
        for name, data in files.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self._git('add', '.')
        self._git('commit', '--quiet', '-m', 'Original execution fixture')
        self.reference = self._git('rev-parse', 'HEAD')
        self._git('tag', 'v1.3.0')
        self._git('tag', 'v1.4.0')
        for name, value in (('ROOT', self.root), ('BASE', self.reference),
                            ('HISTORICAL_1_3', self.reference),
                            ('EXECUTION_REFERENCE', self.reference)):
            replacement = patch.object(verifier, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.entry = {'path': self.path, 'original_sha256': digest(self.original),
                      'redacted_sha256': digest(self.derivative),
                      'reason': 'Replace a private path with a portable placeholder.'}
        self.ledger = {'format': 'eacp.privacy-redactions/1',
                       'original_commit': self.reference, 'files': [self.entry]}
        (self.root / self.path).write_bytes(self.derivative)
        self._write_ledger()
        pdf_ledger = self.root / verifier.PRIVACY_LEDGERS[1]
        pdf_ledger.write_text(json.dumps({**self.ledger, 'files': []}))

    def _git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root,
                                       stderr=subprocess.PIPE).decode().strip()

    def _write_ledger(self):
        target = self.root / verifier.PRIVACY_LEDGERS[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.ledger))

    def _assert_rejected(self, message):
        accepted, errors = verifier.privacy_redactions()
        self.assertNotIn(self.path, accepted)
        self.assertTrue(any(message in error for error in errors), errors)

    def test_valid_derivative_reports_separate_preservation_and_equivalence(self):
        result = verifier.verify()
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['redacted_derivative_files'], 1)
        self.assertEqual(result['historical_files_redacted_derivatives'], 1)
        self.assertEqual(result['historical_files_byte_preserved'], 5)
        self.assertEqual(result['execution_reference'], self.reference)
        self.assertTrue(result['runtime_byte_equivalent'])
        self.assertTrue(result['profile_byte_equivalent'])

    def test_missing_ledger_cannot_allow_historical_edits(self):
        (self.root / verifier.PRIVACY_LEDGERS[0]).unlink()
        self._assert_rejected('missing')
        self.assertIn('unapproved historical change: ' + self.path, verifier.verify()['errors'])

    def test_changed_current_bytes_are_rejected(self):
        (self.root / self.path).write_bytes(self.derivative.replace(b'7', b'8'))
        self._assert_rejected('current derivative hash mismatch')

    def test_false_original_hash_is_rejected(self):
        self.entry['original_sha256'] = '0' * 64
        self._write_ledger()
        self._assert_rejected('original hash mismatch')

    def test_invalid_hash_syntax_is_rejected(self):
        self.entry['redacted_sha256'] = 'not-a-sha256'
        self._write_ledger()
        self._assert_rejected('invalid privacy redaction hashes')

    def test_path_traversal_and_noncanonical_paths_are_rejected(self):
        for name in ('../outside.json', '/tmp/outside.json',
                     'results/hardening-v1.4/../outside.json',
                     'results//hardening-v1.4/reproduction/summary.json',
                     'results/hardening-v1.4/./reproduction/summary.json',
                     'results\\hardening-v1.4\\summary.json'):
            with self.subTest(name=name):
                self.entry['path'] = name
                self._write_ledger()
                self._assert_rejected('ineligible')

    def test_duplicate_entries_fail_the_gate(self):
        self.ledger['files'].append(dict(self.entry))
        self._write_ledger()
        self.assertTrue(any('duplicate' in error for error in verifier.verify()['errors']))

    def test_runtime_and_schema_cannot_become_redaction_exceptions(self):
        for name in ('eacp_hardening/__init__.py', 'spec/schema/core.json'):
            with self.subTest(name=name):
                original = (self.root / name).read_bytes()
                changed = original + b'\n'
                (self.root / name).write_bytes(changed)
                self.ledger['files'] = [{**self.entry, 'path': name,
                                        'original_sha256': digest(original),
                                        'redacted_sha256': digest(changed)}]
                self._write_ledger()
                self._assert_rejected('ineligible')
                result = verifier.verify()
                label = 'runtime' if name.startswith('eacp_hardening/') else 'profile'
                self.assertFalse(result[label + '_byte_equivalent'])
                self.assertIn(label + ' differs from the executed candidate', result['errors'])
                (self.root / name).write_bytes(original)

    def test_archives_attestation_and_verification_inputs_are_ineligible(self):
        for name in ('results/hardening-v1.4/archive.tar.gz',
                     'results/hardening-v1.4/attestation-captured/payload.json',
                     'results/hardening-v1.4/artifact-123/binding.json',
                     'results/hardening-v1.4/verification-01/inputs/binding.json',
                     'results/hardening-v1.4/bundle.jsonl',
                     'paper/unapproved.pdf'):
            with self.subTest(name=name):
                self.entry['path'] = name
                self._write_ledger()
                self._assert_rejected('ineligible')

    def test_alternate_original_commit_is_rejected(self):
        self.ledger['original_commit'] = 'f' * 40
        self._write_ledger()
        self._assert_rejected('execution reference')

    def test_symlink_derivative_is_rejected(self):
        target = self.root / self.path
        external = self.root.parent / 'external.json'
        external.write_bytes(self.derivative)
        target.unlink()
        target.symlink_to(external)
        self._assert_rejected('non-regular derivative')

    def test_freeze_still_requires_a_clean_checkout(self):
        self.assertIn('candidate freeze requires a clean checkout', verifier.verify(True)['errors'])
        self._git('add', '.')
        self._git('commit', '--quiet', '-m', 'Privacy derivative fixture')
        self.assertEqual(verifier.verify(True)['errors'], [])

    def test_historical_tag_drift_is_rejected(self):
        self._git('add', '.')
        self._git('commit', '--quiet', '-m', 'Privacy derivative fixture')
        for tag, label in (('v1.3.0', '1.3'), ('v1.4.0', '1.4')):
            with self.subTest(tag=tag):
                self._git('tag', '-f', tag, 'HEAD')
                self.assertIn('historical ' + label + ' tag changed', verifier.verify()['errors'])
                self._git('tag', '-f', tag, self.reference)

    def test_no_git_history_does_not_fall_back_to_a_snapshot(self):
        empty = self.root.parent / 'without-history'
        empty.mkdir()
        with patch.object(verifier, 'ROOT', empty):
            result = verifier.verify()
        self.assertTrue(any('no snapshot fallback' in error for error in result['errors']))
        self.assertFalse(result['runtime_byte_equivalent'])
        self.assertFalse(result['profile_byte_equivalent'])


if __name__ == '__main__':
    unittest.main()
