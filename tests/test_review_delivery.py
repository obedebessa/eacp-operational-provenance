import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review_delivery', ROOT / 'scripts/package_review_delivery_v1_5.py')
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)


class ReviewDeliveryTests(unittest.TestCase):
    def test_text_redaction_preserves_result_and_digest_fields(self):
        private = '/Users/' + 'fictional-person/project'
        source = {'path': private + '/results.json', 'sha256': 'a' * 64, 'exit': 0, 'passed': 275}
        result = delivery.project(json.dumps(source).encode(),
                                  {'replacements': [{'from': private, 'to': '/workspace/eacp'}]})
        projected = json.loads(result)
        self.assertEqual(projected['path'], '/workspace/eacp/results.json')
        for key in ('sha256', 'exit', 'passed'):
            self.assertEqual(projected[key], source[key])

    def test_encoded_prefix_and_identity_are_redacted(self):
        source = b'/private/review%20folder/record ReviewerOne otherReviewerOne'
        policy = {'replacements': [{'from': '/private/review folder', 'to': '/workspace'},
                                   {'from': 'ReviewerOne', 'to': 'E1', 'word': True}]}
        self.assertEqual(delivery.project(source, policy), b'/workspace/record E1 otherReviewerOne')

    def test_nontext_crypto_bytes_are_not_modified(self):
        original = b'\x80signed ReviewerOne\xff'
        self.assertEqual(delivery.project(original, {'replacements':
                         [{'from': 'ReviewerOne', 'to': 'E1'}]}), original)

    def test_crypto_envelopes_and_archives_are_protected_before_projection(self):
        self.assertTrue(delivery.protected_evidence('bundle.jsonl', b'{"dsseEnvelope":{}}'))
        self.assertTrue(delivery.protected_evidence('verified.json', b'{"verificationResult":{}}'))
        self.assertTrue(delivery.protected_evidence('signed.stdout.txt', b'{"signatures":[]}'))
        self.assertTrue(delivery.protected_evidence('statement.json', b'{"body":{},"signature":"value"}'))
        self.assertTrue(delivery.protected_evidence('evidence.tar.gz', b'anything'))
        self.assertFalse(delivery.protected_evidence('receipt.json', b'{"command":["tool"]}'))

    def test_empty_replacement_rejected(self):
        with self.assertRaises(ValueError):
            delivery.project(b'text', {'replacements': [{'from': '', 'to': 'x'}]})

    def test_input_zip_members_and_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'input.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('package/summary.txt', 'evidence')
                z.writestr('__MACOSX/._package', 'ignored metadata')
            self.assertEqual(delivery.checked_members(archive), {'summary.txt': b'evidence'})

    def test_traversal_and_symlink_rejected_without_extracting(self):
        with tempfile.TemporaryDirectory() as temporary:
            for label in ('traversal', 'symlink'):
                archive = Path(temporary) / (label + '.zip')
                with zipfile.ZipFile(archive, 'w') as z:
                    info = zipfile.ZipInfo('package/../escape' if label == 'traversal' else 'package/link')
                    if label == 'symlink':
                        info.external_attr = 0o120777 << 16
                    z.writestr(info, 'outside')
                with self.assertRaises(ValueError):
                    delivery.checked_members(archive)
            self.assertFalse((Path(temporary) / 'escape').exists())

    def test_existing_delivery_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'delivery'
            output.mkdir()
            existing = output / 'retained.txt'
            existing.write_text('original')
            with self.assertRaises(ValueError):
                delivery.build(output, output, output, output, output)
            self.assertEqual(existing.read_text(), 'original')
