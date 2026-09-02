from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "normalize_attestation_bundle_v1_3.py"
)
SPEC = importlib.util.spec_from_file_location("normalize_attestation_bundle_v1_3", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AttestationBundleFilenameTests(unittest.TestCase):
    def test_colon_form_is_renamed_without_changing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = "a" * 64
            source = root / f"sha256:{digest}.jsonl"
            payload = b'{"verificationMaterial":{}}\n'
            source.write_bytes(payload)

            observed = MODULE.normalize_bundle(root)

            self.assertEqual(observed.name, f"sha256-{digest}.jsonl")
            self.assertEqual(observed.read_bytes(), payload)
            self.assertFalse(source.exists())

    def test_hyphen_form_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"sha256-{'b' * 64}.jsonl"
            path.write_bytes(b"bundle\n")
            self.assertEqual(MODULE.normalize_bundle(root), path)

    def test_ambiguous_or_malformed_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / f"sha256-{'c' * 64}.jsonl").write_bytes(b"one")
            (root / f"sha256:{'d' * 64}.jsonl").write_bytes(b"two")
            with self.assertRaises(MODULE.BundleNameError):
                MODULE.normalize_bundle(root)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sha256-not-a-digest.jsonl").write_bytes(b"bad")
            with self.assertRaises(MODULE.BundleNameError):
                MODULE.normalize_bundle(root)


if __name__ == "__main__":
    unittest.main()
