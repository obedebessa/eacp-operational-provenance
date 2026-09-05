"""Review transfer regressions using tiny disposable Git repositories only.

The fixture verifier deliberately checks only its fixture. The production
manifest generator is copied verbatim, and bundle creation/fresh clones use real
Git. No remote repository, account, network access, or large project clone is used.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("review_package_under_test", ROOT / "scripts/package_hardening_review.py")
assert SPEC is not None and SPEC.loader is not None
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class ReviewPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="eacp-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "source"
        self.repo.mkdir()
        self._git("init", "--quiet")
        self._git("symbolic-ref", "HEAD", "refs/heads/eacp-v1.4-hardening")
        self._git("config", "user.name", "EACP transfer test fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        self._git("config", "commit.gpgsign", "false")
        self._git("config", "core.autocrlf", "false")
        (self.repo / "scripts").mkdir()
        (self.repo / "docs/v1.4").mkdir(parents=True)
        (self.repo / "docs/v1.4/REVIEWER_PACKET.md").write_text(
            "# Synthetic transfer fixture\nNo external review or publication.\n", encoding="utf-8")
        (self.repo / "scripts/generate_manifest.py").write_bytes((ROOT / "scripts/generate_manifest.py").read_bytes())
        (self.repo / "scripts/verify_hardening.py").write_text(
            "from pathlib import Path\n"
            "import sys\n"
            "expected = Path(__file__).resolve().parents[1] / 'candidate.txt'\n"
            "sys.exit(0 if expected.read_text() == 'candidate-fixture\\n' else 1)\n",
            encoding="utf-8")
        (self.repo / "candidate.txt").write_text("historical-fixture\n", encoding="utf-8")
        self._git("add", ".")
        self._git("commit", "--quiet", "-m", "Historical transfer fixture")
        self.historical = self._git("rev-parse", "HEAD")
        self._git("tag", "v1.3.0")
        (self.repo / "candidate.txt").write_text("candidate-fixture\n", encoding="utf-8")
        self._git("add", "candidate.txt")
        subprocess.run([sys.executable, "-B", "scripts/generate_manifest.py", "--manifest",
                        "MANIFEST-v1.4.0-rc1.sha256", "--write"], cwd=self.repo,
                       capture_output=True, check=True, timeout=20)
        self._git("add", "MANIFEST-v1.4.0-rc1.sha256")
        self._git("commit", "--quiet", "-m", "Candidate transfer fixture")
        self.source = self._git("rev-parse", "HEAD")
        self.destination = self.base / "EACP_v1.4.0-rc1_Review_Package"
        self.archive = self.base / "EACP_v1.4.0-rc1_Review_Package.zip"
        self.sidecar = self.base / "EACP_v1.4.0-rc1_Review_Package.zip.sha256"
        self.root_patch = patch.object(packager, "ROOT", self.repo)
        self.history_patch = patch.object(packager, "HISTORICAL_COMMIT", self.historical)
        self.root_patch.start()
        self.history_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.history_patch.stop)

    def _git(self, *args: str, cwd: Path | None = None) -> str:
        return subprocess.run(["git", *args], cwd=cwd or self.repo, text=True,
                              capture_output=True, check=True, timeout=20).stdout.strip()

    def test_shallow_repository_rejects_before_historical_lookup_or_destination_creation(self) -> None:
        shallow = self.base / "shallow"
        self._git("clone", "--quiet", "--depth", "1", "--no-tags", self.repo.as_uri(), str(shallow))
        self.assertEqual(self._git("rev-parse", "--is-shallow-repository", cwd=shallow), "true")
        self.assertEqual(self._git("tag", "--list", cwd=shallow), "")
        with patch.object(packager, "ROOT", shallow), self.assertRaisesRegex(ValueError, "shallow"):
            packager.package(self.destination)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.sidecar.exists())

    def test_full_dotted_version_archive_contains_fresh_clone_verified_exact_source(self) -> None:
        result = packager.package(self.destination)
        self.assertEqual(Path(result["archive"]), self.archive)
        self.assertTrue(self.archive.is_file())
        self.assertFalse((self.base / "EACP_v1.4.zip").exists())
        metadata = json.loads((self.destination / "PACKAGE.json").read_text())
        self.assertEqual(metadata["source_commit"], self.source)
        self.assertEqual(metadata["historical_commit"], self.historical)
        self.assertTrue(metadata["local_transfer_clone_verified"])
        self.assertFalse(metadata["published"])
        self.assertFalse(metadata["external_reproduction_claimed"])
        with zipfile.ZipFile(self.archive) as bundle_zip:
            self.assertIsNone(bundle_zip.testzip())
            self.assertEqual({name.split("/", 1)[0] for name in bundle_zip.namelist()}, {self.destination.name})
            self.assertEqual(json.loads(bundle_zip.read(self.destination.name + "/PACKAGE.json")), metadata)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(result["archive_sha256"], digest)
        self.assertEqual(self.sidecar.read_text(), f"{digest}  {self.archive.name}\n")
        clone = self.base / "recipient"
        self._git("clone", "--quiet", "--branch", "eacp-v1.4-hardening",
                  str(self.destination / "EACP_1.4.0-rc1_source.bundle"), str(clone))
        self.assertEqual(self._git("rev-parse", "HEAD", cwd=clone), self.source)
        self.assertEqual(self._git("rev-parse", "v1.3.0^{commit}", cwd=clone), self.historical)
        self.assertEqual(self._git("rev-parse", "--is-shallow-repository", cwd=clone), "false")

    def test_existing_destination_archive_or_checksum_is_never_overwritten(self) -> None:
        for kind in ("directory", "archive", "checksum"):
            with self.subTest(kind=kind):
                parent = self.base / kind
                parent.mkdir()
                destination = parent / self.destination.name
                archive = parent / self.archive.name
                sidecar = parent / self.sidecar.name
                if kind == "directory":
                    destination.mkdir()
                    existing = destination / "keep.txt"
                else:
                    existing = archive if kind == "archive" else sidecar
                existing.write_bytes(b"existing-user-output-must-survive")
                before = sorted(str(path.relative_to(parent)) for path in parent.rglob("*"))
                with self.assertRaisesRegex(ValueError, "already exist"):
                    packager.package(destination)
                self.assertEqual(existing.read_bytes(), b"existing-user-output-must-survive")
                self.assertEqual(sorted(str(path.relative_to(parent)) for path in parent.rglob("*")), before)

    def test_dirty_source_is_rejected_without_publishing_outputs(self) -> None:
        (self.repo / "candidate.txt").write_text("uncommitted-change\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "clean"):
            packager.package(self.destination)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.sidecar.exists())

    def test_fresh_clone_manifest_failure_cannot_publish_an_archive(self) -> None:
        (self.repo / "MANIFEST-v1.4.0-rc1.sha256").write_text("0" * 64 + "  candidate.txt\n", encoding="utf-8")
        self._git("add", "MANIFEST-v1.4.0-rc1.sha256")
        self._git("commit", "--quiet", "-m", "Deliberately invalid fixture manifest")
        with self.assertRaises(subprocess.CalledProcessError):
            packager.package(self.destination)
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.sidecar.exists())
        self.assertFalse((self.destination / "PACKAGE.json").exists())


if __name__ == "__main__":
    unittest.main()
