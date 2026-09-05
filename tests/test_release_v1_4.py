"""Release gates are local integrity checks, not evidence of publication."""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("final_release_verifier", ROOT / "scripts/verify_hardening.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class FinalReleaseGateTests(unittest.TestCase):
    def simulated_git(self, overrides):
        original = verifier.git
        defaults = {("status", "--porcelain"): "", ("cat-file", "-t", "refs/tags/v1.4.0"): "tag",
                    ("rev-parse", "v1.4.0^{commit}"): "fixture", ("rev-parse", "HEAD"): "fixture"}
        defaults.update(overrides)
        return lambda *args: defaults[args] if args in defaults else original(*args)

    def test_dirty_checkout_rejected(self):
        with patch.object(verifier, "git", self.simulated_git({("status", "--porcelain"): " M README.md"})):
            self.assertIn("release checkout must be clean", verifier.release_errors())

    def test_lightweight_tag_rejected(self):
        with patch.object(verifier, "git", self.simulated_git({("cat-file", "-t", "refs/tags/v1.4.0"): "commit"})):
            self.assertIn("v1.4.0 must be an annotated tag", verifier.release_errors())

    def test_wrong_commit_rejected(self):
        with patch.object(verifier, "git", self.simulated_git({("rev-parse", "v1.4.0^{commit}"): "wrong"})):
            self.assertIn("v1.4.0 tag must identify HEAD", verifier.release_errors())

    def test_manifest_failure_rejected(self):
        original = subprocess.run
        def run(command, **kwargs):
            if any("generate_manifest.py" in str(item) for item in command):
                return subprocess.CompletedProcess(command, 1, "", "fixture rejection")
            return original(command, **kwargs)
        with patch.object(verifier, "git", self.simulated_git({})), patch.object(verifier.subprocess, "run", side_effect=run):
            self.assertIn("final release manifest mismatch or missing", verifier.release_errors())

    def test_runtime_change_rejected(self):
        original = Path.read_bytes
        def read(path):
            data = original(path)
            return data + b"\n# synthetic mutation\n" if path == ROOT / "eacp_hardening/common.py" else data
        with patch.object(verifier, "git", self.simulated_git({})), patch.object(Path, "read_bytes", read):
            self.assertIn("implementation changed beyond version metadata: eacp_hardening/common.py",
                          verifier.release_errors())
