from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RepositoryContractTests(unittest.TestCase):
    def test_versions_and_primary_artifact_citation(self) -> None:
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "1.3.0"', metadata)

        cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        self.assertIn("type: software", cff)
        self.assertIn("version: 1.3.0", cff)
        self.assertIn('doi: "10.5281/zenodo.22283852"', cff)
        self.assertIn(
            'repository-code: "https://github.com/obedebessa/eacp-operational-provenance"',
            cff,
        )
        self.assertIn("identifies the artifact, not the accompanying", cff)
        self.assertIn("article.", cff)
        self.assertNotIn("email:", cff)
        self.assertIn("preferred-citation:", cff)
        self.assertIn('doi: "10.5281/zenodo.22283868"', cff)
        self.assertIn('doi: "10.5281/zenodo.22017662"', cff)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("10.5281/zenodo.22283852", readme)
        self.assertIn("10.5281/zenodo.21817376", readme)
        self.assertIn("10.5281/zenodo.22283868", readme)
        self.assertIn("10.5281/zenodo.22017661", readme)

    def test_scope_caveats_are_explicit(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("has **not undergone peer review**", readme)
        self.assertIn("single local kind control plane", readme)
        self.assertIn("not functionally equivalent", readme)
        self.assertIn("does not present a feature-equivalence", readme)

    def test_mixed_license_map(self) -> None:
        self.assertIn(
            "Apache License",
            (ROOT / "LICENSE").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "Attribution 4.0 International",
            (ROOT / "LICENSES/CC-BY-4.0.txt").read_text(encoding="utf-8"),
        )
        license_map = (ROOT / "LICENSES/README.md").read_text(encoding="utf-8")
        self.assertIn("Data under data/", license_map)
        self.assertIn("paper/EACP_preprint.pdf", license_map)
        self.assertIn("paper/Cross_Plane_Operational_Provenance_Preprint_v1.3.0.pdf", license_map)
        paper_notice = (ROOT / "paper/README.md").read_text(encoding="utf-8")
        paper_notice_normalized = " ".join(paper_notice.split())
        self.assertIn("all-rights-reserved", paper_notice_normalized)
        self.assertIn("Creative Commons Attribution 4.0 International", paper_notice_normalized)
        self.assertIn("not the preprint DOI", paper_notice_normalized)

    def test_checksum_bound_evidence_is_tracked(self) -> None:
        if not (ROOT / ".git").exists():
            self.skipTest("Git index is unavailable in an exported archive")
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
        tracked = {
            name.decode("utf-8") for name in result.stdout.split(b"\0") if name
        }
        evidence_root = ROOT / "experiments/github_actions/results/reference"
        for manifest in sorted(evidence_root.rglob("*SHA256SUMS")):
            if manifest.name not in {"REFERENCE_SHA256SUMS", "OUTCOME_SHA256SUMS"}:
                continue
            with self.subTest(manifest=manifest.relative_to(ROOT)):
                self.assertIn(manifest.relative_to(ROOT).as_posix(), tracked)
                for raw in manifest.read_text(encoding="utf-8").splitlines():
                    if not raw.strip():
                        continue
                    _, raw_name = raw.split(maxsplit=1)
                    target = (manifest.parent / raw_name.strip().lstrip("*")).resolve()
                    self.assertIn(target.relative_to(ROOT).as_posix(), tracked)

    def test_sensitive_runtime_artifacts_are_ignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in ("*kubeconfig*", "*.key", "audit.log", "raw-audit*.jsonl", "*.db-wal"):
            self.assertIn(pattern, gitignore)

    def test_kubernetes_public_subset_and_checksums(self) -> None:
        run = ROOT / "data/kubernetes/20260806T031453Z"
        expected = {
            "analysis/public_filtered_audit.jsonl",
            "analysis/normalized_evidence.csv",
            "analysis/summary.json",
            "operations.csv",
            "policy-denials.txt",
            "kubernetes-version.json",
            "nodes.txt",
            "environment.txt",
        }
        actual = {
            path.relative_to(run).as_posix()
            for path in run.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, expected)
        self.assertEqual(
            sha256(run / "analysis/public_filtered_audit.jsonl"),
            "6aa39ee1cf8d3cbf58cb683ed6c7977ce851ab442c7057b7a85e974cb5400e01",
        )
        self.assertEqual(
            sha256(run / "analysis/normalized_evidence.csv"),
            "ff03698e83a764651aec912fc806a50464374567ae862936fe32251523d796b5",
        )

    def test_collector_claim_is_post_export_preservation(self) -> None:
        summary = json.loads(
            (ROOT / "data/comparison/20260806T032418Z/summary.json").read_text(
                encoding="utf-8"
            )
        )
        collector = summary["solutions"]["opentelemetry"]
        self.assertFalse(collector["collector_natively_maps_eacp_13_field_projection"])
        validation = summary["validation"]["post_export_canonical_projection_preservation"]
        self.assertIn("external validator", validation["mapping_performed_by"])
        equality = validation["field_value_equality"]
        self.assertEqual(equality["compared_field_values"], 4862)
        self.assertEqual(equality["correct_field_values"], 4862)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("preserved the raw Kubernetes audit lines as exported log bodies", readme)
        self.assertIn("external post-export EACP validator", readme)
        self.assertIn("does **not** natively generate EACP’s 13 fields", readme)

    def test_fixed_component_identifiers(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
            readme,
        )
        self.assertIn(
            "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
            readme,
        )
        self.assertTrue(
            (ROOT / "experiments/comparison/opentelemetry/collector-config.yaml").is_file()
        )
        self.assertFalse(
            (ROOT / "experiments/comparison/opentelemetry/otel-config.yaml").exists()
        )

    def test_repository_verifier(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/verify_repository.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_release_profile_verifier(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/verify_repository.py"), "--release"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
