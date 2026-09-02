import json
import tempfile
import unittest
from pathlib import Path

from experiments.github_actions.resolve_kubernetes_target import (
    TARGETS,
    TargetError,
    load_manifest,
    resolve,
    select_version,
    write_github_env,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "kubernetes_targets_v1.3.json"


class TargetResolutionTests(unittest.TestCase):
    def test_manifest_has_exact_digest_pinned_target_set(self):
        manifest = load_manifest(MANIFEST)
        self.assertEqual(set(manifest["targets"]), TARGETS)

    def test_evidence_tags_resolve_exact_versions(self):
        manifest = load_manifest(MANIFEST)
        for version in sorted(TARGETS):
            for replicate in range(1, 4):
                with self.subTest(version=version, replicate=replicate):
                    values = resolve(
                        manifest,
                        event="push",
                        ref_type="tag",
                        ref_name=(
                            f"eacp-v1.3-evidence/k8s-{version}/run-{replicate:02d}"
                        ),
                        requested="",
                    )
                    self.assertEqual(values["KUBERNETES_PROFILE"], version)
                    self.assertIn(f"node:{version}@sha256:", values["KIND_NODE_IMAGE"])

    def test_manual_dispatch_is_allowlisted(self):
        self.assertEqual(
            select_version(
                event="workflow_dispatch",
                ref_type="branch",
                ref_name="eacp-v1.3-candidate",
                requested="v1.35.5",
            ),
            "v1.35.5",
        )
        with self.assertRaises(TargetError):
            select_version(
                event="workflow_dispatch",
                ref_type="branch",
                ref_name="eacp-v1.3-candidate",
                requested="latest",
            )

    def test_malformed_or_unapproved_ref_fails_closed(self):
        for ref_type, ref_name in (
            ("tag", "eacp-v1.3-evidence/k8s-v1.36.1/not-a-run"),
            ("tag", "eacp-v1.3-evidence/k8s-v1.36.1/run-04"),
            ("tag", "eacp-v1.3-evidence/k8s-v1.37.0/run-01"),
            ("branch", "eacp-v1.3-candidate"),
            ("branch", "main"),
        ):
            with self.subTest(ref=ref_name), self.assertRaises(TargetError):
                select_version(
                    event="push",
                    ref_type=ref_type,
                    ref_name=ref_name,
                    requested="",
                )

    def test_github_environment_output_is_exact(self):
        manifest = load_manifest(MANIFEST)
        values = resolve(
            manifest,
            event="push",
            ref_type="tag",
            ref_name="eacp-v1.3-evidence/k8s-v1.36.1/run-03",
            requested="",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github.env"
            write_github_env(output, values)
            parsed = dict(
                line.split("=", 1)
                for line in output.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(parsed, values)
        self.assertEqual(parsed["KUBERNETES_PROFILE"], "v1.36.1")

    def test_tampered_manifest_is_rejected(self):
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        value["targets"]["v1.34.8"]["node_image"] = "kindest/node:latest"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "targets.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(TargetError):
                load_manifest(path)


if __name__ == "__main__":
    unittest.main()
