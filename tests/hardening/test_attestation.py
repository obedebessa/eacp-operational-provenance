"""Policy and workflow regressions; mocked positive output is NOT a live attestation."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from eacp_hardening.attestation import (
    ARCHIVE_NAME, PREDICATE, WORKFLOW, AttestationPolicy,
    classify_stages, validate_binding, verify_archive,
)
from eacp_hardening.common import HardeningError

ROOT = Path(__file__).resolve().parents[2]
POLICY = AttestationPolicy("obedebessa/eacp-operational-provenance", "a" * 40,
                           "refs/heads/main", 12345, 1)


def fixture(digest):
    return [{"verificationResult": {
        "signature": {"certificate": {
            "issuer": "https://token.actions.githubusercontent.com",
            "subjectAlternativeName": POLICY.signer_uri,
            "buildSignerURI": POLICY.signer_uri, "buildSignerDigest": POLICY.source_sha,
            "sourceRepositoryURI": POLICY.repository_uri,
            "sourceRepositoryDigest": POLICY.source_sha, "sourceRepositoryRef": POLICY.source_ref,
            "buildConfigURI": POLICY.signer_uri, "buildConfigDigest": POLICY.source_sha,
            "buildTrigger": "workflow_dispatch", "runInvocationURI": POLICY.invocation_uri,
            "runnerEnvironment": "github-hosted", "sourceRepositoryVisibilityAtSigning": "public",
        }},
        "verifiedTimestamps": [{"type": "Tlog", "timestamp": "2026-09-04T00:00:00Z"}],
        "statement": {
            "_type": "https://in-toto.io/Statement/v1", "predicateType": PREDICATE,
            "subject": [{"name": ARCHIVE_NAME, "digest": {"sha256": digest}}],
            "predicate": {"runDetails": {
                "builder": {"id": POLICY.signer_uri},
                "metadata": {"invocationId": POLICY.invocation_uri},
            }},
        },
    }}]


class AttestationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.archive = root / ARCHIVE_NAME
        self.archive.write_bytes(b"synthetic archive fixture, not a signed artifact")
        self.bundle = root / "bundle.jsonl"
        self.bundle.write_text("fixture only\n")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.verified_fixture = fixture(self.digest)

    def _verify(self, value=None, returncode=0):
        output = self.verified_fixture if value is None else value
        completed = subprocess.CompletedProcess([], returncode, json.dumps(output), "")
        with patch("eacp_hardening.attestation.subprocess.run", return_value=completed) as run:
            result = verify_archive(self.archive, self.bundle, POLICY)
        return result, run.call_args

    def test_fresh_verifier_command_enforces_full_identity(self):
        result, call = self._verify()
        command = call.args[0]
        self.assertEqual(command[:3], ["gh", "attestation", "verify"])
        for flag, expected in {
            "--repo": POLICY.repository, "--source-digest": POLICY.source_sha,
            "--signer-digest": POLICY.source_sha, "--source-ref": POLICY.source_ref,
            "--cert-identity": POLICY.signer_uri, "--predicate-type": PREDICATE,
            "--bundle": str(self.bundle.resolve()),
        }.items():
            self.assertEqual(command[command.index(flag) + 1], expected)
        self.assertIn("--deny-self-hosted-runners", command)
        self.assertNotIn("--signer-workflow", command)
        self.assertNotIn("--signer-repo", command)
        self.assertNotIn("--cert-identity-regex", command)
        self.assertFalse(call.kwargs.get("shell", False))
        self.assertFalse(result["upstream_event_truth_verified"])

    @unittest.skipUnless(shutil.which("gh"), "GitHub CLI unavailable; real offline signature check not executed")
    def test_real_cli_accepts_production_flag_set_against_historical_bundle_offline(self):
        # Exercise the actual production command flags. The values are changed
        # only to match frozen v1.3 evidence; this is NOT a new v1.4 attestation.
        root = ROOT / "experiments/github_actions/results/reference/cross-version-confirmatory-cohort-v1.3/run-33690440169"
        archive = root / "downloaded-artifact/eacp-cross-plane-v1.3-33690440169-1.tar.gz"
        bundle = root / "attestation/sha256-26b609cdec31f26aec7f721114274794940d3e1fcb76665c9f3cd1ebb59dda3b.jsonl"
        trusted_root = root / "attestation/trusted_root.jsonl"
        if not all(path.is_file() for path in (archive, bundle, trusted_root)):
            self.skipTest("Historical archive/bundle/captured trust root unavailable; offline signature check not executed")
        _, call = self._verify()
        command = list(call.args[0])
        command[3] = str(archive)
        historical_ref = "refs/tags/eacp-v1.3-evidence/k8s-v1.35.5/run-06"
        historical_sha = "4cbf7d2fa0bb44585d258a3f37ce0c0d39ddea43"
        historical_signer = (f"https://github.com/{POLICY.repository}/.github/workflows/"
                             f"eacp-cross-plane-v1.3.yml@{historical_ref}")
        for flag, value in {
            "--bundle": str(bundle), "--source-digest": historical_sha,
            "--signer-digest": historical_sha, "--source-ref": historical_ref,
            "--cert-identity": historical_signer,
        }.items():
            command[command.index(flag) + 1] = value
        command += ["--custom-trusted-root", str(trusted_root)]
        # Prevent network fallback. All verification material is on disk; even
        # an unexpected request must fail rather than reaching a remote service.
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9",
                                     "HTTP_PROXY": "http://127.0.0.1:9",
                                     "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "",
                                     "GH_DEBUG": ""}):
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        verified = json.loads(result.stdout)[0]["verificationResult"]
        certificate = verified["signature"]["certificate"]
        self.assertEqual(certificate["subjectAlternativeName"], historical_signer)
        self.assertEqual(certificate["runInvocationURI"], f"{POLICY.repository_uri}/actions/runs/33690440169/attempts/1")
        self.assertTrue(verified["verifiedTimestamps"])
        self.assertEqual(verified["statement"]["predicate"]["runDetails"]["builder"]["id"], historical_signer)

    def test_wrong_certificate_identity_rejected(self):
        mutations = {
            "runInvocationURI": POLICY.invocation_uri.replace("12345", "54321"),
            "sourceRepositoryRef": "refs/heads/other",
            "sourceRepositoryDigest": "b" * 40,
            "buildSignerDigest": "b" * 40,
            "subjectAlternativeName": POLICY.signer_uri.replace("hardening", "malicious"),
            "buildSignerURI": POLICY.signer_uri.replace("hardening", "malicious"),
            "sourceRepositoryURI": "https://github.com/attacker/fork",
            "buildTrigger": "pull_request", "runnerEnvironment": "self-hosted",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                output = copy.deepcopy(self.verified_fixture)
                output[0]["verificationResult"]["signature"]["certificate"][field] = value
                with self.assertRaises(HardeningError):
                    self._verify(output)

    def test_altered_archive_is_rejected_against_verified_subject(self):
        self.archive.write_bytes(b"altered after originally signed")
        with self.assertRaisesRegex(HardeningError, "subject"):
            self._verify()

    def test_wrong_predicate_subject_and_statement_run_rejected(self):
        for field in ("predicateType", "subject", "run"):
            output = copy.deepcopy(self.verified_fixture)
            statement = output[0]["verificationResult"]["statement"]
            if field == "run":
                statement["predicate"]["runDetails"]["metadata"]["invocationId"] = "wrong"
            else:
                statement[field] = "wrong"
            with self.subTest(field=field), self.assertRaises(HardeningError):
                self._verify(output)

    def test_cryptographic_failure_never_accepts_success_json(self):
        with self.assertRaisesRegex(HardeningError, "CLI rejected"):
            self._verify(returncode=1)

    def test_missing_cli_or_timeout_fails_closed(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("gh", 60)):
            with self.subTest(error=error), patch(
                "eacp_hardening.attestation.subprocess.run", side_effect=error
            ), self.assertRaises(HardeningError):
                verify_archive(self.archive, self.bundle, POLICY)

    def test_missing_duplicate_or_malformed_verification_rejected(self):
        for value in ([], {}, [self.verified_fixture[0], self.verified_fixture[0]], [{"verified": True}]):
            with self.subTest(value=value), self.assertRaises(HardeningError):
                self._verify(value)

    def test_missing_verified_timestamp_rejected(self):
        output = copy.deepcopy(self.verified_fixture)
        output[0]["verificationResult"]["verifiedTimestamps"] = []
        with self.assertRaises(HardeningError):
            self._verify(output)

    def test_archive_changed_during_verification_rejected(self):
        def changed(*args, **kwargs):
            self.archive.write_bytes(b"changed during subprocess")
            return subprocess.CompletedProcess([], 0, json.dumps(self.verified_fixture), "")
        with patch("eacp_hardening.attestation.subprocess.run", side_effect=changed), self.assertRaisesRegex(
            HardeningError, "input changed"
        ):
            verify_archive(self.archive, self.bundle, POLICY)

    def test_custom_root_is_explicitly_forwarded_and_hashed(self):
        root = Path(self.temporary.name) / "trusted_root.jsonl"
        root.write_text("operator-selected root fixture")
        completed = subprocess.CompletedProcess([], 0, json.dumps(self.verified_fixture), "")
        with patch("eacp_hardening.attestation.subprocess.run", return_value=completed) as run:
            result = verify_archive(self.archive, self.bundle, POLICY, trusted_root=root)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--custom-trusted-root") + 1], str(root.resolve()))
        self.assertEqual(result["trusted_root_sha256"], hashlib.sha256(root.read_bytes()).hexdigest())

    def test_symlink_input_rejected(self):
        linked = Path(self.temporary.name) / "linked.jsonl"
        linked.symlink_to(self.bundle)
        with self.assertRaises(HardeningError):
            verify_archive(self.archive, linked, POLICY)

    def test_binding_checks_both_context_and_bytes(self):
        binding = {
            "schema": "eacp.hardening-archive-binding/1", "repository": POLICY.repository,
            "workflow": WORKFLOW, "source_sha": POLICY.source_sha, "source_ref": POLICY.source_ref,
            "run_id": POLICY.run_id, "run_attempt": POLICY.run_attempt,
            "artifact_name": f"eacp-hardening-v1.4-{POLICY.run_id}-{POLICY.run_attempt}",
            "archive_name": ARCHIVE_NAME, "archive_sha256": self.digest,
            "evidence_class": "synthetic_local_hardening_campaign",
        }
        validate_binding(self.archive, binding, POLICY)
        for field, value in (("run_id", 9), ("source_sha", "b" * 40), ("source_ref", "other"),
                             ("archive_sha256", "0" * 64), ("run_attempt", True)):
            with self.subTest(field=field), self.assertRaises(HardeningError):
                validate_binding(self.archive, dict(binding, **{field: value}), POLICY)

    def test_policy_requires_exact_commit_main_and_nonboolean_run(self):
        for change in ({"source_sha": "main"}, {"source_ref": "refs/pull/1/merge"},
                       {"run_id": True}, {"workflow": "other.yml"}):
            values = dict(repository=POLICY.repository, source_sha=POLICY.source_sha,
                          source_ref=POLICY.source_ref, run_id=POLICY.run_id)
            with self.subTest(change=change), self.assertRaises(HardeningError):
                AttestationPolicy(**dict(values, **change))

    def test_failure_stages_do_not_overclaim_verification(self):
        self.assertEqual(classify_stages("failure", "skipped"), "execution_failure")
        self.assertEqual(classify_stages("success", "failure"), "attestation_failure")
        self.assertEqual(classify_stages("success", "skipped"), "attestation_skipped")
        self.assertEqual(classify_stages("success", "success"), "attestation_completed_requires_verification")
        with self.assertRaises(HardeningError):
            classify_stages("failure", "success")


class WorkflowPrivilegeTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / WORKFLOW).read_text()
        self.producer, self.signer = self.workflow.split("\n  attest:\n", 1)

    def test_producer_has_no_signing_permissions_and_signer_is_gated(self):
        for permission in ("id-token: write", "attestations: write"):
            self.assertNotIn(permission, self.producer)
            self.assertIn(permission, self.signer)
        self.assertIn("persist-credentials: false", self.producer)
        for guard in ("github.event_name == 'workflow_dispatch'", "github.ref_protected",
                      "github.ref == 'refs/heads/main'", "needs.execute.result == 'success'",
                      "github.repository == 'obedebessa/eacp-operational-provenance'"):
            self.assertIn(guard, self.signer)
        self.assertNotIn("pull_request_target:", self.workflow)

    def test_signer_does_not_execute_checkout_or_archive_content(self):
        for unsafe in ("uses: actions/checkout", "python -m eacp_hardening", "pip install",
                       "tar -", "tar --", "bash scripts/", "uses: actions/cache"):
            self.assertNotIn(unsafe, self.signer)
        self.assertIn("artifact-ids: ${{ needs.execute.outputs.artifact_id }}", self.signer)
        self.assertIn('metadata.get("workflow_run", {}).get("id") != run', self.signer)
        self.assertIn('metadata.get("workflow_run", {}).get("head_sha") != sha', self.signer)
        self.assertIn('hashlib.file_digest(stream, "sha256")', self.signer)

    def test_all_actions_are_commit_pinned(self):
        actions = re.findall(r"uses:\s+(\S+)", self.workflow)
        self.assertGreaterEqual(len(actions), 5)
        self.assertTrue(all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", action) for action in actions))

    def _signer_python(self):
        blocks = re.findall(r"python3 -I - <<'PY'\n(.*?)\n          PY", self.signer, re.DOTALL)
        self.assertEqual(len(blocks), 2)
        return [compile(textwrap.dedent(block), "reviewed-workflow-inline.py", "exec") for block in blocks]

    def test_inline_metadata_gate_rejects_wrong_origin_before_download(self):
        metadata_gate, _ = self._signer_python()
        env = {
            "GITHUB_REPOSITORY": POLICY.repository, "GITHUB_SHA": POLICY.source_sha,
            "GITHUB_RUN_ID": str(POLICY.run_id), "GITHUB_RUN_ATTEMPT": "1",
            "EACP_ARTIFACT_ID": "98765", "EACP_ARTIFACT_DIGEST": "d" * 64,
        }
        metadata = {
            "id": 98765, "name": f"eacp-hardening-v1.4-{POLICY.run_id}-1",
            "expired": False, "digest": "sha256:" + "d" * 64,
            "workflow_run": {"id": POLICY.run_id, "head_sha": POLICY.source_sha},
            "size_in_bytes": 1024,
        }
        def execute(value):
            with patch.dict(os.environ, env, clear=True), patch(
                "subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(value), "")
            ):
                exec(metadata_gate, {})
        execute(metadata)
        for field, value in (("id", 111), ("digest", "sha256:" + "e" * 64),
                             ("size_in_bytes", 250_000_001), ("expired", True),
                             ("workflow_run", {"id": 999, "head_sha": POLICY.source_sha}),
                             ("workflow_run", {"id": POLICY.run_id, "head_sha": "b" * 40})):
            with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                execute(dict(metadata, **{field: value}))
        self.assertLess(self.signer.index("Validate uploaded artifact metadata"),
                        self.signer.index("uses: actions/download-artifact"))

    def test_inline_data_gate_rejects_altered_archive_and_foreign_binding(self):
        _, data_gate = self._signer_python()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "eacp-hardening-handoff"
            root.mkdir()
            archive = root / ARCHIVE_NAME
            archive.write_bytes(b"inline validator fixture; no execution")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (root / "SHA256SUMS").write_text(f"{digest}  {ARCHIVE_NAME}\n")
            binding = {
                "schema": "eacp.hardening-archive-binding/1", "repository": POLICY.repository,
                "workflow": WORKFLOW, "source_sha": POLICY.source_sha, "source_ref": POLICY.source_ref,
                "run_id": POLICY.run_id, "run_attempt": POLICY.run_attempt,
                "artifact_name": f"eacp-hardening-v1.4-{POLICY.run_id}-1",
                "archive_name": ARCHIVE_NAME, "archive_sha256": digest,
                "evidence_class": "synthetic_local_hardening_campaign",
            }
            binding_path = root / "binding.json"
            binding_path.write_text(json.dumps(binding))
            env = {
                "RUNNER_TEMP": temporary, "GITHUB_REPOSITORY": POLICY.repository,
                "GITHUB_SHA": POLICY.source_sha, "GITHUB_REF": POLICY.source_ref,
                "GITHUB_RUN_ID": str(POLICY.run_id), "GITHUB_RUN_ATTEMPT": "1",
            }
            with patch.dict(os.environ, env, clear=True), patch("builtins.print"):
                exec(data_gate, {})
                binding_path.write_text(json.dumps(dict(binding, run_id=999)))
                with self.assertRaises(SystemExit):
                    exec(data_gate, {})
                binding_path.write_text(json.dumps(binding))
                archive.write_bytes(b"changed archive")
                with self.assertRaises(SystemExit):
                    exec(data_gate, {})


if __name__ == "__main__":
    unittest.main()
