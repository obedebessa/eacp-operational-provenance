"""Strict policy over fresh GitHub CLI cryptographic attestation verification.

The CLI binary, local host and independently chosen policy/trust root are trusted.
An archive or downloaded JSON report never establishes its own authenticity.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import HardeningError

WORKFLOW = ".github/workflows/eacp-hardening-v1.4.yml"
PREDICATE = "https://slsa.dev/provenance/v1"
ARCHIVE_NAME = "eacp-hardening-v1.4.tar.gz"


@dataclass(frozen=True)
class AttestationPolicy:
    repository: str
    source_sha: str
    source_ref: str
    run_id: int
    run_attempt: int = 1
    workflow: str = WORKFLOW

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository
        ):
            raise HardeningError("invalid expected repository")
        if not isinstance(self.source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", self.source_sha):
            raise HardeningError("an exact expected source commit is required")
        if self.source_ref != "refs/heads/main" or self.workflow != WORKFLOW:
            raise HardeningError("the candidate signing policy permits only its main workflow")
        if any(type(value) is not int or value <= 0 for value in (self.run_id, self.run_attempt)):
            raise HardeningError("positive run and attempt identifiers are required")

    @property
    def repository_uri(self) -> str:
        return f"https://github.com/{self.repository}"

    @property
    def signer_uri(self) -> str:
        return f"{self.repository_uri}/{self.workflow}@{self.source_ref}"

    @property
    def invocation_uri(self) -> str:
        return f"{self.repository_uri}/actions/runs/{self.run_id}/attempts/{self.run_attempt}"


def _regular(path: Path, label: str) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise HardeningError(f"{label} must be a nonempty regular file")
    return path.resolve()


def _digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise HardeningError(f"missing or malformed {label}")
    return value


def _matches(value: dict, expected: dict, label: str) -> None:
    for key, target in expected.items():
        if value.get(key) != target:
            raise HardeningError(f"{label} mismatch: {key}")


def validate_binding(archive: Path, binding: dict, policy: AttestationPolicy) -> None:
    """Check an untrusted handoff manifest against caller-selected expectations.

    This is a consistency check, not cryptographic verification.
    """
    archive = _regular(archive, "archive")
    expected = {
        "schema": "eacp.hardening-archive-binding/1",
        "repository": policy.repository,
        "workflow": policy.workflow,
        "source_sha": policy.source_sha,
        "source_ref": policy.source_ref,
        "run_id": policy.run_id,
        "run_attempt": policy.run_attempt,
        "artifact_name": f"eacp-hardening-v1.4-{policy.run_id}-{policy.run_attempt}",
        "archive_name": ARCHIVE_NAME,
        "archive_sha256": _digest(archive),
        "evidence_class": "synthetic_local_hardening_campaign",
    }
    binding = _object(binding, "binding")
    if any(type(binding.get(key)) is not int for key in ("run_id", "run_attempt")):
        raise HardeningError("archive binding run identifiers must be integers")
    if set(binding) != set(expected):
        raise HardeningError("unexpected archive binding fields")
    _matches(binding, expected, "archive binding")


def _check_verified_output(output: str, digest: str, policy: AttestationPolicy) -> None:
    """Only called on stdout of a successful, freshly executed gh verifier."""
    try:
        result = json.loads(output)
    except (TypeError, ValueError) as exc:
        raise HardeningError("GitHub CLI returned invalid verification JSON") from exc
    if not isinstance(result, list) or len(result) != 1:
        raise HardeningError("expected exactly one verified attestation")
    record = _object(result[0], "verification record")
    verified = _object(record.get("verificationResult"), "verification result")
    signature = _object(verified.get("signature"), "verified signature")
    certificate = _object(signature.get("certificate"), "verified certificate")
    _matches(certificate, {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": policy.signer_uri,
        "buildSignerURI": policy.signer_uri,
        "buildSignerDigest": policy.source_sha,
        "sourceRepositoryURI": policy.repository_uri,
        "sourceRepositoryDigest": policy.source_sha,
        "sourceRepositoryRef": policy.source_ref,
        "buildConfigURI": policy.signer_uri,
        "buildConfigDigest": policy.source_sha,
        "buildTrigger": "workflow_dispatch",
        "runInvocationURI": policy.invocation_uri,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryVisibilityAtSigning": "public",
    }, "verified certificate")
    timestamps = verified.get("verifiedTimestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise HardeningError("verified timestamp evidence is required")
    statement = _object(verified.get("statement"), "verified statement")
    _matches(statement, {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": PREDICATE,
        "subject": [{"name": ARCHIVE_NAME, "digest": {"sha256": digest}}],
    }, "verified subject")
    predicate = _object(statement.get("predicate"), "verified predicate")
    details = _object(predicate.get("runDetails"), "run details")
    _matches(_object(details.get("builder"), "builder"), {"id": policy.signer_uri}, "builder")
    _matches(_object(details.get("metadata"), "run metadata"),
             {"invocationId": policy.invocation_uri}, "run metadata")


def verify_archive(archive: Path, bundle: Path, policy: AttestationPolicy, *,
                   trusted_root: Path | None = None) -> dict:
    """Verify archive bytes with real gh, then enforce the exact certificate policy.

    No argument accepts a precomputed verification result. A custom root is an
    explicit caller trust choice, not authenticated merely by accompanying a bundle.
    """
    archive = _regular(archive, "archive")
    bundle = _regular(bundle, "bundle")
    if archive.name != ARCHIVE_NAME:
        raise HardeningError("unexpected archive filename")
    before = {archive: _digest(archive), bundle: _digest(bundle)}
    command = [
        "gh", "attestation", "verify", str(archive), "--hostname", "github.com",
        "--bundle", str(bundle), "--repo", policy.repository,
        "--signer-workflow", f"{policy.repository}/{policy.workflow}",
        "--signer-digest", policy.source_sha, "--source-digest", policy.source_sha,
        "--source-ref", policy.source_ref, "--cert-identity", policy.signer_uri,
        "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
        "--predicate-type", PREDICATE, "--deny-self-hosted-runners", "--format", "json",
    ]
    if trusted_root is not None:
        trusted_root = _regular(trusted_root, "trusted root")
        before[trusted_root] = _digest(trusted_root)
        command += ["--custom-trusted-root", str(trusted_root)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HardeningError("GitHub CLI attestation verification could not complete") from exc
    if result.returncode != 0:
        raise HardeningError("GitHub CLI rejected the attestation")
    if any(_digest(path) != digest for path, digest in before.items()):
        raise HardeningError("verification input changed during verification")
    _check_verified_output(result.stdout, before[archive], policy)
    return {
        "verified": True,
        "method": "fresh_gh_attestation_verify_then_certificate_and_subject_policy",
        "archive_sha256": before[archive],
        "bundle_sha256": before[bundle],
        "repository": policy.repository,
        "source_sha": policy.source_sha,
        "source_ref": policy.source_ref,
        "run_id": policy.run_id,
        "run_attempt": policy.run_attempt,
        "trusted_root_sha256": before.get(trusted_root),
        "scope": "archive_bytes_and_workflow_identity_only",
        "upstream_event_truth_verified": False,
    }


def classify_stages(execution: str, attestation: str) -> str:
    """Classify CI outcomes without equating a signing step to verification."""
    allowed = {"success", "failure", "cancelled", "skipped"}
    if execution not in allowed or attestation not in allowed:
        raise HardeningError("unknown workflow stage result")
    if execution != "success":
        if attestation != "skipped":
            raise HardeningError("attestation must be skipped after unsuccessful execution")
        return f"execution_{execution}"
    if attestation != "success":
        return f"attestation_{attestation}"
    return "attestation_completed_requires_verification"
