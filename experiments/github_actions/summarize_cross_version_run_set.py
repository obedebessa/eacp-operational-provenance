#!/usr/bin/env python3
"""Validate and summarize the separately triggered EACP cross-version cohort."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterator, Sequence

from resolve_kubernetes_target import load_manifest


REPOSITORY = "obedebessa/eacp-operational-provenance"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
WORKFLOW_PATH = ".github/workflows/eacp-cross-plane-v1.3.yml"
SIGNER_WORKFLOW = f"{REPOSITORY}/{WORKFLOW_PATH}"
SUBJECT_URI = "registry.k8s.io/pause"
SUBJECT_DIGEST = "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
JOIN_STATUS = "observed_cross_plane_link_with_subject_digest"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
VERIFICATION_RESULT_MEDIA_TYPE = "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
MAX_ARCHIVE_MEMBERS = 2_048
MAX_ARCHIVE_FILE_SIZE = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_SIZE = 128 * 1024 * 1024
REPEATS_PER_VERSION = 3
EXPECTED_RUNS = 9
RUN_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
    "success",
    "timed_out",
}
DEFAULT_ROOT = Path(__file__).resolve().parent / "results/reference/cross-version-cohort-v1.3"


class CohortError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CohortError(f"expected JSON object: {path}")
    return value


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CohortError(f"expected JSON object at {label}")
    return value


def parse_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise CohortError(f"missing timestamp at {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CohortError(f"malformed timestamp at {label}: {value!r}") from exc
    if parsed.tzinfo is None:
        raise CohortError(f"timestamp lacks a timezone at {label}: {value!r}")


def normalized_tar_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise CohortError(f"unsafe TAR member path {name!r}")
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise CohortError(f"unsafe TAR member path {name!r}")
    normalized = PurePosixPath(*(part for part in candidate.parts if part != "."))
    if str(normalized) in {"", "."}:
        return PurePosixPath(".")
    return normalized


def filesystem_inventory(root: Path) -> dict[str, tuple[str, int]]:
    if not root.is_dir() or root.is_symlink():
        raise CohortError(f"expected ordinary results directory: {root}")
    inventory: dict[str, tuple[str, int]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise CohortError(f"results tree contains a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise CohortError(f"results tree contains a special file: {path}")
        relative = path.relative_to(root).as_posix()
        inventory[relative] = (sha256(path), path.stat().st_size)
    if not inventory:
        raise CohortError(f"results tree is empty: {root}")
    return inventory


def describe_inventory_difference(
    archive_inventory: dict[str, tuple[str, int]],
    results_inventory: dict[str, tuple[str, int]],
) -> str:
    archive_paths = set(archive_inventory)
    results_paths = set(results_inventory)
    only_archive = sorted(archive_paths - results_paths)
    only_results = sorted(results_paths - archive_paths)
    changed = sorted(
        path
        for path in archive_paths & results_paths
        if archive_inventory[path] != results_inventory[path]
    )
    pieces = []
    if only_archive:
        pieces.append(f"only in TAR={only_archive[:5]!r}")
    if only_results:
        pieces.append(f"only in sibling tree={only_results[:5]!r}")
    if changed:
        pieces.append(f"digest/size mismatch={changed[:5]!r}")
    return "; ".join(pieces) or "unknown inventory difference"


@contextmanager
def validated_archive_tree(archive: Path, sibling_results: Path) -> Iterator[Path]:
    """Materialize only safe regular files and prove parity with the sibling results tree."""

    sibling_inventory = filesystem_inventory(sibling_results)
    archive_digest_before = sha256(archive)
    with tempfile.TemporaryDirectory(prefix="eacp-attested-tar-") as temporary:
        destination = Path(temporary)
        archive_inventory: dict[str, tuple[str, int]] = {}
        seen: set[str] = set()
        total_size = 0
        try:
            opened = tarfile.open(archive, mode="r:gz")
        except (tarfile.TarError, OSError) as exc:
            raise CohortError(f"cannot open evidence TAR {archive}: {exc}") from exc
        with opened:
            members = opened.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise CohortError(f"evidence TAR contains too many members: {len(members)}")
            for member in members:
                relative = normalized_tar_path(member.name)
                relative_text = relative.as_posix()
                if relative_text in seen:
                    raise CohortError(f"duplicate normalized TAR member: {member.name!r}")
                seen.add(relative_text)
                if member.isdir():
                    if relative_text != ".":
                        (destination / Path(*relative.parts)).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isreg():
                    raise CohortError(
                        f"evidence TAR contains a non-regular member: {member.name!r}"
                    )
                if relative_text == ".":
                    raise CohortError("evidence TAR uses the root path for a regular file")
                if member.size < 0 or member.size > MAX_ARCHIVE_FILE_SIZE:
                    raise CohortError(
                        f"evidence TAR member exceeds the size limit: {member.name!r}"
                    )
                total_size += member.size
                if total_size > MAX_ARCHIVE_TOTAL_SIZE:
                    raise CohortError("evidence TAR exceeds the total uncompressed size limit")
                source = opened.extractfile(member)
                if source is None:
                    raise CohortError(f"cannot read TAR member: {member.name!r}")
                target = destination / Path(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                observed_size = 0
                with source, target.open("xb") as output:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        observed_size += len(block)
                        if observed_size > member.size:
                            raise CohortError(f"TAR member is larger than declared: {member.name!r}")
                        digest.update(block)
                        output.write(block)
                if observed_size != member.size:
                    raise CohortError(f"TAR member is shorter than declared: {member.name!r}")
                archive_inventory[relative_text] = (digest.hexdigest(), observed_size)
        if sha256(archive) != archive_digest_before:
            raise CohortError(f"evidence TAR changed while it was being validated: {archive}")
        if archive_inventory != sibling_inventory:
            detail = describe_inventory_difference(archive_inventory, sibling_inventory)
            raise CohortError(f"attested TAR and sibling results tree differ: {detail}")
        if filesystem_inventory(destination) != archive_inventory:
            raise CohortError("safely materialized TAR differs from its streamed inventory")
        yield destination


def verify_manifest(root: Path, manifest: Path) -> int:
    count = 0
    for number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            expected, relative = raw.split(None, 1)
        except ValueError as exc:
            raise CohortError(f"malformed manifest line {manifest}:{number}") from exc
        relative = relative.strip().lstrip("*")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise CohortError(f"unsafe manifest path {relative!r}")
        target = (root / candidate).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            raise CohortError(f"manifest path escapes root: {relative!r}")
        if not target.is_file() or sha256(target) != expected.lower():
            raise CohortError(f"checksum mismatch: {target}")
        count += 1
    if not count:
        raise CohortError(f"empty checksum manifest: {manifest}")
    return count


def load_sigstore_bundle(bundle: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    lines = [line for line in bundle.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise CohortError(f"expected exactly one attestation in {bundle}")
    value = require_object(json.loads(lines[0]), f"{bundle} JSONL entry")
    if value.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        raise CohortError(f"unexpected Sigstore bundle type: {bundle}")
    envelope = require_object(value.get("dsseEnvelope"), f"{bundle} dsseEnvelope")
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise CohortError(f"unexpected DSSE payload type: {bundle}")
    signatures = envelope.get("signatures")
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], dict)
        or not isinstance(signatures[0].get("sig"), str)
        or not signatures[0]["sig"]
    ):
        raise CohortError(f"expected exactly one DSSE signature: {bundle}")
    material = require_object(value.get("verificationMaterial"), f"{bundle} verificationMaterial")
    certificate = require_object(material.get("certificate"), f"{bundle} certificate")
    if not isinstance(certificate.get("rawBytes"), str) or not certificate["rawBytes"]:
        raise CohortError(f"missing signing certificate: {bundle}")
    tlog_entries = material.get("tlogEntries")
    if not isinstance(tlog_entries, list) or not tlog_entries:
        raise CohortError(f"missing transparency-log material: {bundle}")
    encoded = envelope.get("payload")
    if not isinstance(encoded, str):
        raise CohortError(f"missing DSSE payload: {bundle}")
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        statement = require_object(json.loads(decoded), f"{bundle} DSSE statement")
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CohortError(f"invalid DSSE statement: {bundle}") from exc
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise CohortError(f"unexpected in-toto statement type: {bundle}")
    return value, statement


def decode_statement(bundle: Path) -> dict[str, Any]:
    return load_sigstore_bundle(bundle)[1]


def expected_identity(
    *, protocol_commit: str, tag: str, run_id: int
) -> dict[str, str]:
    source_ref = f"refs/tags/{tag}"
    signer_uri = f"{REPOSITORY_URL}/{WORKFLOW_PATH}@{source_ref}"
    return {
        "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
        "subjectAlternativeName": signer_uri,
        "issuer": "https://token.actions.githubusercontent.com",
        "githubWorkflowTrigger": "push",
        "githubWorkflowSHA": protocol_commit,
        "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowRef": source_ref,
        "buildSignerURI": signer_uri,
        "buildSignerDigest": protocol_commit,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": REPOSITORY_URL,
        "sourceRepositoryDigest": protocol_commit,
        "sourceRepositoryRef": source_ref,
        "buildConfigURI": signer_uri,
        "buildConfigDigest": protocol_commit,
        "buildTrigger": "push",
        "runInvocationURI": f"{REPOSITORY_URL}/actions/runs/{run_id}/attempts/1",
        "sourceRepositoryVisibilityAtSigning": "public",
    }


def validate_verification_value(
    value: Any,
    *,
    sigstore_bundle: dict[str, Any],
    statement: dict[str, Any],
    protocol_commit: str,
    tag: str,
    run_id: int,
) -> int:
    if not isinstance(value, list) or len(value) != 1:
        raise CohortError(
            f"run {run_id} must have exactly one successful attestation verification result"
        )
    record = require_object(value[0], f"run {run_id} verification record")
    attestation = require_object(record.get("attestation"), f"run {run_id} attestation")
    if attestation.get("bundle") != sigstore_bundle:
        raise CohortError(f"run {run_id} verification output does not contain the exact bundle")
    result = require_object(record.get("verificationResult"), f"run {run_id} verificationResult")
    if result.get("mediaType") != VERIFICATION_RESULT_MEDIA_TYPE:
        raise CohortError(f"run {run_id} verification-result media type mismatch")
    if result.get("statement") != statement:
        raise CohortError(f"run {run_id} verified statement differs from the DSSE payload")

    signature = require_object(result.get("signature"), f"run {run_id} signature")
    certificate = require_object(signature.get("certificate"), f"run {run_id} certificate")
    for field, expected in expected_identity(
        protocol_commit=protocol_commit, tag=tag, run_id=run_id
    ).items():
        if certificate.get(field) != expected:
            raise CohortError(
                f"run {run_id} verified certificate {field}={certificate.get(field)!r}; "
                f"expected {expected!r}"
            )

    timestamps = result.get("verifiedTimestamps")
    if not isinstance(timestamps, list) or not timestamps:
        raise CohortError(f"run {run_id} has no verified timestamp")
    rekor_timestamps = [
        item
        for item in timestamps
        if isinstance(item, dict)
        and item.get("type") == "Tlog"
        and item.get("uri") == "https://rekor.sigstore.dev"
        and isinstance(item.get("timestamp"), str)
    ]
    if not rekor_timestamps:
        raise CohortError(f"run {run_id} has no verified Rekor timestamp")
    for item in rekor_timestamps:
        parse_timestamp(item["timestamp"], f"run {run_id} verified Rekor timestamp")

    verified_identity = require_object(
        result.get("verifiedIdentity"), f"run {run_id} verifiedIdentity"
    )
    if verified_identity.get("runnerEnvironment") != "github-hosted":
        raise CohortError(f"run {run_id} did not verify a GitHub-hosted runner identity")

    predicate = require_object(statement.get("predicate"), f"run {run_id} SLSA predicate")
    build_definition = require_object(
        predicate.get("buildDefinition"), f"run {run_id} buildDefinition"
    )
    if build_definition.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1":
        raise CohortError(f"run {run_id} SLSA build type mismatch")
    external = require_object(
        build_definition.get("externalParameters"), f"run {run_id} externalParameters"
    )
    workflow = require_object(external.get("workflow"), f"run {run_id} predicate workflow")
    source_ref = f"refs/tags/{tag}"
    expected_workflow = {
        "path": WORKFLOW_PATH,
        "ref": source_ref,
        "repository": REPOSITORY_URL,
    }
    if workflow != expected_workflow:
        raise CohortError(f"run {run_id} predicate workflow identity mismatch")
    internal = require_object(
        build_definition.get("internalParameters"), f"run {run_id} internalParameters"
    )
    github = require_object(internal.get("github"), f"run {run_id} internal GitHub parameters")
    if github.get("event_name") != "push" or github.get("runner_environment") != "github-hosted":
        raise CohortError(f"run {run_id} predicate event or runner class mismatch")
    dependencies = build_definition.get("resolvedDependencies")
    expected_dependency = {
        "uri": f"git+{REPOSITORY_URL}@{source_ref}",
        "digest": {"gitCommit": protocol_commit},
    }
    if not isinstance(dependencies, list) or expected_dependency not in dependencies:
        raise CohortError(f"run {run_id} predicate lacks the exact source dependency")
    run_details = require_object(predicate.get("runDetails"), f"run {run_id} runDetails")
    builder = require_object(run_details.get("builder"), f"run {run_id} builder")
    metadata = require_object(run_details.get("metadata"), f"run {run_id} run metadata")
    expected_signer = f"{REPOSITORY_URL}/{WORKFLOW_PATH}@{source_ref}"
    if builder.get("id") != expected_signer:
        raise CohortError(f"run {run_id} predicate builder identity mismatch")
    if metadata.get("invocationId") != f"{REPOSITORY_URL}/actions/runs/{run_id}/attempts/1":
        raise CohortError(f"run {run_id} predicate invocation mismatch")
    return 1


def validate_verification_file(
    path: Path,
    *,
    sigstore_bundle: dict[str, Any],
    statement: dict[str, Any],
    protocol_commit: str,
    tag: str,
    run_id: int,
) -> int:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CohortError(f"run {run_id} has invalid stored verification JSON") from exc
    return validate_verification_value(
        value,
        sigstore_bundle=sigstore_bundle,
        statement=statement,
        protocol_commit=protocol_commit,
        tag=tag,
        run_id=run_id,
    )


def validate_attestation_policy(run_root: Path, protocol_commit: str, tag: str) -> Path:
    attestation_root = run_root / "attestation"
    trusted_root = attestation_root / "trusted_root.jsonl"
    if not trusted_root.is_file() or trusted_root.is_symlink() or trusted_root.stat().st_size == 0:
        raise CohortError(f"{run_root.name} lacks a regular captured trusted-root file")
    trusted_lines = [
        line for line in trusted_root.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not trusted_lines:
        raise CohortError(f"{run_root.name} captured an empty trusted-root file")
    for number, line in enumerate(trusted_lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CohortError(f"{run_root.name} trusted-root line {number} is not JSON") from exc
        if (
            not isinstance(value, dict)
            or value.get("mediaType")
            != "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
        ):
            raise CohortError(f"{run_root.name} trusted-root line {number} has wrong type")

    policy = load_object(attestation_root / "verification-policy.json")
    expected_policy = {
        "schema_version": "eacp.attestation-verification-policy/1.3.0",
        "repository": REPOSITORY,
        "signer_workflow": SIGNER_WORKFLOW,
        "source_digest": protocol_commit,
        "source_ref": f"refs/tags/{tag}",
        "predicate_type": PREDICATE_TYPE,
        "deny_self_hosted_runners": True,
        "bundle_on_disk": True,
        "custom_trusted_root_on_disk": True,
    }
    if policy != expected_policy:
        raise CohortError(f"{run_root.name} attestation verification policy mismatch")
    return trusted_root


def reverify_attestation(
    archive: Path,
    bundle: Path,
    trusted_root: Path,
    *,
    sigstore_bundle: dict[str, Any],
    statement: dict[str, Any],
    protocol_commit: str,
    tag: str,
    run_id: int,
) -> None:
    command = [
        "gh",
        "attestation",
        "verify",
        str(archive),
        "--bundle",
        str(bundle),
        "--custom-trusted-root",
        str(trusted_root),
        "--repo",
        REPOSITORY,
        "--signer-workflow",
        SIGNER_WORKFLOW,
        "--source-digest",
        protocol_commit,
        "--source-ref",
        f"refs/tags/{tag}",
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise CohortError(f"run {run_id} could not execute fresh gh verification: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"exit status {completed.returncode}"
        raise CohortError(f"run {run_id} fresh gh attestation verification failed: {detail}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CohortError(f"run {run_id} fresh gh verification returned invalid JSON") from exc
    validate_verification_value(
        value,
        sigstore_bundle=sigstore_bundle,
        statement=statement,
        protocol_commit=protocol_commit,
        tag=tag,
        run_id=run_id,
    )


def member_identity(
    root: Path,
    row: dict[str, Any],
    protocol_commit: str,
    targets: dict[str, Any],
) -> dict[str, Any]:
    version = row.get("kubernetes_version")
    run_id = row.get("run_id")
    tag = row.get("evidence_tag")
    if not isinstance(version, str) or version not in targets:
        raise CohortError(f"invalid Kubernetes version in run-set row: {version!r}")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise CohortError(f"invalid workflow run ID in run-set row: {run_id!r}")
    if not isinstance(tag, str):
        raise CohortError(f"invalid evidence tag in run-set row for run {run_id}")
    allowed_tags = {
        f"eacp-v1.3-evidence/k8s-{version}/run-{repeat:02d}"
        for repeat in range(1, REPEATS_PER_VERSION + 1)
    }
    if tag not in allowed_tags:
        raise CohortError(f"unexpected evidence tag for {version}: {tag}")
    repeat = int(tag.rsplit("-", 1)[1])
    run_url = f"{REPOSITORY_URL}/actions/runs/{run_id}"
    if row.get("run_url") != run_url:
        raise CohortError(f"run {run_id} has a non-canonical predeclared run URL")
    run_root = root / f"run-{run_id}"
    metadata = load_object(run_root / "run_metadata.json")
    expected_metadata = {
        "attempt": 1,
        "event": "push",
        "headBranch": tag,
        "headSha": protocol_commit,
        "status": "completed",
        "url": run_url,
        "workflowName": "EACP cross-plane v1.3",
    }
    for field, expected in expected_metadata.items():
        if metadata.get(field) != expected:
            raise CohortError(
                f"run {run_id} metadata {field}={metadata.get(field)!r}; expected {expected!r}"
            )
    conclusion = metadata.get("conclusion")
    if conclusion not in RUN_CONCLUSIONS:
        raise CohortError(f"run {run_id} has unsupported completed conclusion {conclusion!r}")
    return {
        "kubernetes_version": version,
        "repeat": repeat,
        "run_id": run_id,
        "run_url": run_url,
        "evidence_tag": tag,
        "head_sha": protocol_commit,
        "status": "completed",
        "conclusion": conclusion,
        "run_root": run_root,
        "metadata": metadata,
    }


def verify_non_success_outcome(identity: dict[str, Any]) -> dict[str, Any]:
    run_root = identity["run_root"]
    run_id = identity["run_id"]
    conclusion = identity["conclusion"]
    if conclusion == "success":
        raise CohortError(f"run {run_id} cannot use the non-success evidence path")
    expected_inventory = {"run_metadata.json", "job_outcome.json", "OUTCOME_SHA256SUMS"}
    inventory = filesystem_inventory(run_root)
    if set(inventory) != expected_inventory:
        raise CohortError(
            f"non-success run {run_id} must contain only the frozen minimal outcome files"
        )
    checks = verify_manifest(run_root, run_root / "OUTCOME_SHA256SUMS")
    if checks != 2:
        raise CohortError(f"non-success run {run_id} outcome manifest must bind two JSON files")
    listed_paths = []
    for raw in (run_root / "OUTCOME_SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if raw.strip():
            _, relative = raw.split(None, 1)
            listed_paths.append(relative.strip().lstrip("*").removeprefix("./"))
    if sorted(listed_paths) != ["job_outcome.json", "run_metadata.json"]:
        raise CohortError(
            f"non-success run {run_id} outcome manifest has the wrong exact inventory"
        )
    outcome = load_object(run_root / "job_outcome.json")
    expected_outcome_fields = {
        "schema_version",
        "repository",
        "run_id",
        "run_attempt",
        "head_sha",
        "evidence_tag",
        "run_index",
        "kubernetes_version",
        "run_url",
        "workflow_name",
        "event",
        "status",
        "conclusion",
        "captured_at",
        "source_acquisition",
        "jobs",
    }
    if set(outcome) != expected_outcome_fields:
        raise CohortError(f"non-success run {run_id} outcome fields differ from the schema")
    expected = {
        "schema_version": "eacp.cross-version-run-outcome/1.3.0",
        "repository": REPOSITORY,
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": identity["head_sha"],
        "evidence_tag": identity["evidence_tag"],
        "kubernetes_version": identity["kubernetes_version"],
        "run_url": identity["run_url"],
        "workflow_name": "EACP cross-plane v1.3",
        "event": "push",
        "status": "completed",
        "conclusion": conclusion,
        "run_index": identity["repeat"],
    }
    for field, value in expected.items():
        if outcome.get(field) != value:
            raise CohortError(
                f"non-success run {run_id} outcome {field}={outcome.get(field)!r}; "
                f"expected {value!r}"
            )
    parse_timestamp(outcome.get("captured_at"), f"run {run_id} outcome captured_at")
    if not isinstance(outcome.get("source_acquisition"), str) or not outcome[
        "source_acquisition"
    ]:
        raise CohortError(f"non-success run {run_id} lacks its source acquisition method")
    jobs = outcome.get("jobs")
    if not isinstance(jobs, list) or len(jobs) > 1:
        raise CohortError(f"non-success run {run_id} must contain zero or one workflow job")
    job = jobs[0] if jobs else None
    steps: list[dict[str, Any]] = []
    if job is not None:
        if not isinstance(job, dict):
            raise CohortError(f"non-success run {run_id} job is not an object")
        expected_job_fields = {
            "database_id",
            "name",
            "labels",
            "status",
            "conclusion",
            "started_at",
            "completed_at",
            "steps",
        }
        if set(job) != expected_job_fields:
            raise CohortError(f"non-success run {run_id} job fields differ from the schema")
        if job.get("name") != "github-actions-to-kubernetes":
            raise CohortError(f"non-success run {run_id} has an unexpected workflow job")
        if job.get("labels") != ["ubuntu-24.04"]:
            raise CohortError(f"non-success run {run_id} has an unexpected runner label")
        if job.get("status") != "completed" or job.get("conclusion") != conclusion:
            raise CohortError(f"non-success run {run_id} job outcome differs from the run")
        steps_value = job.get("steps")
        if not isinstance(steps_value, list):
            raise CohortError(f"non-success run {run_id} job steps are not a list")
        for index, step in enumerate(steps_value):
            if not isinstance(step, dict):
                raise CohortError(f"non-success run {run_id} step {index} is not an object")
            if set(step) != {
                "number",
                "name",
                "status",
                "conclusion",
                "started_at",
                "completed_at",
            }:
                raise CohortError(
                    f"non-success run {run_id} step {index} fields differ from the schema"
                )
            if not isinstance(step.get("number"), int) or not isinstance(step.get("name"), str):
                raise CohortError(f"non-success run {run_id} step {index} lacks identity")
            if step.get("status") not in {"completed", "in_progress", "queued", "pending"}:
                raise CohortError(f"non-success run {run_id} step {index} has unknown status")
            steps.append(step)
    failed_steps = [
        step.get("name")
        for step in steps
        if step.get("conclusion") not in {None, "success", "skipped"}
    ]
    return {
        key: value for key, value in identity.items() if key not in {"run_root", "metadata"}
    } | {
        "criteria_status": "not_satisfied",
        "full_evidence_verified": False,
        "failure_evidence_classification": "frozen_github_run_job_and_step_outcome",
        "job_conclusion": job.get("conclusion") if job else None,
        "non_success_steps": failed_steps,
        "verified_manifest_entries": checks,
    }


def verify_cohort_member(
    root: Path,
    row: dict[str, Any],
    protocol_commit: str,
    targets: dict[str, Any],
    *,
    reverify_attestations: bool = False,
) -> dict[str, Any]:
    identity = member_identity(root, row, protocol_commit, targets)
    if identity["conclusion"] != "success":
        return verify_non_success_outcome(identity)
    result = verify_run(
        root,
        row,
        protocol_commit,
        targets,
        reverify_attestations=reverify_attestations,
    )
    result.update(
        {
            "status": "completed",
            "conclusion": "success",
            "criteria_status": "satisfied",
            "full_evidence_verified": True,
        }
    )
    return result


def verify_run(
    root: Path,
    row: dict[str, Any],
    protocol_commit: str,
    targets: dict[str, Any],
    *,
    reverify_attestations: bool = False,
) -> dict[str, Any]:
    version = str(row["kubernetes_version"])
    run_id = int(row["run_id"])
    tag = str(row["evidence_tag"])
    allowed_tags = {
        f"eacp-v1.3-evidence/k8s-{version}/run-{repeat:02d}"
        for repeat in range(1, REPEATS_PER_VERSION + 1)
    }
    if tag not in allowed_tags:
        raise CohortError(f"unexpected evidence tag for {version}: {tag}")
    repeat = int(tag.rsplit("-", 1)[1])
    run_root = root / f"run-{run_id}"
    outer_checks = verify_manifest(run_root, run_root / "RUN_SHA256SUMS")
    downloaded = run_root / "downloaded-artifact"
    sibling_runtime = downloaded / "eacp-cross-plane-v1.3-results"
    finalized = run_root / "finalized"
    archive = downloaded / f"eacp-cross-plane-v1.3-{run_id}-1.tar.gz"
    archive_checks = verify_manifest(downloaded, archive.with_suffix(archive.suffix + ".sha256"))
    final_checks = verify_manifest(finalized, finalized / "SHA256SUMS")
    with validated_archive_tree(archive, sibling_runtime) as runtime:
        public_checks = verify_manifest(runtime, runtime / "PUBLIC_SHA256SUMS")
        github_checks = verify_manifest(runtime / "github", runtime / "github/SHA256SUMS")
        audit_checks = verify_manifest(
            runtime / "kubernetes/audit", runtime / "kubernetes/audit/SHA256SUMS"
        )
        environment = load_object(runtime / "environment.json")
        versions = load_object(runtime / "kubernetes/kubernetes_version.json")
        kubelet = (runtime / "kubernetes/kubelet_version.txt").read_text(
            encoding="utf-8"
        ).strip()
        audit = load_object(runtime / "kubernetes/audit/audit_summary.json")
        attested_join = load_object(runtime / "cross_plane_join.json")
        source_manifest_digest = sha256(runtime / "PUBLIC_SHA256SUMS")

    completed = load_object(finalized / "github_completed/source/github_actions.json")
    completed_summary = load_object(finalized / "github_completed/summary.json")
    join = load_object(finalized / "cross_plane_join_completed.json")
    finalization = load_object(finalized / "finalization.json")
    run_metadata = load_object(run_root / "run_metadata.json")
    target = targets[version]
    correlation = f"eacp-gha-1324720646-{run_id}-1"
    run_url = f"{REPOSITORY_URL}/actions/runs/{run_id}"
    source_ref = f"refs/tags/{tag}"

    expected_environment = {
        "repository": REPOSITORY,
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": protocol_commit,
        "correlation_id": correlation,
        "expected_kubernetes_version": version,
        "observed_kubectl_version": version,
        "observed_kubernetes_server_version": version,
        "kind_node_image": target["node_image"],
        "subject_uri": SUBJECT_URI,
        "subject_digest": SUBJECT_DIGEST,
        "github_ref": source_ref,
        "github_ref_name": tag,
        "github_ref_type": "tag",
        "runner_os": "Linux",
        "runner_arch": "X64",
        "runner_image_os": "ubuntu24",
        "correlation_origin": "workflow_generated",
        "identifier_discovery_evaluated": False,
    }
    for key, expected in expected_environment.items():
        if environment.get(key) != expected:
            raise CohortError(
                f"run {run_id} environment {key}={environment.get(key)!r}; expected {expected!r}"
            )
    if not isinstance(environment.get("runner_image_version"), str) or not environment[
        "runner_image_version"
    ]:
        raise CohortError(f"run {run_id} lacks the captured GitHub runner image version")
    if environment.get("observed_kubelet_versions") != [version] or kubelet != f"Kubernetes {version}":
        raise CohortError(f"run {run_id} kubelet version mismatch")
    if versions.get("clientVersion", {}).get("gitVersion") != version:
        raise CohortError(f"run {run_id} kubectl version mismatch")
    if versions.get("serverVersion", {}).get("gitVersion") != version:
        raise CohortError(f"run {run_id} API-server version mismatch")

    source_run = completed.get("run", {})
    expected_run = {
        "id": run_id,
        "run_attempt": 1,
        "head_sha": protocol_commit,
        "head_branch": tag,
        "status": "completed",
        "conclusion": "success",
    }
    for key, expected in expected_run.items():
        if source_run.get(key) != expected:
            raise CohortError(f"run {run_id} completed source mismatch for {key}")
    if source_run.get("html_url") != run_url or row.get("run_url") != run_url:
        raise CohortError(f"run {run_id} URL differs across the predeclared and completed evidence")
    if (
        run_metadata.get("attempt") != 1
        or run_metadata.get("headSha") != protocol_commit
        or run_metadata.get("headBranch") != tag
        or run_metadata.get("event") != "push"
        or run_metadata.get("status") != "completed"
        or run_metadata.get("conclusion") != "success"
        or run_metadata.get("url") != run_url
        or run_metadata.get("workflowName") != "EACP cross-plane v1.3"
    ):
        raise CohortError(f"run {run_id} public metadata mismatch")

    jobs = completed.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 1:
        raise CohortError(f"run {run_id} must contain exactly one completed source job")
    job = require_object(jobs[0], f"run {run_id} completed job")
    expected_job = {
        "name": "github-actions-to-kubernetes",
        "labels": ["ubuntu-24.04"],
        "run_id": run_id,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "workflow_name": "EACP cross-plane v1.3",
    }
    for key, expected in expected_job.items():
        if job.get(key) != expected:
            raise CohortError(f"run {run_id} completed job mismatch for {key}")
    artifacts = completed.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise CohortError(f"run {run_id} must contain exactly one uploaded evidence artifact")
    artifact = require_object(artifacts[0], f"run {run_id} uploaded artifact")
    expected_artifact_name = f"eacp-cross-plane-v1.3-{run_id}-1"
    if (
        artifact.get("name") != expected_artifact_name
        or artifact.get("workflow_run_id") != run_id
        or artifact.get("expired") is not False
        or not isinstance(artifact.get("id"), int)
        or artifact.get("id", 0) <= 0
        or artifact.get("archive_download_url")
        != f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact.get('id')}/zip"
    ):
        raise CohortError(f"run {run_id} uploaded evidence artifact identity mismatch")
    projection = require_object(
        completed_summary.get("projection"), f"run {run_id} completed projection"
    )
    if (
        projection.get("evidence_rows") != 3
        or projection.get("profile_records") != 3
        or projection.get("unique_source_keys") != 3
        or projection.get("subject")
        != {"uri": SUBJECT_URI, "digest": SUBJECT_DIGEST}
        or projection.get("rows_by_source_type")
        != {
            "github.actions.artifact": 1,
            "github.actions.job": 1,
            "github.actions.run": 1,
        }
    ):
        raise CohortError(f"run {run_id} completed source evidence inventory mismatch")

    if join.get("status") != JOIN_STATUS or join.get("correlation_id") != correlation:
        raise CohortError(f"run {run_id} completed join mismatch")
    if join.get("github_actions", {}).get("evidence_rows") != 3:
        raise CohortError(f"run {run_id} completed join does not contain exactly three source rows")
    for key, value in attested_join.items():
        if key != "github_actions" and join.get(key) != value:
            raise CohortError(
                f"run {run_id} completed join changed attested Kubernetes field {key!r}"
            )
    expected_source_identity = {
        "repository": REPOSITORY,
        "run_id": run_id,
        "run_attempt": 1,
        "commit_sha": protocol_commit,
        "source_url": run_url,
    }
    for field, expected in expected_source_identity.items():
        if join.get("github_actions", {}).get(field) != expected:
            raise CohortError(f"run {run_id} completed join source mismatch for {field}")
    if (
        finalization.get("schema_version") != "eacp.cross-plane-finalization/1.3.0"
        or finalization.get("source_results_manifest_sha256") != source_manifest_digest
        or finalization.get("github_run_status") != "completed"
        or finalization.get("github_run_conclusion") != "success"
        or finalization.get("join_status") != JOIN_STATUS
    ):
        raise CohortError(f"run {run_id} finalization is not bound to the attested results")
    kubernetes = join.get("kubernetes", {})
    negative = kubernetes.get("negative_control", {})
    denial = kubernetes.get("rbac_denial_binding", {})
    pods = kubernetes.get("pods", {})
    if not negative.get("correlation_annotation_absent"):
        raise CohortError(f"run {run_id} negative control joined")
    if (
        denial.get("binding_method") != "adapter_explicit_exact_target"
        or denial.get("matching_http_403_records") != 1
        or denial.get("source_native_correlation_records") != 0
    ):
        raise CohortError(f"run {run_id} HTTP 403 binding boundary mismatch")
    if not (
        pods.get("all_pods_have_exact_correlation_id")
        and pods.get("pod_spec_subject_exact_match")
        and pods.get("runtime_image_id_exact_subject_digest_match")
    ):
        raise CohortError(f"run {run_id} Pod identity or digest mismatch")
    positive_count = int(audit.get("positive_control", {}).get("matching_audit_records") or 0)
    negative_count = int(audit.get("negative_control", {}).get("audit_records") or 0)
    if positive_count < 1 or negative_count < 1:
        raise CohortError(f"run {run_id} lacks a declared positive or negative observation")

    bundles = list((run_root / "attestation").glob("sha256-*.jsonl"))
    if len(bundles) != 1:
        raise CohortError(f"run {run_id} must contain exactly one attestation bundle")
    sigstore_bundle, statement = load_sigstore_bundle(bundles[0])
    archive_digest = sha256(archive)
    if statement.get("subject") != [
        {"name": archive.name, "digest": {"sha256": archive_digest}}
    ]:
        raise CohortError(f"run {run_id} attestation subject mismatch")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise CohortError(f"run {run_id} attestation predicate mismatch")
    verification_records = validate_verification_file(
        run_root / "attestation/verification.json",
        sigstore_bundle=sigstore_bundle,
        statement=statement,
        protocol_commit=protocol_commit,
        tag=tag,
        run_id=run_id,
    )
    trusted_root = validate_attestation_policy(run_root, protocol_commit, tag)
    if reverify_attestations:
        reverify_attestation(
            archive,
            bundles[0],
            trusted_root,
            sigstore_bundle=sigstore_bundle,
            statement=statement,
            protocol_commit=protocol_commit,
            tag=tag,
            run_id=run_id,
        )

    return {
        "kubernetes_version": version,
        "repeat": repeat,
        "run_id": run_id,
        "run_url": row["run_url"],
        "evidence_tag": tag,
        "head_sha": protocol_commit,
        "correlation_id": correlation,
        "github_completed_evidence_records": join["github_actions"]["evidence_rows"],
        "kubernetes_namespace_records": audit["scope"]["namespace_records"],
        "kubernetes_source_native_positive_records": positive_count,
        "negative_control_audit_records": negative_count,
        "negative_control_unjoined": True,
        "target_bound_http_403_records": 1,
        "rbac_source_native_correlation_records": 0,
        "separate_oci_digest_check": True,
        "archive_sha256": archive_digest,
        "attestation_bundle_sha256": sha256(bundles[0]),
        "stored_attestation_verification_records": verification_records,
        "attested_tar_matches_sibling_results_tree": True,
        "verified_manifest_entries": (
            outer_checks + archive_checks + public_checks + github_checks + audit_checks + final_checks
        ),
    }


def summarize(
    root: Path,
    target_manifest: Path,
    *,
    reverify_attestations: bool = False,
) -> dict[str, Any]:
    run_set = load_object(root / "run_set.json")
    if run_set.get("schema_version") != "eacp.cross-version-run-set/1.3.0":
        raise CohortError("unexpected run-set schema")
    protocol_commit = str(run_set.get("protocol_commit") or "")
    if len(protocol_commit) != 40 or any(ch not in "0123456789abcdef" for ch in protocol_commit):
        raise CohortError("run set lacks a lowercase 40-hex protocol commit")
    manifest = load_manifest(target_manifest)
    rows = run_set.get("runs")
    if not isinstance(rows, list) or len(rows) != EXPECTED_RUNS:
        raise CohortError(f"run set must contain exactly {EXPECTED_RUNS} cohort members")
    if any(not isinstance(row, dict) for row in rows):
        raise CohortError("every run-set member must be a JSON object")
    expected_members = {
        (
            version,
            f"eacp-v1.3-evidence/k8s-{version}/run-{repeat:02d}",
        )
        for version in manifest["targets"]
        for repeat in range(1, REPEATS_PER_VERSION + 1)
    }
    observed_members = {
        (str(row.get("kubernetes_version")), str(row.get("evidence_tag"))) for row in rows
    }
    if observed_members != expected_members:
        raise CohortError("run-set members differ from the exact balanced 3-by-3 design")
    results = [
        verify_cohort_member(
            root,
            row,
            protocol_commit,
            manifest["targets"],
            reverify_attestations=reverify_attestations,
        )
        for row in sorted(
            rows, key=lambda value: (value["kubernetes_version"], value["evidence_tag"])
        )
    ]
    if len({row["run_id"] for row in results}) != EXPECTED_RUNS:
        raise CohortError("cohort run IDs are not distinct")
    successful = [row for row in results if row["conclusion"] == "success"]
    correlations = [row["correlation_id"] for row in successful]
    if len(set(correlations)) != len(correlations):
        raise CohortError("successful cohort correlation IDs are not distinct")
    if len({row["head_sha"] for row in results}) != 1:
        raise CohortError("cohort does not share one protocol commit")
    success_count = len(successful)
    overall_status = (
        "complete_success"
        if success_count == EXPECTED_RUNS
        else "failed"
        if success_count == 0
        else "partial"
    )
    per_version = {
        version: {
            "first_attempt_outcomes": len(
                [row for row in results if row["kubernetes_version"] == version]
            ),
            "successful_full_evidence_runs": len(
                [
                    row
                    for row in successful
                    if row["kubernetes_version"] == version
                ]
            ),
            "non_successful_runs": len(
                [
                    row
                    for row in results
                    if row["kubernetes_version"] == version and row["conclusion"] != "success"
                ]
            ),
            "predeclared_criteria_satisfied": len(
                [
                    row
                    for row in successful
                    if row["kubernetes_version"] == version
                ]
            ),
            "run_ids": [
                row["run_id"] for row in results if row["kubernetes_version"] == version
            ],
        }
        for version in sorted(manifest["targets"])
    }
    if any(
        value["first_attempt_outcomes"] != REPEATS_PER_VERSION
        for value in per_version.values()
    ):
        raise CohortError("cohort is not balanced at three first-attempt runs per version")
    source_classification = (
        "controlled_public_github_actions_and_kubernetes_api_evidence"
        if overall_status == "complete_success"
        else "preserved_public_github_actions_outcomes_with_partial_kubernetes_evidence"
        if overall_status == "partial"
        else "preserved_public_github_actions_outcomes_without_successful_kubernetes_evidence"
    )
    return {
        "schema_version": "eacp.cross-version-summary/1.3.0",
        "source_classification": source_classification,
        "overall_status": overall_status,
        "protocol_commit": protocol_commit,
        "kind_version": manifest["kind"]["version"],
        "target_versions": sorted(manifest["targets"]),
        "run_results": results,
        "per_version": per_version,
        "aggregate": {
            "preserved_first_attempt_outcomes": EXPECTED_RUNS,
            "successful_full_evidence_runs": success_count,
            "non_successful_first_attempt_runs": EXPECTED_RUNS - success_count,
            "distinct_successful_correlation_ids": len(correlations),
            "first_attempt_outcomes_per_version": REPEATS_PER_VERSION,
            "exact_client_server_kubelet_version_checks": success_count,
            "successful_positive_controls": success_count,
            "successful_negative_controls": success_count,
            "successful_adapter_explicit_403_controls": success_count,
            "successful_separate_oci_digest_checks": success_count,
            "attested_tar_parity_checks": success_count,
            "capture_time_offline_attestation_verifications": success_count,
            "external_reproductions": 0,
            "independent_organizations": 0,
            "identifier_discovery_evaluated": False,
        },
        "attestation_verification_boundary": {
            "capture_time": (
                "Each stored verification result was produced with gh attestation verify, the "
                "downloaded bundle, an on-disk trusted root, exact repository/workflow/source "
                "digest/source-ref constraints, and denial of self-hosted runners."
            ),
            "repository_verify_mode": (
                "The --verify command re-performs cryptographic verification for every successful "
                "run archive against its captured trusted root and then enforces exact certificate, Rekor "
                "timestamp, statement, subject, builder, source, ref, runner, and invocation fields."
            ),
            "semantic_limit": (
                "The attestation authenticates the archive digest and builder identity; it does "
                "not establish the semantic truth of workflow-controlled predicate or event data."
            ),
        },
        "claim_boundary": (
            "Nine preserved, separately identified first-attempt workflow outcomes form a balanced "
            "three-version by three-repeat controlled cohort. Successful runs hold one protocol "
            "commit, workflow, kind binary, workload, subject digest, and hosted-runner class "
            "constant while changing the "
            "pinned Kubernetes minor version. The repeats show procedural repeatability only; no "
            "confidence interval, failure-rate inference, or production reliability claim is made. "
            "The workflow generates the joining identifier. This is not identifier discovery, "
            "cross-provider or cross-organization replication, a field deployment, or external "
            "reproduction."
        ),
    }


def render_manifest(root: Path) -> str:
    paths = sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and path.name != "REFERENCE_SHA256SUMS"
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    return "".join(
        f"{sha256(path)}  ./{path.relative_to(root).as_posix()}\n" for path in paths
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    value.add_argument(
        "--target-manifest",
        type=Path,
        default=Path(__file__).resolve().parent / "kubernetes_targets_v1.3.json",
    )
    mode = value.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    summary = summarize(
        args.root,
        args.target_manifest,
        reverify_attestations=args.verify,
    )
    summary_path = args.root / "cross_version_summary.json"
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.write:
        summary_path.write_text(rendered, encoding="utf-8")
        (args.root / "REFERENCE_SHA256SUMS").write_text(
            render_manifest(args.root), encoding="utf-8"
        )
        print(f"Wrote validated cohort summary under {args.root}")
        return 0
    if not summary_path.is_file() or summary_path.read_text(encoding="utf-8") != rendered:
        raise SystemExit("cross_version_summary.json differs from validated source bundles")
    expected_manifest = render_manifest(args.root)
    manifest_path = args.root / "REFERENCE_SHA256SUMS"
    if not manifest_path.is_file() or manifest_path.read_text(encoding="utf-8") != expected_manifest:
        raise SystemExit("REFERENCE_SHA256SUMS differs from the cohort file inventory")
    verify_manifest(args.root, manifest_path)
    print("Cross-version cohort verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
