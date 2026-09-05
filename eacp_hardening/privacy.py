"""Explicit public projections; unlisted input is never copied to output/reports.

This is a bounded publication policy, not a universal secret detector. Identity
fields remain attributable and require a disclosure review before publication.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from .common import HardeningError, identifier, utc_time


POLICY = "eacp.public-projection/1.4.0"


@dataclass(frozen=True)
class ProjectionResult:
    payload: dict[str, Any]
    report: dict[str, Any]


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise HardeningError("public projection requires a JSON object with string keys")
    return value


def _pattern(pattern: str, *, empty: bool = False) -> Callable[[Any], str]:
    def validate(value: Any) -> str:
        if value == "" and empty:
            return ""
        value = identifier(value, "public identifier")
        if not re.fullmatch(pattern, value, flags=re.ASCII):
            raise HardeningError("public identifier does not match its declared syntax")
        return value
    return validate


_ID = _pattern(r"[A-Za-z0-9][A-Za-z0-9_.:/+@-]{0,511}")
_NAME = _pattern(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}")
_GROUP = _pattern(r"[a-z0-9][a-z0-9.-]{0,252}", empty=True)
_SHA = _pattern(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_DIGEST = _pattern(r"sha256:[0-9a-f]{64}")
_DECIMAL = _pattern(r"[1-9][0-9]{0,19}")
_CORRELATION = _pattern(r"[A-Za-z0-9](?:[A-Za-z0-9._:/+-]{0,254}[A-Za-z0-9])?")
_REPOSITORY_SYNTAX = _pattern(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_OCI = _pattern(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:/[a-z0-9][a-z0-9._-]*)+")


def _integer(value: Any) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise HardeningError("public identifier must be a positive integer")
    return value


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise HardeningError("public projection expected a boolean")
    return value


def _time(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value):
        raise HardeningError("public timestamp requires an RFC3339 UTC instant")
    try:
        utc_time(value)
    except HardeningError:
        raise HardeningError("public timestamp is invalid") from None
    return value


def _repository(value: Any) -> str:
    value = _REPOSITORY_SYNTAX(value)
    if any(component in {".", ".."} for component in value.split("/")):
        raise HardeningError("public repository identity contains a path traversal segment")
    return value


def _enum(*values: str) -> Callable[[Any], str]:
    def validate(value: Any) -> str:
        if not isinstance(value, str) or value not in values:
            raise HardeningError("public projection received an unsupported enumerated value")
        return value
    return validate


def _nullable(rule: Callable[[Any], Any]) -> Callable[[Any], Any]:
    return lambda value: None if value is None else rule(value)


class _Projector:
    def __init__(self, source_type: str):
        self.source_type = source_type
        self.drops: Counter[tuple[str, str]] = Counter()

    def drop(self, path: str, count: int = 1, reason: str = "not_allowlisted") -> None:
        if count:
            self.drops[path, reason] += count

    def object(self, value: Any, rules: dict[str, Callable[[Any], Any]],
               path: str = "", required: tuple[str, ...] = ()) -> dict[str, Any]:
        value = _mapping(value)
        if any(key not in value for key in required):
            raise HardeningError("required public linkage field is missing")
        # Unknown field names may themselves contain secrets. The report uses a
        # static wildcard, never those names, hashes, source IDs, or raw values.
        self.drop(path + "/*", sum(key not in rules for key in value))
        result = {}
        for key, rule in rules.items():
            if key in value:
                result[key] = rule(value[key])
        return result

    def result(self, payload: dict[str, Any]) -> ProjectionResult:
        entries = [{"path": path, "reason": reason, "count": count}
                   for (path, reason), count in sorted(self.drops.items())]
        return ProjectionResult(payload, {
            "policy": POLICY,
            "source_type": self.source_type,
            "dropped_member_count": sum(self.drops.values()),
            "drops": entries,
            "raw_values_retained_in_report": False,
            "manual_publication_review_required": True,
            "unknown_subtrees_are_counted_once": True,
        })


def project_kubernetes_audit(record: Any, *, namespace: str | None = None) -> ProjectionResult:
    """Project one audit event, retaining exact identity and declared typed links.

    Missing/malformed required linkage identity rejects the whole event. Secret
    resources reject the whole event. Every body subtree except allowlisted
    object metadata is omitted; requestURI is omitted in its entirety.
    """
    p = _Projector("kubernetes.audit")

    def metadata(value: Any, path: str) -> dict[str, Any]:
        annotations = {
            "eacp.io/correlation-id": _CORRELATION,
            "eacp.io/github-repository-id": _DECIMAL,
            "eacp.io/github-run-id": _DECIMAL,
            "eacp.io/github-run-attempt": _DECIMAL,
            "eacp.io/github-commit-sha": _SHA,
            "eacp.io/subject-uri": _OCI,
            "eacp.io/subject-digest": _DIGEST,
        }
        result = p.object(value, {
            "name": _NAME, "namespace": _NAME, "uid": _ID,
            "labels": lambda item: p.object(item, {"app.kubernetes.io/name": _NAME}, path + "/labels"),
            "annotations": lambda item: p.object(item, annotations, path + "/annotations"),
        }, path)
        links = result.get("annotations", {})
        if ("eacp.io/subject-uri" in links) != ("eacp.io/subject-digest" in links):
            raise HardeningError("artifact URI and digest must be supplied together")
        return result

    def body(value: Any, path: str) -> dict[str, Any]:
        # JSON Patch arrays are legal API bodies but carry no public metadata
        # under this policy. Never recurse into their arbitrary path/value pairs.
        if isinstance(value, list) or value is None:
            p.drop(path, reason="body_without_allowlisted_metadata")
            return {}
        return p.object(value, {"metadata": lambda item: metadata(item, path + "/metadata")}, path)

    def code(value: Any) -> int:
        if type(value) is not int or not 100 <= value <= 599:
            raise HardeningError("audit HTTP status must be an integer from 100 through 599")
        return value

    actor = lambda item, path: p.object(item, {"username": _ID}, path, ("username",))
    payload = p.object(record, {
        "kind": _enum("Event"), "apiVersion": _enum("audit.k8s.io/v1"),
        "auditID": _ID,
        "stage": _enum("RequestReceived", "ResponseStarted", "ResponseComplete", "Panic"),
        "requestReceivedTimestamp": _time, "stageTimestamp": _time,
        "verb": _enum("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "connect", "proxy"),
        "user": lambda item: actor(item, "/user"),
        "impersonatedUser": lambda item: actor(item, "/impersonatedUser"),
        "objectRef": lambda item: p.object(item, {
            "apiGroup": _GROUP, "apiVersion": _NAME, "resource": _NAME,
            "namespace": _NAME, "name": _NAME, "uid": _ID, "subresource": _NAME,
        }, "/objectRef", ("resource", "namespace")),
        "requestObject": lambda item: body(item, "/requestObject"),
        "responseObject": lambda item: body(item, "/responseObject"),
        # reason/message/status are free text and unnecessary for an exact 403
        # control. Preserve the integer code only, not guessed message redaction.
        "responseStatus": lambda item: p.object(item, {"code": code}, "/responseStatus", ("code",)),
    }, required=("auditID", "stage", "requestReceivedTimestamp", "stageTimestamp", "verb", "user", "objectRef", "responseStatus"))
    ref = payload["objectRef"]
    if namespace is not None and ref["namespace"] != _NAME(namespace):
        raise HardeningError("audit record is outside the declared namespace")
    if ref["resource"] in {"secrets", "tokenreviews", "subjectaccessreviews", "selfsubjectaccessreviews", "localsubjectaccessreviews"} or ref.get("subresource") == "token":
        raise HardeningError("sensitive audit resource is not publishable")
    for name in ("requestObject", "responseObject"):
        meta = payload.get(name, {}).get("metadata", {})
        for key in ("name", "namespace"):
            if key in meta and key in ref and meta[key] != ref[key]:
                raise HardeningError("audit object identity conflicts with its source reference")
    request_links = payload.get("requestObject", {}).get("metadata", {}).get("annotations", {})
    response_links = payload.get("responseObject", {}).get("metadata", {}).get("annotations", {})
    if any(request_links[key] != response_links[key] for key in request_links.keys() & response_links.keys()):
        raise HardeningError("audit request and response linkage declarations conflict")
    return p.result(payload)


_STATUS = _enum("queued", "in_progress", "completed", "waiting", "pending", "requested")
_CONCLUSION = _nullable(_enum("success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure"))


def project_github_metadata(record: Any, *, kind: str = "run") -> ProjectionResult:
    """Allowlist one public GitHub run/job/artifact REST object.

    Human-readable names, branch names, workflow paths, arbitrary URLs, logs,
    runner IDs, event payloads and commit messages are not publication fields.
    A run's public URL is reconstructed from its validated repository and ID.
    """
    p = _Projector("github.actions." + kind if kind in {"run", "job", "artifact"} else "unsupported")
    if kind not in {"run", "job", "artifact"}:
        raise HardeningError("unsupported GitHub projection kind")

    def repository(value: Any) -> dict[str, Any]:
        result = p.object(value, {"id": _integer, "full_name": _repository, "private": _boolean}, "/repository", ("id", "full_name", "private"))
        if result["private"]:
            raise HardeningError("private repository is not publishable by the public projection")
        return result

    def actor(value: Any, path: str) -> dict[str, Any]:
        return p.object(value, {"id": _integer, "login": _pattern(r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\[bot\])?"), "type": _enum("User", "Bot", "Organization", "Mannequin")}, path, ("id", "login"))

    rules: dict[str, Callable[[Any], Any]] = {"id": _integer}
    required = ("id",)
    if kind == "run":
        rules.update({
            "repository": repository, "run_attempt": _integer, "run_number": _integer,
            "workflow_id": _integer, "head_sha": _SHA, "status": _STATUS,
            "conclusion": _CONCLUSION, "created_at": _time, "updated_at": _time,
            "run_started_at": _nullable(_time),
            "actor": lambda item: actor(item, "/actor"),
            "triggering_actor": lambda item: actor(item, "/triggering_actor"),
        })
        required += ("repository", "run_attempt", "head_sha", "created_at", "updated_at", "actor")
    elif kind == "job":
        rules.update({"run_id": _integer, "run_attempt": _integer, "status": _STATUS,
                      "conclusion": _CONCLUSION, "created_at": _nullable(_time),
                      "started_at": _nullable(_time), "completed_at": _nullable(_time)})
        required += ("run_id", "run_attempt")
    else:
        rules.update({"digest": _nullable(_DIGEST), "expired": _boolean,
                      "created_at": _time, "updated_at": _time, "expires_at": _nullable(_time),
                      "workflow_run": lambda item: p.object(item, {
                          "id": _integer, "repository_id": _integer, "head_sha": _SHA,
                      }, "/workflow_run", ("id",))})
        required += ("workflow_run",)
    payload = p.object(record, rules, required=required)
    if kind == "run":
        payload["html_url"] = f"https://github.com/{payload['repository']['full_name']}/actions/runs/{payload['id']}"
    return p.result(payload)


def project_github_actions(run: Any, jobs: Any, artifacts: Any) -> ProjectionResult:
    """Project a finite run bundle and reject mismatched/duplicate source IDs."""
    if not isinstance(jobs, list) or not isinstance(artifacts, list):
        raise HardeningError("GitHub jobs and artifacts must be arrays")
    run_result = project_github_metadata(run)
    job_results = [project_github_metadata(value, kind="job") for value in jobs]
    artifact_results = [project_github_metadata(value, kind="artifact") for value in artifacts]
    payload = run_result.payload
    for result in job_results:
        if result.payload["run_id"] != payload["id"] or result.payload["run_attempt"] != payload["run_attempt"]:
            raise HardeningError("GitHub job is outside the declared run and attempt")
    for result in artifact_results:
        link = result.payload["workflow_run"]
        if link["id"] != payload["id"] or ("repository_id" in link and link["repository_id"] != payload["repository"]["id"]) or ("head_sha" in link and link["head_sha"] != payload["head_sha"]):
            raise HardeningError("GitHub artifact is outside the declared run identity")
    for group in (job_results, artifact_results):
        if len({result.payload["id"] for result in group}) != len(group):
            raise HardeningError("duplicate GitHub source identifier")
    p = _Projector("github.actions.bundle")
    for prefix, group in (("/run", [run_result]), ("/jobs/*", job_results), ("/artifacts/*", artifact_results)):
        for result in group:
            for item in result.report["drops"]:
                p.drop(prefix + item["path"], item["count"], item["reason"])
    return p.result({"run": payload, "jobs": sorted((r.payload for r in job_results), key=lambda item: item["id"]),
                     "artifacts": sorted((r.payload for r in artifact_results), key=lambda item: item["id"])})


def check_oci_digest(declared: Any, observed: Any) -> dict[str, Any]:
    """Exact digest comparison independent of operational correlation.

    The caller supplies observations and establishes their trust separately.
    A matching annotation alone is not an observation of a running artifact.
    """
    return {"comparison": "exact_sha256", "matched": _DIGEST(declared) == _DIGEST(observed),
            "independent_of_correlation": True, "source_authenticity_established": False}
