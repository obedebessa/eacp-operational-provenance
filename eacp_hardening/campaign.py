"""Finite, author-executed fault campaign; NOT an independent or field study."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import platform
import random
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import __version__
from .common import HardeningError, Principal, canonical_bytes
from .integrity import AnchorPolicy, create_checkpoint, digest, verify_checkpoint
from .privacy import project_kubernetes_audit
from .store import ConflictError, EvidenceStore, QueueFullError
from .trust import CollectorPolicy, TrustRegistry, sign_statement

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_TIME = "2026-09-04T12:00:00Z"
FIXTURE_ORIGIN = "https://source.fixture.invalid"


def _audit_fixture() -> dict:
    return {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "fixture-audit-1",
            "stage": "ResponseComplete", "requestReceivedTimestamp": FIXTURE_TIME,
            "stageTimestamp": FIXTURE_TIME, "verb": "patch", "user": {"username": "fixture-operator"},
            "objectRef": {"apiGroup": "apps", "resource": "deployments", "namespace": "fixture", "name": "service"},
            "requestObject": {"metadata": {"name": "service", "namespace": "fixture", "uid": "fixture-uid",
                "annotations": {"eacp.io/correlation-id": "fixture-correlation-1"}}},
            "responseStatus": {"code": 200}}


def run_campaign(*, seeds: int = 5, events: int = 40) -> dict:
    if not 1 <= seeds <= 100 or not 10 <= events <= 1000:
        raise HardeningError("campaign bounds: 1..100 seeds and 10..1000 events")
    cases: list[dict] = []
    observations: list[dict] = []

    def check(name, condition, *, category="control", detail=None):
        cases.append({"id": name, "category": category, "passed": bool(condition), "detail": detail})

    def rejects(name, function):
        try:
            function()
        except HardeningError:
            check(name, True)
        else:
            check(name, False)

    # Public deterministic fixture identities, NEVER deployment credentials.
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"EACP PUBLIC TEST COLLECTOR ONLY").digest())
    anchor_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"EACP PUBLIC TEST ANCHOR ONLY").digest())
    storage_key = hashlib.sha256(b"EACP PUBLIC TEST ENCRYPTION ONLY").digest()
    policy = CollectorPolicy("fixture-collector-key", key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                             "fixture-tenant", "fixture-source", "fixture-collector", "a" * 64,
                             "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z", (FIXTURE_ORIGIN,), True)
    registry = TrustRegistry([policy])
    principal = Principal("fixture-operator", "fixture-tenant", frozenset({"writer", "reader", "operator", "auditor"}))
    raw = _audit_fixture()
    raw["requestObject"]["metadata"]["annotations"]["example.invalid/note"] = "CANARY_ANNOTATION_14"
    raw["requestObject"]["spec"] = {"containers": [{"env": [{"name": "PASSWORD", "value": "CANARY_ENV_14"}]}]}
    raw["requestObject"]["data"] = {"application_password": "CANARY_CONFIG_14"}
    raw["requestURI"] = "/api/v1/pods?credential=CANARY_QUERY_14"
    projected = project_kubernetes_audit(raw, namespace="fixture")
    public_bytes = canonical_bytes({"payload": projected.payload, "report": projected.report})
    for surface in ("ANNOTATION", "ENV", "CONFIG", "QUERY"):
        check("privacy_" + surface.lower(), ("CANARY_" + surface + "_14").encode() not in public_bytes)
    check("privacy_correlation_preserved", projected.payload["requestObject"]["metadata"]["annotations"]["eacp.io/correlation-id"] == "fixture-correlation-1")

    def statement(content, kind="event"):
        body = {"kind": kind, "tenant_id": policy.tenant_id, "source_id": policy.source_id,
                "collector_id": policy.collector_id, "issued_at": FIXTURE_TIME, "adapter_sha256": policy.adapter_sha256,
                "acquisition": {"method": "fixture", "origin": FIXTURE_ORIGIN, "raw_sha256": hashlib.sha256(canonical_bytes(raw)).hexdigest()},
                "content": content}
        return sign_statement(body, key_id=policy.key_id, private_key=key)

    def event(index):
        return registry.verify(statement({"event_id": f"event-{index:04d}", "sequence": index,
                                          "source_ts": FIXTURE_TIME, "payload": projected.payload}), now=FIXTURE_TIME)

    sample = statement({"event_id": "event-0000", "sequence": 0, "source_ts": FIXTURE_TIME, "payload": projected.payload})
    check("source_signature_valid", registry.verify(sample, now=FIXTURE_TIME).source_id == policy.source_id)
    altered = copy.deepcopy(sample)
    altered["body"]["content"]["event_id"] = "forged"
    rejects("source_signature_alteration", lambda: registry.verify(altered, now=FIXTURE_TIME))
    rejects("source_key_revocation", lambda: TrustRegistry([replace(policy, revoked=True)]).verify(sample, now=FIXTURE_TIME))
    rejects("source_wrong_scope", lambda: TrustRegistry([replace(policy, tenant_id="another-tenant")]).verify(sample, now=FIXTURE_TIME))
    rejects("source_freshness", lambda: registry.verify(sample, now="2026-09-04T12:06:00Z"))
    false_content = {"event_id": "false-fixture", "sequence": 99, "source_ts": FIXTURE_TIME,
                     "payload": {"claim": "intentionally false but correctly signed"}}
    accepted_false = registry.verify(statement(false_content), now=FIXTURE_TIME)
    check("source_semantic_falsehood_remains_undetectable", accepted_false.payload == false_content["payload"],
          category="boundary", detail="Signature authenticates the collector statement, not source truth.")

    expected = [f"event-{i:04d}" for i in range(events)]
    inventory = registry.verify(statement({"inventory_id": "finite-inventory-1", "expected_event_ids": expected}, "inventory"), now=FIXTURE_TIME)
    with tempfile.TemporaryDirectory(prefix="eacp-hardening-campaign-") as work:
        work = Path(work)
        for seed in range(seeds):
            for loss_rate in (0.0, 0.05, 0.20):
                label = f"seed-{seed}-loss-{int(loss_rate * 100)}"
                path = work / (label + ".sqlite")
                rng = random.Random(seed)
                order = list(range(events))
                rng.shuffle(order)
                lost = set(order[:int(events * loss_rate)])
                delivered = [i for i in order if i not in lost]
                with EvidenceStore(path, storage_key, max_pending=events + 1) as store:
                    store.register_inventory(principal, inventory)
                    duplicates = 0
                    for position, index in enumerate(delivered):
                        store.enqueue(principal, event(index))
                        if position % 7 == 0:
                            duplicates += store.enqueue(principal, event(index))["status"] == "duplicate"
                    store.drain(principal)
                    before = store.status(principal, policy.source_id)
                # A real connection/process-lifetime boundary, not a counter reset.
                with EvidenceStore(path, storage_key) as store:
                    after_restart = store.status(principal, policy.source_id)
                    check(label + "_restart", before["status"] == after_restart["status"])
                    check(label + "_no_silent_completeness", before["status"] == ("INCOMPLETE" if lost else "COMPLETE"))
                    check(label + "_distinct_count", len(store.read_events(principal, policy.source_id)) == len(delivered))
                    for index in sorted(lost):
                        store.enqueue(principal, event(index))
                    store.drain(principal)
                    final = store.status(principal, policy.source_id)
                    check(label + "_late_recovery", final["status"] == "COMPLETE" and len(store.read_events(principal, policy.source_id)) == events)
                observations.append({"seed": seed, "loss_rate": loss_rate, "expected": events,
                                     "initial_delivered_distinct": len(delivered), "initial_missing": len(lost),
                                     "duplicate_attempts": duplicates, "initial_status": before["status"],
                                     "after_recovery_status": final["status"], "recovered_distinct": events})

        with EvidenceStore(work / "controls.sqlite", storage_key, max_pending=2) as store:
            store.enqueue(principal, event(0))
            old_material = store.checkpoint_material(principal)
            old_checkpoint = create_checkpoint(old_material, sequence=1, issued_at=FIXTURE_TIME, key_id="fixture-anchor", private_key=anchor_key)
            store.enqueue(principal, event(1))
            rejects("queue_full_rejects_without_ack", lambda: store.enqueue(principal, event(2)))
            check("unknown_source_completeness", store.status(principal, policy.source_id)["status"] == "UNKNOWN", category="boundary")
            store.drain(principal)
            rejects("conflicting_event_is_not_overwritten", lambda: store.enqueue(principal, replace(event(0), payload={"changed": True})))
            check("conflict_quarantined", len(store.read_quarantine(principal)) == 1)
            rejects("cross_tenant_write_denied", lambda: store.enqueue(replace(principal, tenant_id="other"), event(2)))
            rejects("writer_cannot_read", lambda: store.read_events(replace(principal, roles=frozenset({"writer"})), policy.source_id))
            check("other_tenant_cannot_observe_records", store.read_events(replace(principal, tenant_id="other"), policy.source_id) == [])
            material = store.checkpoint_material(principal)
            checkpoint = create_checkpoint(material, sequence=2, issued_at=FIXTURE_TIME, key_id="fixture-anchor", private_key=anchor_key,
                                           previous_checkpoint_sha256=digest(old_checkpoint))
            anchor = AnchorPolicy("fixture-anchor", anchor_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                  policy.tenant_id, store.store_id, digest(checkpoint), 2)
            check("external_checkpoint_intact", verify_checkpoint(material, checkpoint, anchor, now=FIXTURE_TIME)["status"] == "VERIFIED_RELATIVE_TO_CHECKPOINT")
            changed = copy.deepcopy(material)
            changed["events"] = changed["events"][:-1]
            rejects("external_checkpoint_truncation", lambda: verify_checkpoint(changed, checkpoint, anchor, now=FIXTURE_TIME))
            forged_manifest = {**checkpoint, "material_sha256": digest(changed)}
            rejects("consistent_content_manifest_replacement", lambda: verify_checkpoint(changed, forged_manifest, anchor, now=FIXTURE_TIME))
            rejects("old_valid_snapshot_rollback", lambda: verify_checkpoint(old_material, old_checkpoint, anchor, now=FIXTURE_TIME))
            check("without_external_anchor_unknown", verify_checkpoint(old_material, old_checkpoint, None, now=FIXTURE_TIME)["status"] == "UNKNOWN", category="boundary")
            store.set_hold(principal, policy.source_id, "event-0000", True, "synthetic preservation hold")
            store.prune(principal, "2100-01-01T00:00:00Z", "synthetic retention test")
            check("retention_hold_honored", [e["event_id"] for e in store.read_events(principal, policy.source_id)] == ["event-0000"])
            check("retained_tombstone_no_resurrection", store.enqueue(principal, event(1))["status"] == "pruned")
            check("access_denials_audited", any(row["outcome"] == "denied" for row in store.audit_log(principal)))

    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        revision, dirty = "unavailable", None
    return {"schema": "eacp.hardening-campaign/1.4", "software_version": __version__,
            "method": "author_executed_finite_synthetic_fault_campaign", "fixture_time": FIXTURE_TIME,
            "environment": {"python": platform.python_version(), "cryptography": cryptography.__version__,
                            "platform": platform.platform(), "source_commit": revision, "working_tree_dirty": dirty},
            "design": {"seeds": seeds, "events_per_case": events, "initial_loss_rates": [0, 0.05, 0.20]},
            "summary": {"checks": len(cases), "passed": sum(c["passed"] for c in cases),
                        "failed": sum(not c["passed"] for c in cases),
                        "boundary_demonstrations": sum(c["category"] == "boundary" for c in cases)},
            "cases": cases, "ingestion_observations": observations,
            "not_established": ["independent reproduction", "real organizational pilot", "live v1.4 GitHub attestation",
                                "source semantic truth", "production HA or privacy certification",
                                "rollback protection when the external anchor authority is compromised"],
            "fixture_key_warning": "All campaign credentials are public test fixtures; never use them in deployment."}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--events", type=int, default=40)
    args = parser.parse_args(argv)
    if args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
        parser.error("output must be absent or an empty directory; existing evidence is never overwritten")
    args.output.mkdir(parents=True, exist_ok=True)
    report = run_campaign(seeds=args.seeds, events=args.events)
    (args.output / "campaign.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    rows = report["ingestion_observations"]
    with (args.output / "ingestion.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    source_files = sorted((ROOT / "eacp_hardening").glob("*.py"))
    (args.output / "SOURCE_SHA256SUMS").write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(ROOT).as_posix() + "\n" for path in source_files))
    print(json.dumps(report["summary"], sort_keys=True))
    return 1 if report["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
