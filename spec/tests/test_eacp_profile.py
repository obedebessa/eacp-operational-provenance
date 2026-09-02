from __future__ import annotations

import copy
import csv
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SPEC_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = SPEC_ROOT / "tools/eacp_profile.py"
EXAMPLE_PATH = SPEC_ROOT / "examples/valid-record-v1.3.json"

module_spec = importlib.util.spec_from_file_location("eacp_profile", TOOL_PATH)
assert module_spec is not None and module_spec.loader is not None
profile = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(profile)


def valid_record() -> dict:
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


def source_key(record: dict) -> tuple[str, str]:
    return record["source_type"], record["source_id"]


class ProfileSchemaTests(unittest.TestCase):
    def test_schema_documents_are_valid_json_and_tuple_identity_is_required(self) -> None:
        schema_dir = SPEC_ROOT / "schema"
        schemas = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in schema_dir.glob("*.json")
        ]
        self.assertEqual(len(schemas), 3)
        core = next(item for item in schemas if item["title"].endswith("core evidence record"))
        self.assertIn("source_type", core["required"])
        self.assertIn("source_id", core["required"])
        self.assertEqual(core["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_valid_example_passes_reference_validator(self) -> None:
        self.assertEqual(profile.validate_record(valid_record()), [])

    def test_flat_actor_and_unscoped_service_are_rejected(self) -> None:
        record = valid_record()
        record["actors"] = "example-user"
        record["service"] = "checkout-api"
        errors = profile.validate_record(record)
        self.assertTrue(any("$.actors: expected object" in item for item in errors))
        self.assertTrue(any("$.service: expected object" in item for item in errors))

    def test_actor_roles_are_closed_and_missing_roles_are_not_fabricated(self) -> None:
        record = valid_record()
        record["actors"] = {}
        self.assertEqual(profile.validate_record(record), [])

        record = valid_record()
        record["actors"] = {
            "approver": {
                "id": "someone",
                "type": "human",
                "scope": {"type": "organization", "id": "example"},
            }
        }
        errors = profile.validate_record(record)
        self.assertTrue(any("unknown field 'approver'" in item for item in errors))
        self.assertFalse(any("execution_principal" in item for item in errors))

    def test_inferred_confidence_is_required_and_exclusive(self) -> None:
        record = valid_record()
        link = record["links"][0]
        link["evidence_method"] = "inferred"
        errors = profile.validate_record(record)
        self.assertTrue(any("inferred links require" in item for item in errors))

        link["confidence"] = 0.73
        self.assertEqual(profile.validate_record(record), [])

        link["evidence_method"] = "explicit"
        errors = profile.validate_record(record)
        self.assertTrue(any("forbidden unless" in item for item in errors))

    def test_digest_match_and_artifact_digest_are_constrained(self) -> None:
        record = valid_record()
        record["links"][0]["evidence_method"] = "digest_match"
        errors = profile.validate_record(record)
        self.assertTrue(any("valid only for artifact_digest" in item for item in errors))

        record = valid_record()
        artifact = next(link for link in record["links"] if link["type"] == "artifact_digest")
        artifact["value"] = "sha256:not-a-digest"
        errors = profile.validate_record(record)
        self.assertTrue(any("artifact_digest requires" in item for item in errors))

    def test_non_inferred_duplicate_link_key_is_rejected_even_if_method_differs(self) -> None:
        record = valid_record()
        duplicate = copy.deepcopy(record["links"][0])
        duplicate["evidence_method"] = "source_native"
        record["links"].append(duplicate)
        errors = profile.validate_record(record)
        self.assertTrue(any("duplicates typed/scoped key" in item for item in errors))

    def test_optional_source_digest_has_explicit_representation(self) -> None:
        record = valid_record()
        del record["source_digest"]["canonicalization"]
        errors = profile.validate_record(record)
        self.assertTrue(any("canonicalization: required" in item for item in errors))

        record["source_digest"]["representation"] = "raw_bytes"
        self.assertEqual(profile.validate_record(record), [])

    def test_collection_source_identity_is_composite_and_unique(self) -> None:
        first = valid_record()
        same_id_other_type = copy.deepcopy(first)
        same_id_other_type["source_type"] = "kubernetes.audit"
        self.assertEqual(profile.validate_collection([first, same_id_other_type]), [])

        duplicate = copy.deepcopy(first)
        errors = profile.validate_collection([first, duplicate])
        self.assertTrue(any("duplicate source_key" in item for item in errors))

    def test_timestamps_require_an_offset_but_clock_skew_is_allowed(self) -> None:
        record = valid_record()
        record["observed_ts"] = "2026-09-02T13:59:59Z"
        self.assertEqual(profile.validate_record(record), [])
        record["observed_ts"] = "2026-09-02T13:59:59"
        errors = profile.validate_record(record)
        self.assertTrue(any("UTC offset" in item for item in errors))


class SafeResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = valid_record()
        # Keep the test relation surface focused on operational correlation.
        self.seed["links"] = [copy.deepcopy(self.seed["links"][0])]

    def resolve(self, records: list[dict], **overrides: object) -> dict:
        arguments = {
            "source_type": self.seed["source_type"],
            "source_id": self.seed["source_id"],
            "link_type": "operational_correlation",
        }
        arguments.update(overrides)
        return profile.resolve_record_links(records, **arguments)

    def test_missing_link_abstains_without_matches(self) -> None:
        self.seed["links"] = []
        result = self.resolve([self.seed])
        self.assertEqual(result["status"], "missing")
        self.assertTrue(result["abstained"])
        self.assertIsNone(result["selected_link"])
        self.assertEqual(result["matches"], [])

    def test_multivalued_seed_link_abstains_as_ambiguous(self) -> None:
        second = copy.deepcopy(self.seed["links"][0])
        second["value"] = "another-release"
        self.seed["links"].append(second)
        result = self.resolve([self.seed])
        self.assertEqual(result["status"], "ambiguous")
        self.assertTrue(result["abstained"])
        self.assertEqual(result["matches"], [])
        self.assertEqual(len(result["ambiguous_candidates"]), 2)

    def test_exact_resolution_excludes_an_ambiguous_bridge_record(self) -> None:
        peer = copy.deepcopy(self.seed)
        peer["source_type"] = "kubernetes.audit"
        peer["source_id"] = "kubernetes-audit://event-1"

        bridge = copy.deepcopy(peer)
        bridge["source_id"] = "kubernetes-audit://event-bridge"
        another = copy.deepcopy(bridge["links"][0])
        another["value"] = "unrelated-release"
        bridge["links"].append(another)

        result = self.resolve([self.seed, peer, bridge])
        self.assertEqual(result["status"], "resolved")
        self.assertFalse(result["abstained"])
        self.assertEqual(
            {(item["source_type"], item["source_id"]) for item in result["matches"]},
            {source_key(self.seed), source_key(peer)},
        )
        self.assertEqual(
            result["excluded_ambiguous_records"],
            [{"source_type": bridge["source_type"], "source_id": bridge["source_id"]}],
        )

    def test_inferred_links_are_opt_in_and_thresholded(self) -> None:
        link = self.seed["links"][0]
        link["evidence_method"] = "inferred"
        link["confidence"] = 0.8
        self.assertEqual(self.resolve([self.seed])["status"], "missing")
        self.assertEqual(
            self.resolve(
                [self.seed], allow_inferred=True, minimum_confidence=0.81
            )["status"],
            "missing",
        )
        self.assertEqual(
            self.resolve(
                [self.seed], allow_inferred=True, minimum_confidence=0.8
            )["status"],
            "resolved",
        )

    def test_scope_filter_prevents_cross_scope_value_collision(self) -> None:
        same_value = copy.deepcopy(self.seed["links"][0])
        same_value["scope"] = {"type": "environment", "id": "other-environment"}
        self.seed["links"].append(same_value)
        result = self.resolve(
            [self.seed],
            scope_type="environment",
            scope_id="urn:eacp:environment:example:production",
        )
        self.assertEqual(result["status"], "resolved")


class LegacyMigrationTests(unittest.TestCase):
    def legacy_row(self, correlation_id: str = "release-42") -> dict[str, str]:
        return {
            "source_type": "kubernetes.audit",
            "source_id": "audit-42:ResponseComplete",
            "source_ts": "2026-09-02T14:00:00Z",
            "observed_ts": "2026-09-02T14:00:01Z",
            "actor": "system:serviceaccount:demo:deployer",
            "service": "demo/checkout-api",
            "intent": "operational_provenance",
            "policy": "kubernetes-rbac-admission",
            "action": "patch",
            "outcome": "200",
            "source_pointer": "kubernetes-audit://audit-42",
            "correlation_id": correlation_id,
            "content_hash": "a" * 64,
        }

    def test_migration_preserves_all_13_values_without_digest_promotion(self) -> None:
        original = self.legacy_row()
        record = profile.migrate_legacy_row(
            original,
            scope_type="legacy_dataset",
            scope_id="urn:eacp:dataset:test",
        )
        self.assertEqual(profile.validate_record(record), [])
        self.assertEqual(
            record["extensions"]["org.eacp/legacy_v1_2"]["original_row"], original
        )
        self.assertNotIn("source_digest", record)
        self.assertEqual(record["source_type"], original["source_type"])
        self.assertEqual(record["source_id"], original["source_id"])
        self.assertEqual(
            record["actors"]["execution_principal"]["type"], "legacy_opaque"
        )
        self.assertEqual(record["service"]["type"], "legacy_opaque")
        self.assertEqual(record["links"][0]["evidence_method"], "explicit")

    def test_missing_legacy_correlation_becomes_no_link_and_abstains(self) -> None:
        record = profile.migrate_legacy_row(
            self.legacy_row(correlation_id=""),
            scope_type="legacy_dataset",
            scope_id="urn:eacp:dataset:test",
        )
        self.assertEqual(record["links"], [])
        result = profile.resolve_record_links(
            [record],
            source_type=record["source_type"],
            source_id=record["source_id"],
            link_type="operational_correlation",
        )
        self.assertEqual(result["status"], "missing")
        self.assertTrue(result["abstained"])

    def test_csv_migration_accepts_reordered_exact_header_and_cli_validates_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "legacy.csv"
            output = directory / "migrated.jsonl"
            fields = tuple(reversed(profile.LEGACY_FIELDS))
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow(self.legacy_row())
            migrate = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "migrate",
                    str(source),
                    str(output),
                    "--scope-type",
                    "legacy_dataset",
                    "--scope-id",
                    "urn:eacp:dataset:test",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(migrate.returncode, 0, migrate.stdout + migrate.stderr)
            summary = json.loads(migrate.stdout)
            self.assertFalse(summary["source_digest_promoted_from_legacy_content_hash"])
            validate = subprocess.run(
                [sys.executable, str(TOOL_PATH), "validate", str(output)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(validate.returncode, 0, validate.stdout + validate.stderr)
            self.assertTrue(json.loads(validate.stdout)["valid"])

    def test_csv_header_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "legacy.csv"
            fields = list(profile.LEGACY_FIELDS) + ["unexpected"]
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({**self.legacy_row(), "unexpected": "value"})
            with self.assertRaisesRegex(profile.ProfileError, "header differs"):
                profile.read_legacy_csv(
                    source,
                    scope_type="legacy_dataset",
                    scope_id="urn:eacp:dataset:test",
                )


if __name__ == "__main__":
    unittest.main()
