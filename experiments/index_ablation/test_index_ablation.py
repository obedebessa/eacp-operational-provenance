from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


EXPERIMENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXPERIMENT_DIR))

import index_ablation as experiment  # noqa: E402


class IndexAblationTests(unittest.TestCase):
    def test_original_benchmark_is_imported_and_anchored(self) -> None:
        self.assertEqual(
            Path(experiment.ORIGINAL.__file__).resolve(),
            experiment.BENCHMARK_PATH.resolve(),
        )
        self.assertEqual(
            experiment.sha256_file(experiment.BENCHMARK_PATH),
            hashlib.sha256(experiment.BENCHMARK_PATH.read_bytes()).hexdigest(),
        )
        generated = list(experiment.ORIGINAL.generate_events(13, 4, 9238))
        self.assertEqual(
            generated[0], experiment.ORIGINAL.make_event(0, 4, 9238)
        )
        self.assertEqual(len(generated), 13)

    def test_schema_treatments_remove_only_requested_indexes(self) -> None:
        original_without_lookup_indexes = experiment.ORIGINAL.EACP_SCHEMA.replace(
            experiment.SERVICE_INDEX_SQL, ""
        ).replace(experiment.CORRELATION_INDEX_SQL, "")
        self.assertEqual(
            experiment.schema_for_variant(
                experiment.VARIANT_BY_NAME["no_lookup_indexes"]
            ),
            original_without_lookup_indexes,
        )

        for variant in experiment.VARIANTS:
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript(experiment.schema_for_variant(variant))
                self.assertEqual(
                    experiment.user_index_names(connection),
                    experiment._expected_indexes(variant),
                )
                table_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='evidence'"
                ).fetchone()[0]
                self.assertIn("UNIQUE(source_type, source_id)", table_sql)
                trigger_count = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"
                ).fetchone()[0]
                self.assertEqual(trigger_count, 2)
            finally:
                connection.close()

    def test_query_keys_match_original_schedule(self) -> None:
        event_count = 1_003
        services = 17
        samples = 11
        seed = 9238
        service_keys, correlation_keys = experiment.exact_query_keys(
            event_count, services, samples, seed
        )

        import random

        rng = random.Random(seed + 77)
        expected_service = [
            f"svc-{rng.randrange(services):04d}" for _ in range(samples)
        ]
        chain_count = (
            event_count + len(experiment.ORIGINAL.SOURCE_TYPES) - 1
        ) // len(experiment.ORIGINAL.SOURCE_TYPES)
        expected_correlation = [
            f"corr-{seed:04d}-{rng.randrange(chain_count):08d}"
            for _ in range(samples)
        ]
        self.assertEqual(service_keys, expected_service)
        self.assertEqual(correlation_keys, expected_correlation)

    def test_tiny_campaign_is_equivalent_and_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "results"
            args = Namespace(
                sizes=[600],
                trials=2,
                services=20,
                query_samples=8,
                cold_open_samples=2,
                output=output,
                keep_databases=False,
            )
            experiment.run_campaign(args)

            self.assertEqual(experiment.verify_checksums(output), [])
            self.assertFalse((output / "work").exists())
            for name in experiment.RESULT_FILENAMES:
                self.assertTrue((output / name).is_file(), name)

            with (output / "trial_results.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                trial_rows = list(csv.DictReader(handle))
            self.assertEqual(len(trial_rows), 2 * len(experiment.VARIANTS))
            self.assertTrue(
                all(row["all_outputs_equivalent"] == "1" for row in trial_rows)
            )
            self.assertEqual(
                len({row["full_projection_sha256"] for row in trial_rows}), 2
            )
            self.assertTrue(all(row["integrity_check"] == "ok" for row in trial_rows))

            with (output / "query_measurements.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                warm_rows = list(csv.DictReader(handle))
            self.assertEqual(len(warm_rows), 2 * 2 * 8)
            self.assertEqual({row["query_type"] for row in warm_rows}, {
                "service",
                "correlation",
            })

            with (output / "cold_open_measurements.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                cold_rows = list(csv.DictReader(handle))
            self.assertEqual(len(cold_rows), 2 * 2 * 2)

            plans = json.loads(
                (output / "query_plans.json").read_text(encoding="utf-8")
            )["plans"]
            self.assertEqual(len(plans), len(experiment.VARIANTS))
            by_variant = {row["variant"]: row for row in plans}
            self.assertEqual(
                by_variant["full_indexes"]["service_uses_target_index"], 1
            )
            self.assertEqual(
                by_variant["full_indexes"]["correlation_uses_target_index"], 1
            )
            self.assertEqual(
                by_variant["no_lookup_indexes"]["service_uses_target_index"], 0
            )
            self.assertEqual(
                by_variant["no_lookup_indexes"][
                    "correlation_uses_target_index"
                ],
                0,
            )

            summary = json.loads(
                (output / "summary_results.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary["inferential_statistics"])
            self.assertEqual(summary["analysis_unit"], "one event-count/seed trial")
            self.assertEqual(len(summary["rows"]), len(experiment.VARIANTS))
            self.assertTrue(
                all(row["trials"] == 2 for row in summary["rows"])
            )
            method = json.loads((output / "method.json").read_text(encoding="utf-8"))
            self.assertEqual(
                method["experiment_source_sha256"],
                experiment.sha256_file(experiment.EXPERIMENT_SOURCE_PATH),
            )
            self.assertEqual(
                method["benchmark_source_sha256"],
                experiment.sha256_file(experiment.BENCHMARK_PATH),
            )

    def test_checksum_verifier_detects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            for name in experiment.RESULT_FILENAMES:
                (output / name).write_text(f"{name}\n", encoding="utf-8")
            (output / "method.json").write_text(
                json.dumps(
                    {
                        "experiment_source_sha256": experiment.sha256_file(
                            experiment.EXPERIMENT_SOURCE_PATH
                        ),
                        "benchmark_source_sha256": experiment.sha256_file(
                            experiment.BENCHMARK_PATH
                        ),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            experiment.write_checksums(output)
            self.assertEqual(experiment.verify_checksums(output), [])
            (output / experiment.RESULT_FILENAMES[0]).write_text(
                "changed\n", encoding="utf-8"
            )
            self.assertIn(
                f"checksum mismatch: {experiment.RESULT_FILENAMES[0]}",
                experiment.verify_checksums(output),
            )

    def test_frozen_reference_contract(self) -> None:
        reference = EXPERIMENT_DIR / "results" / "reference"
        self.assertEqual(experiment.verify_checksums(reference), [])

        method = json.loads((reference / "method.json").read_text(encoding="utf-8"))
        self.assertEqual(method["event_counts"], [10_000, 50_000, 100_000])
        self.assertEqual(method["trials_per_event_count"], 10)
        self.assertEqual(method["warm_query_samples_per_type_per_trial"], 300)
        self.assertEqual(method["cold_open_samples_per_type_per_trial"], 20)
        self.assertEqual(len(method["seeds"]), 10)

        with (reference / "trial_results.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            trial_rows = list(csv.DictReader(handle))
        self.assertEqual(len(trial_rows), 3 * 10 * len(experiment.VARIANTS))
        self.assertTrue(
            all(row["all_outputs_equivalent"] == "1" for row in trial_rows)
        )
        self.assertTrue(all(row["integrity_check"] == "ok" for row in trial_rows))

        digest_sets: dict[tuple[str, str], set[str]] = {}
        for row in trial_rows:
            key = (row["event_count"], row["trial"])
            digest_sets.setdefault(key, set()).add(row["full_projection_sha256"])
        self.assertEqual(len(digest_sets), 30)
        self.assertTrue(all(len(values) == 1 for values in digest_sets.values()))

        plans = json.loads(
            (reference / "query_plans.json").read_text(encoding="utf-8")
        )["plans"]
        self.assertEqual(len(plans), 3 * len(experiment.VARIANTS))
        for row in plans:
            variant = experiment.VARIANT_BY_NAME[row["variant"]]
            self.assertEqual(
                row["service_uses_target_index"], int(variant.service_index)
            )
            self.assertEqual(
                row["correlation_uses_target_index"],
                int(variant.correlation_index),
            )


if __name__ == "__main__":
    unittest.main()
