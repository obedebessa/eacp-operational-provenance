from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from correlation_robustness import (
    DEFAULT_SOURCE_OFFSETS_MS,
    SOURCE_TYPES,
    apply_scenario,
    correlation_only_reconstruct,
    evaluate,
    generate_events,
    main,
    parse_args,
    run_campaign,
    strict_reconstruct,
    temporal_reconstruct,
)


SEED = 104729
CHAINS = 120
SERVICES = 12
OVERLAP = 0.25
TEMPORAL_WINDOW_MS = 1500
MAXIMUM_CHAIN_SPAN_MS = max(DEFAULT_SOURCE_OFFSETS_MS)


def pristine_events():
    return generate_events(CHAINS, SERVICES, SEED, OVERLAP)


class CorrelationRobustnessTests(unittest.TestCase):
    def test_generator_is_deterministic_and_has_six_plane_ground_truth(self) -> None:
        first = pristine_events()
        second = pristine_events()
        self.assertEqual(first, second)
        self.assertEqual(len(first), CHAINS * len(SOURCE_TYPES))

        per_chain: dict[str, set[str]] = {}
        for event in first:
            per_chain.setdefault(event.truth_chain_id, set()).add(event.source_type)
        self.assertEqual(len(per_chain), CHAINS)
        self.assertTrue(all(planes == set(SOURCE_TYPES) for planes in per_chain.values()))

    def test_strict_control_exactly_recovers_ground_truth(self) -> None:
        events = pristine_events()
        result = evaluate(
            events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        self.assertEqual(result["complete_chain_coverage"], 1.0)
        self.assertEqual(result["join_precision"], 1.0)
        self.assertEqual(result["join_recall"], 1.0)
        self.assertEqual(result["exact_chain_accuracy"], 1.0)
        self.assertEqual(result["exact_chain_f1"], 1.0)
        self.assertEqual(result["abstention_rate"], 0.0)
        self.assertEqual(result["missed_join_count"], 0)
        self.assertEqual(result["false_join_count"], 0)
        self.assertIsNone(result["ambiguity_detection_precision"])
        self.assertIsNone(result["ambiguity_detection_recall"])

    def test_random_missing_ids_reduce_recall_without_false_joins(self) -> None:
        events, mutation = apply_scenario(
            pristine_events(),
            {"name": "test-missing", "kind": "missing_random", "rate": 0.20},
            SEED,
        )
        result = evaluate(
            events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        self.assertEqual(mutation["missing_id_events"], round(len(events) * 0.20))
        self.assertLess(result["complete_chain_coverage"], 1.0)
        self.assertLess(result["join_recall"], 1.0)
        self.assertEqual(result["join_precision"], 1.0)
        self.assertEqual(result["false_join_count"], 0)

    def test_plane_concentrated_absence_breaks_every_exact_chain(self) -> None:
        events, mutation = apply_scenario(
            pristine_events(),
            {
                "name": "test-plane",
                "kind": "missing_plane",
                "source_type": "policy",
            },
            SEED,
        )
        result = evaluate(
            events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        self.assertEqual(mutation["missing_id_events"], CHAINS)
        self.assertEqual(result["complete_chain_coverage"], 0.0)
        self.assertEqual(result["exact_chain_f1"], 0.0)
        self.assertAlmostEqual(result["missed_join_rate"], 1.0 / 3.0)
        self.assertEqual(result["false_join_rate"], 0.0)

    def test_same_service_collisions_are_harmful_and_detected(self) -> None:
        events, mutation = apply_scenario(
            pristine_events(),
            {
                "name": "test-same-service-collision",
                "kind": "collision_same_service",
                "rate": 0.05,
            },
            SEED,
        )
        result = evaluate(
            events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        unsafe_ablation = evaluate(
            events, correlation_only_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        self.assertEqual(mutation["collision_pairs"], round(CHAINS * 0.05))
        self.assertEqual(result["false_join_count"], 0)
        self.assertEqual(result["accepted_ambiguous_group_count"], 0)
        self.assertGreater(result["abstention_rate"], 0)
        self.assertEqual(result["ambiguity_detection_precision"], 1.0)
        self.assertEqual(result["ambiguity_detection_recall"], 1.0)
        self.assertGreater(unsafe_ablation["false_join_count"], 0)

    def test_composite_key_contains_cross_service_reuse(self) -> None:
        events, mutation = apply_scenario(
            pristine_events(),
            {
                "name": "test-cross-service-collision",
                "kind": "collision_cross_service",
                "rate": 0.05,
            },
            SEED,
        )
        result = evaluate(
            events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        correlation_only = evaluate(
            events, correlation_only_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        )
        self.assertGreater(mutation["collision_pairs"], 0)
        self.assertEqual(result["complete_chain_coverage"], 1.0)
        self.assertEqual(result["false_join_count"], 0)
        self.assertGreater(correlation_only["false_join_count"], 0)
        self.assertLess(correlation_only["complete_chain_coverage"], 1.0)

    def test_temporal_comparator_exposes_precision_recall_tradeoff(self) -> None:
        control = pristine_events()
        missing, _mutation = apply_scenario(
            control,
            {"name": "test-missing", "kind": "missing_random", "rate": 0.20},
            SEED,
        )
        control_result = evaluate(
            control,
            temporal_reconstruct(
                control, TEMPORAL_WINDOW_MS, MAXIMUM_CHAIN_SPAN_MS
            ),
        )
        missing_result = evaluate(
            missing,
            temporal_reconstruct(
                missing, TEMPORAL_WINDOW_MS, MAXIMUM_CHAIN_SPAN_MS
            ),
        )
        self.assertGreater(control_result["false_join_count"], 0)
        self.assertGreater(control_result["missed_join_count"], 0)
        for metric in (
            "complete_chain_coverage",
            "missed_join_count",
            "false_join_count",
        ):
            self.assertEqual(control_result[metric], missing_result[metric])

    def test_delay_changes_availability_not_strict_membership(self) -> None:
        control = pristine_events()
        delayed, mutation = apply_scenario(
            control,
            {
                "name": "test-late",
                "kind": "late_arrival",
                "rate": 0.10,
                "delay_ms": 30_000,
            },
            SEED,
        )
        control_result = evaluate(
            control, strict_reconstruct(control, MAXIMUM_CHAIN_SPAN_MS)
        )
        delayed_result = evaluate(
            delayed, strict_reconstruct(delayed, MAXIMUM_CHAIN_SPAN_MS)
        )
        self.assertEqual(mutation["late_events"], round(len(control) * 0.10))
        self.assertEqual(
            control_result["complete_chain_coverage"],
            delayed_result["complete_chain_coverage"],
        )
        self.assertEqual(control_result["false_join_count"], delayed_result["false_join_count"])
        self.assertGreater(
            delayed_result["time_to_completeness_p95_ms"],
            control_result["time_to_completeness_p95_ms"],
        )
        self.assertGreater(delayed_result["arrival_inversion_count"], 0)

    def test_wrong_ids_trigger_safe_abstention_without_silent_union(self) -> None:
        events, mutation = apply_scenario(
            pristine_events(),
            {"name": "test-wrong", "kind": "wrong_id", "rate": 0.10},
            SEED,
        )
        result = evaluate(events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS))
        self.assertEqual(mutation["wrong_id_events"], round(len(events) * 0.10))
        self.assertGreater(result["ambiguous_group_count"], 0)
        self.assertEqual(result["accepted_ambiguous_group_count"], 0)
        self.assertEqual(result["false_join_count"], 0)
        self.assertGreater(result["abstention_rate"], 0)

    def test_clock_skew_is_separate_from_arrival_reordering(self) -> None:
        events, mutation = apply_scenario(
            pristine_events(),
            {
                "name": "test-skew",
                "kind": "clock_skew",
                "rate": 0.10,
                "skew_ms": 5_000,
            },
            SEED,
        )
        result = evaluate(events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS))
        self.assertEqual(mutation["clock_skewed_events"], round(len(events) * 0.10))
        self.assertEqual(result["arrival_inversion_count"], 0)
        self.assertEqual(result["false_join_count"], 0)
        self.assertGreater(result["abstention_rate"], 0)

    def test_exact_duplicates_are_suppressed_without_changing_chains(self) -> None:
        canonical = pristine_events()
        events, mutation = apply_scenario(
            canonical,
            {"name": "test-duplicate", "kind": "duplicate_exact", "rate": 0.10},
            SEED,
        )
        result = evaluate(events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS))
        self.assertEqual(mutation["exact_duplicate_observations"], round(len(canonical) * 0.10))
        self.assertEqual(result["complete_chain_coverage"], 1.0)
        self.assertEqual(result["false_join_count"], 0)
        self.assertEqual(
            result["deduplicated_observation_count"],
            mutation["exact_duplicate_observations"],
        )

    def test_conflicting_duplicates_are_detected_and_abstained(self) -> None:
        canonical = pristine_events()
        events, mutation = apply_scenario(
            canonical,
            {
                "name": "test-conflict",
                "kind": "duplicate_source_conflict",
                "rate": 0.05,
            },
            SEED,
        )
        result = evaluate(events, strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS))
        self.assertEqual(
            mutation["conflicting_duplicate_observations"], round(len(canonical) * 0.05)
        )
        self.assertEqual(result["source_conflict_detection_precision"], 1.0)
        self.assertEqual(result["source_conflict_detection_recall"], 1.0)
        self.assertEqual(result["false_join_count"], 0)
        self.assertGreater(result["abstention_rate"], 0)

    def test_reconstructors_do_not_use_evaluation_only_truth_fields(self) -> None:
        events = pristine_events()
        redacted_truth = [
            replace(
                event,
                truth_chain_id=f"redacted-{index % 7}",
                truth_source_ms=-1,
                canonical_event_id=f"opaque-{index}",
                observation_kind="opaque",
            )
            for index, event in enumerate(events)
        ]
        original = strict_reconstruct(events, MAXIMUM_CHAIN_SPAN_MS)
        redacted = strict_reconstruct(redacted_truth, MAXIMUM_CHAIN_SPAN_MS)
        original_membership = {
            key: tuple(event.event_id for event in group)
            for key, group in original.groups.items()
        }
        redacted_membership = {
            key: tuple(event.event_id for event in group)
            for key, group in redacted.groups.items()
        }
        self.assertEqual(original_membership, redacted_membership)
        self.assertEqual(original.ambiguity_flags, redacted.ambiguity_flags)
        self.assertEqual(original.abstained_event_ids, redacted.abstained_event_ids)

    def test_campaign_results_are_deterministic(self) -> None:
        args = parse_args(
            [
                "--chains",
                "60",
                "--services",
                "6",
                "--seeds",
                str(SEED),
            ]
        )
        first = run_campaign(args)
        second = run_campaign(args)
        self.assertEqual(first, second)

    def test_reference_default_uses_thirty_predetermined_seeds(self) -> None:
        args = parse_args([])
        self.assertEqual(len(args.seeds), 30)
        self.assertEqual(args.seeds[0], 9238)
        self.assertEqual(args.seeds[-1], 12167)

    def test_cli_writes_json_csv_and_verifiable_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            return_code = main(
                [
                    "--chains",
                    "60",
                    "--services",
                    "6",
                    "--seeds",
                    str(SEED),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(return_code, 0)
            expected = {
                "trial_results.csv",
                "summary_results.csv",
                "trial_results.json",
                "summary_results.json",
                "environment.json",
                "figure_correlation_robustness.svg",
                "SHA256SUMS",
            }
            self.assertEqual({path.name for path in output.iterdir()}, expected)
            summary = json.loads((output / "summary_results.json").read_text())
            self.assertEqual(summary["schema_version"], "1.0")
            self.assertEqual(summary["data_classification"], "fully synthetic; contains no user or production data")
            figure = (output / "figure_correlation_robustness.svg").read_text()
            self.assertIn("<svg", figure)
            self.assertIn("Missing IDs", figure)
            self.assertIn("strict false-join rate: 0%", figure)

            for line in (output / "SHA256SUMS").read_text().splitlines():
                expected_hash, filename = line.split("  ", 1)
                actual_hash = hashlib.sha256((output / filename).read_bytes()).hexdigest()
                self.assertEqual(actual_hash, expected_hash)


if __name__ == "__main__":
    unittest.main()
