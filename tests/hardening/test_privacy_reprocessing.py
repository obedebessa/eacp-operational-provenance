from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from eacp_hardening.common import HardeningError, canonical_bytes


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("privacy_reprocessing", ROOT / "scripts/reprocess_frozen_privacy_v1_4.py")
reprocessing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reprocessing)


class FrozenPrivacyReprocessingTests(unittest.TestCase):
    def test_frozen_inputs_are_bound_and_all_controls_remain_compatible(self):
        result = reprocessing.reprocess_frozen_corpus(ROOT)
        self.assertEqual(result["method"], "author_reprocessing_frozen_corpus")
        self.assertEqual(result["cohort_count"], 9)
        self.assertEqual(result["totals"]["input_records"], 457)
        self.assertEqual(result["totals"]["retained_records"], 457)
        self.assertEqual(result["totals"]["native_positive_records"], 69)
        self.assertEqual(result["totals"]["adapter_explicit_403_records"], 9)
        self.assertEqual(result["totals"]["present_unjoined_no_id_records"], 27)
        self.assertFalse(result["assertions"]["independent_reproduction"])
        self.assertFalse(result["assertions"]["new_live_collection"])
        self.assertFalse(result["assertions"]["source_authenticity_established"])
        for run in result["runs"]:
            self.assertTrue(run["controls_passed"])
            self.assertEqual(len(run["sources"]), 5)
            for source in run["sources"]:
                self.assertFalse(Path(source["path"]).is_absolute())
                self.assertEqual(hashlib.sha256((ROOT / source["path"]).read_bytes()).hexdigest(), source["sha256"])
        self.assertNotIn(str(ROOT), canonical_bytes(result).decode("utf-8"))

    def test_summary_output_is_exclusive_and_contains_no_raw_records(self):
        summary = {"method": "author_reprocessing_frozen_corpus", "totals": {"retained_records": 457}}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "summary.json"
            reprocessing.write_summary_exclusive(output, summary)
            self.assertEqual(json.loads(output.read_bytes()), summary)
            before = output.read_bytes()
            with self.assertRaises(HardeningError):
                reprocessing.write_summary_exclusive(output, {"replacement": True})
            self.assertEqual(output.read_bytes(), before)

    def test_incomplete_cohort_rejects_instead_of_claiming_reference_compatibility(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(HardeningError):
                reprocessing.reprocess_frozen_corpus(Path(temporary))

    def test_changed_source_bytes_fail_the_colocated_manifest_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in reprocessing.AUDIT_FILES:
                (root / name).write_bytes(b"{}\n")
            digest = hashlib.sha256(b"{}\n").hexdigest()
            (root / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name in sorted(reprocessing.AUDIT_FILES)), encoding="utf-8")
            reprocessing._verified_audit_sources(root, root)
            (root / "audit_summary.json").write_bytes(b"{\"changed\":true}\n")
            with self.assertRaises(HardeningError):
                reprocessing._verified_audit_sources(root, root)


if __name__ == "__main__":
    unittest.main()
