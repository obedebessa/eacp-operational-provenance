import unittest

from eacp_hardening.campaign import run_campaign


class CampaignTests(unittest.TestCase):
    def test_integrated_finite_campaign_and_boundaries(self):
        report = run_campaign(seeds=1, events=20)
        failed = [row for row in report["cases"] if not row["passed"]]
        self.assertEqual(failed, [])
        self.assertGreaterEqual(report["summary"]["checks"], 30)
        self.assertEqual(len(report["ingestion_observations"]), 3)
        self.assertEqual(report["method"], "author_executed_finite_synthetic_fault_campaign")
        self.assertIn("independent reproduction", report["not_established"])


if __name__ == "__main__":
    unittest.main()
