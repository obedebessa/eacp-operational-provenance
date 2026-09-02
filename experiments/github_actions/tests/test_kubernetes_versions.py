import unittest

from experiments.github_actions.verify_kubernetes_versions import VersionError, verify


class KubernetesVersionTests(unittest.TestCase):
    def test_exact_client_server_and_kubelet_pass(self):
        snapshot = {
            "clientVersion": {"gitVersion": "v1.35.5"},
            "serverVersion": {"gitVersion": "v1.35.5"},
        }
        observed = verify(snapshot, "Kubernetes v1.35.5\n", "v1.35.5")
        self.assertEqual(set(observed.values()), {"v1.35.5"})

    def test_any_version_skew_fails(self):
        baseline = {
            "clientVersion": {"gitVersion": "v1.35.5"},
            "serverVersion": {"gitVersion": "v1.35.5"},
        }
        cases = [
            ({**baseline, "clientVersion": {"gitVersion": "v1.36.1"}}, "Kubernetes v1.35.5"),
            ({**baseline, "serverVersion": {"gitVersion": "v1.34.8"}}, "Kubernetes v1.35.5"),
            (baseline, "Kubernetes v1.35.4"),
        ]
        for snapshot, kubelet in cases:
            with self.subTest(snapshot=snapshot, kubelet=kubelet), self.assertRaises(VersionError):
                verify(snapshot, kubelet, "v1.35.5")

    def test_invalid_expected_version_fails(self):
        with self.assertRaises(VersionError):
            verify({}, "", "latest")


if __name__ == "__main__":
    unittest.main()
