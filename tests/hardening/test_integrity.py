from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from eacp_hardening.common import HardeningError
from eacp_hardening.integrity import AnchorPolicy, create_checkpoint, digest, verify_checkpoint

NOW = "2026-09-04T12:00:00Z"


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.material = {"store_id": "store-1", "tenant_id": "tenant-a", "events": [{"id": "a"}, {"id": "b"}]}
        self.checkpoint = create_checkpoint(self.material, sequence=2, issued_at=NOW, key_id="external-key", private_key=self.key)
        self.policy = AnchorPolicy("external-key", self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                   "tenant-a", "store-1", digest(self.checkpoint), 2)

    def test_intact_and_no_anchor_boundary(self):
        self.assertEqual(verify_checkpoint(self.material, self.checkpoint, self.policy, now=NOW)["status"], "VERIFIED_RELATIVE_TO_CHECKPOINT")
        self.assertEqual(verify_checkpoint(self.material, self.checkpoint, None, now=NOW)["status"], "UNKNOWN")

    def test_alteration_truncation_consistent_manifest_replacement(self):
        for changed in ({"store_id": "store-1", "tenant_id": "tenant-a", "events": [{"id": "changed"}]},
                        {"store_id": "store-1", "tenant_id": "tenant-a", "events": []}):
            with self.assertRaises(HardeningError):
                verify_checkpoint(changed, self.checkpoint, self.policy, now=NOW)
            forged = copy.deepcopy(self.checkpoint)
            forged["material_sha256"] = digest(changed)
            with self.assertRaises(HardeningError):
                verify_checkpoint(changed, forged, self.policy, now=NOW)

    def test_old_valid_snapshot_rejected_by_current_anchor_and_floor(self):
        old = {"store_id": "store-1", "tenant_id": "tenant-a", "events": [{"id": "a"}]}
        old_checkpoint = create_checkpoint(old, sequence=1, issued_at=NOW, key_id="external-key", private_key=self.key)
        with self.assertRaises(HardeningError):
            verify_checkpoint(old, old_checkpoint, self.policy, now=NOW)
        with self.assertRaises(HardeningError):
            verify_checkpoint(old, old_checkpoint, replace(self.policy, checkpoint_sha256=digest(old_checkpoint)), now=NOW)

    def test_wrong_key_scope_revocation_and_freshness(self):
        for policy in (replace(self.policy, revoked=True), replace(self.policy, tenant_id="tenant-b"),
                       replace(self.policy, store_id="store-2"), replace(self.policy, public_key=b"x" * 32)):
            with self.assertRaises(HardeningError):
                verify_checkpoint(self.material, self.checkpoint, policy, now=NOW)
        for now in ("2026-09-04T11:59:59Z", "2026-09-04T13:00:01Z"):
            with self.assertRaises(HardeningError):
                verify_checkpoint(self.material, self.checkpoint, self.policy, now=now)

    def test_compromised_anchor_is_an_explicit_limit(self):
        forged = {"store_id": "store-1", "tenant_id": "tenant-a", "events": [{"id": "false"}]}
        signed = create_checkpoint(forged, sequence=3, issued_at=NOW, key_id="external-key", private_key=self.key)
        replaced_policy = replace(self.policy, checkpoint_sha256=digest(signed), minimum_sequence=3)
        result = verify_checkpoint(forged, signed, replaced_policy, now=NOW)
        self.assertFalse(result["source_truth_verified"])
        self.assertFalse(result["rollback_prevented"])


if __name__ == "__main__":
    unittest.main()
