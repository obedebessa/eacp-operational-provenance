from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from eacp_hardening.common import HardeningError, VerifiedEvent, VerifiedInventory
from eacp_hardening.trust import CollectorPolicy, TokenPolicy, TrustRegistry, authenticate_token, fetch_https_json, sign_statement

NOW = "2026-09-04T12:00:00Z"


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.policy = CollectorPolicy(
            "collector-key-1", self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "tenant-a", "source-a", "collector-a", "a" * 64,
            "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z",
            ("https://api.example.invalid",), True,
        )
        self.body = {"kind": "event", "tenant_id": "tenant-a", "source_id": "source-a",
                     "collector_id": "collector-a", "issued_at": NOW, "adapter_sha256": "a" * 64,
                     "acquisition": {"method": "fixture", "origin": "https://api.example.invalid", "raw_sha256": "b" * 64},
                     "content": {"event_id": "event-1", "sequence": 1, "source_ts": NOW,
                                 "payload": {"action": "deploy", "status": "observed"}}}

    def signed(self, body=None):
        return sign_statement(self.body if body is None else body, key_id=self.policy.key_id, private_key=self.key)

    def verify(self, statement, policy=None, now=NOW):
        return TrustRegistry([policy or self.policy]).verify(statement, now=now)

    def test_event_and_input_mutation(self):
        statement = self.signed()
        event = self.verify(statement)
        self.assertIsInstance(event, VerifiedEvent)
        statement["body"]["content"]["payload"]["action"] = "changed"
        self.assertEqual(event.payload["action"], "deploy")

    def test_tampered_payload_and_signature_rejected(self):
        statement = self.signed()
        statement["body"]["content"]["payload"]["action"] = "forged"
        with self.assertRaises(HardeningError):
            self.verify(statement)
        statement = self.signed()
        statement["signature"] = "invalid"
        with self.assertRaises(HardeningError):
            self.verify(statement)

    def test_wrong_source_tenant_collector_adapter_origin(self):
        for field in ("tenant_id", "source_id", "collector_id", "adapter_sha256"):
            with self.subTest(field=field):
                body = copy.deepcopy(self.body)
                body[field] = "unexpected"
                with self.assertRaises(HardeningError):
                    self.verify(self.signed(body))
        body = copy.deepcopy(self.body)
        body["acquisition"]["origin"] = "https://other.example.invalid"
        with self.assertRaises(HardeningError):
            self.verify(self.signed(body))

    def test_revoked_unknown_expired_key(self):
        with self.assertRaises(HardeningError):
            self.verify(self.signed(), replace(self.policy, revoked=True))
        with self.assertRaises(HardeningError):
            TrustRegistry([]).verify(self.signed(), now=NOW)
        with self.assertRaises(HardeningError):
            self.verify(self.signed(), now="2027-01-01T00:00:00Z")

    def test_rotation_requires_explicit_new_public_key(self):
        next_key = Ed25519PrivateKey.generate()
        statement = sign_statement(self.body, key_id="collector-key-2", private_key=next_key)
        with self.assertRaises(HardeningError):
            self.verify(statement)
        next_policy = replace(self.policy, key_id="collector-key-2",
                              public_key=next_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.assertIsInstance(self.verify(statement, next_policy), VerifiedEvent)

    def test_freshness_future_and_fixture_policy(self):
        for timestamp in ("2026-09-04T11:54:59Z", "2026-09-04T12:00:31Z"):
            body = copy.deepcopy(self.body)
            body["issued_at"] = timestamp
            with self.assertRaises(HardeningError):
                self.verify(self.signed(body))
        with self.assertRaises(HardeningError):
            self.verify(self.signed(), replace(self.policy, allow_fixture=False))

    def test_malformed_events_rejected(self):
        for value in (True, -1, 2**63, 1.5, "1"):
            body = copy.deepcopy(self.body)
            body["content"]["sequence"] = value
            with self.assertRaises(HardeningError):
                self.verify(self.signed(body))
        body = copy.deepcopy(self.body)
        body["content"]["payload"] = []
        with self.assertRaises(HardeningError):
            self.verify(self.signed(body))

    def test_inventory_authentication_and_duplicates(self):
        body = copy.deepcopy(self.body)
        body["kind"] = "inventory"
        body["content"] = {"inventory_id": "inventory-1", "expected_event_ids": ["event-1", "event-2"]}
        self.assertIsInstance(self.verify(self.signed(body)), VerifiedInventory)
        body["content"]["expected_event_ids"].append("event-1")
        with self.assertRaises(HardeningError):
            self.verify(self.signed(body))

    def test_internally_consistent_source_falsehood_is_not_detected(self):
        body = copy.deepcopy(self.body)
        body["content"]["payload"] = {"claim": "deliberately_false_fixture_claim"}
        event = self.verify(self.signed(body))
        self.assertEqual(event.payload["claim"], "deliberately_false_fixture_claim")
        # Expected boundary: the authenticated collector can still lie.

    def test_access_tokens_scope_expiry_revocation(self):
        token = "synthetic-fixture-token-not-a-real-secret-12345"
        policy = TokenPolicy(hashlib.sha256(token.encode()).hexdigest(), "reviewer", "tenant-a",
                             frozenset({"reader"}), "2027-01-01T00:00:00Z")
        self.assertEqual(authenticate_token(token, [policy], now=NOW).tenant_id, "tenant-a")
        for policies in ([replace(policy, revoked=True)], [replace(policy, valid_until=NOW)], [], [policy, policy]):
            with self.assertRaises(HardeningError):
                authenticate_token(token, policies, now=NOW)
        with self.assertRaises(HardeningError):
            authenticate_token("wrong" * 20, [policy], now=NOW)

    def test_https_denies_unapproved_origin_and_credentials_before_network(self):
        with mock.patch("urllib.request.build_opener") as opener:
            for url in ("http://api.example.invalid/events", "https://user:pass@api.example.invalid/events",
                        "https://other.example.invalid/events", "https://api.example.invalid/events#secret"):
                with self.assertRaises(HardeningError):
                    fetch_https_json(url, allowed_origins=("https://api.example.invalid",))
            opener.assert_not_called()

    def test_https_limits_reads_and_suppresses_errors(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"safe":true}'
        with mock.patch("urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            value, acquisition = fetch_https_json("https://api.example.invalid/events", allowed_origins=("https://api.example.invalid",))
            self.assertEqual(value, {"safe": True})
            self.assertEqual(acquisition["method"], "https")
            response.read.return_value = b"x" * 11
            with self.assertRaises(HardeningError):
                fetch_https_json("https://api.example.invalid/events", allowed_origins=("https://api.example.invalid",), max_bytes=10)

    def test_malformed_policy_flags_and_duplicate_https_json_rejected(self):
        for policy in (replace(self.policy, allow_fixture="false"), replace(self.policy, revoked="false")):
            with self.assertRaises(HardeningError):
                TrustRegistry([policy])
        with self.assertRaises(HardeningError):
            TrustRegistry([self.policy], max_age_seconds=True)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        for raw in (b'{"id":1,"id":2}', b'{"body":{"id":1,"id":2}}'):
            response.read.return_value = raw
            with mock.patch("urllib.request.build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(HardeningError):
                    fetch_https_json("https://api.example.invalid/events", allowed_origins=("https://api.example.invalid",))


if __name__ == "__main__":
    unittest.main()
