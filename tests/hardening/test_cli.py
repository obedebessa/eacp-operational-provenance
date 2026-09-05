from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from eacp_hardening import cli
from eacp_hardening.common import HardeningError, strict_json, utc_time
from eacp_hardening.trust import sign_statement

NOW = "2026-09-04T12:00:00Z"


class BoundaryCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.token = "test-only-token-with-more-than-32-characters"
        self.settings = {"access": [{"token_sha256": hashlib.sha256(self.token.encode()).hexdigest(),
            "subject": "fixture-operator", "tenant_id": "tenant-a", "roles": ["reader", "writer", "operator", "auditor"],
            "valid_until": "2027-01-01T00:00:00Z"}], "collectors": [{
            "key_id": "key-a", "public_key_hex": self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "tenant_id": "tenant-a", "source_id": "source-a", "collector_id": "collector-a", "adapter_sha256": "a" * 64,
            "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
            "allowed_origins": ["https://source.example.invalid"], "allow_fixture": True}]}
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps(self.settings))
        body = {"kind": "event", "tenant_id": "tenant-a", "source_id": "source-a", "collector_id": "collector-a",
                "issued_at": NOW, "adapter_sha256": "a" * 64,
                "acquisition": {"method": "fixture", "origin": "https://source.example.invalid", "raw_sha256": "b" * 64},
                "content": {"event_id": "event-a", "sequence": 1, "source_ts": NOW,
                            "payload": {"secret": "private-fixture-value"}}}
        self.statement = self.root / "statement.json"
        self.statement.write_text(json.dumps(sign_statement(body, key_id="key-a", private_key=self.key)))
        self.database = self.root / "store.sqlite"
        self.env = {"EACP_ACCESS_TOKEN": self.token, "EACP_STORAGE_KEY_HEX": "11" * 32}

    def invoke(self, command, *args, env=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict("os.environ", self.env if env is None else env, clear=True), \
                mock.patch.object(cli, "now_utc", return_value=NOW), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main([command, *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def dbargs(self):
        return ["--database", str(self.database), "--config", str(self.config)]

    def test_authenticated_ingest_drain_read_checkpoint_path(self):
        code, out, err = self.invoke("ingest", *self.dbargs(), "--statement", str(self.statement))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["status"], "queued")
        code, out, err = self.invoke("drain", *self.dbargs())
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["drained"], 1)
        code, out, err = self.invoke("status", *self.dbargs(), "--source", "source-a")
        self.assertEqual(json.loads(out)["status"], "UNKNOWN")
        code, out, err = self.invoke("read", *self.dbargs(), "--source", "source-a")
        self.assertEqual(code, 0, err)
        self.assertIn("signed_statement", json.loads(out)[0]["source_proof"])
        code, out, err = self.invoke("checkpoint-export", *self.dbargs())
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["tenant_id"], "tenant-a")
        self.assertNotIn(b"private-fixture-value", self.database.read_bytes())

    def test_denied_auth_does_not_create_store_or_echo_token(self):
        code, out, err = self.invoke("ingest", *self.dbargs(), "--statement", str(self.statement), env={})
        self.assertEqual(code, 2)
        self.assertFalse(self.database.exists())
        self.assertNotIn(self.token, err)
        self.assertEqual(json.loads(err)["message"], "authentication failed")

    def test_verified_source_summary_never_echoes_payload(self):
        code, out, err = self.invoke("verify-source", "--config", str(self.config), "--statement", str(self.statement))
        self.assertEqual(code, 0, err)
        self.assertNotIn("private-fixture-value", out)
        self.assertFalse(json.loads(out)["source_truth_verified"])

    def test_config_shape_errors_are_safe_json_not_traceback(self):
        for config in ([], {"access": {}}, {"access": [None]}, {"access": [{"roles": "reader"}]},
                       {"collectors": [{"allowed_origins": "https://source.example.invalid"}]}):
            self.config.write_text(json.dumps(config))
            code, out, err = self.invoke("status", *self.dbargs(), "--source", "source-a")
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(err)["status"], "error")
            self.assertNotIn("Traceback", err)

    def test_output_exclusive_creation(self):
        target = self.root / "retained.json"
        target.write_text("original evidence")
        with self.assertRaises(FileExistsError):
            cli.emit({"new": "data"}, str(target))
        self.assertEqual(target.read_text(), "original evidence")

    def test_strict_json_and_timestamps(self):
        for text in ('{"id":1,"id":2}', '{"body":{"id":1,"id":2}}', '{"x":NaN}'):
            with self.assertRaises(HardeningError):
                strict_json(text)
        for timestamp in ("2026-09-04Z", "2026-09-04 12:00:00Z", "2026-09-04T12:00:00+00:00Z"):
            with self.assertRaises(HardeningError):
                utc_time(timestamp)


if __name__ == "__main__":
    unittest.main()
