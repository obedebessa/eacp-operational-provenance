"""Authenticated collector statements with pinned, revocable Ed25519 identities.

This verifies a collector statement, not the truth of an upstream event. The
registry and the clock are trusted inputs outside the evidence-store boundary.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .common import HardeningError, Principal, VerifiedEvent, VerifiedInventory, canonical_bytes, identifier, strict_json, utc_time

SCHEMA = "eacp.collector-statement/1.4"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROLES = frozenset({"writer", "reader", "operator", "auditor"})
MAX_STATEMENT_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class CollectorPolicy:
    key_id: str
    public_key: bytes
    tenant_id: str
    source_id: str
    collector_id: str
    adapter_sha256: str
    valid_from: str
    valid_until: str
    allowed_origins: tuple[str, ...]
    allow_fixture: bool = False
    revoked: bool = False


@dataclass(frozen=True)
class TokenPolicy:
    token_sha256: str
    subject: str
    tenant_id: str
    roles: frozenset[str]
    valid_until: str
    revoked: bool = False


def authenticate_token(token: str, policies: list[TokenPolicy], *, now: str) -> Principal:
    """Authenticate high-entropy bearer tokens; no tokens are logged or retained."""
    when = utc_time(now)
    if not isinstance(token, str) or len(token) < 32 or len(token) > 4096:
        raise HardeningError("authentication failed")
    if not isinstance(policies, list):
        raise HardeningError("invalid access policy collection")
    for item in policies:
        if (not isinstance(item, TokenPolicy) or type(item.revoked) is not bool
                or not isinstance(item.token_sha256, str) or not SHA256.fullmatch(item.token_sha256)
                or not isinstance(item.roles, frozenset)):
            raise HardeningError("invalid access policy")
    fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matches = [p for p in policies if hmac.compare_digest(p.token_sha256, fingerprint)]
    if len(matches) != 1:
        raise HardeningError("authentication failed")
    policy = matches[0]
    if policy.revoked or when >= utc_time(policy.valid_until):
        raise HardeningError("authentication failed")
    if not policy.roles or not policy.roles <= ROLES:
        raise HardeningError("invalid access policy")
    return Principal(identifier(policy.subject), identifier(policy.tenant_id), policy.roles)


def sign_statement(body: Mapping[str, Any], *, key_id: str,
                   private_key: Ed25519PrivateKey) -> dict[str, Any]:
    unsigned = {"schema": SCHEMA, "key_id": identifier(key_id), "body": dict(body)}
    encoded = canonical_bytes(unsigned)
    if len(encoded) > MAX_STATEMENT_BYTES:
        raise HardeningError("statement exceeds size limit")
    signature = private_key.sign(encoded)
    return {**unsigned, "signature": base64.b64encode(signature).decode("ascii")}


def _exact(value: Any, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise HardeningError(f"invalid {label} fields")
    return value


def _origin(url: str) -> str:
    if not isinstance(url, str):
        raise HardeningError("invalid source origin")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise HardeningError("invalid source origin") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise HardeningError("source origin must be credential-free HTTPS")
    if parsed.path not in {"", "/"}:
        raise HardeningError("source origin must not contain a path")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port and port != 443 else "")


class TrustRegistry:
    def __init__(self, policies: list[CollectorPolicy], *, max_age_seconds: int = 300,
                 future_skew_seconds: int = 30):
        if (type(max_age_seconds) is not int or type(future_skew_seconds) is not int
                or max_age_seconds <= 0 or future_skew_seconds < 0):
            raise HardeningError("invalid freshness policy")
        self.policies: dict[str, CollectorPolicy] = {}
        self.max_age = timedelta(seconds=max_age_seconds)
        self.future_skew = timedelta(seconds=future_skew_seconds)
        if not isinstance(policies, list):
            raise HardeningError("invalid collector policy collection")
        for policy in policies:
            if (not isinstance(policy, CollectorPolicy) or type(policy.allow_fixture) is not bool
                    or type(policy.revoked) is not bool or not isinstance(policy.public_key, bytes)
                    or not isinstance(policy.allowed_origins, tuple)):
                raise HardeningError("invalid collector policy types")
            for name in (policy.key_id, policy.tenant_id, policy.source_id, policy.collector_id):
                identifier(name)
            if policy.key_id in self.policies or len(policy.public_key) != 32:
                raise HardeningError("duplicate key identity or invalid public key")
            if not isinstance(policy.adapter_sha256, str) or not SHA256.fullmatch(policy.adapter_sha256):
                raise HardeningError("invalid pinned adapter digest")
            if utc_time(policy.valid_from) >= utc_time(policy.valid_until):
                raise HardeningError("invalid key validity interval")
            if not policy.allowed_origins:
                raise HardeningError("source origin allowlist required")
            for origin in policy.allowed_origins:
                if _origin(origin) != origin:
                    raise HardeningError("noncanonical source origin in policy")
            self.policies[policy.key_id] = policy

    def verify(self, statement: dict, *, now: str) -> VerifiedEvent | VerifiedInventory:
        _exact(statement, {"schema", "key_id", "body", "signature"}, "statement")
        if statement["schema"] != SCHEMA:
            raise HardeningError("unsupported collector statement")
        key_id = identifier(statement["key_id"])
        policy = self.policies.get(key_id)
        when = utc_time(now)
        if policy is None or policy.revoked:
            raise HardeningError("collector identity is not trusted")
        if not utc_time(policy.valid_from) <= when < utc_time(policy.valid_until):
            raise HardeningError("collector key is not currently valid")
        unsigned = {name: statement[name] for name in ("schema", "key_id", "body")}
        encoded = canonical_bytes(unsigned)
        if len(encoded) > MAX_STATEMENT_BYTES:
            raise HardeningError("statement exceeds size limit")
        try:
            signature = base64.b64decode(statement["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(policy.public_key).verify(signature, encoded)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise HardeningError("collector signature verification failed") from exc
        body = _exact(statement["body"], {
            "kind", "tenant_id", "source_id", "collector_id", "issued_at",
            "adapter_sha256", "acquisition", "content",
        }, "statement body")
        for name in ("tenant_id", "source_id", "collector_id", "adapter_sha256"):
            if body[name] != getattr(policy, name):
                raise HardeningError("collector statement does not match source policy")
        issued = utc_time(body["issued_at"])
        if not utc_time(policy.valid_from) <= issued < utc_time(policy.valid_until):
            raise HardeningError("statement issued outside key validity")
        if issued > when + self.future_skew or issued < when - self.max_age:
            raise HardeningError("collector statement outside freshness window")
        acquisition = _exact(body["acquisition"], {"method", "origin", "raw_sha256"}, "acquisition")
        if _origin(acquisition["origin"]) not in policy.allowed_origins:
            raise HardeningError("untrusted source origin")
        if acquisition["method"] not in {"https", "fixture"}:
            raise HardeningError("unsupported collection method")
        if acquisition["method"] == "fixture" and not policy.allow_fixture:
            raise HardeningError("fixture source is forbidden by policy")
        if not isinstance(acquisition["raw_sha256"], str) or not SHA256.fullmatch(acquisition["raw_sha256"]):
            raise HardeningError("invalid acquired representation digest")
        common = {"tenant_id": policy.tenant_id, "source_id": policy.source_id,
                  "collector_id": policy.collector_id, "key_id": key_id, "received_at": now,
                  "source_proof": {"assurance": "authenticated_collector_statement_only",
                                   "statement_sha256": hashlib.sha256(canonical_bytes(statement)).hexdigest(),
                                   "signed_statement": json.loads(canonical_bytes(statement))}}
        if body["kind"] == "event":
            content = _exact(body["content"], {"event_id", "sequence", "source_ts", "payload"}, "event")
            event_id = identifier(content["event_id"])
            if type(content["sequence"]) is not int or not 0 <= content["sequence"] < 2**63:
                raise HardeningError("invalid source sequence")
            utc_time(content["source_ts"])
            if not isinstance(content["payload"], dict):
                raise HardeningError("event payload must be an object")
            # Own a copy so subsequent mutation of the untrusted input cannot alter
            # what the signature verified. In-process code remains trusted.
            payload = json.loads(canonical_bytes(content["payload"]))
            return VerifiedEvent(event_id=event_id, sequence=content["sequence"],
                                 source_ts=content["source_ts"], payload=payload, **common)
        if body["kind"] == "inventory":
            content = _exact(body["content"], {"inventory_id", "expected_event_ids"}, "inventory")
            expected = content["expected_event_ids"]
            if not isinstance(expected, list) or len(expected) > 100000:
                raise HardeningError("invalid finite source inventory")
            expected = tuple(identifier(item) for item in expected)
            if len(set(expected)) != len(expected):
                raise HardeningError("duplicate inventory identity")
            return VerifiedInventory(inventory_id=identifier(content["inventory_id"]),
                                     expected_event_ids=expected, **common)
        raise HardeningError("unsupported statement kind")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HardeningError("collector redirects are forbidden")


def fetch_https_json(url: str, *, allowed_origins: tuple[str, ...],
                     bearer_token: str | None = None, max_bytes: int = 1048576,
                     timeout: float = 15.0) -> tuple[Any, dict[str, str]]:
    """Bounded authenticated TLS acquisition; redirects cannot leak credentials.

Network/DNS/CA trust and the source are deployment trust assumptions. The caller
must project/sanitize before persistence or publication. Response bytes are never
written by this function. No source-side per-event signature is invented.
    """
    if not isinstance(url, str) or any(ord(c) < 32 for c in url):
        raise HardeningError("invalid collection URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        origin = _origin(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))
    except ValueError as exc:
        raise HardeningError("invalid collection URL") from exc
    if parsed.fragment or origin not in allowed_origins:
        raise HardeningError("collection origin not allowed")
    if not 1 <= max_bytes <= MAX_STATEMENT_BYTES or timeout <= 0:
        raise HardeningError("invalid collection resource limit")
    headers = {"Accept": "application/json", "User-Agent": "EACP-reference-collector/1.4"}
    if bearer_token is not None:
        if not isinstance(bearer_token, str) or not bearer_token or any(ord(c) < 32 for c in bearer_token):
            raise HardeningError("invalid collector credential")
        headers["Authorization"] = "Bearer " + bearer_token
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise HardeningError("unexpected source response")
            raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise HardeningError("source response exceeds size limit")
        value = strict_json(raw)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, UnicodeError) as exc:
        # Do not echo token, URL query, response body or server error text.
        raise HardeningError("authenticated source collection failed") from None
    return value, {"method": "https", "origin": origin, "raw_sha256": hashlib.sha256(raw).hexdigest()}
