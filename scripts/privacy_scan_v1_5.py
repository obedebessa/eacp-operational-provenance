#!/usr/bin/env python3
"""Read-only, bounded privacy review of an export or archive; never imports it.

Private deny literals and approved public email addresses belong in an external
JSON policy, not in this file. Findings contain relative paths and reason counts,
never matched values. This is a targeted privacy gate, not proof of anonymity or
a comprehensive secret scanner. Signed records are inspected without alteration.

ZIP/WHL and gzip TAR members are recursively inspected within fixed budgets.
Git history must be omitted. PDF inspection uses optional pypdf; unavailable or
incomplete PDF inspection is explicit. PDF parsing is not a hostile-file sandbox.
Images/OCR, encrypted content, arbitrary encodings, and identity inference from
public identifiers are outside scope. Certificates are not decoded as DSSE text.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import gzip
import hashlib
import html
import io
import json
import os
import re
import stat
import tarfile
import unicodedata
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote


@dataclass(frozen=True)
class Limits:
    member_bytes: int = 32 * 1024 * 1024
    total_bytes: int = 256 * 1024 * 1024
    members: int = 12000
    depth: int = 4
    pdf_pages: int = 100
    pdf_object_nodes: int = 50000
    object_nodes: int = 20000


NEGATIVE_TAR = (
    "results/hardening-v1.4/live-signing-33945266470/verification-01/"
    "negative/altered-archive/eacp-hardening-v1.4.tar.gz"
)
NEGATIVE_TAR_SHA256 = "3a68cad2c78257c8510304a06bd1d5a8bf9e6f22f566034c0e12afbfc80234df"
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HTTP_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
# macOS spelling is deliberately case-sensitive: API routes named /users are
# not workstation paths. Windows paths use an explicit drive and ignore case.
MAC_HOME = re.compile(r"/Users/[^/\s\"'<>:;,\[\]{}]+")
LINUX_HOME = re.compile(r"/home" + r"/([^/\s\"'<>:;,\[\]{}]+)")
WINDOWS_HOME = re.compile(r"\b[A-Za-z]:/(?:Users|Documents and Settings)/[^/\s\"'<>:;,\[\]{}]+", re.IGNORECASE)
JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def normalize(value: str) -> str:
    """Decode common textual path encodings without interpreting executable data."""
    for _ in range(4):
        changed = unquote(html.unescape(value))
        changed = JSON_ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), changed)
        changed = changed.replace("\\/", "/").replace("\\\\", "\\")
        if changed == value:
            break
        value = changed
    return unicodedata.normalize("NFKC", value).replace("\\", "/")


class BudgetExceeded(Exception):
    pass


class TarBudgetReader:
    """Account for all decompressed TAR bytes, including large PAX headers."""
    def __init__(self, stream, scanner):
        self.stream = stream
        self.scanner = scanner

    def read(self, size=-1):
        remaining = self.scanner.limits.total_bytes - self.scanner.bytes_read
        request = min(size if size >= 0 else 65536, 65536, remaining + 1)
        data = self.stream.read(request)
        self.scanner.charge_bytes(len(data))
        return data


class Scanner:
    def __init__(self, policy=None, limits=None):
        self.limits = limits or Limits()
        policy = policy or {}
        if set(policy) - {"deny_literals", "allow_emails"}:
            raise ValueError("invalid policy")
        for key in ("deny_literals", "allow_emails"):
            values = policy.get(key, [])
            if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
                raise ValueError("invalid policy")
        self.deny = tuple(sorted({normalize(v).casefold() for v in policy.get("deny_literals", [])}))
        self.allow_emails = {v.casefold() for v in policy.get("allow_emails", [])}
        self.findings = Counter()
        self.review = Counter()
        self.limitations = Counter()
        self.notices = Counter()
        self.bytes_read = 0
        self.members_read = 0
        self.incomplete = False

    def allowed_email(self, email):
        email = email.casefold()
        domain = email.rsplit("@", 1)[-1]
        return (email in self.allow_emails or email == "noreply@github.com"
                or domain in {"users.noreply.github.com", "noreply.github.com", "example.com", "example.org", "example.net"}
                or domain.endswith((".invalid", ".test")))

    def safe_path(self, path):
        result = normalize(path)
        for literal in self.deny:
            result = re.sub(re.escape(literal), "[private]", result, flags=re.IGNORECASE)
        if any(literal in result.casefold() for literal in self.deny):
            return "<private-path>"
        for pattern in (MAC_HOME, LINUX_HOME, WINDOWS_HOME):
            result = pattern.sub("[home]", result)
        result = EMAIL.sub(lambda m: m.group(0) if self.allowed_email(m.group(0)) else "[email]", result)
        return result

    def add(self, group, path, reason, count=1):
        group[(self.safe_path(path), reason)] += count

    def charge_bytes(self, size):
        if self.bytes_read + size > self.limits.total_bytes:
            raise BudgetExceeded
        self.bytes_read += size

    def member(self, path, size=0, charge=True):
        self.members_read += 1
        if self.members_read > self.limits.members:
            raise BudgetExceeded
        if size > self.limits.member_bytes:
            self.add(self.findings, path, "member_size_budget_exceeded")
            self.incomplete = True
            return False
        if charge:
            self.charge_bytes(size)
        return True

    def text(self, value, path):
        value = normalize(value)
        folded = value.casefold()
        for literal in self.deny:
            count = folded.count(literal)
            if count:
                self.add(self.findings, path, "private_literal", count)
        # HTTP API paths and public repository URLs are not local home paths.
        local = HTTP_URL.sub("", value)
        counts = {
            "private_macos_home": len(MAC_HOME.findall(local)),
            "private_windows_home": len(WINDOWS_HOME.findall(local)),
            "private_linux_home": sum(user != "runner" for user in LINUX_HOME.findall(local)),
        }
        for reason, count in counts.items():
            if count:
                self.add(self.findings, path, reason, count)
        count = sum(not self.allowed_email(m.group(0)) for m in EMAIL.finditer(value))
        if count:
            self.add(self.review, path, "email_requires_review", count)

    def opaque_history(self, path, data=b""):
        parts = path.replace("!", "/").split("/")
        if ".git" in {part.casefold() for part in parts} or path.lower().endswith(".bundle") or data.startswith((b"# v2 git bundle", b"# v3 git bundle")):
            self.add(self.findings, path, "git_history_requires_omission")
            return True
        return False

    def archive_name(self, name):
        value = normalize(name)
        if not value or "\x00" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
            return None
        parts = value.split("/")
        if ".." in parts:
            return None
        parts = [part for part in parts if part not in {"", "."}]
        return "/".join(parts) or "."

    def inspect(self, data, path, depth=0):
        if self.opaque_history(path, data):
            return
        self.text(path, path)
        self.text(data.decode("utf-8", errors="replace"), path)
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            self.text(data.decode("utf-16", errors="replace"), path)
        name = path.lower()
        is_zip = name.endswith((".zip", ".whl", ".docx", ".xlsx", ".pptx")) or data.startswith((b"PK\x03\x04", b"PK\x05\x06"))
        is_tar = name.endswith((".tar.gz", ".tgz", ".tar")) or data.startswith(b"\x1f\x8b")
        if is_zip or is_tar:
            if depth >= self.limits.depth:
                self.add(self.findings, path, "archive_depth_budget_exceeded")
                self.incomplete = True
                return
            if is_zip:
                self.zip(data, path, depth + 1)
            else:
                self.tar(data, path, depth + 1)
        elif name.endswith(".pdf") or data.startswith(b"%PDF-"):
            self.pdf(data, path)
        else:
            self.dsse(data, path, depth)

    def zip(self, data, path, depth):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.text(archive.comment.decode("utf-8", errors="replace"), path)
                seen = set()
                for index, item in enumerate(archive.infolist()):
                    anonymous = path + f"!<member-{index:05d}>"
                    name = self.archive_name(item.filename)
                    if name is None:
                        self.add(self.findings, anonymous, "unsafe_archive_path")
                        self.incomplete = True
                        if not self.member(anonymous):
                            return
                        continue
                    target = path + "!" + name
                    self.text(item.filename, target)
                    self.text(item.comment.decode("utf-8", errors="replace"), target)
                    self.text(item.extra.decode("utf-8", errors="replace"), target)
                    if name in seen:
                        self.add(self.findings, target, "duplicate_archive_member")
                        self.incomplete = True
                    seen.add(name)
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                        self.add(self.findings, target, "archive_link_or_special_member")
                        self.incomplete = True
                        self.member(target)
                        continue
                    if self.opaque_history(target):
                        self.member(target)
                        continue
                    if not self.member(target, item.file_size):
                        continue
                    if not item.is_dir():
                        if item.flag_bits & 1:
                            self.add(self.findings, target, "encrypted_archive_member")
                            self.incomplete = True
                            continue
                        with archive.open(item) as stream:
                            payload = stream.read(self.limits.member_bytes + 1)
                        if len(payload) != item.file_size:
                            self.add(self.findings, target, "archive_member_size_mismatch")
                            self.incomplete = True
                            continue
                        self.inspect(payload, target, depth)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, ValueError, EOFError, zlib.error):
            self.add(self.findings, path, "unreadable_zip")
            self.incomplete = True

    def tar(self, data, path, depth):
        try:
            compressed = not path.lower().endswith(".tar")
            stream = gzip.GzipFile(fileobj=io.BytesIO(data)) if compressed else io.BytesIO(data)
            with stream, tarfile.open(fileobj=TarBudgetReader(stream, self), mode="r|") as archive:
                seen = set()
                for index, item in enumerate(archive):
                    anonymous = path + f"!<member-{index:05d}>"
                    name = self.archive_name(item.name)
                    if name is None:
                        self.add(self.findings, anonymous, "unsafe_archive_path")
                        self.incomplete = True
                        self.member(anonymous, charge=False)
                        continue
                    target = path + "!" + name
                    self.text(item.name, target)
                    self.text(item.uname + " " + item.gname + " " + json.dumps(item.pax_headers), target)
                    if name in seen:
                        self.add(self.findings, target, "duplicate_archive_member")
                        self.incomplete = True
                    seen.add(name)
                    if not item.isfile() and not item.isdir():
                        self.add(self.findings, target, "archive_link_or_special_member")
                        self.incomplete = True
                        self.member(target, charge=False)
                        continue
                    if self.opaque_history(target):
                        self.member(target, charge=False)
                        continue
                    if not self.member(target, item.size, charge=False):
                        continue
                    if item.isfile():
                        member = archive.extractfile(item)
                        if member is None:
                            raise tarfile.ReadError
                        self.inspect(member.read(self.limits.member_bytes + 1), target, depth)
        except (tarfile.TarError, OSError, ValueError, EOFError, zlib.error):
            known_path = path == NEGATIVE_TAR or path.endswith("/" + NEGATIVE_TAR)
            if known_path and hashlib.sha256(data).hexdigest() == NEGATIVE_TAR_SHA256:
                self.add(self.notices, path, "retained_negative_binary_not_inspected")
            else:
                self.add(self.findings, path, "unreadable_tar")
                self.incomplete = True

    def dsse(self, data, path, depth):
        if not data.lstrip().startswith((b"{", b"[")) or (b'"dsseEnvelope"' not in data and b'"payloadType"' not in data):
            return
        try:
            text = data.decode("utf-8")
            try:
                documents = [json.loads(text)]
            except json.JSONDecodeError:
                documents = [json.loads(line) for line in text.splitlines() if line.strip()]
            pending = list(documents)
            nodes = 0
            while pending:
                node = pending.pop()
                nodes += 1
                if nodes > self.limits.object_nodes:
                    raise BudgetExceeded
                if isinstance(node, dict):
                    if "payload" in node and "payloadType" in node:
                        if depth >= self.limits.depth or not isinstance(node["payload"], str):
                            raise ValueError
                        payload = base64.b64decode(node["payload"], validate=True)
                        target = path + "!<dsse-payload>"
                        if self.member(target, len(payload)):
                            self.inspect(payload, target, depth + 1)
                    pending.extend(node.values())
                elif isinstance(node, list):
                    pending.extend(node)
        except (ValueError, UnicodeError, binascii.Error, RecursionError):
            self.add(self.findings, path, "unreadable_dsse_payload")
            self.incomplete = True

    def pdf(self, data, path):
        # Include lazy object/page decoding in the diagnostic suppression.
        with contextlib.redirect_stderr(io.StringIO()):
            self.pdf_content(data, path)

    def pdf_content(self, data, path):
        try:
            from pypdf import PdfReader
            from pypdf.generic import IndirectObject
        except ImportError:
            self.add(self.limitations, path, "pdf_requires_separate_inspection")
            return
        phase = "structure"
        try:
            # pypdf can print document-derived diagnostics. Keep those out of
            # the scanner's machine output; findings never include exceptions.
            with contextlib.redirect_stderr(io.StringIO()):
                reader = PdfReader(io.BytesIO(data), strict=True)
            if reader.is_encrypted:
                self.add(self.findings, path, "encrypted_pdf")
                self.incomplete = True
                return
            phase = "objects"
            pending, seen, nodes = [reader.trailer], set(), 0
            while pending:
                value = pending.pop()
                nodes += 1
                if nodes > self.limits.pdf_object_nodes:
                    self.add(self.limitations, path, "pdf_object_budget_exceeded")
                    return
                if isinstance(value, IndirectObject):
                    key = (value.idnum, value.generation)
                    if key in seen:
                        continue
                    seen.add(key)
                    pending.append(value.get_object())
                elif isinstance(value, dict):
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
                elif isinstance(value, str):
                    self.text(value, path)
            phase = "pages"
            if len(reader.pages) > self.limits.pdf_pages:
                self.add(self.limitations, path, "pdf_page_budget_exceeded")
                return
            phase = "text"
            for page in reader.pages:
                content = page.extract_text() or ""
                encoded = content.encode("utf-8")
                if not self.member(path, len(encoded)):
                    return
                self.text(content, path)
        except BudgetExceeded:
            raise
        except Exception:
            # Parser exceptions can include document values: never echo them.
            self.add(self.limitations, path, "pdf_" + phase + "_inspection_failed")

    def directory(self, root, relative=""):
        with os.scandir(root) as entries:
            bounded = []
            for item in entries:
                bounded.append(item)
                if len(bounded) + self.members_read > self.limits.members:
                    raise BudgetExceeded
            for item in sorted(bounded, key=lambda e: e.name):
                name = relative + item.name
                self.text(name, name)
                if item.is_symlink():
                    self.add(self.findings, name, "filesystem_symlink")
                    self.incomplete = True
                    self.member(name)
                elif self.opaque_history(name):
                    self.member(name)
                elif item.is_dir(follow_symlinks=False):
                    self.member(name)
                    self.directory(Path(item.path), name + "/")
                elif item.is_file(follow_symlinks=False):
                    size = item.stat(follow_symlinks=False).st_size
                    if self.member(name, size):
                        data = self.read_file(item.path, size, name)
                        if data is not None:
                            self.inspect(data, name)
                else:
                    self.add(self.findings, name, "filesystem_special_file")
                    self.incomplete = True
                    self.member(name)

    def read_file(self, path, size, logical):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                self.add(self.findings, logical, "file_changed_during_scan")
                self.incomplete = True
                return None
            data = stream.read(self.limits.member_bytes + 1)
            after = os.fstat(stream.fileno())
        if len(data) != size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            self.add(self.findings, logical, "file_changed_during_scan")
            self.incomplete = True
            return None
        return data

    def report(self):
        def rows(group):
            return [{"path": path, "reason": reason, "count": count} for (path, reason), count in sorted(group.items())]
        status = ("incomplete" if self.incomplete else "findings" if self.findings else
                  "review_required" if self.review else "passed_with_limits" if self.limitations or self.notices else "passed")
        return {"format": "eacp.privacy-scan/1", "status": status,
                "findings": rows(self.findings), "review": rows(self.review),
                "limitations": rows(self.limitations), "notices": rows(self.notices),
                "counts": {"members": self.members_read, "bytes": self.bytes_read}}

    def scan(self, root):
        root = Path(root)
        try:
            if root.is_symlink():
                self.add(self.findings, ".", "filesystem_symlink")
                self.incomplete = True
            elif root.name.casefold() == ".git":
                self.opaque_history(".git")
            elif root.is_dir():
                self.directory(root)
            elif root.is_file():
                self.text(root.name, ".")
                size = root.stat().st_size
                if self.member(".", size):
                    data = self.read_file(root, size, ".")
                    # The root filename may itself be private: keep it out of reports.
                    extensions = (".tar.gz", ".tgz", ".tar", ".zip", ".whl", ".docx", ".xlsx", ".pptx", ".pdf", ".bundle", ".jsonl", ".json", ".txt", ".py")
                    suffix = next((ext for ext in extensions if root.name.lower().endswith(ext)), "")
                    if data is not None:
                        self.inspect(data, "<input>" + suffix)
            else:
                self.add(self.findings, ".", "unreadable_input")
                self.incomplete = True
        except BudgetExceeded:
            self.add(self.findings, ".", "aggregate_resource_budget_exceeded")
            self.incomplete = True
        except (OSError, RecursionError):
            self.add(self.findings, ".", "unreadable_input")
            self.incomplete = True
        return self.report()


def scan(path, policy=None, limits=None):
    return Scanner(policy, limits).scan(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--policy", type=Path, help="external JSON containing deny_literals and allow_emails")
    args = parser.parse_args(argv)
    try:
        policy = None
        if args.policy:
            resolved = args.policy.resolve()
            repo = Path(__file__).resolve().parents[1]
            target = args.input.resolve()
            if resolved.is_relative_to(repo) or (target.is_dir() and resolved.is_relative_to(target)):
                raise ValueError
            if args.policy.stat().st_size > 65536:
                raise ValueError
            policy = json.loads(args.policy.read_text(encoding="utf-8"))
            if not isinstance(policy, dict):
                raise ValueError
        report = scan(args.input, policy)
    except (OSError, ValueError, TypeError, UnicodeError):
        report = {"format": "eacp.privacy-scan/1", "status": "incomplete",
                  "findings": [{"path": ".", "reason": "invalid_or_nonexternal_policy", "count": 1}],
                  "review": [], "limitations": [], "notices": [], "counts": {"members": 0, "bytes": 0}}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] in {"passed", "passed_with_limits"} and not report["limitations"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
