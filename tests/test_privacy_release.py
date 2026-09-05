"""Privacy checks use fictitious data; private policy values never belong here."""
import base64
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("privacy_scan_v1_5", ROOT / "scripts/privacy_scan_v1_5.py")
privacy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = privacy
SPEC.loader.exec_module(privacy)


# Assemble fictitious sensitive strings at runtime so the distributable test
# source does not itself resemble an accidentally retained execution receipt.
MAC_PATH = "/" + "Users" + "/avery/work"
LINUX_PATH = "/" + "home" + "/avery/work"
WINDOWS_PATH = "C:" + "\\" + "Users" + "\\avery\\work"


def private_email(local="reviewer"):
    return local + "@" + "private.example"


def zip_bytes(members):
    output = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        warnings.simplefilter("ignore", UserWarning)
        for name, data in members:
            archive.writestr(name, data)
    return output.getvalue()


def tar_bytes(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in members:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


class PrivacyReleaseTests(unittest.TestCase):
    def scan_bytes(self, data, name="sample.txt", policy=None, limits=None):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / name
            path.write_bytes(data)
            before = path.read_bytes()
            report = privacy.scan(path, policy, limits)
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn(temporary, json.dumps(report))
            return report

    def reasons(self, report, group="findings"):
        return {item["reason"] for item in report[group]}

    def test_paths_and_encodings_without_echoing_values(self):
        examples = [
            MAC_PATH + "/Private Case", "file://" + MAC_PATH,
            quote(MAC_PATH, safe=""), quote(quote(MAC_PATH, safe=""), safe=""),
            MAC_PATH.replace("/", "\\" + "u002f"), WINDOWS_PATH,
            WINDOWS_PATH.replace("\\", "\\\\"), LINUX_PATH,
        ]
        report = self.scan_bytes(json.dumps(examples).encode(), policy={"deny_literals": ["Private Case"]})
        self.assertTrue({"private_literal", "private_macos_home", "private_windows_home", "private_linux_home"} <= self.reasons(report))
        self.assertNotIn("avery", json.dumps(report))
        self.assertNotIn("Private Case", json.dumps(report))

    def test_official_urls_and_generic_runner_are_allowed(self):
        value = "https://api.github.com/users/public-project https://sample.test/Users/public /home/runner/work/project"
        report = self.scan_bytes(value.encode())
        self.assertEqual(report["status"], "passed")

    def test_policy_approves_only_selected_email_and_names_remain_public(self):
        approved = "scholar" + "@" + "public.example"
        value = "Published Author contact@public.invalid 42+team@users.noreply.github.com " + approved + " " + private_email()
        report = self.scan_bytes(value.encode(), policy={"allow_emails": [approved]})
        self.assertEqual(report["status"], "review_required")
        self.assertEqual(report["review"][0]["count"], 1)
        self.assertNotIn(private_email(), json.dumps(report))
        self.assertFalse(report["findings"])

    def test_nested_archive_and_dsse_decode_without_changing_signature(self):
        statement = json.dumps({"path": MAC_PATH}).encode()
        envelope = json.dumps({"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(statement).decode(), "signatures": [{"sig": "unchanged"}]}}).encode()
        nested = zip_bytes([("proof.tar.gz", tar_bytes([("bundle.jsonl", envelope)]))])
        report = self.scan_bytes(nested, "review.zip")
        self.assertIn("private_macos_home", self.reasons(report))
        self.assertTrue(any("<dsse-payload>" in row["path"] for row in report["findings"]))

    def test_zip_members_fail_closed(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        report = self.scan_bytes(zip_bytes([("../escape", b"x"), ("same", b"x"), ("./same", b"y"), (link, b"target")]), "review.whl")
        self.assertTrue({"unsafe_archive_path", "duplicate_archive_member", "archive_link_or_special_member"} <= self.reasons(report))
        self.assertEqual(report["status"], "incomplete")

    def test_tar_link_duplicate_and_traversal_fail_closed(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name in ["../escape", "same", "./same"]:
                entry = tarfile.TarInfo(name)
                archive.addfile(entry)
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "outside"
            archive.addfile(link)
        report = self.scan_bytes(output.getvalue(), "review.tar.gz")
        self.assertTrue({"unsafe_archive_path", "duplicate_archive_member", "archive_link_or_special_member"} <= self.reasons(report))

    def test_budgets_fail_closed(self):
        compressed = zip_bytes([("large.txt", b"A" * 4096)])
        report = self.scan_bytes(compressed, "review.zip", limits=privacy.Limits(member_bytes=1024))
        self.assertIn("member_size_budget_exceeded", self.reasons(report))
        report = self.scan_bytes(compressed, "review.zip", limits=privacy.Limits(total_bytes=1024))
        self.assertIn("aggregate_resource_budget_exceeded", self.reasons(report))
        report = self.scan_bytes(zip_bytes([("one", b""), ("two", b"")]), "review.zip", limits=privacy.Limits(members=2))
        self.assertIn("aggregate_resource_budget_exceeded", self.reasons(report))
        report = self.scan_bytes(zip_bytes([("nested.zip", zip_bytes([("a", b"x")]))]), "review.zip", limits=privacy.Limits(depth=1))
        self.assertIn("archive_depth_budget_exceeded", self.reasons(report))

    def test_tar_expansion_budget_includes_headers(self):
        report = self.scan_bytes(tar_bytes([("large", b"x" * 50000)]), "review.tar.gz", limits=privacy.Limits(total_bytes=20000))
        self.assertIn("aggregate_resource_budget_exceeded", self.reasons(report))

    def test_git_is_opaque_and_filesystem_links_are_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("private identity")
            (root / "history.bundle").write_bytes(b"# v2 git bundle\n")
            (root / "link").symlink_to(root / ".git")
            report = privacy.scan(root)
            self.assertIn("git_history_requires_omission", self.reasons(report))
            self.assertIn("filesystem_symlink", self.reasons(report))
            self.assertFalse(any("config" in row["path"] for row in report["findings"]))

    def test_known_corrupt_negative_has_explicit_retained_status(self):
        known = "source/" + privacy.NEGATIVE_TAR
        fixture = b"intentionally invalid"
        with patch.object(privacy, "NEGATIVE_TAR_SHA256", hashlib.sha256(fixture).hexdigest()):
            report = self.scan_bytes(zip_bytes([(known, fixture)]), "review.zip")
        self.assertEqual(report["status"], "passed_with_limits")
        self.assertIn("retained_negative_binary_not_inspected", self.reasons(report, "notices"))
        changed = self.scan_bytes(zip_bytes([(known, b"different binary")]), "review.zip")
        self.assertEqual(changed["status"], "incomplete")
        unrelated = self.scan_bytes(b"invalid", "other.tar.gz")
        self.assertEqual(unrelated["status"], "incomplete")

    def test_private_names_in_paths_are_suppressed(self):
        report = self.scan_bytes(zip_bytes([("Avery Reviewer/notes.txt", b"safe")]), "review.zip", policy={"deny_literals": ["Avery Reviewer"]})
        self.assertIn("private_literal", self.reasons(report))
        self.assertNotIn("Avery Reviewer", json.dumps(report))
        self.assertTrue(any("[private]" in row["path"] for row in report["findings"]))

    def test_missing_pdf_dependency_is_not_a_successful_privacy_gate(self):
        with patch.dict(sys.modules, {"pypdf": None}):
            report = self.scan_bytes(b"%PDF-1.7\nopaque", "paper.pdf")
        self.assertIn("pdf_requires_separate_inspection", self.reasons(report, "limitations"))

    def test_optional_pdf_metadata_and_annotation_strings(self):
        try:
            from pypdf import PdfWriter
            from pypdf.generic import DictionaryObject, NameObject, TextStringObject
        except ImportError:
            self.skipTest("optional pypdf is unavailable")
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.add_metadata({"/Author": "Public Author", "/Subject": MAC_PATH})
        writer._root_object[NameObject("/Extra")] = DictionaryObject({NameObject("/URI"): TextStringObject("mailto:" + private_email())})
        output = io.BytesIO()
        writer.write(output)
        report = self.scan_bytes(output.getvalue(), "paper.pdf")
        self.assertIn("private_macos_home", self.reasons(report))
        self.assertIn("email_requires_review", self.reasons(report, "review"))

    def test_pdf_budget_covers_large_valid_document_and_still_fails_closed(self):
        try:
            from pypdf import PdfWriter
            from pypdf.generic import ArrayObject, NameObject, NumberObject, TextStringObject
        except ImportError:
            self.skipTest("optional pypdf is unavailable")
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        values = ArrayObject([TextStringObject(private_email())])
        values.extend(NumberObject(i) for i in range(22000))
        writer._root_object[NameObject("/BudgetExercise")] = values
        output = io.BytesIO()
        writer.write(output)
        report = self.scan_bytes(output.getvalue(), "large-valid.pdf")
        self.assertFalse(report["limitations"])
        self.assertIn("email_requires_review", self.reasons(report, "review"))
        limited = self.scan_bytes(output.getvalue(), "large-valid.pdf", limits=privacy.Limits(pdf_object_nodes=20000))
        self.assertIn("pdf_object_budget_exceeded", self.reasons(limited, "limitations"))
        self.assertNotEqual(limited["status"], "passed")

    def test_unreadable_pdf_has_explicit_parser_phase(self):
        try:
            import pypdf  # noqa: F401 -- this case exercises the optional parser
        except ImportError:
            self.skipTest("optional pypdf is unavailable")
        report = self.scan_bytes(b"%PDF-1.7\nnot a readable PDF", "broken.pdf")
        self.assertIn("pdf_structure_inspection_failed", self.reasons(report, "limitations"))

    def test_invalid_dsse_is_incomplete(self):
        report = self.scan_bytes(b'{"payloadType":"application/vnd.in-toto+json","payload":"!bad!"}')
        self.assertIn("unreadable_dsse_payload", self.reasons(report))

    def test_external_policy_cli_rejects_policy_inside_scanned_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root / "policy.json"
            policy.write_text(json.dumps({"deny_literals": ["Fictitious Reviewer"]}))
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                result = privacy.main([str(root), "--policy", str(policy)])
            self.assertEqual(result, 1)
            self.assertNotIn("Fictitious Reviewer", output.getvalue())
            self.assertNotIn(temporary, output.getvalue())


if __name__ == "__main__":
    unittest.main()
