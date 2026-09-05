import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from eacp_hardening.cli import validate_config, now_utc
from eacp_hardening.common import HardeningError
from eacp_hardening.demo import fixture
from eacp_hardening.github_reader import collect_run

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('candidate_packager', ROOT / 'scripts/package_candidate_v1_5.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class ArtifactContractTests(unittest.TestCase):
    def test_P01_full_dotted_candidate_filename_preserved(self):
        self.assertEqual(packager.archive_path(Path('/tmp/eacp-1.5.0rc1')), Path('/tmp/eacp-1.5.0rc1.zip'))

    def test_P02_existing_output_is_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / 'candidate'
            output.mkdir()
            original = output / 'original'
            original.write_text('retained evidence')
            with self.assertRaises(ValueError):
                packager.package(output, Path(d) / 'unused')
            self.assertEqual(original.read_text(), 'retained evidence')

    def test_P03_imports_do_not_create_files_in_operator_directory(self):
        with tempfile.TemporaryDirectory() as d:
            code = "import sys;sys.path.insert(0,sys.argv[1]);import eacp_hardening.cli,eacp_hardening.operations,eacp_hardening.demo"
            result = subprocess.run([sys.executable, '-c', code, str(ROOT)], cwd=d, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_B06_huge_freshness_is_rejected_before_timedelta_overflow(self):
        config, *_ = fixture('2026-09-05T06:00:00Z')
        config['max_statement_age_seconds'] = 10**100
        with self.assertRaises(HardeningError):
            validate_config(config)

    def test_T01_cutoff_default_retains_microsecond_precision(self):
        self.assertRegex(now_utc(), r'T\d\d:\d\d:\d\d\.\d{6}Z$')

    def test_G05_provider_repository_schema_change_fails_safely(self):
        def fetch(*a, **k):
            return {'id': 7, 'run_attempt': 1, 'repository': []}, {}
        with self.assertRaises(HardeningError):
            collect_run('owner/repo', 7, 1, fetch=fetch)
