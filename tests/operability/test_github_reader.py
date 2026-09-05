import unittest
from eacp_hardening.common import HardeningError
from eacp_hardening.github_reader import collect_run


class GitHubReadTests(unittest.TestCase):
    def fetch(self, totals=(2, 2), ids=(1, 2), attempt=1):
        def get(url, **kwargs):
            self.assertEqual(kwargs['allowed_origins'], ('https://api.github.com',))
            if '/jobs?' not in url:
                return {'id': 7, 'run_attempt': 1, 'repository': {'id': 3, 'full_name': 'owner/repo', 'private': False},
                        'head_sha': 'a' * 40, 'created_at': '2026-09-05T06:00:00Z', 'updated_at': '2026-09-05T06:00:00Z',
                        'actor': {'id': 2, 'login': 'synthetic'}}, {'raw_sha256': 'a' * 64}
            page = int(url.rsplit('=', 1)[1]) - 1
            return {'total_count': totals[page], 'jobs': [{'id': ids[page], 'run_id': 7, 'run_attempt': attempt}]}, {'raw_sha256': 'b' * 64}
        return get

    def test_G01_two_page_fixture_preserves_attempt_and_job_identity(self):
        result = collect_run('owner/repo', 7, 1, per_page=1, fetch=self.fetch())
        self.assertEqual(result['reported_total'], 2)
        self.assertEqual([j['id'] for j in result['jobs']], [1, 2])

    def test_G02_duplicate_changed_total_and_wrong_attempt_rejected(self):
        for fetch in (self.fetch(ids=(1, 1)), self.fetch(totals=(2, 3)), self.fetch(attempt=2)):
            with self.assertRaises(HardeningError):
                collect_run('owner/repo', 7, 1, per_page=1, fetch=fetch)

    def test_G03_no_network_for_path_injection_or_resource_abuse(self):
        for repo, run, attempt in [('owner/repo/../../internal', 7, 1), ('owner/repo', True, 1), ('owner/repo', 7, 0)]:
            with self.assertRaises(HardeningError):
                collect_run(repo, run, attempt, fetch=lambda *a, **k: self.fail('network must not be invoked'))

    def test_G04_rate_limit_does_not_return_partial_success(self):
        def fail(url, **kwargs):
            if '/jobs?' in url:
                raise HardeningError('source rate limited; retry later')
            return self.fetch()(url, **kwargs)
        with self.assertRaises(HardeningError):
            collect_run('owner/repo', 7, 1, fetch=fail)
