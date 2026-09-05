"""Bounded read-only GitHub run/attempt/job acquisition with fail-closed paging.

Public API GET only; no deployments, workflow dispatch, or artifact execution.
Stable totals are necessary but not sufficient for source truth/completeness.
On rate limits or transport failure the caller retries the entire bounded read;
there is no silently committed partial capture or automatically aggressive retry.
"""
import re
from .common import HardeningError
from .privacy import project_github_metadata
from .trust import fetch_https_json


def collect_run(repository, run_id, attempt, *, max_pages=10, per_page=100, fetch=fetch_https_json):
    if not isinstance(repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise HardeningError('invalid GitHub repository')
    if any(type(x) is not int or x < 1 for x in (run_id, attempt, max_pages, per_page)) or max_pages > 10 or per_page > 100:
        raise HardeningError('invalid bounded GitHub query')
    base = f'https://api.github.com/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}'
    options = {'allowed_origins': ('https://api.github.com',), 'timeout': 10.0}
    run, receipt = fetch(base, **options)
    if not isinstance(run, dict) or run.get('id') != run_id or run.get('run_attempt') != attempt:
        raise HardeningError('GitHub run or attempt mismatch')
    if not isinstance(run.get('repository'), dict) or run['repository'].get('full_name') != repository:
        raise HardeningError('GitHub repository mismatch')
    jobs, seen, receipts, total = [], set(), [receipt], None
    for page in range(1, max_pages + 1):
        data, proof = fetch(base + f'/jobs?per_page={per_page}&page={page}', **options)
        if not isinstance(data, dict) or type(data.get('total_count')) is not int or not isinstance(data.get('jobs'), list):
            raise HardeningError('GitHub pagination schema mismatch')
        if not 0 <= data['total_count'] <= max_pages * per_page or len(data['jobs']) > per_page:
            raise HardeningError('GitHub capture exceeds pagination budget')
        if total is not None and data['total_count'] != total:
            raise HardeningError('GitHub total changed during capture; retry complete read')
        total = data['total_count']
        for job in data['jobs']:
            if (not isinstance(job, dict) or type(job.get('id')) is not int or job['id'] in seen
                    or job.get('run_id') != run_id or job.get('run_attempt') != attempt):
                raise HardeningError('GitHub duplicate job or context mismatch')
            seen.add(job['id'])
            jobs.append(project_github_metadata(job, kind='job').payload)
        receipts.append(proof)
        if len(jobs) == total:
            return {'format': 'eacp.github-bounded-read/1', 'repository': repository, 'run_id': run_id,
                    'run_attempt': attempt, 'run': project_github_metadata(run, kind='run').payload,
                    'jobs': jobs, 'acquisition_receipts': receipts, 'reported_total': total,
                    'status': 'CAPTURED_REPORTED_SET', 'source_truth_verified': False,
                    'scope': 'one public run attempt; no atomic provider snapshot or live Kubernetes execution'}
        if len(data['jobs']) < per_page or len(jobs) > total:
            raise HardeningError('GitHub pagination ended before reported set was captured')
    raise HardeningError('GitHub pagination limit reached without complete reported set')
