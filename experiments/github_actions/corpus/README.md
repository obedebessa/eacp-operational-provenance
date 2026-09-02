# Frozen real GitHub Actions API capture

`github-public-run-31075453078/` is a minimized, checksummed capture of the
public GitHub Actions run at:

<https://github.com/obedebessa/eacp-operational-provenance/actions/runs/31075453078>

Capture facts:

- REST capture time: `2026-09-02T20:36:24Z`;
- source run time: `2026-08-06T05:52:51Z` to `2026-08-06T05:53:05Z`;
- repository ID: `1324720646`;
- run attempt: `1`;
- commit: `829d1babff46c0b52c01dfcc856148d91b50dc93`;
- conclusion: `success`;
- EACP projection: one workflow row and two job rows;
- source artifacts reported by the API: zero.

The capture was made through an authenticated, read-only `gh api` session. The
records are real GitHub API metadata, but this adapter does not independently
authenticate GitHub's statements. The raw API response, logs, event payload,
commit author data, runner identity, and artifact contents were not retained.

This historical run did not emit the new Kubernetes annotation. The generated
patch is therefore a hand-off proposal, not evidence that the Kubernetes plane
was observed. `summary.json` records `patch_generated_not_observed` for that
reason. Do not use this corpus as the positive cross-plane result; use it to
reproduce and audit the GitHub adapter before executing the v1.3 workflow.

Verify it with:

```bash
python3 experiments/github_actions/eacp_gha_v1_3.py verify \
  --bundle experiments/github_actions/corpus/github-public-run-31075453078
```
