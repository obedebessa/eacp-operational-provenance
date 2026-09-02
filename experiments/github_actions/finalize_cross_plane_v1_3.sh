#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_RESULTS=${1:?Usage: finalize_cross_plane_v1_3.sh EXTRACTED_RESULTS_DIR FINAL_OUTPUT_DIR}
FINAL_OUTPUT=${2:?Usage: finalize_cross_plane_v1_3.sh EXTRACTED_RESULTS_DIR FINAL_OUTPUT_DIR}

for command_name in gh python3 shasum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command not found: ${command_name}" >&2
    exit 1
  fi
done
if [[ ! -f "${SOURCE_RESULTS}/environment.json" || ! -f "${SOURCE_RESULTS}/PUBLIC_SHA256SUMS" ]]; then
  echo "Source directory is not an extracted cross-plane result bundle: ${SOURCE_RESULTS}" >&2
  exit 1
fi
if [[ -e "${FINAL_OUTPUT}" ]]; then
  echo "Refusing to overwrite final output: ${FINAL_OUTPUT}" >&2
  exit 1
fi
(
  cd "${SOURCE_RESULTS}"
  shasum -a 256 -c PUBLIC_SHA256SUMS
)

IFS=$'\t' read -r REPOSITORY RUN_ID RUN_ATTEMPT CORRELATION_ID SUBJECT_URI SUBJECT_DIGEST < <(
python3 - "${SOURCE_RESULTS}/environment.json" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
keys = ("repository", "run_id", "run_attempt", "correlation_id", "subject_uri", "subject_digest")
fields = [str(value[key]) for key in keys]
if any("\t" in field or "\n" in field for field in fields):
    raise SystemExit("environment identity fields contain unsupported control characters")
print("\t".join(fields))
PY
)

mkdir -p "${FINAL_OUTPUT}"
python3 "${SCRIPT_DIR}/eacp_gha_v1_3.py" capture \
  --repo "${REPOSITORY}" \
  --run-id "${RUN_ID}" \
  --output-dir "${FINAL_OUTPUT}/github_completed" \
  --service "${REPOSITORY}" \
  --deployment eacp-cross-plane \
  --namespace eacp-cross-plane-v13 \
  --subject-uri "${SUBJECT_URI}" \
  --subject-digest "${SUBJECT_DIGEST}" >/dev/null

python3 - "${FINAL_OUTPUT}/github_completed/source/github_actions.json" \
  "${RUN_ATTEMPT}" "${CORRELATION_ID}" <<'PY'
import json
import sys
from pathlib import Path

snapshot = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected_attempt = int(sys.argv[2])
expected_correlation = sys.argv[3]
run = snapshot["run"]
if run["run_attempt"] != expected_attempt:
    raise SystemExit(f"run attempt changed: expected {expected_attempt}, observed {run['run_attempt']}")
if snapshot["projection"]["correlation_id"] != expected_correlation:
    raise SystemExit("completed capture correlation differs from the runtime evidence")
if run["status"] != "completed" or not run["conclusion"]:
    raise SystemExit(f"GitHub run is not final yet: status={run['status']!r}, conclusion={run['conclusion']!r}")
PY

python3 "${SCRIPT_DIR}/eacp_gha_v1_3.py" join \
  --bundle "${FINAL_OUTPUT}/github_completed" \
  --kubernetes-evidence-csv "${SOURCE_RESULTS}/kubernetes/audit/normalized_evidence.csv" \
  --kubernetes-object-json "${SOURCE_RESULTS}/kubernetes/deployment.json" \
  --negative-control-object-json "${SOURCE_RESULTS}/kubernetes/negative_control.json" \
  --kubernetes-pods-json "${SOURCE_RESULTS}/kubernetes/pods.json" \
  --kubernetes-audit-summary-json "${SOURCE_RESULTS}/kubernetes/audit/audit_summary.json" \
  --output "${FINAL_OUTPUT}/cross_plane_join_completed.json"

python3 - "${FINAL_OUTPUT}/cross_plane_join_completed.json" \
  "${SOURCE_RESULTS}/PUBLIC_SHA256SUMS" "${FINAL_OUTPUT}/finalization.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

join_path, source_manifest, output_path = map(Path, sys.argv[1:])
report = json.loads(join_path.read_text(encoding="utf-8"))
if report["status"] != "observed_cross_plane_link_with_subject_digest":
    raise SystemExit(f"completed join validation failed: {report['status']}")
binding = report["kubernetes"]["rbac_denial_binding"]
if not binding or binding["binding_method"] != "adapter_explicit_exact_target":
    raise SystemExit("completed join is missing the target-bound adapter-explicit RBAC denial")
value = {
    "schema_version": "eacp.cross-plane-finalization/1.3.0",
    "source_results_manifest_sha256": hashlib.sha256(source_manifest.read_bytes()).hexdigest(),
    "github_run_status": "completed",
    "github_run_conclusion": json.loads(
        (join_path.parent / "github_completed/source/github_actions.json").read_text(encoding="utf-8")
    )["run"]["conclusion"],
    "join_status": report["status"],
    "claim_boundary": (
        "Post-run capture closes API timestamps and artifact metadata. It does not retroactively change "
        "the already checksummed Kubernetes observation."
    ),
}
output_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 - "${FINAL_OUTPUT}" > "${FINAL_OUTPUT}/SHA256SUMS" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
for path in sorted(
    (candidate for candidate in root.rglob("*") if candidate.is_file() and candidate.name != "SHA256SUMS"),
    key=lambda candidate: candidate.relative_to(root).as_posix(),
):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    relative = "./" + path.relative_to(root).as_posix()
    print(f"{digest}  {relative}")
PY

echo "Completed-run finalization written to ${FINAL_OUTPUT}"
