#!/usr/bin/env bash
set -euo pipefail

RUN_ID=${1:?Usage: capture_completed_run_v1_3.sh RUN_ID OUTPUT_DIR}
OUTPUT_DIR=${2:?Usage: capture_completed_run_v1_3.sh RUN_ID OUTPUT_DIR}
REPOSITORY=obedebessa/eacp-operational-provenance
SIGNER_WORKFLOW=obedebessa/eacp-operational-provenance/.github/workflows/eacp-cross-plane-v1.3.yml

for command_name in gh python3 shasum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command not found: ${command_name}" >&2
    exit 1
  fi
done
if [[ ! "${RUN_ID}" =~ ^[0-9]+$ ]]; then
  echo "RUN_ID must be a positive decimal integer." >&2
  exit 1
fi
if [[ -e "${OUTPUT_DIR}" ]]; then
  echo "Refusing to overwrite output: ${OUTPUT_DIR}" >&2
  exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/eacp-capture-run.XXXXXX")
cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  rm -rf -- "${WORK_DIR}"
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

RUN_METADATA="${WORK_DIR}/run_metadata.json"
gh run view "${RUN_ID}" --repo "${REPOSITORY}" \
  --json attempt,conclusion,event,headBranch,headSha,status,url,workflowName \
  > "${RUN_METADATA}"

IFS=$'\t' read -r RUN_ATTEMPT HEAD_SHA HEAD_BRANCH STATUS CONCLUSION EVENT WORKFLOW_NAME < <(
  python3 - "${RUN_METADATA}" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
fields = [
    value.get("attempt"), value.get("headSha"), value.get("headBranch"),
    value.get("status"), value.get("conclusion"), value.get("event"),
    value.get("workflowName"),
]
print("\t".join(str(field or "") for field in fields))
PY
)
if [[ "${STATUS}" != "completed" || "${CONCLUSION}" != "success" ]]; then
  echo "Run ${RUN_ID} is not completed/success: ${STATUS}/${CONCLUSION}" >&2
  exit 1
fi
if [[ "${EVENT}" != "push" ]] || ! [[ "${HEAD_BRANCH}" =~ ^eacp-v1\.3-evidence/k8s-v1\.(34\.8|35\.5|36\.1)/run-0[1-6]$ ]]; then
  echo "Run ${RUN_ID} is not an approved evidence-tag push: ${EVENT}/${HEAD_BRANCH}" >&2
  exit 1
fi
if [[ "${WORKFLOW_NAME}" != ".github/workflows/eacp-cross-plane-v1.3.yml" ]]; then
  echo "Run ${RUN_ID} came from an unexpected workflow: ${WORKFLOW_NAME}" >&2
  exit 1
fi
if [[ "${RUN_ATTEMPT}" != "1" ]]; then
  echo "Cohort capture accepts only first attempts; observed ${RUN_ATTEMPT}." >&2
  exit 1
fi
TAG_INVOCATION="${WORK_DIR}/tag_invocation.json"
python3 "$(dirname "$0")/capture_tag_invocation_v1_3.py" \
  --repo "${REPOSITORY}" \
  --tag "${HEAD_BRANCH}" \
  --run-id "${RUN_ID}" \
  --protocol-commit "${HEAD_SHA}" \
  --conclusion "${CONCLUSION}" \
  --output "${TAG_INVOCATION}" >/dev/null

ARTIFACT_NAME="eacp-cross-plane-v1.3-${RUN_ID}-${RUN_ATTEMPT}"
DOWNLOAD_DIR="${WORK_DIR}/downloaded-artifact"
mkdir -p "${DOWNLOAD_DIR}"
gh run download "${RUN_ID}" --repo "${REPOSITORY}" \
  --name "${ARTIFACT_NAME}" --dir "${DOWNLOAD_DIR}"

RESULTS_DIR="${DOWNLOAD_DIR}/eacp-cross-plane-v1.3-results"
ARCHIVE="${DOWNLOAD_DIR}/${ARTIFACT_NAME}.tar.gz"
ARCHIVE_MANIFEST="${ARCHIVE}.sha256"
if [[ ! -d "${RESULTS_DIR}" || ! -f "${ARCHIVE}" || ! -f "${ARCHIVE_MANIFEST}" ]]; then
  echo "Downloaded artifact has an unexpected layout." >&2
  exit 1
fi
(
  cd "${DOWNLOAD_DIR}"
  shasum -a 256 -c "$(basename "${ARCHIVE_MANIFEST}")"
)
(
  cd "${RESULTS_DIR}"
  shasum -a 256 -c PUBLIC_SHA256SUMS
)

mkdir -p "${OUTPUT_DIR}"
cp -R "${DOWNLOAD_DIR}" "${OUTPUT_DIR}/downloaded-artifact"
cp "${RUN_METADATA}" "${OUTPUT_DIR}/run_metadata.json"
cp "${TAG_INVOCATION}" "${OUTPUT_DIR}/tag_invocation.json"
bash "$(dirname "$0")/finalize_cross_plane_v1_3.sh" \
  "${OUTPUT_DIR}/downloaded-artifact/eacp-cross-plane-v1.3-results" \
  "${OUTPUT_DIR}/finalized"

mkdir -p "${OUTPUT_DIR}/attestation"
(
  cd "${OUTPUT_DIR}/attestation"
  gh attestation download "../downloaded-artifact/${ARTIFACT_NAME}.tar.gz" \
    --repo "${REPOSITORY}"
)
BUNDLE=$(python3 "$(dirname "$0")/normalize_attestation_bundle_v1_3.py" \
  "${OUTPUT_DIR}/attestation")
SOURCE_REF="refs/tags/${HEAD_BRANCH}"
TRUSTED_ROOT="${OUTPUT_DIR}/attestation/trusted_root.jsonl"
DEFAULT_VERIFICATION="${OUTPUT_DIR}/attestation/verification-default-trust.json"
CAPTURED_ROOT_VERIFICATION="${OUTPUT_DIR}/attestation/verification-captured-root.json"
gh attestation verify "${OUTPUT_DIR}/downloaded-artifact/${ARTIFACT_NAME}.tar.gz" \
  --hostname github.com \
  --bundle "${BUNDLE}" \
  --repo "${REPOSITORY}" \
  --signer-workflow "${SIGNER_WORKFLOW}" \
  --signer-digest "${HEAD_SHA}" \
  --source-digest "${HEAD_SHA}" \
  --source-ref "${SOURCE_REF}" \
  --predicate-type https://slsa.dev/provenance/v1 \
  --deny-self-hosted-runners \
  --format json > "${DEFAULT_VERIFICATION}"
gh attestation trusted-root --hostname github.com > "${TRUSTED_ROOT}"
gh attestation verify "${OUTPUT_DIR}/downloaded-artifact/${ARTIFACT_NAME}.tar.gz" \
  --hostname github.com \
  --bundle "${BUNDLE}" \
  --custom-trusted-root "${TRUSTED_ROOT}" \
  --repo "${REPOSITORY}" \
  --signer-workflow "${SIGNER_WORKFLOW}" \
  --signer-digest "${HEAD_SHA}" \
  --source-digest "${HEAD_SHA}" \
  --source-ref "${SOURCE_REF}" \
  --predicate-type https://slsa.dev/provenance/v1 \
  --deny-self-hosted-runners \
  --format json > "${CAPTURED_ROOT_VERIFICATION}"

python3 - "${DEFAULT_VERIFICATION}" "${CAPTURED_ROOT_VERIFICATION}" <<'PY'
import json
import sys
from pathlib import Path

default_path, captured_path = map(Path, sys.argv[1:])
default = json.loads(default_path.read_text(encoding="utf-8"))
captured = json.loads(captured_path.read_text(encoding="utf-8"))
if default != captured:
    raise SystemExit(
        "default-trust and captured-root verification results differ semantically"
    )
PY

GH_VERSION=$(gh --version | sed -n '1p')
TRUSTED_ROOT_SHA256=$(shasum -a 256 "${TRUSTED_ROOT}" | awk '{print $1}')

python3 - "${OUTPUT_DIR}/attestation/verification-policy.json" \
  "${REPOSITORY}" "${SIGNER_WORKFLOW}" "${HEAD_SHA}" "${SOURCE_REF}" \
  "${GH_VERSION}" "${TRUSTED_ROOT_SHA256}" <<'PY'
import json
import sys
from pathlib import Path

(
    output, repository, signer_workflow, source_digest, source_ref,
    gh_version, trusted_root_sha256,
) = sys.argv[1:]
Path(output).write_text(
    json.dumps(
        {
            "schema_version": "eacp.attestation-verification-policy/1.3.1",
            "repository": repository,
            "signer_workflow": signer_workflow,
            "signer_digest": source_digest,
            "source_digest": source_digest,
            "source_ref": source_ref,
            "predicate_type": "https://slsa.dev/provenance/v1",
            "deny_self_hosted_runners": True,
            "bundle_on_disk": True,
            "capture_time_default_trust_verification": True,
            "capture_time_captured_root_verification": True,
            "custom_trusted_root_on_disk": True,
            "trusted_root_sha256": trusted_root_sha256,
            "gh_cli_version": gh_version,
            "attested_scope": "in_run_tar_archive_only",
            "completed_finalization_builder_attested": False,
            "trust_bootstrap_boundary": (
                "The captured root makes later verification offline and reproducible relative "
                "to those root bytes. Its authenticity is not self-proving; capture therefore "
                "also verifies the same bundle with GitHub CLI's default trust configuration."
            ),
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

python3 - "${OUTPUT_DIR}" > "${OUTPUT_DIR}/RUN_SHA256SUMS" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
for path in sorted(
    (item for item in root.rglob("*") if item.is_file() and item.name != "RUN_SHA256SUMS"),
    key=lambda item: item.relative_to(root).as_posix(),
):
    print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(root).as_posix()}")
PY
(
  cd "${OUTPUT_DIR}"
  shasum -a 256 -c RUN_SHA256SUMS
)
echo "Captured and offline-verified run ${RUN_ID} at ${OUTPUT_DIR}"
