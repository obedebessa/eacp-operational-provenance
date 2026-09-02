#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPOSITORY=${EACP_REPOSITORY:?Set EACP_REPOSITORY to owner/repository}
RUN_ID=${EACP_RUN_ID:?Set EACP_RUN_ID to the GitHub Actions run ID}
EXPECTED_ATTEMPT=${EACP_RUN_ATTEMPT:-}
NAMESPACE=eacp-cross-plane-v13
DEPLOYMENT=eacp-cross-plane
NEGATIVE_CONTROL=negative-control-no-correlation
DENIED_PRINCIPAL="system:serviceaccount:${NAMESPACE}:eacp-observer"
SUBJECT_URI=registry.k8s.io/pause
SUBJECT_DIGEST=sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a
SUBJECT_IMAGE="registry.k8s.io/pause@${SUBJECT_DIGEST}"
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
KEEP_CLUSTER=${KEEP_CLUSTER:-0}
RUN_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS_DIR=${RESULTS_DIR:-"${SCRIPT_DIR}/results/${RUN_ID}-${RUN_STAMP}"}
if [[ -n "${WORK_DIR:-}" ]]; then
  WORK_DIR_CREATED=0
else
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/eacp-v1.3-cross-plane.XXXXXX")
  WORK_DIR_CREATED=1
fi
AUDIT_HOST_DIR="${WORK_DIR}/audit-host"
STAGING_BUNDLE="${WORK_DIR}/github-staging"
KIND_CONFIG="${WORK_DIR}/kind-config.yaml"
WORKLOAD="${WORK_DIR}/workload.yaml"
CLUSTER_CREATED=0

for command_name in docker git gh kind kubectl python3 shasum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command not found: ${command_name}" >&2
    exit 1
  fi
done
if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but its daemon is unavailable." >&2
  exit 1
fi
if [[ -e "${RESULTS_DIR}" ]]; then
  echo "Refusing to overwrite existing result directory: ${RESULTS_DIR}" >&2
  exit 1
fi
mkdir -p "${AUDIT_HOST_DIR}"

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  if [[ "${CLUSTER_CREATED}" == "1" && "${KEEP_CLUSTER}" != "1" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
  if [[ "${WORK_DIR_CREATED}" == "1" && -z "${EACP_KEEP_WORK_DIR:-}" ]]; then
    rm -rf -- "${WORK_DIR}"
  fi
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# The first read resolves immutable source fields before Kubernetes mutation.
# It is staging only; the publication bundle is recaptured near the end.
python3 "${SCRIPT_DIR}/eacp_gha_v1_3.py" capture \
  --repo "${REPOSITORY}" \
  --run-id "${RUN_ID}" \
  --output-dir "${STAGING_BUNDLE}" \
  --service "${REPOSITORY}" \
  --deployment "${DEPLOYMENT}" \
  --namespace "${NAMESPACE}" \
  --subject-uri "${SUBJECT_URI}" \
  --subject-digest "${SUBJECT_DIGEST}" >/dev/null

readarray -t SOURCE_FIELDS < <(python3 - "${STAGING_BUNDLE}/source/github_actions.json" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(value["repository"]["id"])
print(value["run"]["run_attempt"])
print(value["run"]["head_sha"])
print(value["run"]["html_url"])
print(value["projection"]["correlation_id"])
PY
)
REPOSITORY_ID=${SOURCE_FIELDS[0]}
RUN_ATTEMPT=${SOURCE_FIELDS[1]}
HEAD_SHA=${SOURCE_FIELDS[2]}
SOURCE_URL=${SOURCE_FIELDS[3]}
CORRELATION_ID=${SOURCE_FIELDS[4]}
if [[ -n "${EXPECTED_ATTEMPT}" && "${RUN_ATTEMPT}" != "${EXPECTED_ATTEMPT}" ]]; then
  echo "API run attempt ${RUN_ATTEMPT} does not match EACP_RUN_ATTEMPT=${EXPECTED_ATTEMPT}." >&2
  exit 1
fi
CHECKED_OUT_SHA=$(git -C "${SCRIPT_DIR}" rev-parse HEAD)
if [[ "${CHECKED_OUT_SHA}" != "${HEAD_SHA}" ]]; then
  echo "Checked-out commit ${CHECKED_OUT_SHA} does not match source run head SHA ${HEAD_SHA}." >&2
  exit 1
fi
CLUSTER_NAME="eacp-v13-${RUN_ID}-${RUN_ATTEMPT}"
if kind get clusters 2>/dev/null | grep -Fxq "${CLUSTER_NAME}"; then
  echo "Refusing to replace existing kind cluster: ${CLUSTER_NAME}" >&2
  exit 1
fi

python3 - \
  "${SCRIPT_DIR}/kind-config-v1.3.template.yaml" "${KIND_CONFIG}" \
  "${SCRIPT_DIR}/audit-policy-v1.3.yaml" "${AUDIT_HOST_DIR}" \
  "${SCRIPT_DIR}/workload-v1.3.template.yaml" "${WORKLOAD}" \
  "${CORRELATION_ID}" "${REPOSITORY}" "${REPOSITORY_ID}" "${RUN_ID}" "${RUN_ATTEMPT}" \
  "${HEAD_SHA}" "${SOURCE_URL}" "${SUBJECT_URI}" "${SUBJECT_DIGEST}" "${SUBJECT_IMAGE}" <<'PY'
import json
import sys
from pathlib import Path

kind_template, kind_output, audit_policy, audit_output = map(Path, sys.argv[1:5])
workload_template, workload_output = map(Path, sys.argv[5:7])
correlation, repository, repository_id, run_id, attempt, head_sha, source_url, subject_uri, subject_digest, subject_image = sys.argv[7:]
kind_text = kind_template.read_text(encoding="utf-8")
kind_text = kind_text.replace("__AUDIT_POLICY_PATH__", json.dumps(str(audit_policy.resolve())))
kind_text = kind_text.replace("__AUDIT_OUTPUT_PATH__", json.dumps(str(audit_output.resolve())))
kind_output.write_text(kind_text, encoding="utf-8")
workload_text = workload_template.read_text(encoding="utf-8")
replacements = {
    "__CORRELATION_ID__": correlation,
    "__GITHUB_REPOSITORY__": repository,
    "__GITHUB_REPOSITORY_ID__": repository_id,
    "__GITHUB_RUN_ID__": run_id,
    "__GITHUB_RUN_ATTEMPT__": attempt,
    "__GITHUB_HEAD_SHA__": head_sha,
    "__GITHUB_SOURCE_URL__": source_url,
    "__SUBJECT_URI__": subject_uri,
    "__SUBJECT_DIGEST__": subject_digest,
    "__SUBJECT_IMAGE__": subject_image,
}
for marker, value in replacements.items():
    workload_text = workload_text.replace(marker, json.dumps(value))
if "__" in workload_text:
    raise SystemExit("unresolved marker remains in workload template")
workload_output.write_text(workload_text, encoding="utf-8")
PY

echo "Creating isolated audited cluster ${CLUSTER_NAME}..."
CLUSTER_CREATED=1
kind create cluster \
  --name "${CLUSTER_NAME}" \
  --image "${KIND_NODE_IMAGE}" \
  --config "${KIND_CONFIG}" \
  --wait 120s
CONTEXT="kind-${CLUSTER_NAME}"
kubectl --context "${CONTEXT}" apply -f "${WORKLOAD}"
kubectl --context "${CONTEXT}" --namespace "${NAMESPACE}" \
  wait --for=condition=Available "deployment/${DEPLOYMENT}" --timeout=120s

# The denied request repeats the positive correlation in its request body so
# the audit record can be joined even though admission correctly rejects it.
DENIAL_PATCH=$(python3 - "${CORRELATION_ID}" <<'PY'
import json
import sys
print(json.dumps({"metadata": {"annotations": {
    "eacp.io/correlation-id": sys.argv[1],
    "eacp.io/denied-probe": "expected-rbac-denial"
}}}, separators=(",", ":")))
PY
)
set +e
DENIAL_OUTPUT=$(kubectl --context "${CONTEXT}" --namespace "${NAMESPACE}" \
  --as="${DENIED_PRINCIPAL}" patch "deployment/${DEPLOYMENT}" \
  --type=merge -p "${DENIAL_PATCH}" 2>&1)
DENIAL_STATUS=$?
set -e
if [[ "${DENIAL_STATUS}" == "0" || "${DENIAL_OUTPUT}" != *"Forbidden"* ]]; then
  echo "Expected RBAC denial was not observed: ${DENIAL_OUTPUT}" >&2
  exit 1
fi

mkdir -p "${RESULTS_DIR}/kubernetes"
kubectl --context "${CONTEXT}" --namespace "${NAMESPACE}" get "deployment/${DEPLOYMENT}" -o json \
  > "${RESULTS_DIR}/kubernetes/deployment.json"
kubectl --context "${CONTEXT}" --namespace "${NAMESPACE}" get pods \
  -l app.kubernetes.io/name=eacp-cross-plane -o json \
  > "${RESULTS_DIR}/kubernetes/pods.json"
kubectl --context "${CONTEXT}" --namespace "${NAMESPACE}" get \
  "configmap/${NEGATIVE_CONTROL}" -o json \
  > "${RESULTS_DIR}/kubernetes/negative_control.json"
kubectl --context "${CONTEXT}" version -o json \
  > "${RESULTS_DIR}/kubernetes/kubernetes_version.json"

sleep 3
docker exec "${CLUSTER_NAME}-control-plane" sync
# kube-apiserver creates the bind-mounted audit log as root with restrictive
# permissions. Stream it through the already-required Docker control channel
# so the unprivileged Actions runner receives a readable, byte-for-byte copy.
AUDIT_LOG="${WORK_DIR}/audit-readable.log"
docker exec "${CLUSTER_NAME}-control-plane" \
  cat /var/log/kubernetes/audit.log > "${AUDIT_LOG}"
if [[ ! -s "${AUDIT_LOG}" ]]; then
  echo "Kubernetes API server did not emit the expected audit log." >&2
  exit 1
fi
python3 "${SCRIPT_DIR}/extract_kubernetes_audit_v1_3.py" \
  --audit-log "${AUDIT_LOG}" \
  --output-dir "${RESULTS_DIR}/kubernetes/audit" \
  --namespace "${NAMESPACE}" \
  --correlation-id "${CORRELATION_ID}" \
  --denied-principal "${DENIED_PRINCIPAL}" \
  --negative-control-name "${NEGATIVE_CONTROL}" \
  --cluster-id "kind://${CLUSTER_NAME}" >/dev/null

# Capture again after the Kubernetes work so the API snapshot includes the
# current job and its available timestamps. The run itself is necessarily
# still in progress; the post-run finalization command in README produces the
# completed API view without changing the Kubernetes evidence.
rm -rf -- "${STAGING_BUNDLE}"
python3 "${SCRIPT_DIR}/eacp_gha_v1_3.py" capture \
  --repo "${REPOSITORY}" \
  --run-id "${RUN_ID}" \
  --output-dir "${RESULTS_DIR}/github" \
  --service "${REPOSITORY}" \
  --deployment "${DEPLOYMENT}" \
  --namespace "${NAMESPACE}" \
  --subject-uri "${SUBJECT_URI}" \
  --subject-digest "${SUBJECT_DIGEST}" >/dev/null

python3 "${SCRIPT_DIR}/eacp_gha_v1_3.py" join \
  --bundle "${RESULTS_DIR}/github" \
  --kubernetes-evidence-csv "${RESULTS_DIR}/kubernetes/audit/normalized_evidence.csv" \
  --kubernetes-object-json "${RESULTS_DIR}/kubernetes/deployment.json" \
  --negative-control-object-json "${RESULTS_DIR}/kubernetes/negative_control.json" \
  --kubernetes-pods-json "${RESULTS_DIR}/kubernetes/pods.json" \
  --output "${RESULTS_DIR}/cross_plane_join.json"

python3 - "${RESULTS_DIR}/cross_plane_join.json" \
  "${RESULTS_DIR}/kubernetes/pods.json" "${SUBJECT_IMAGE}" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
pods = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
expected_image = sys.argv[3]
if report["status"] != "observed_cross_plane_link_with_subject_digest":
    raise SystemExit(f"cross-plane validation failed: {report['status']}")
if report["kubernetes"]["rbac_denied_rows_with_exact_id"] < 1:
    raise SystemExit("cross-plane validation failed: correlated RBAC denial is missing")
negative = report["kubernetes"]["negative_control"]
if not negative or not negative["correlation_annotation_absent"]:
    raise SystemExit("cross-plane validation failed: negative control contains a correlation ID")
items = pods.get("items") or []
if not items:
    raise SystemExit("cross-plane validation failed: no workload Pod was captured")
pod_images = [
    container.get("image")
    for item in items
    for container in ((item.get("spec") or {}).get("containers") or [])
]
if expected_image not in pod_images:
    raise SystemExit(f"cross-plane validation failed: Pod does not retain {expected_image}")
print("Validated exact correlation, immutable subject digest, negative control, and RBAC denial.")
PY

python3 - "${RESULTS_DIR}/environment.json" \
  "${RUN_STAMP}" "${REPOSITORY}" "${REPOSITORY_ID}" "${RUN_ID}" "${RUN_ATTEMPT}" \
  "${HEAD_SHA}" "${CORRELATION_ID}" "${GITHUB_ACTOR:-unavailable-outside-actions}" \
  "${GITHUB_TRIGGERING_ACTOR:-unavailable-outside-actions}" "${DENIED_PRINCIPAL}" \
  "${SUBJECT_URI}" "${SUBJECT_DIGEST}" "${KIND_NODE_IMAGE}" "${KEEP_CLUSTER}" <<'PY'
import json
import platform
import subprocess
import sys
from pathlib import Path

def version(argv):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return result.stdout.strip()

(
    output_path, run_stamp, repository, repository_id, run_id, attempt,
    head_sha, correlation, github_actor, triggering_actor, denied_principal,
    subject_uri, subject_digest, kind_node_image, keep_cluster,
) = sys.argv[1:]
value = {
    "run_started_utc": run_stamp,
    "repository": repository,
    "repository_id": int(repository_id),
    "run_id": int(run_id),
    "run_attempt": int(attempt),
    "head_sha": head_sha,
    "correlation_id": correlation,
    "github_actor": github_actor,
    "github_triggering_actor": triggering_actor,
    "kubernetes_allowed_principal": "kubernetes-admin",
    "kubernetes_denied_principal": denied_principal,
    "subject_uri": subject_uri,
    "subject_digest": subject_digest,
    "kind_node_image": kind_node_image,
    "python": platform.python_version(),
    "platform": platform.platform(),
    "kind": version(["kind", "version"]),
    "kubectl_client": version(["kubectl", "version", "--client"]),
    "docker": version(["docker", "version", "--format", "{{.Client.Version}}"]),
    "cluster_retained": keep_cluster == "1",
}
Path(output_path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

(
  cd "${RESULTS_DIR}"
  find . -type f ! -name PUBLIC_SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 shasum -a 256
) > "${RESULTS_DIR}/PUBLIC_SHA256SUMS"

echo "Cross-plane experiment complete: ${RESULTS_DIR}"
echo "Correlation ID: ${CORRELATION_ID}"
echo "Run the documented post-run finalization after GitHub marks this run completed."
