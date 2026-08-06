#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CLUSTER_NAME=${CLUSTER_NAME:-eacp-eval}
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
NAMESPACE=eacp-k8s-eval
WORKLOAD_ROUNDS=${WORKLOAD_ROUNDS:-3}
OBJECTS_PER_ROUND=${OBJECTS_PER_ROUND:-20}
LISTS_PER_ROUND=${LISTS_PER_ROUND:-10}
KEEP_CLUSTER=${KEEP_CLUSTER:-0}
RUN_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULTS_DIR=${RESULTS_DIR:-"${SCRIPT_DIR}/results/${RUN_STAMP}"}
AUDIT_HOST_DIR="${RESULTS_DIR}/audit-host"
ANALYSIS_DIR="${RESULTS_DIR}/analysis"
KUBECTL_CONTEXT="kind-${CLUSTER_NAME}"
CONTROL_PLANE_CONTAINER="${CLUSTER_NAME}-control-plane"
CLUSTER_CREATED=0

for command_name in docker kubectl python3 shasum; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command not found: ${command_name}" >&2
    exit 1
  fi
done

KIND_BIN=${KIND_BIN:-$(command -v kind 2>/dev/null || true)}
if [[ -z "${KIND_BIN}" && -x /opt/homebrew/opt/kind/bin/kind ]]; then
  KIND_BIN=/opt/homebrew/opt/kind/bin/kind
fi
if [[ -z "${KIND_BIN}" ]]; then
  echo "kind is required. Install it with 'brew install kind'." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed but its daemon is not available." >&2
  exit 1
fi

if "${KIND_BIN}" get clusters 2>/dev/null | grep -Fxq "${CLUSTER_NAME}"; then
  echo "Refusing to replace an existing kind cluster named ${CLUSTER_NAME}." >&2
  echo "Delete or rename it explicitly, or set CLUSTER_NAME to an unused name." >&2
  exit 1
fi

mkdir -p "${AUDIT_HOST_DIR}" "${ANALYSIS_DIR}"

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  if [[ "${CLUSTER_CREATED}" == "1" && "${KEEP_CLUSTER}" != "1" ]]; then
    "${KIND_BIN}" delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  fi
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

python3 - "${SCRIPT_DIR}/kind-config.template.yaml" "${RESULTS_DIR}/kind-config.yaml" \
  "${SCRIPT_DIR}/audit-policy.yaml" "${AUDIT_HOST_DIR}" <<'PY'
import json
import sys
from pathlib import Path

template_path, output_path, audit_policy, audit_output = map(Path, sys.argv[1:])
text = template_path.read_text(encoding="utf-8")
text = text.replace("__AUDIT_POLICY_PATH__", json.dumps(str(audit_policy.resolve())))
text = text.replace("__AUDIT_OUTPUT_PATH__", json.dumps(str(audit_output.resolve())))
Path(output_path).write_text(text, encoding="utf-8")
PY

cp "${SCRIPT_DIR}/audit-policy.yaml" "${RESULTS_DIR}/audit-policy.yaml"
cp "${SCRIPT_DIR}/workload.yaml" "${RESULTS_DIR}/workload.yaml"

{
  echo "run_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "cluster_name=${CLUSTER_NAME}"
  echo "kind_node_image=${KIND_NODE_IMAGE}"
  echo "workload_rounds=${WORKLOAD_ROUNDS}"
  echo "objects_per_round=${OBJECTS_PER_ROUND}"
  echo "lists_per_round=${LISTS_PER_ROUND}"
  echo "host_os=$(uname -srvmo)"
  echo "host_arch=$(uname -m)"
  echo "host_logical_cpus=$(sysctl -n hw.logicalcpu 2>/dev/null || true)"
  echo "host_memory_bytes=$(sysctl -n hw.memsize 2>/dev/null || true)"
  echo "docker_client=$(docker version --format '{{.Client.Version}}')"
  echo "docker_server=$(docker version --format '{{.Server.Version}}')"
  echo "kind=$(${KIND_BIN} version)"
  echo "kubectl_client=$(kubectl version --client -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["clientVersion"]["gitVersion"])')"
  echo "python=$(python3 --version 2>&1)"
} > "${RESULTS_DIR}/environment.txt"

echo "Creating isolated kind cluster ${CLUSTER_NAME} with Kubernetes audit enabled..."
CLUSTER_CREATED=1
"${KIND_BIN}" create cluster \
  --name "${CLUSTER_NAME}" \
  --image "${KIND_NODE_IMAGE}" \
  --config "${RESULTS_DIR}/kind-config.yaml" \
  --wait 120s

kubectl --context "${KUBECTL_CONTEXT}" version -o json > "${RESULTS_DIR}/kubernetes-version.json"
kubectl --context "${KUBECTL_CONTEXT}" get nodes -o wide > "${RESULTS_DIR}/nodes.txt"
kubectl --context "${KUBECTL_CONTEXT}" apply -f "${SCRIPT_DIR}/workload.yaml"
kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" \
  wait --for=condition=Available deployment/eacp-demo --timeout=120s

printf 'timestamp_utc,round,operation,resource\n' > "${RESULTS_DIR}/operations.csv"
for round in $(seq 1 "${WORKLOAD_ROUNDS}"); do
  round_tag=$(printf '%02d' "${round}")
  kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" annotate deployment/eacp-demo \
    "eacp.io/evaluation-round=${round_tag}" \
    "eacp.io/correlation-id=eacp-round-${round_tag}" --overwrite >/dev/null
  printf '%s,%s,patch,deployment/eacp-demo\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" \
    >> "${RESULTS_DIR}/operations.csv"

  for sequence in $(seq 1 "${OBJECTS_PER_ROUND}"); do
    object_name=$(printf 'eacp-r%02d-cm%03d' "${round}" "${sequence}")
    kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" create configmap "${object_name}" \
      --from-literal="round=${round}" --from-literal="sequence=${sequence}" >/dev/null
    printf '%s,%s,create,configmap/%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" "${object_name}" \
      >> "${RESULTS_DIR}/operations.csv"

    kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" patch configmap "${object_name}" --type=merge \
      -p "{\"metadata\":{\"labels\":{\"app.kubernetes.io/name\":\"eacp-demo\",\"eacp.io/evaluation-round\":\"${round_tag}\"},\"annotations\":{\"eacp.io/correlation-id\":\"eacp-round-${round_tag}\"}}}" >/dev/null
    printf '%s,%s,patch,configmap/%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" "${object_name}" \
      >> "${RESULTS_DIR}/operations.csv"

    kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" get configmap "${object_name}" -o name >/dev/null
    printf '%s,%s,get,configmap/%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" "${object_name}" \
      >> "${RESULTS_DIR}/operations.csv"
  done

  for _ in $(seq 1 "${LISTS_PER_ROUND}"); do
    kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" get configmaps \
      -l app.kubernetes.io/name=eacp-demo -o name >/dev/null
    printf '%s,%s,list,configmaps\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" \
      >> "${RESULTS_DIR}/operations.csv"
  done

  if (( round % 2 == 1 )); then
    denied_resource="deployment/eacp-demo"
  else
    denied_resource=$(printf 'configmap/eacp-r%02d-cm%03d' "${round}" 1)
  fi
  set +e
  denial_output=$(kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" \
    --as="system:serviceaccount:${NAMESPACE}:eacp-observer" \
    patch "${denied_resource}" --type=merge \
    -p "{\"metadata\":{\"annotations\":{\"eacp.io/unauthorized-round\":\"${round_tag}\"}}}" 2>&1)
  denial_status=$?
  set -e
  if [[ "${denial_status}" == "0" || "${denial_output}" != *"Forbidden"* ]]; then
    echo "Expected RBAC denial did not occur for ${denied_resource}: ${denial_output}" >&2
    exit 1
  fi
  printf '%s,%s,patch-denied,%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" "${denied_resource}" \
    >> "${RESULTS_DIR}/operations.csv"
  printf 'round=%s resource=%s status=403 result=Forbidden\n' "${round}" "${denied_resource}" \
    >> "${RESULTS_DIR}/policy-denials.txt"

  delete_count=$((OBJECTS_PER_ROUND / 5))
  if [[ "${delete_count}" -lt 1 ]]; then
    delete_count=1
  fi
  for sequence in $(seq 1 "${delete_count}"); do
    object_name=$(printf 'eacp-r%02d-cm%03d' "${round}" "${sequence}")
    kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" delete configmap "${object_name}" \
      --wait=true >/dev/null
    printf '%s,%s,delete,configmap/%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${round}" "${object_name}" \
      >> "${RESULTS_DIR}/operations.csv"
  done
done

kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" get all,configmaps,serviceaccounts,roles,rolebindings \
  -o yaml > "${RESULTS_DIR}/cluster-state.yaml"
kubectl --context "${KUBECTL_CONTEXT}" -n "${NAMESPACE}" get events --sort-by=.metadata.creationTimestamp \
  > "${RESULTS_DIR}/namespace-events.txt" || true

sleep 3
docker exec "${CONTROL_PLANE_CONTAINER}" sync
AUDIT_LOG="${AUDIT_HOST_DIR}/audit.log"
if [[ ! -s "${AUDIT_LOG}" ]]; then
  echo "Kubernetes API server did not produce the expected audit log: ${AUDIT_LOG}" >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/analyze_audit.py" \
  --audit-log "${AUDIT_LOG}" \
  --output-dir "${ANALYSIS_DIR}" \
  --namespace "${NAMESPACE}" \
  --trials 10 \
  --queries 300 \
  > "${RESULTS_DIR}/analysis-console.json"

python3 - "${ANALYSIS_DIR}/summary.json" "${WORKLOAD_ROUNDS}" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = int(sys.argv[2])
observed = int(summary["rbac_denials"]["count"])
if observed < expected or not summary["rbac_denials"]["all_status_403"]:
    raise SystemExit(f"RBAC audit validation failed: expected at least {expected} denials, observed {observed}")
print(f"Validated {observed} audited RBAC denials (HTTP 403).")
PY

if [[ "${KEEP_CLUSTER}" != "1" ]]; then
  "${KIND_BIN}" delete cluster --name "${CLUSTER_NAME}" >/dev/null
  CLUSTER_CREATED=0
fi

{
  echo "run_finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "result_directory=results/${RUN_STAMP}"
  echo "cluster_retained=${KEEP_CLUSTER}"
} >> "${RESULTS_DIR}/environment.txt"

{
  cd "${RESULTS_DIR}"
  shasum -a 256 \
    analysis/public_filtered_audit.jsonl \
    analysis/normalized_evidence.csv \
    analysis/summary.json \
    operations.csv \
    policy-denials.txt \
    kubernetes-version.json \
    nodes.txt \
    environment.txt
} > "${RESULTS_DIR}/PUBLIC_SHA256SUMS"

{
  cd "${RESULTS_DIR}"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 shasum -a 256
} > "${RESULTS_DIR}/SHA256SUMS"

echo "Experiment complete: ${RESULTS_DIR}"
echo "Summary: ${ANALYSIS_DIR}/summary.json"
