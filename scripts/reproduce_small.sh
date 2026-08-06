#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
benchmark_script="$repo_root/benchmark/sqlite/eacp_benchmark.py"

if [[ ! -f "$benchmark_script" ]]; then
  echo "Scaffold check: benchmark script has not been staged yet; skipping the execution smoke test."
  echo "Release verification will fail until the frozen benchmark is present."
  exit 0
fi

result_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$result_dir"
}
trap cleanup EXIT

python3 "$benchmark_script" \
  --sizes 1000 \
  --trials 1 \
  --services 20 \
  --query-samples 20 \
  --output "$result_dir"

test -s "$result_dir/trial_results.csv"
test -s "$result_dir/summary_results.csv"
test -s "$result_dir/summary_results.json"

echo "Small deterministic reproduction completed successfully."

