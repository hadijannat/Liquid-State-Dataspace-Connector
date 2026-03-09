#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export LSDC_ALLOW_DEV_DEFAULTS=1
export LSDC_API_BEARER_TOKEN="${LSDC_API_BEARER_TOKEN:-phase3-demo-token}"
export LSDC_PROOF_SECRET="${LSDC_PROOF_SECRET:-phase3-proof-secret}"
export LSDC_FORGETTING_SECRET="${LSDC_FORGETTING_SECRET:-phase3-forgetting-secret}"
export LSDC_PRICING_SECRET="${LSDC_PRICING_SECRET:-phase3-pricing-secret}"
export LSDC_ATTESTATION_SECRET="${LSDC_ATTESTATION_SECRET:-phase3-attestation-secret}"

if [[ ! -x ".venv/bin/python" ]]; then
  echo "expected .venv/bin/python; run ./scripts/bootstrap-ubuntu.sh first" >&2
  exit 1
fi

mkdir -p target/tmp/phase3
rm -f target/tmp/phase3/*.db

cleanup() {
  if [[ ${#PIDS[@]} -gt 0 ]]; then
    kill "${PIDS[@]}" 2>/dev/null || true
  fi
}

declare -a PIDS=()
trap cleanup EXIT INT TERM

(
  cd python/pricing-oracle
  "$ROOT_DIR/.venv/bin/python" -m lsdc_pricing_oracle.server
) &
PIDS+=("$!")

cargo run -p liquid-agent -- --config configs/phase3/tier-a-agent.toml &
PIDS+=("$!")
cargo run -p liquid-agent -- --config configs/phase3/tier-b-agent.toml &
PIDS+=("$!")
cargo run -p liquid-agent -- --config configs/phase3/tier-c-agent.toml &
PIDS+=("$!")

cargo run -p control-plane-api -- --config configs/phase3/tier-a-api.toml &
PIDS+=("$!")
cargo run -p control-plane-api -- --config configs/phase3/tier-b-api.toml &
PIDS+=("$!")
cargo run -p control-plane-api -- --config configs/phase3/tier-c-api.toml &
PIDS+=("$!")

echo "Phase 3 reference stack is starting."
echo "tier-a API: http://127.0.0.1:7001"
echo "tier-b API: http://127.0.0.1:7002"
echo "tier-c API: http://127.0.0.1:7003"
echo "pricing health: http://127.0.0.1:8000/health"
echo "API bearer token: ${LSDC_API_BEARER_TOKEN}"
echo "Press Ctrl+C to stop all processes."

wait
