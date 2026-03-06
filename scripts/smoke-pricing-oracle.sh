#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
GRPC_PORT="${LSDC_PRICING_GRPC_PORT:-50051}"
HTTP_PORT="${LSDC_PRICING_HTTP_PORT:-8000}"

if [[ ! -d "${VENV_DIR}" ]]; then
  python3 -m venv "${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip >/dev/null
python -m pip install -e "${ROOT_DIR}/python/pricing-oracle[dev]" >/dev/null

pushd "${ROOT_DIR}/python/pricing-oracle" >/dev/null
LSDC_PRICING_GRPC_PORT="${GRPC_PORT}" LSDC_PRICING_HTTP_PORT="${HTTP_PORT}" python -m src.server &
SERVER_PID=$!
popd >/dev/null

cleanup() {
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in {1..20}; do
  if curl --silent "http://127.0.0.1:${HTTP_PORT}/health" >/dev/null; then
    break
  fi
  sleep 1
done

cargo run -p control-plane --example pricing_smoke -- "http://127.0.0.1:${GRPC_PORT}"
