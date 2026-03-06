#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

rustup toolchain install nightly --component rustfmt --component clippy --component rust-src
rustup default nightly

sudo apt-get update
sudo apt-get install -y \
  clang \
  llvm \
  libelf-dev \
  libpcap-dev \
  gcc-multilib \
  build-essential \
  bpftool \
  python3-venv \
  python3-pip

python3 -m venv "$ROOT_DIR/.venv"
# shellcheck disable=SC1091
source "$ROOT_DIR/.venv/bin/activate"
python -m pip install --upgrade pip
python -m pip install -e "$ROOT_DIR/python/pricing-oracle[dev]"

echo "Bootstrap complete."
echo "Rust workspace: cargo test --workspace"
echo "Python tests: .venv/bin/python -m pytest python/pricing-oracle/tests"
