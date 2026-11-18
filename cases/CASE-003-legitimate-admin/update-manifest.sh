#!/usr/bin/env bash
set -euo pipefail

CASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$CASE_DIR"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

find . -type f \
  ! -path './SHA256SUMS' \
  ! -name 'CASE-003-4688-window.evtx' \
  ! -name 'timeline-original.csv' \
  ! -path '*/__pycache__/*' \
  ! -name '*.pyc' -print0 |
  sort -z |
  xargs -0 -r sha256sum > "$tmp"

mv "$tmp" SHA256SUMS
trap - EXIT
echo "Updated CASE-003 SHA256SUMS."
