#!/usr/bin/env bash
set -euo pipefail

CASE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$CASE_DIR"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

find . -type f \
  ! -path './SHA256SUMS' \
  ! -path '*/__pycache__/*' \
  ! -name '*.pyc' -print0 |
  sort -z |
  xargs -0 -r sha256sum > "$tmp"

echo "ec77f256e309ec7e9eda8dcd3c422b5524119c50d23a7485772838269a0c4d89  evidence/part-b/netmetria-multi-behavior-scenario.pcap" >> "$tmp"

mv "$tmp" SHA256SUMS
trap - EXIT

echo "Updated CASE-005 SHA256SUMS."
sha256sum --ignore-missing -c SHA256SUMS
