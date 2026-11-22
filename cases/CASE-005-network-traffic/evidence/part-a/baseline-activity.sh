#!/usr/bin/env bash
set -u

OUT="$(dirname "$0")/baseline-activity.txt"

{
    echo "Controlled network baseline"
    echo "Timestamp: $(date --iso-8601=seconds)"
    echo

    for domain in example.com ubuntu.com debian.org github.com; do
        echo "DNS lookup: $domain"
        getent ahosts "$domain" | awk '!seen[$1]++ {print $1}'
        echo
    done

    echo "HTTPS request: https://example.com/"
    python3 - <<'PY'
import urllib.request
from datetime import datetime

url = "https://example.com/"
print("Timestamp:", datetime.now().astimezone().isoformat())

try:
    request = urllib.request.Request(
        url, headers={"User-Agent": "SOC-Casebook-Baseline"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print("HTTP status:", response.status)
        print("Content type:", response.headers.get("Content-Type"))
        response.read(256)
except Exception as exc:
    print("HTTPS request failed:", type(exc).__name__, str(exc))
PY

} > "$OUT" 2>&1

cat "$OUT"
