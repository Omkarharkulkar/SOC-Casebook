#!/usr/bin/env bash
set -u

OUT="$(dirname "$0")/baseline-activity.txt"

{
    echo "CASE-005 Part A - Controlled DNS Baseline"
    echo "Start: $(date -Is)"
    echo "Hostname: $(hostname)"
    echo "Interface: enp0s3"
    echo

    for domain in example.com ubuntu.com debian.org github.com; do
        echo "[$(date -Is)] DNS lookup: $domain"
        getent ahostsv4 "$domain" || echo "Resolution failed"
        echo
    done

    echo "End: $(date -Is)"
} | tee "$OUT"
