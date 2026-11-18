"""Enrich the public timeline from a private Hayabusa timeline.

Requires ~/case003-private/analysis/timeline-original.csv. This private
input is intentionally not included in the public repository; readers
cannot reproduce the enrichment without obtaining the original local
timeline independently.
"""
import csv
from pathlib import Path

PRIVATE_TIMELINE = Path.home() / "case003-private/analysis/timeline-original.csv"
CASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT = CASE_DIR / "analysis/sanitized-timeline.csv"



def parse_details(value):
    details = {}
    for part in value.split("¦"):
        if ":" in part:
            key, val = part.split(":", 1)
            details[key.strip()] = val.strip()
    return details


with PRIVATE_TIMELINE.open(encoding="utf-8-sig", newline="") as f:
    raw_rows = list(csv.DictReader(f))

event_details = {}

for row in raw_rows:
    if row["EventID"] == "4688" and row["RuleTitle"] == "Proc Exec":
        event_details[row["RecordID"]] = parse_details(row["Details"])

with OUTPUT.open(encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

if len(rows) != 13 or len(event_details) != 13:
    raise SystemExit("Unexpected event count; refusing to update timeline.")

controlled_users = {
    d.get("User", "") for d in event_details.values()
    if d.get("User") and not d["User"].endswith("$")
}
machine_users = {
    d.get("User", "") for d in event_details.values()
    if d.get("User", "").endswith("$")
}
controlled_sessions = {
    d.get("LID", "").lower() for d in event_details.values()
    if d.get("User", "") in controlled_users
}
system_sessions = {
    d.get("LID", "").lower() for d in event_details.values()
    if d.get("User", "") in machine_users
}

if not all(len(x) == 1 for x in (
    controlled_users, machine_users, controlled_sessions, system_sessions
)):
    raise SystemExit("Unexpected account/session grouping; inspect privately.")

controlled_user = next(iter(controlled_users))
machine_user = next(iter(machine_users))
controlled_session = next(iter(controlled_sessions))
system_session = next(iter(system_sessions))

for row in rows:
    details = event_details.get(row["record_id"])
    if not details:
        raise SystemExit(f"Missing raw event: {row['record_id']}")

    user = details.get("User", "")
    logon_id = details.get("LID", "").lower()

    row["image_path"] = details.get("Proc", "")
    row["command_line"] = details.get("Cmdline", "")
    row["account_ref"] = (
        "USER-01" if user == controlled_user
        else "HOST-ACCOUNT-01" if user == machine_user
        else "REVIEW-REQUIRED"
    )
    row["logon_session_ref"] = (
        "SESSION-01" if logon_id == controlled_session
        else "SYSTEM-SESSION" if logon_id == system_session
        else "REVIEW-REQUIRED"
    )

if any("REVIEW-REQUIRED" in r.values() for r in rows):
    raise SystemExit("Unmapped account/session found; inspect before publishing.")

controlled = [
    r for r in rows
    if r["account_ref"] == "USER-01"
    and r["logon_session_ref"] == "SESSION-01"
]
background = [
    r for r in rows
    if r["account_ref"] == "HOST-ACCOUNT-01"
    and r["logon_session_ref"] == "SYSTEM-SESSION"
]

if len(controlled) != 8 or len(background) != 5:
    raise SystemExit("Account/session grouping did not match expected counts.")

with OUTPUT.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

print("Updated:", OUTPUT)
print("Total events:", len(rows))
print("Controlled activity:", len(controlled))
print("Background activity:", len(background))
