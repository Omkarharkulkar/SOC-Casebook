import csv
from collections import Counter
from pathlib import Path

case = Path(__file__).resolve().parents[1]
source = case / "evidence"

def load(name):
    with (source / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

hosts = load("host_events.csv")
directory = load("directory_events.csv")
selected = {"1102", "4672", "4688", "4728", "4740", "4771", "7045"}
timeline = []

for filename, records in (("host", hosts), ("directory", directory)):
    for event in records:
        if event["event_code"] not in selected:
            continue
        timeline.append({
            "timestamp": event["logged_at"],
            "source": filename,
            "hostname": event["hostname"],
            "event_id": event["event_code"],
            "category": event["category"],
            "account_id": event.get("account_id", ""),
            "process": event.get("process_name", ""),
            "service": event.get("service_name", ""),
            "group": event.get("group_name", ""),
            "logon_type": event.get("logon_type", ""),
            "failure_reason": event.get("failure_reason", "")
        })

timeline.sort(key=lambda x: (x["timestamp"], x["hostname"], x["event_id"]))
fields = list(timeline[0])
with (case / "analysis/part-b-review-timeline.csv").open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(timeline)

summary = []
for label, records in (("host", hosts), ("directory", directory)):
    counts = Counter((e["event_code"], e["category"]) for e in records)
    for (code, category), count in sorted(counts.items()):
        summary.append({"source": label, "event_id": code, "category": category, "count": count})

with (case / "analysis/part-b-event-summary.csv").open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["source", "event_id", "category", "count"])
    writer.writeheader()
    writer.writerows(summary)

print("Host events:", len(hosts), "| Directory events:", len(directory))
print("Review timeline:", len(timeline))
for event in timeline:
    if event["event_id"] in {"1102", "7045", "4728"}:
        print(event["timestamp"], event["hostname"], event["event_id"], event["category"], "account_id=" + event["account_id"], "service=" + event["service"], "group=" + event["group"])
print("Created analysis/part-b-review-timeline.csv and analysis/part-b-event-summary.csv")
