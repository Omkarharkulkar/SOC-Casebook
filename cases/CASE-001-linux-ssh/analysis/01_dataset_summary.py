import csv
from collections import Counter

CSV_PATH = (
    "cases/CASE-001-linux-ssh/evidence/"
    "ssh_honeypot_dataset.csv"
)

events = Counter()
source_ips = Counter()
sessions = set()
first_time = None
last_time = None
total = 0

with open(CSV_PATH, newline="", encoding="utf-8") as file:
    for row in csv.DictReader(file):
        total += 1

        events[row["event_type"]] += 1

        if row["ip"]:
            source_ips[row["ip"]] += 1

        if row["session_id"]:
            sessions.add(row["session_id"])

        timestamp = row["timestamp"]
        if timestamp:
            first_time = min(first_time, timestamp) if first_time else timestamp
            last_time = max(last_time, timestamp) if last_time else timestamp

print(f"Total records: {total}")
print(f"Time range: {first_time} to {last_time}")
print(f"Unique sessions: {len(sessions)}")
print(f"Unique source IPs: {len(source_ips)}")

print("\nEvent types:")
for event, count in events.most_common():
    print(f"  {event}: {count}")

print("\nTop 10 source IPs:")
for ip, count in source_ips.most_common(10):
    print(f"  {ip}: {count}")
