import csv

CSV_PATH = (
    "cases/CASE-001-linux-ssh/evidence/"
    "ssh_honeypot_dataset.csv"
)

count = 0

with open(CSV_PATH, newline="", encoding="utf-8") as file:
    for row in csv.DictReader(file):
        if row["event_type"] != "exec_command":
            continue

        count += 1
        command = row["command"]

        print(f"\nEvent {count}")
        print(f"  Timestamp: {row['timestamp']}")
        print(f"  Source IP: {row['ip']}")
        print(f"  Session:   {row['session_id']}")
        print(f"  Level:     {row['level']}")
        print(f"  Command length: {len(command)} characters")

        # Show a short preview instead of exposing
        # the complete submitted command or its arguments.
        print(f"  Command preview: {command[:100]}")

print(f"\nTotal command events reviewed: {count}")
