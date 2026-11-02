import csv

CSV_PATH = (
    "cases/CASE-001-linux-ssh/evidence/"
    "ssh_honeypot_dataset.csv"
)

TARGET_SESSION = "9caa7e8b-7378-41b7-9bdd-4ae800e2466e"

events = []

with open(CSV_PATH, newline="", encoding="utf-8") as file:
    for row in csv.DictReader(file):
        if row["session_id"] == TARGET_SESSION:
            events.append(row)

events.sort(key=lambda row: row["timestamp"])

print(f"Session: {TARGET_SESSION}")
print(f"Total events: {len(events)}")

for row in events:
    print(f"\nTimestamp: {row['timestamp']}")
    print(f"Event:     {row['event_type']}")
    print(f"Source IP: {row['ip']}")

    if row["event_type"] == "SSH login":
        # Avoid displaying submitted passwords.
        marker = "Bot entered username: "
        message = row["message"]

        if marker in message:
            username = message.split(marker, 1)[1].split(",", 1)[0]
            print(f"Username submitted: {username}")

    elif row["event_type"] == "exec_command":
        command = row["command"]
        print(f"Command length: {len(command)} characters")
        print(f"Command preview: {command[:100]}")

    else:
        print(f"Message: {row['message'][:200]}")
