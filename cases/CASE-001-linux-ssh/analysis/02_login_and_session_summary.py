import csv
from collections import Counter, defaultdict

CSV_PATH = (
    "cases/CASE-001-linux-ssh/evidence/"
    "ssh_honeypot_dataset.csv"
)

login_users = Counter()
command_sessions = defaultdict(list)

with open(CSV_PATH, newline="", encoding="utf-8") as file:
    for row in csv.DictReader(file):
        if row["event_type"] == "SSH login":
            marker = "Bot entered username: "
            message = row["message"]

            if marker in message:
                username = message.split(marker, 1)[1].split(",", 1)[0]
                login_users[username] += 1

        if row["event_type"] == "exec_command":
            command_sessions[row["session_id"]].append(row)

print("=== COMMON LOGIN USERNAMES ===")
for username, count in login_users.most_common(12):
    print(f"{count:5}  {username}")

print("\n=== COMMAND EXECUTION SUMMARY ===")
print(f"Sessions with command events: {len(command_sessions)}")
print(
    "Total command events:",
    sum(len(events) for events in command_sessions.values())
)

print("\n=== SESSIONS WITH COMMAND EVENTS ===")

for session_id, events in command_sessions.items():
    print(f"\nSession: {session_id}")
    print(f"Command events: {len(events)}")

    for event in events:
        command = event["command"]
        print(f"  Time: {event['timestamp']}")
        print(f"  Recorded command length: {len(command)} characters")
