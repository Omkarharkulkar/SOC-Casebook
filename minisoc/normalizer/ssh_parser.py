#!/usr/bin/env python3
"""Parse Ubuntu OpenSSH authentication log entries."""

import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


HEADER_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

IP_PORT = r"(?P<src_ip>[0-9a-fA-F:.]+)\s+port\s+(?P<src_port>\d+)"

EVENT_PATTERNS = [
    (
        "failed_password",
        re.compile(
            rf"Failed password for (?:invalid user )?"
            rf"(?P<username>\S+) from {IP_PORT}"
        ),
    ),
    (
        "accepted_password",
        re.compile(
            rf"Accepted password for (?P<username>\S+) from {IP_PORT}"
        ),
    ),
    (
        "accepted_publickey",
        re.compile(
            rf"Accepted publickey for (?P<username>\S+) from {IP_PORT}"
        ),
    ),
    (
        "invalid_user",
        re.compile(
            rf"Invalid user (?P<username>\S+) from {IP_PORT}"
        ),
    ),
    (
        "connection_closed",
        re.compile(
            rf"Connection closed by "
            rf"(?:authenticating user (?P<auth_user>\S+)\s+)?"
            rf"(?:invalid user (?P<invalid_user>\S+)\s+)?"
            rf"{IP_PORT}"
        ),
    ),
]


def parse_line(line):
    """Parse one SSH log line into a normalized event."""

    header = HEADER_PATTERN.match(line.strip())

    if not header:
        return None

    data = header.groupdict()
    message = data["message"]

    for event_type, pattern in EVENT_PATTERNS:
        match = pattern.search(message)

        if not match:
            continue

        details = match.groupdict()

        username = (
            details.get("username")
            or details.get("auth_user")
            or details.get("invalid_user")
        )

        timestamp = datetime.fromisoformat(data["timestamp"])

        event = {
            "event_type": event_type,
            "timestamp": data["timestamp"],
            "timestamp_utc": timestamp.astimezone(
                timezone.utc
            ).isoformat(),
            "hostname": data["hostname"],
            "process_id": int(data["pid"]),
            "username": username,
            "source_ip": details.get("src_ip"),
            "source_port": (
                int(details["src_port"])
                if details.get("src_port")
                else None
            ),
            "raw_message": message,
        }

        return event

    return None


def parse_file(file_path):
    """Parse a file and return recognized SSH events."""

    events = []

    with Path(file_path).open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:
        for line in log_file:
            event = parse_line(line)

            if event is not None:
                events.append(event)

    return events


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python3 ssh_parser.py <auth-log-file>",
            file=sys.stderr,
        )
        return 1

    events = parse_file(sys.argv[1])
    counts = Counter(event["event_type"] for event in events)

    print("===== SSH LOG PARSER SUMMARY =====")
    print(f"Recognized events: {len(events)}")

    for event_type, count in sorted(counts.items()):
        print(f"{event_type}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
