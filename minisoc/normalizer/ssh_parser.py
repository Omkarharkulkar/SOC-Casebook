#!/usr/bin/env python3
"""Parse common Ubuntu OpenSSH authentication and session log entries."""

import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


HEADER_PATTERN = re.compile(
    r"^(?P<timestamp>\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd(?:-session)?\[(?P<pid>\d+)\]:\s+"
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
        "failed_publickey",
        re.compile(
            rf"Failed publickey for (?:invalid user )?"
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
        "pam_auth_failure",
        re.compile(
            r"pam_unix\(sshd:auth\): authentication failure;.*?"
            r"rhost=(?P<src_ip>\S+).*?user=(?P<username>\S+)"
        ),
    ),
    (
        "pam_session_opened",
        re.compile(
            r"pam_unix\(sshd:session\): session opened for user "
            r"(?P<username>[^(\s]+)"
        ),
    ),
    (
        "pam_session_closed",
        re.compile(
            r"pam_unix\(sshd:session\): session closed for user "
            r"(?P<username>\S+)"
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
    (
        "disconnected",
        re.compile(
            rf"Disconnected from "
            rf"(?:authenticating user (?P<auth_user>\S+)\s+)?"
            rf"(?:invalid user (?P<invalid_user>\S+)\s+)?"
            rf"{IP_PORT}"
        ),
    ),
    (
        "ssh_server_listening",
        re.compile(
            r"Server listening on (?P<listen_address>\S+) "
            r"port (?P<listen_port>\d+)"
        ),
    ),
]


def get_utc_timestamp(timestamp):
    """Convert timezone-aware ISO timestamps to UTC.

    Return None when the timestamp has no timezone or is not ISO format.
    """

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None

    if parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc).isoformat()


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

        event = {
            "event_type": event_type,
            "timestamp": data["timestamp"],
            "timestamp_utc": get_utc_timestamp(data["timestamp"]),
            "hostname": data["hostname"],
            "process_id": int(data["pid"]),
            "username": username,
            "source_ip": details.get("src_ip"),
            "source_port": (
                int(details["src_port"])
                if details.get("src_port")
                else None
            ),
            "listening_address": details.get("listen_address"),
            "listening_port": (
                int(details["listen_port"])
                if details.get("listen_port")
                else None
            ),
            "raw_message": message,
        }

        return event

    return None


def parse_file_with_stats(file_path):
    """Parse a log file and return events and basic parsing statistics."""

    events = []
    total_lines = 0
    unrecognized_lines = 0

    with Path(file_path).open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:
        for line in log_file:
            total_lines += 1
            event = parse_line(line)

            if event is not None:
                events.append(event)
            else:
                unrecognized_lines += 1

    return events, total_lines, unrecognized_lines


def parse_file(file_path):
    """Parse a file and return recognized SSH events."""

    events, _, _ = parse_file_with_stats(file_path)
    return events


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python3 ssh_parser.py <ssh-log-file>",
            file=sys.stderr,
        )
        return 1

    events, total_lines, unrecognized = parse_file_with_stats(sys.argv[1])
    counts = Counter(event["event_type"] for event in events)

    print("===== SSH LOG PARSER SUMMARY =====")
    print(f"Total input lines: {total_lines}")
    print(f"Recognized events: {len(events)}")
    print(f"Unrecognized lines: {unrecognized}")

    for event_type, count in sorted(counts.items()):
        print(f"{event_type}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
