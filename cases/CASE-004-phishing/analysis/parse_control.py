#!/usr/bin/env python3
"""Offline parser for the CASE-004 Part A synthetic email control."""
from email import policy
from email.parser import BytesParser
from pathlib import Path

email_path = Path(__file__).resolve().parents[1] / "evidence" / "benign-control.eml"
msg = BytesParser(policy=policy.default).parsebytes(email_path.read_bytes())

headers = (
    "From", "To", "Reply-To", "Return-Path", "Date",
    "Message-ID", "Subject", "Received", "Authentication-Results"
)

print("CASE-004 Part A — Offline Email Review")
for name in headers:
    values = msg.get_all(name, [])
    print(f"{name}:")
    for value in values:
        print(f"  {value}")

body = msg.get_body(preferencelist=("plain",))
print("\\nBody:")
print(body.get_content() if body else "(No plain-text body)")

attachments = [part for part in msg.walk() if part.get_filename()]
print("\\nAttachment count:", len(attachments))
