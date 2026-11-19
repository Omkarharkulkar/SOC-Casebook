#!/usr/bin/env python3
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO
from urllib.parse import urlsplit, urlunsplit
import hashlib
import re
import sys

PRIVATE = Path.home() / "case004-private"
SOURCE = PRIVATE / "Security alert.eml"
PRIVATE_FILE = PRIVATE / "private-strings.txt"
OUTPUT = Path("evidence/control-google-security-alert-sanitized.eml")

REMOVE = {
    "x-notifications",
    "x-notifications-bounce-info",
    "x-gm-message-state",
}

EMAIL_RE = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def redact_email(match):
    local, domain = match.group(0).split("@", 1)
    return "[REDACTED]@" + domain.replace(".", "[.]")

def clean_url(match):
    raw = match.group(0)
    url = raw.rstrip(".,;)")
    suffix = raw[len(url):]
    p = urlsplit(url)
    if not p.hostname:
        return "[URL-REDACTED]" + suffix
    host = p.hostname.replace(".", "[.]")
    scheme = "hxxps" if p.scheme.lower() == "https" else "hxxp"
    return f"{scheme}://{host}" + suffix

def clean_text(text):
    text = URL_RE.sub(clean_url, text)
    text = re.sub(
        r'(?i)(https?://)?lh3[.]googleusercontent[.]com/[^\s"\'<>]+',
        'https://lh3[.]googleusercontent[.]com/[REDACTED-PATH]',
        text
    )
    return EMAIL_RE.sub(redact_email, text)

def main():
    if not SOURCE.is_file() or not PRIVATE_FILE.is_file():
        sys.exit("Missing private source or private-strings.txt")

    private_values = [
        x.strip() for x in PRIVATE_FILE.read_text().splitlines() if x.strip()
    ]
    if not private_values:
        sys.exit("Private strings file is empty.")

    raw = SOURCE.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    # Preserve all header occurrences while sanitizing duplicate Received headers.
    new_headers = []
    for name, value in msg.items():
        lname = name.lower()
        if lname in REMOVE or lname.startswith("x-notifications-"):
            continue
        value = str(value)

        if lname in {"to", "cc", "bcc"}:
            value = "[REDACTED]"
        elif lname == "message-id":
            value = "<redacted@notifications.google.com>"
        elif lname in {"received", "return-path", "authentication-results"}:
            value = EMAIL_RE.sub(redact_email, value)

        new_headers.append((name, value))

    msg._headers = []
    for name, value in new_headers:
        msg[name] = value

    for part in msg.walk():
        if part.get_content_maintype() == "text":
            try:
                content = part.get_content()
            except Exception:
                continue
            if isinstance(content, str):
                part.set_content(
                    clean_text(content),
                    subtype=part.get_content_subtype(),
                    charset=part.get_content_charset() or "utf-8"
                )

    buffer = BytesIO()
    BytesGenerator(buffer, policy=policy.default).flatten(msg)
    output = buffer.getvalue()

    # Final privacy pass across every serialized header and body section.
    decoded = output.decode("utf-8", errors="replace")

    # Preserve the verified Return-Path domain, not its private local part.
    decoded = re.sub(
        r"(?im)^Return-Path:.*$",
        "Return-Path: <[REDACTED]@gaia.bounces.google.com>",
        decoded,
    )
    for value in private_values:
        decoded = decoded.replace(value, "[REDACTED]")
        decoded = decoded.replace(value.lower(), "[REDACTED]")
        decoded = decoded.replace(value.upper(), "[REDACTED]")
    output = decoded.encode("utf-8")
    decoded = output.decode("utf-8", errors="replace")

    # Final fail-closed checks.
    for value in private_values:
        if value.casefold() in decoded.casefold():
            sys.exit("PRIVACY CHECK FAILED: private value remains; no output written.")

    if re.search(r'lh3[.]googleusercontent[.]com/(?!\[REDACTED-PATH\])\S+', decoded, re.I):
        sys.exit("PRIVACY CHECK FAILED: avatar path remains.")

    for header in REMOVE:
        if re.search(rf'(?im)^{re.escape(header)}:', decoded):
            sys.exit("PRIVACY CHECK FAILED: token header remains.")

    OUTPUT.write_bytes(output)
    print("PASS: sanitized email generated")
    print("PASS: private-string leak check")
    print("PASS: token headers removed")
    print("PASS: avatar paths redacted")
    print("Raw SHA-256:", sha256(raw))
    print("Sanitized SHA-256:", sha256(output))

if __name__ == "__main__":
    main()
