#!/usr/bin/env python3
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO
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
    _, domain = match.group(0).split("@", 1)
    return "[REDACTED]@" + domain


def redact_private(text, values):
    for value in sorted(values, key=len, reverse=True):
        text = re.sub(re.escape(value), "[REDACTED]", text, flags=re.I)
    return text


def clean_url(match):
    raw = match.group(0)
    url = raw.rstrip(".,;)")
    suffix = raw[len(url):]
    from urllib.parse import urlsplit

    try:
        p = urlsplit(url)
        host = p.hostname
    except ValueError:
        return "[URL-REDACTED]" + suffix

    if not host:
        return "[URL-REDACTED]" + suffix

    host = host.replace(".", "[.]")
    scheme = "hxxps" if p.scheme.lower() == "https" else "hxxp"
    return f"{scheme}://{host}" + suffix


def clean_text(text, private_values):
    text = re.sub(
        r'(?i)(https?://)?lh3[.]googleusercontent[.]com/[^\s"\'<>]+',
        'https://lh3[.]googleusercontent[.]com/[REDACTED-PATH]',
        text,
    )
    text = URL_RE.sub(clean_url, text)
    text = EMAIL_RE.sub(redact_email, text)
    return redact_private(text, private_values)


def main():
    if not SOURCE.is_file() or not PRIVATE_FILE.is_file():
        sys.exit("Missing private source or private-strings.txt")

    raw = SOURCE.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    # Decode headers and add the per-message Google bounce local part
    # to the private list without displaying it.
    decoded_headers = [(name, str(value)) for name, value in msg.items()]
    private_values = [
        x.strip()
        for x in PRIVATE_FILE.read_text().splitlines()
        if x.strip()
    ]

    new_private_values = []
    for name, value in decoded_headers:
        if name.lower() in {"arc-authentication-results", "received-spf"}:
            for match in EMAIL_RE.finditer(value):
                local, domain = match.group(0).rsplit("@", 1)
                if domain.lower() == "gaia.bounces.google.com":
                    if local.casefold() not in {
                        x.casefold() for x in private_values + new_private_values
                    }:
                        new_private_values.append(local)

    if new_private_values:
        with PRIVATE_FILE.open("a") as f:
            for value in new_private_values:
                f.write(value + "\n")
        private_values.extend(new_private_values)

    if not private_values:
        sys.exit("Private strings file is empty.")

    # Sanitize every header occurrence after RFC 2047 decoding.
    new_headers = []
    for name, value in decoded_headers:
        lname = name.lower()

        if lname in REMOVE or lname.startswith("x-notifications-"):
            continue

        if lname in {
            "to", "cc", "bcc", "delivered-to", "envelope-to",
            "x-original-to", "apparently-to", "resent-to"
        }:
            value = "[REDACTED]"
        elif lname == "from":
            # Preserve the verified public sender address.
            value = redact_private(value, private_values)
        elif lname == "message-id":
            value = "<redacted@notifications.google.com>"
        elif lname == "return-path":
            value = "<[REDACTED]@gaia.bounces.google.com>"
        else:
            value = clean_text(value, private_values)

        new_headers.append((name, value))

    # Remove headers using the public email API, then restore sanitized ones.
    for name in list(msg.keys()):
        del msg[name]

    for name, value in new_headers:
        msg[name] = value

    # Sanitize text MIME parts.
    for part in msg.walk():
        if part.get_content_maintype() == "text":
            try:
                content = part.get_content()
            except Exception:
                continue

            if isinstance(content, str):
                part.set_content(
                    clean_text(content, private_values),
                    subtype=part.get_content_subtype(),
                    charset=part.get_content_charset() or "utf-8",
                )

    buffer = BytesIO()
    BytesGenerator(buffer, policy=policy.default).flatten(msg)
    output = buffer.getvalue()

    # Reparse and inspect decoded headers and bodies BEFORE writing.
    check_msg = BytesParser(policy=policy.default).parsebytes(output)
    decoded_parts = [str(value) for _, value in check_msg.items()]

    for part in check_msg.walk():
        if part.get_content_maintype() == "text":
            try:
                content = part.get_content()
                if isinstance(content, str):
                    decoded_parts.append(content)
            except Exception:
                pass

    decoded_output = "\n".join(decoded_parts)

    for value in private_values:
        if value.casefold() in decoded_output.casefold():
            sys.exit("PRIVACY CHECK FAILED: private value remains; no output written.")

    if re.search(
        r'lh3[.]googleusercontent[.]com/(?!\[REDACTED-PATH\])\S+',
        decoded_output,
        re.I,
    ):
        sys.exit("PRIVACY CHECK FAILED: avatar path remains.")

    for header in REMOVE:
        if check_msg.get_all(header):
            sys.exit("PRIVACY CHECK FAILED: token header remains.")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(output)

    print("PASS: sanitized email generated")
    print("PASS: decoded-header and body privacy check")
    print("PASS: bounce identifier redacted")
    print("PASS: token headers removed")
    print("PASS: avatar paths redacted")
    print("Email parses:", not check_msg.defects)
    print("Raw SHA-256:", sha256(raw))
    print("Sanitized SHA-256:", sha256(output))


if __name__ == "__main__":
    main()
