#!/usr/bin/env python3
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.generator import BytesGenerator
from io import BytesIO
import hashlib
import re

SOURCE = Path("evidence/Security alert.eml")
OUTPUT = Path("evidence/control-google-security-alert-sanitized.eml")

EMAIL_RE = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_url(match):
    url = match.group(0).rstrip('.,;)')
    suffix = match.group(0)[len(url):]
    url = re.sub(r'[?#].*$', '', url)
    url = url.replace('https://', 'hxxps://')
    url = url.replace('http://', 'hxxp://')
    url = re.sub(
        r'(?<=://)([^/]+)',
        lambda m: m.group(1).replace('.', '[.]'),
        url
    )
    return url + suffix


def sanitize(text):
    text = EMAIL_RE.sub('[REDACTED-EMAIL]', text)
    return URL_RE.sub(clean_url, text)


def main():
    original_hash = sha256(SOURCE)
    msg = BytesParser(policy=policy.default).parsebytes(
        SOURCE.read_bytes()
    )

    for header in ("To", "Cc", "Bcc"):
        if header in msg:
            msg.replace_header(header, "[REDACTED]")

    if "Message-ID" in msg:
        msg.replace_header("Message-ID", "[REDACTED]")

    for header in list(msg.keys()):
        if header not in ("To", "Cc", "Bcc", "Message-ID"):
            value = str(msg[header])
            cleaned = EMAIL_RE.sub("[REDACTED-EMAIL]", value)
            if cleaned != value:
                msg.replace_header(header, cleaned)

    for part in msg.walk():
        if part.get_content_maintype() == "text":
            try:
                content = part.get_content()
            except Exception:
                continue

            if isinstance(content, str):
                part.set_content(
                    sanitize(content),
                    subtype=part.get_content_subtype(),
                    charset=part.get_content_charset() or "utf-8"
                )

    buffer = BytesIO()
    BytesGenerator(buffer, policy=policy.default).flatten(msg)
    OUTPUT.write_bytes(buffer.getvalue())

    print("Sanitized copy regenerated.")
    print(f"Raw SHA-256:       {original_hash}")
    print(f"Sanitized SHA-256: {sha256(OUTPUT)}")
    print("Original unchanged.")


if __name__ == "__main__":
    main()
