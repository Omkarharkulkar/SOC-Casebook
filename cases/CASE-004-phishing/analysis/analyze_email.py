#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


def defang(value):
    return value.replace(".", "[.]")


def extract_urls(text):
    return re.findall(r'https?://[^\s<>"\']+', text or "", re.I)


def analyze(path):
    raw = path.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    text_parts = []
    html_parts = []
    attachments = []
    mime_types = []
    received = []

    for header in msg.get_all("Received", []):
        received.append(str(header))

    for part in msg.walk():
        mime_types.append(part.get_content_type())

        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            attachments.append({
                "filename": filename or "(unnamed)",
                "content_type": part.get_content_type(),
            })
            continue

        if part.get_content_type() not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if not isinstance(content, str):
            continue

        if part.get_content_type() == "text/plain":
            text_parts.append(content)
        else:
            html_parts.append(content)

    all_text = "\n".join(text_parts + html_parts)
    urls = set(extract_urls(all_text))

    domains = set()
    url_analysis = []

    for url in urls:
        parsed = urlparse(url.rstrip(".,;!?"))
        hostname = parsed.hostname
        userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""

        if hostname:
            domains.add(hostname.lower())

        url_analysis.append({
            "hostname_defanged": defang(hostname.lower()) if hostname else None,
            "userinfo_present": bool(userinfo),
            "userinfo_contains_hotmail": "hotmail" in userinfo.lower(),
            "userinfo_redacted": "[redacted]" if userinfo else None,
        })

    authentication = msg.get_all("Authentication-Results", [])
    received_spf = msg.get_all("Received-SPF", [])
    dkim = msg.get_all("DKIM-Signature", [])

    result = {
        "filename": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "headers": {
            "subject": str(msg.get("Subject", "")),
            "from": str(msg.get("From", "")),
            "date": str(msg.get("Date", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "return_path": str(msg.get("Return-Path", "")),
        },
        "authentication": {
            "authentication_results": [str(x) for x in authentication],
            "received_spf": [str(x) for x in received_spf],
            "dkim_signature_present": bool(dkim),
        },
        "received_headers": received,
        "mime_types": mime_types,
        "attachments": attachments,
        "url_count": len(urls),
        "url_domains_defanged": sorted(defang(d) for d in domains),
        "url_analysis": url_analysis,
        "limitations": [
            "URLs were not visited.",
            "Attachments were not opened or executed.",
            "Domain reputation was not checked.",
        ],
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Offline static email metadata analyzer"
    )
    parser.add_argument("email", help="Path to .eml file")
    parser.add_argument("-o", "--output", help="Optional JSON output path")
    args = parser.parse_args()

    from pathlib import Path

    path = Path(args.email)
    result = analyze(path)
    rendered = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"Analysis saved: {args.output}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
