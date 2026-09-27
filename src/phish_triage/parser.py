"""Deterministic extraction of forgery-relevant facts from a raw email."""

import json
import re
import sys
from email import message_from_string
from email.utils import parseaddr
from urllib.parse import urlsplit


URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def get_body(msg) -> str:
    """Return the plain-text body, or an empty string if there isn't one."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
        return ""
    payload = msg.get_payload(decode=True)
    if payload:
        return payload.decode("utf-8", errors="replace")
    return ""


def extract_iocs(body: str) -> dict:
    """Pull indicators of compromise out of the message body."""
    urls = URL_PATTERN.findall(body)

    domains = []
    for url in urls:
        host = urlsplit(url).hostname
        if host:
            domains.append(host)

    ips = IPV4_PATTERN.findall(body)

    return {
        "urls": sorted(set(urls)),
        "domains": sorted(set(domains)),
        "ipv4": sorted(set(ips)),
    }

def parse_email(raw: str) -> dict:
    """Pull the headers that determine whether an email is forged."""
    msg = message_from_string(raw)

    from_display, from_address = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))

    auth_raw = msg.get("Authentication-Results", "")
    auth_results = " ".join(auth_raw.split())

    return {
        "subject": msg.get("Subject", ""),
        "from_display_name": from_display,
        "from_address": from_address,
        "reply_to": reply_to,
        "return_path": return_path,
        "auth_results": auth_results,
        "iocs": extract_iocs(get_body(msg)),
    }


if __name__== "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        raw = f.read()
    print(json.dumps(parse_email(raw), indent=2))

    