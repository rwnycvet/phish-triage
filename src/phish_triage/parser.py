"""Deterministic extraction of forgery-relevant facts from a raw email."""

import json
import sys
from email import message_from_string
from email.utils import parseaddr


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
    }


if __name__== "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        raw = f.read()
    print(json.dumps(parse_email(raw), indent=2))