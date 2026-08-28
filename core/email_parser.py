"""
core/email_parser.py

Reads a raw .eml file and turns it into a Python email.message.EmailMessage
object using the modern (policy.default) email API, then hands back the
pieces the rest of the pipeline needs: headers, body text/html, attachments.

This module does ONE job: parsing. It does not decide anything about risk.
That separation is deliberate -- same pattern as ThreatLens keeping ingestion
and scoring in different modules.
"""

import hashlib
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage

from core.models import Attachment


def load_eml(path: str) -> EmailMessage:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def get_header(msg: EmailMessage, name: str) -> str | None:
    value = msg.get(name)
    return str(value) if value is not None else None


def extract_body(msg: EmailMessage) -> tuple[str, str, bool]:
    """
    Returns (text_body, html_body, has_html_body).
    Walks all parts; prefers the first text/plain part for text_body and
    the first text/html part for html_body. Skips attachments.
    """
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type == "text/plain" and not text_body:
                try:
                    text_body = part.get_content()
                except Exception:
                    pass
            elif content_type == "text/html" and not html_body:
                try:
                    html_body = part.get_content()
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if content_type == "text/html":
            html_body = content
        else:
            text_body = content

    return text_body, html_body, bool(html_body)


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size_bytes=len(payload),
                    md5=hashlib.md5(payload).hexdigest(),
                    sha1=hashlib.sha1(payload).hexdigest(),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
    return attachments

