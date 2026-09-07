import base64
import email as stdlib_email
from email_handler.display_time import format_display_datetime
from email_handler.thread_identity import canonical_thread_id
import re
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Dict, Optional


# Decode an email header value.
def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    decoded_parts = decode_header(value)
    result = ""
    for text, encoding in decoded_parts:
        if isinstance(text, bytes):
            result += text.decode(encoding or "utf-8", errors="ignore")
        else:
            result += text
    return result


# Convert HTML content to plain text.
def _strip_html(html: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# Remove unsafe HTML before display.
def _sanitize_html(html: str) -> str:

    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<noscript[^>]*>.*?</noscript>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'\son\w+\s*=\s*"[^"]*"', "", html, flags=re.IGNORECASE)
    html = re.sub(r"\son\w+\s*=\s*'[^']*'", "", html, flags=re.IGNORECASE)
    html = re.sub(r'(href|src)\s*=\s*"javascript:[^"]*"', r'\1="#"', html, flags=re.IGNORECASE)
    html = re.sub(r"(href|src)\s*=\s*'javascript:[^']*'", r"\1='#'", html, flags=re.IGNORECASE)
    # Preserve the original email layout as much as possible.
    # Avoid forcing proxy-like image behavior here because it can break
    # provider-hosted assets and make previews look different from
    # Gmail / Outlook.
    return html


# Replace CID image links with embedded data.
def _resolve_inline_images(html: str, cid_images: Dict[str, tuple]) -> str:

    for cid_key, (content_type, payload) in cid_images.items():
        b64 = base64.b64encode(payload).decode("ascii")
        data_uri = f"data:{content_type};base64,{b64}"
        html = html.replace(f"cid:{cid_key}", data_uri)
    return html

def parse_email(raw_bytes: bytes, uid: str = "") -> Dict:
    # Parse a raw RFC822 message into a structured dict.
    msg = stdlib_email.message_from_bytes(raw_bytes)

    subject = _decode(msg.get("Subject"))
    from_addr = _decode(msg.get("From"))
    to_addr = _decode(msg.get("To"))
    cc_addr = _decode(msg.get("Cc"))
    date_str = msg.get("Date")
    attachment_hint = str(msg.get("X-MailMind-Has-Attachment") or "").strip().casefold()
    message_id = _decode(msg.get("Message-ID")).strip()
    in_reply_to = _decode(msg.get("In-Reply-To")).strip()
    references = _decode(msg.get("References")).strip()
    gmail_thread_id = _decode(msg.get("X-MailMind-Gmail-Thread-ID")).strip()
    conversation_id = _decode(msg.get("X-MailMind-Conversation-ID")).strip()
    provider_thread_count = _decode(msg.get("X-MailMind-Thread-Count")).strip()
    reply_to = _decode(msg.get("Reply-To")).strip()
    spam_headers = []
    for header in ("X-MailMind-Provider-Folder", "X-Spam-Flag", "X-Spam-Status", "X-Microsoft-Antispam", "Authentication-Results"):
        value = _decode(msg.get(header)).strip()
        if value:
            spam_headers.append(f"{header}={value}")

    try:
        date_obj = parsedate_to_datetime(date_str) if date_str else None
    except (TypeError, ValueError):
        date_obj = None

    body_text = ""
    body_html = ""
    links = []
    attachments = []
    cid_images: Dict[str, tuple] = {}  # content-id -> (content_type, raw bytes)

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            filename = part.get_filename()
            content_id = part.get("Content-ID")

            if content_id and content_type.startswith("image/"):
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = None
                if payload:
                    cid_images[content_id.strip("<>")] = (content_type, payload)
                continue

            if "attachment" in disposition or filename:
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = None
                if payload and filename:
                    attachments.append({
                        "filename": _decode(filename),
                        "content_type": content_type,
                        "size": len(payload),
                        "data": payload,
                    })
                continue

            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="ignore")
            if content_type == "text/plain" and not body_text:
                body_text = decoded
            elif content_type == "text/html" and not body_html:
                body_html = decoded
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="ignore") if payload else ""
        except Exception:
            decoded = msg.get_payload() or ""
        if msg.get_content_type() == "text/html":
            body_html = decoded
        else:
            body_text = decoded

    if not body_text and body_html:
        body_text = _strip_html(body_html)

    if body_html:
        links = re.findall(r'''(?i)href\s*=\s*["'](https?://[^"']+)''', body_html)
        if cid_images:
            body_html = _resolve_inline_images(body_html, cid_images)
        body_html = _sanitize_html(body_html)

    snippet_source = body_text.strip()
    snippet = (snippet_source[:150] + "...") if len(snippet_source) > 150 else snippet_source

    parsed = {
        "uid": uid,
        "subject": subject or "(No Subject)",
        "from": from_addr,
        "to": to_addr,
        "cc": cc_addr,
        "date": date_obj.isoformat() if date_obj else "",
        "date_display": format_display_datetime(date_obj),
        "body_text": body_text.strip(),
        "body_html": body_html,
        "snippet": snippet,
        "attachments": attachments,
        "has_attachment": bool(attachments) or attachment_hint in {"1", "true", "yes"},
        "message_id": message_id,
        "in_reply_to": in_reply_to,
        "references": references,
        "gmail_thread_id": gmail_thread_id,
        "conversation_id": conversation_id,
        "provider_thread_count": (
            int(provider_thread_count) if provider_thread_count.isdigit() else 1
        ),
        "reply_to": reply_to,
        "spam_evidence": " | ".join(spam_headers),
        "links": links,
    }
    parsed["canonical_thread_id"] = canonical_thread_id(parsed)
    return parsed
