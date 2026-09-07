import json
import re
from typing import Any, Dict, Iterable, Optional


_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)

_REPLY_HISTORY_ON_WROTE_RE = re.compile(r"^\s*On .+ wrote:\s*$", re.IGNORECASE)
_REPLY_HISTORY_ORIGINAL_RE = re.compile(r"^\s*-{2,}\s*Original Message\s*-{2,}\s*$", re.IGNORECASE)


def _strip_reply_quoted_history(value: str) -> tuple[str, bool]:
    """Return only the current reply text when a standard quoted history follows.

    Security evaluates the message being delivered now, not the stale conversation
    copied underneath it by Gmail/Outlook. We strip a quoted tail only when there is
    meaningful current text before the boundary; quote-only/forwarded content is
    preserved so security never loses the actual payload.
    """
    text = str(value or "")
    if not text.strip():
        return text, False
    lines = text.splitlines()
    boundary = None
    for index, line in enumerate(lines):
        if _REPLY_HISTORY_ON_WROTE_RE.match(line) or _REPLY_HISTORY_ORIGINAL_RE.match(line):
            boundary = index
            break
        if line.lstrip().startswith(">"):
            boundary = index
            break
        # Outlook often starts a quoted block with From:/Sent:/To:/Subject:.
        # Require at least one companion header nearby so ordinary prose such as
        # "From: Finance" is not mistaken for a reply boundary.
        if re.match(r"^\s*From:\s*", line, re.IGNORECASE):
            nearby = lines[index + 1:index + 6]
            header_kinds = {
                re.match(r"^\s*(Sent|To|Subject):\s*", candidate, re.IGNORECASE).group(1).casefold()
                for candidate in nearby
                if re.match(r"^\s*(Sent|To|Subject):\s*", candidate, re.IGNORECASE)
            }
            if len(header_kinds) >= 2:
                boundary = index
                break
    if boundary is None:
        return text, False
    current = "\n".join(lines[:boundary]).strip()
    if not current:
        return text, False
    return current, True


def _as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "y", "spam", "junk"}
    return bool(value)


def _unique_text(values: Iterable[Any]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def serialize_security_links(links) -> str:
    return json.dumps(_unique_text(links or []), ensure_ascii=False, separators=(",", ":"))


def deserialize_security_links(value) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return _unique_text(value)
    text = str(value or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _unique_text(_URL_RE.findall(text))
    if isinstance(decoded, list):
        return _unique_text(decoded)
    return []


def normalize_security_input(
    email_data: Optional[Dict],
    *,
    provider_spam: Optional[bool] = None,
    attachments: Optional[list] = None,
    full_message: Optional[bool] = None,
) -> Dict:
    # Build one provider-neutral input contract for security classification.
    # Gmail/Outlook/Hotmail/Yahoo can expose different provider metadata, but
    # detect_spam() should always receive the same normalized MailMind fields.
    source = dict(email_data or {})
    normalized = dict(source)

    normalized["uid"] = str(source.get("uid") or "")
    normalized["subject"] = str(source.get("subject") or "")
    normalized["from"] = str(source.get("from") or source.get("sender") or "")
    normalized["to"] = str(source.get("to") or source.get("recipient") or "")
    normalized["cc"] = str(source.get("cc") or "")
    normalized["reply_to"] = str(source.get("reply_to") or "")
    original_body_text = str(source.get("body_text") or "")
    current_body_text, quoted_history_stripped = _strip_reply_quoted_history(original_body_text)
    normalized["security_original_body_text"] = original_body_text
    normalized["security_quoted_history_stripped"] = 1 if quoted_history_stripped else 0
    normalized["body_text"] = current_body_text
    normalized["body_html"] = str(source.get("body_html") or "")
    normalized["snippet"] = str(source.get("snippet") or "")

    evidence = str(source.get("spam_evidence") or "").strip()
    raw_evidence_parts = [part.strip() for part in evidence.split("|") if part.strip()]
    evidence_provider_spam = any(
        "provider-folder=spam" in part.casefold()
        or "provider-folder=junk" in part.casefold()
        for part in raw_evidence_parts
    )

    # Provider location has one source of truth. For freshly parsed provider
    # messages, the synthetic X-MailMind-Provider-Folder header is allowed to
    # establish the initial location. Once a persisted/current provider_spam
    # value is supplied, that explicit value wins and any historical folder
    # marker in spam_evidence is rewritten instead of being allowed to revive
    # an old Spam/Junk location during a later full-body/catch-up scan.
    if provider_spam is not None:
        provider_flag = bool(provider_spam)
    elif "provider_spam" in source:
        provider_flag = _as_bool(source.get("provider_spam"))
    else:
        provider_flag = evidence_provider_spam
    normalized["provider_spam"] = 1 if provider_flag else 0

    evidence_parts = [
        part
        for part in raw_evidence_parts
        if "provider-folder=spam" not in part.casefold()
        and "provider-folder=junk" not in part.casefold()
    ]
    if provider_flag:
        evidence_parts.insert(0, "X-MailMind-Provider-Folder=spam")
    normalized["spam_evidence"] = " | ".join(_unique_text(evidence_parts))

    link_values = []
    if quoted_history_stripped:
        # Provider-extracted links and body_html can include the quoted prior
        # conversation. Recompute from the current reply only so a previously
        # flagged URL cannot poison a legitimate follow-up in the same thread.
        link_values.extend(_URL_RE.findall(normalized["body_text"]))
    else:
        raw_links = source.get("links") or deserialize_security_links(source.get("security_links_json"))
        if isinstance(raw_links, str):
            link_values.extend(_URL_RE.findall(raw_links))
        else:
            try:
                link_values.extend(raw_links)
            except TypeError:
                pass
        link_values.extend(_URL_RE.findall(normalized["body_text"]))
        link_values.extend(_URL_RE.findall(normalized["body_html"]))
    normalized["links"] = _unique_text(link_values)

    if attachments is not None:
        normalized["attachments"] = list(attachments or [])
    else:
        normalized["attachments"] = list(source.get("attachments") or [])
    normalized["has_attachment"] = bool(
        normalized["attachments"] or source.get("has_attachment")
    )

    if full_message is None:
        normalized["is_full"] = 1 if _as_bool(source.get("is_full")) else 0
    else:
        normalized["is_full"] = 1 if full_message else 0

    return normalized
