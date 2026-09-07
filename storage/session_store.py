import secrets
from typing import Dict, Optional

_sessions: Dict[str, dict] = {}


def create_session(client, email_address: str) -> str:
    # Save the live login under a random session token.
    token = secrets.token_urlsafe(24)
    _sessions[token] = {"client": client, "email_address": email_address}
    return token


def get_session(token: Optional[str]) -> Optional[dict]:
    # Return the saved login for a valid token.
    if not token:
        return None
    return _sessions.get(token)


def delete_session(token: Optional[str]) -> None:
    # Remove the saved login during logout.
    if token:
        _sessions.pop(token, None)


def save_reply_draft(token: Optional[str], uid: str, draft: str, state_fingerprint: str = "") -> bool:
    # Store a non-empty draft without letting transient blank UI state erase it.
    session = get_session(token)
    if session is None:
        return False

    value = str(draft or "")
    drafts = session.setdefault("reply_drafts", {})

    # A Streamlit widget can briefly report an empty value while a dialog is
    # being removed/recreated. Closing a dialog is not a draft-delete action,
    # so an empty value must never replace a previously saved draft. Explicit
    # deletion is handled only by delete_reply_draft().
    if not value.strip():
        return True

    key = str(uid)
    drafts[key] = value
    if state_fingerprint:
        session.setdefault("reply_draft_state_fingerprints", {})[key] = str(state_fingerprint)
    return True


def save_reply_draft_attachments(token: Optional[str], uid: str, attachments: list[dict]) -> bool:
    """Persist user-added reply attachments independently from AI draft text.

    Attachments intentionally survive reply-text invalidation/regeneration so a
    status-driven AI rewrite cannot discard files the user already saved.
    """
    session = get_session(token)
    if session is None:
        return False

    key = str(uid)
    normalized: list[dict] = []
    for attachment in attachments or []:
        if not isinstance(attachment, dict):
            continue
        data = attachment.get("data") or b""
        if not isinstance(data, (bytes, bytearray)) or not data:
            continue
        normalized.append({
            "filename": str(attachment.get("filename") or "attachment"),
            "content_type": str(
                attachment.get("content_type") or "application/octet-stream"
            ),
            "size": int(attachment.get("size") or len(data)),
            "data": bytes(data),
        })

    saved = session.setdefault("reply_draft_attachments", {})
    if normalized:
        saved[key] = normalized
    else:
        saved.pop(key, None)
    return True


def get_reply_draft_attachments(token: Optional[str], uid: str) -> list[dict]:
    """Return durable user-added files for one reply draft."""
    session = get_session(token)
    if session is None:
        return []
    items = session.get("reply_draft_attachments", {}).get(str(uid), []) or []
    return [dict(item) for item in items if isinstance(item, dict)]


def delete_reply_draft_attachments(token: Optional[str], uid: str) -> bool:
    """Explicitly clear saved reply attachments after send/discard."""
    session = get_session(token)
    if session is None:
        return False
    saved = session.get("reply_draft_attachments", {})
    return saved.pop(str(uid), None) is not None


def get_reply_draft(token: Optional[str], uid: str) -> str:
    # Return a prepared draft without exposing it in the URL.
    session = get_session(token)
    if session is None:
        return ""
    return str(session.get("reply_drafts", {}).get(str(uid), ""))


def get_reply_draft_state_fingerprint(token: Optional[str], uid: str) -> str:
    """Return the task-state fingerprint captured when the draft was generated."""
    session = get_session(token)
    if session is None:
        return ""
    return str(session.get("reply_draft_state_fingerprints", {}).get(str(uid), ""))


def delete_reply_draft(token: Optional[str], uid: str) -> bool:
    # Delete one prepared draft from the authenticated server-side session.
    session = get_session(token)
    if session is None:
        return False
    key = str(uid)
    drafts = session.get("reply_drafts", {})
    existed = key in drafts
    drafts.pop(key, None)
    session.get("reply_draft_state_fingerprints", {}).pop(key, None)
    return existed
