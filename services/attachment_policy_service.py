"""Outbound attachment risk policy for Draft Email uploads."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from config import ATTACHMENT_POLICY_CACHE_SIZE
import json


_POLICY_PATH = Path(__file__).resolve().parents[1] / "data" / "app_data.json"


@lru_cache(maxsize=ATTACHMENT_POLICY_CACHE_SIZE)
def _policy() -> dict:
    try:
        with _POLICY_PATH.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        return {}
    value = payload.get("attachment_policy")
    return value if isinstance(value, dict) else {}


def _extension(filename: str) -> str:
    name = str(filename or "").strip().casefold()
    if not name or "." not in Path(name).name:
        return ""
    return Path(name).suffix.casefold()


def _lookup(extension: str, group_name: str) -> tuple[str, str] | None:
    groups = _policy().get(group_name) or {}
    if not isinstance(groups, dict):
        return None
    for category, values in groups.items():
        normalized = {str(value).strip().casefold() for value in (values or [])}
        if extension in normalized:
            return str(category), extension
    return None


def classify_attachment(filename: str, content_type: str = "") -> dict:
    """Return safe/warning/high_risk classification for one outbound file.

    The final filename extension is authoritative for double-extension names.
    A clearly riskier MIME type may elevate the result, but never downgrade it.
    Unknown file types are allowed with a warning rather than silently trusted.
    """
    name = str(filename or "attachment").strip() or "attachment"
    extension = _extension(name)
    mime = str(content_type or "").strip().casefold().split(";", 1)[0]

    high = _lookup(extension, "high_risk") if extension else None
    warning = _lookup(extension, "warning") if extension else None
    safe = _lookup(extension, "safe") if extension else None

    high_mimes = {str(item).casefold() for item in (_policy().get("high_risk_mime_types") or [])}
    warning_mimes = {str(item).casefold() for item in (_policy().get("warning_mime_types") or [])}

    if high or mime in high_mimes:
        category = high[0] if high else "Runnable file"
        return {
            "filename": name,
            "extension": extension,
            "content_type": mime,
            "risk": "high_risk",
            "category": category,
            "title": "High-risk attachment",
            "message": "This file type can contain runnable or system-level content and may be blocked by your email provider. Send it only if you trust the file and intended recipient.",
        }

    if warning or mime in warning_mimes:
        category = warning[0] if warning else "Potentially active content"
        return {
            "filename": name,
            "extension": extension,
            "content_type": mime,
            "risk": "warning",
            "category": category,
            "title": "Attachment warning",
            "message": "This file type can contain compressed, active, macro-enabled, or packaged content and may be blocked by your email provider. Review it before sending.",
        }

    if safe:
        return {
            "filename": name,
            "extension": extension,
            "content_type": mime,
            "risk": "safe",
            "category": safe[0],
            "title": "Allowed attachment",
            "message": "",
        }

    return {
        "filename": name,
        "extension": extension,
        "content_type": mime,
        "risk": "warning",
        "category": "Unknown file type",
        "title": "Attachment warning",
        "message": "MailMind does not recognize this file type. It is allowed, but review it before sending because your email provider may block it.",
    }


def classify_attachments(files) -> list[dict]:
    results = []
    for uploaded in files or []:
        results.append(
            classify_attachment(
                getattr(uploaded, "name", "attachment"),
                getattr(uploaded, "type", ""),
            )
        )
    return results
