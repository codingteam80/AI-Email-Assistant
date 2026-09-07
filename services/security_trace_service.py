# Temporary observational trace for the MailMind security-classification pipeline.
# This module must never alter classification, routing, storage, or UI behavior.
import contextvars
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

_TRACE_LOCK = threading.Lock()
_TRACE_MAX_BYTES = 8 * 1024 * 1024
_TRACE_MAX_TEXT = 8000
_TRACE_BODY = 5000
_TRACE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "debug",
    "security_detection_trace.log",
)
_LAST_FINGERPRINTS = {}
_TRACE_MODE = contextvars.ContextVar("mailmind_security_trace_mode", default="")


def _trace_enabled() -> bool:
    value = str(os.getenv("MAILMIND_SECURITY_TRACE", "1") or "1").strip().casefold()
    return value not in {"0", "false", "no", "off", "disabled"}


def _compact(value, *, limit=_TRACE_MAX_TEXT):
    if isinstance(value, dict):
        return {str(k): _compact(v, limit=limit) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_compact(v, limit=limit) for v in value]
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…"
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _compact(str(value), limit=limit)


def _email_snapshot(email: dict) -> dict:
    data = email if isinstance(email, dict) else {}
    attachments = []
    for item in (data.get("attachments") or [])[:12]:
        item = item if isinstance(item, dict) else {}
        attachments.append({
            "filename": _compact(str(item.get("filename") or ""), limit=500),
            "content_type": _compact(str(item.get("content_type") or ""), limit=300),
            "size": int(item.get("size") or 0),
        })
    return {
        "uid": str(data.get("uid") or data.get("message_id") or ""),
        "subject": _compact(str(data.get("subject") or ""), limit=1000),
        "from": _compact(str(data.get("from") or ""), limit=1000),
        "reply_to": _compact(str(data.get("reply_to") or ""), limit=1000),
        "to": _compact(str(data.get("to") or ""), limit=1500),
        "provider_spam": bool(data.get("provider_spam")),
        "full_message": bool(data.get("full_message")),
        "security_input_version": int(data.get("security_input_version") or 0),
        "spam_evidence": _compact(str(data.get("spam_evidence") or ""), limit=4000),
        "links": _compact(list(data.get("links") or [])[:20], limit=1500),
        "attachments": attachments,
        "body_excerpt": _compact(
            str(data.get("body_text") or data.get("snippet") or data.get("body") or ""),
            limit=_TRACE_BODY,
        ),
    }


def _classification_snapshot(data: dict) -> dict:
    value = data if isinstance(data, dict) else {}
    return {
        "category": str(value.get("category") or value.get("security_category") or ""),
        "score": int(value.get("score") or value.get("spam_score") or 0),
        "confidence": int(value.get("confidence") or value.get("security_confidence") or 0),
        "source": str(value.get("source") or value.get("security_source") or ""),
        "malicious": bool(value.get("malicious")),
        "is_spam": bool(value.get("is_spam")),
        "provider_flagged": bool(value.get("provider_flagged")),
        "non_provider_score": int(value.get("non_provider_score") or 0),
        "reason": _compact(str(value.get("reason") or value.get("spam_reason") or ""), limit=5000),
        "reasons": _compact(value.get("reasons") or [], limit=1500),
        "strong_flags": _compact(value.get("strong_flags") or [], limit=1000),
        "rule_hits": _compact(value.get("rule_hits") or [], limit=1000),
        "category_scores": _compact(value.get("category_scores") or {}, limit=1000),
    }


@contextmanager
def security_trace_mode(mode: str):
    token = _TRACE_MODE.set(str(mode or ""))
    try:
        yield
    finally:
        _TRACE_MODE.reset(token)


def trace_security_detection(
    stage: str,
    *,
    email=None,
    baseline=None,
    classification=None,
    payload=None,
    mode: str | None = None,
) -> None:
    """Append one compact JSONL security snapshot; tracing failures are ignored."""
    if not _trace_enabled():
        return
    try:
        email = email if isinstance(email, dict) else {}
        baseline = baseline if isinstance(baseline, dict) else {}
        classification = classification if isinstance(classification, dict) else {}
        resolved_mode = str(mode if mode is not None else _TRACE_MODE.get() or "unknown")
        email_snapshot = _email_snapshot(email)
        fingerprint_payload = {
            "stage": str(stage or "unknown"),
            "mode": resolved_mode,
            "email": email_snapshot,
            "baseline": _classification_snapshot(baseline),
            "classification": _classification_snapshot(classification),
            "payload": _compact(payload or {}),
        }
        fingerprint = json.dumps(
            fingerprint_payload, ensure_ascii=False, sort_keys=True, default=str
        )
        uid = str(email_snapshot.get("uid") or "")
        subject = str(email_snapshot.get("subject") or "")
        cache_key = (str(stage or "unknown"), resolved_mode, uid or subject)

        with _TRACE_LOCK:
            if _LAST_FINGERPRINTS.get(cache_key) == fingerprint:
                return
            _LAST_FINGERPRINTS[cache_key] = fingerprint
            event = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                **fingerprint_payload,
            }
            os.makedirs(os.path.dirname(_TRACE_PATH), exist_ok=True)
            if os.path.exists(_TRACE_PATH) and os.path.getsize(_TRACE_PATH) > _TRACE_MAX_BYTES:
                backup = _TRACE_PATH + ".1"
                try:
                    if os.path.exists(backup):
                        os.remove(backup)
                    os.replace(_TRACE_PATH, backup)
                except OSError:
                    pass
            with open(_TRACE_PATH, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    except Exception:
        return


def security_trace_path() -> str:
    return _TRACE_PATH
