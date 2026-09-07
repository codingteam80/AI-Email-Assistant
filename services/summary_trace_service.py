# Temporary observational trace for the full AI-summary pipeline.
# This module must never alter application behavior.
import json
import os
import threading
from datetime import datetime, timezone

_TRACE_LOCK = threading.Lock()
_TRACE_MAX_BYTES = 4 * 1024 * 1024
_TRACE_MAX_TEXT = 6000
_TRACE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "debug",
    "summary_pipeline_trace.log",
)
_LAST_FINGERPRINTS = {}


def _trace_enabled() -> bool:
    value = str(os.getenv("MAILMIND_SUMMARY_TRACE", "1") or "1").strip().casefold()
    return value not in {"0", "false", "no", "off", "disabled"}


def _compact(value):
    if isinstance(value, dict):
        return {str(k): _compact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_compact(v) for v in value]
    if isinstance(value, str):
        return value if len(value) <= _TRACE_MAX_TEXT else value[:_TRACE_MAX_TEXT] + "…"
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _compact(str(value))


def _summary_snapshot(summary: dict) -> dict:
    data = summary if isinstance(summary, dict) else {}
    return {
        "summary": _compact(data.get("summary")),
        "task_title": _compact(data.get("task_title")),
        "priority": _compact(data.get("priority")),
        "status": _compact(data.get("status")),
        "key_points": _compact(data.get("key_points")),
        "deadlines": _compact(data.get("deadlines")),
        "action_items": _compact(data.get("action_items")),
        "action_item_details": _compact(data.get("action_item_details")),
        "task_due_date": _compact(data.get("task_due_date")),
        "deadline_mode": _compact(data.get("deadline_mode")),
    }


def trace_summary_pipeline(stage: str, *, email=None, summary=None, payload=None) -> None:
    """Append one compact JSONL snapshot; tracing failures are ignored.

    Identical repeated events for the same stage/UID are suppressed so Streamlit
    reruns do not bury the useful pipeline transitions in duplicate UI/storage rows.
    """
    if not _trace_enabled():
        return
    try:
        email = email if isinstance(email, dict) else {}
        summary = summary if isinstance(summary, dict) else {}
        snapshot = _summary_snapshot(summary)
        uid = str(summary.get("uid") or email.get("uid") or email.get("message_id") or "")
        subject = str(summary.get("subject") or email.get("subject") or "")
        compact_payload = _compact(payload or {})
        fingerprint_payload = {
            "stage": str(stage or "unknown"),
            "uid": uid,
            "subject": subject,
            **snapshot,
            "payload": compact_payload,
        }
        fingerprint = json.dumps(fingerprint_payload, ensure_ascii=False, sort_keys=True, default=str)
        cache_key = (str(stage or "unknown"), uid or subject)

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


def summary_trace_path() -> str:
    return _TRACE_PATH
