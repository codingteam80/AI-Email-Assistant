# Temporary observational trace for the deadline pipeline.
# This module must never alter application behavior.
import json
import os
import threading
from datetime import datetime, timezone

_TRACE_LOCK = threading.Lock()
_TRACE_MAX_BYTES = 2 * 1024 * 1024
_TRACE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "debug",
    "deadline_pipeline_trace.log",
)


def _compact(value):
    if isinstance(value, dict):
        return {str(k): _compact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_compact(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def trace_deadline_pipeline(stage: str, *, email=None, summary=None, payload=None) -> None:
    """Append one compact JSONL event; tracing failures are ignored."""
    try:
        email = email if isinstance(email, dict) else {}
        summary = summary if isinstance(summary, dict) else {}
        event = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "stage": str(stage or "unknown"),
            "uid": str(summary.get("uid") or email.get("uid") or email.get("message_id") or ""),
            "subject": str(summary.get("subject") or email.get("subject") or ""),
            "deadlines": _compact(summary.get("deadlines")) if summary else None,
            "action_items": _compact(summary.get("action_items")) if summary else None,
            "action_item_details": _compact(summary.get("action_item_details")) if summary else None,
            "payload": _compact(payload or {}),
        }
        with _TRACE_LOCK:
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


def deadline_trace_path() -> str:
    return _TRACE_PATH
