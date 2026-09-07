"""Pure helpers for tying a generated Reply Draft to its current task state."""
from __future__ import annotations

import hashlib
import json


def reply_draft_state_fingerprint(summary: dict) -> str:
    """Fingerprint the reply-relevant current state without UI/session dependencies."""
    if not isinstance(summary, dict):
        return ""

    details = []
    for item in (summary.get("action_item_details") or []):
        if not isinstance(item, dict):
            continue
        details.append({
            "action": " ".join(str(item.get("action") or "").split()),
            "action_id": str(item.get("action_id") or ""),
            "completed": bool(item.get("completed")),
            "cancelled": bool(item.get("cancelled")),
            "completion_status": str(item.get("completion_status") or item.get("status") or "").strip(),
            "due_date": str(item.get("due_date") or item.get("deadline") or "").strip(),
        })

    payload = {
        "status": str(summary.get("status") or "Not Started").strip(),
        "status_source": str(summary.get("status_source") or "").strip(),
        "priority": str(summary.get("priority") or "").strip(),
        "deadlines": [str(value or "").strip() for value in (summary.get("deadlines") or [])],
        "action_items": [" ".join(str(value or "").split()) for value in (summary.get("action_items") or [])],
        "action_item_details": details,
        "task_revision": int(summary.get("task_revision") or 0),
        "summary_updated_at": str(summary.get("summary_updated_at") or summary.get("updated_at") or "").strip(),
        "summary_activity_at": str(summary.get("summary_activity_at") or "").strip(),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
