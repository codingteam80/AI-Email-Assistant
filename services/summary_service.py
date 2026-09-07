# Business logic for building structured email summaries.
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from difflib import SequenceMatcher
from email.utils import parseaddr
import hashlib
import re
import unicodedata
from uuid import uuid4

from services.task_status import aggregate_task_status, normalize_task_status
from services.summary_trace_service import trace_summary_pipeline

from services.ai_service import (
    _phase1b_keypoint_is_action_restatement,
    _phase1b_recipient_request_signal,
    _phase1c_deadline_identity,
    _phase1c_dedupe_deadlines,
    _phase1g_effective_turn_text,
    _incremental_actions_semantically_same,
    _incremental_current_turn_text,
    summarize_email, summarize_email_batch, summarize_incremental_email,
)


def _summary_now_utc() -> str:
    # Store summary activity in UTC using the same format as SQLite CURRENT_TIMESTAMP.
    # The UI converts this value to the configured display timezone.
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _stamp_new_summary(summary: dict) -> dict:
    # A newly created card starts with the same creation and activity timestamp.
    stamped = dict(summary)
    now = _summary_now_utc()
    stamped["summary_created_at"] = str(stamped.get("summary_created_at") or now)
    stamped["summary_activity_at"] = str(stamped.get("summary_activity_at") or now)
    return stamped


def _stamp_content_update(summary: dict, existing: dict | None = None) -> dict:
    # New thread content updates list activity without changing original creation time.
    stamped = dict(summary)
    existing = existing or {}
    created = (
        stamped.get("summary_created_at")
        or existing.get("summary_created_at")
        or existing.get("generated_at")
        or _summary_now_utc()
    )
    stamped["summary_created_at"] = str(created)
    stamped["summary_activity_at"] = _summary_now_utc()
    return stamped


def _normalized_action_key(value: str) -> str:
    return " ".join(str(value or "").casefold().split()).rstrip(".")


def _batch_deadline_key(value: str) -> str:
    """Keep distinct clock/timezone cutoffs that share one calendar day.

    Per-email deadline validation may intentionally collapse formatting aliases,
    but a Batch card aggregates unrelated source emails.  Two tasks due on the
    same date at 4:30 PM and 5:00 PM are therefore different deadlines and must
    both survive.  Use the semantic date identity plus an explicit clock/timezone
    suffix when present; date-only aliases still collapse normally.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;")
    if not text:
        return ""
    base = _phase1c_deadline_identity(text)
    clock = re.search(
        r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b|\b(noon|midnight)\b",
        text,
        flags=re.IGNORECASE,
    )
    if not clock:
        return base or text.casefold()
    if clock.group(4):
        clock_key = "12:00pm" if clock.group(4).casefold() == "noon" else "12:00am"
    else:
        clock_key = f"{int(clock.group(1))}:{int(clock.group(2) or 0):02d}{clock.group(3).casefold()}"
    zone_match = re.search(
        r"\b((?:UTC|GMT)(?:[+-]\d{1,2}(?::?\d{2})?)?|[A-Z]{3,4})\b",
        text,
    )
    zone = ""
    if zone_match and zone_match.group(1).upper() not in {"EOD", "COB"}:
        zone = f"|zone:{zone_match.group(1).casefold()}"
    return f"{base or text.casefold()}|clock:{clock_key}{zone}"


def _dedupe_batch_deadlines(values) -> list[str]:
    """Deduplicate Batch deadline aliases without flattening distinct cutoffs."""
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;")
        if not text:
            continue
        key = _batch_deadline_key(text)
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _stable_action_id(seed: str, action: str, index: int = 0) -> str:
    raw = f"{seed}|{index}|{_normalized_action_key(action)}"
    return f"act_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:18]}"


def _deadline_mode(details: list[dict]) -> str:
    # Active work without a current explicit date always falls back to the
    # standard planned deadline. A removed explicit date stays suppressed at
    # action level (deadline_state="none"), but the task itself uses +14 days
    # from the latest thread update instead of becoming open-ended.
    open_rows = [item for item in details if not bool(item.get("completed")) and not bool(item.get("cancelled"))]
    if any(str(item.get("due_date") or "").strip() for item in open_rows):
        return "explicit"
    return "auto"


def _action_similarity(left: str, right: str) -> float:
    left_key, right_key = _normalized_action_key(left), _normalized_action_key(right)
    if not left_key or not right_key:
        return 0.0
    if left_key == right_key:
        return 1.0
    left_tokens, right_tokens = set(re.findall(r"[a-z0-9]+", left_key)), set(re.findall(r"[a-z0-9]+", right_key))
    token_score = len(left_tokens & right_tokens) / max(1, min(len(left_tokens), len(right_tokens)))
    return max(token_score, SequenceMatcher(None, left_key, right_key).ratio())


def _action_non_latin_scripts(value: str) -> set[str]:
    """Return coarse non-Latin writing scripts used by action text.

    This is a grounding signal only. Accented Latin text stays Latin, while Han
    ideographs share one stable identity across their Unicode block names.
    """
    scripts: set[str] = set()
    for char in str(value or ""):
        if not unicodedata.category(char).startswith("L"):
            continue
        name = unicodedata.name(char, "")
        if not name or "LATIN" in name:
            continue
        if "CJK" in name or "IDEOGRAPH" in name:
            scripts.add("HAN")
        else:
            scripts.add(name.split(" ", 1)[0])
    return scripts


def _action_introduces_unsupported_script(action: str, source: str) -> bool:
    """Reject a generated language/script variant absent from the source email."""
    return bool(_action_non_latin_scripts(action) - _action_non_latin_scripts(source))


def _completed_status_label(value: str) -> bool:
    """Return True for a declarative Update/Status line describing finished work.

    A status label is not an imperative action. Keep a real request after the
    label eligible and require explicit completion grammar to avoid suppressing
    ordinary open-work updates.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    match = re.match(
        r"^(?:(?:status|progress)\s+)?update\s*[:–—-]\s*(.+)$",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        return False
    statement = match.group(1).strip()
    if not statement or _phase1b_recipient_request_signal(statement):
        return False
    completed = (
        r"(?:submitted|completed|finished|done|sent|uploaded|processed|"
        r"approved|resolved|received)"
    )
    return bool(
        re.search(
            rf"\b(?:is|are|was|were|has|have|had)\s+(?:already\s+)?"
            rf"(?:been\s+)?(?:successfully\s+)?{completed}\b",
            statement,
            flags=re.IGNORECASE,
        )
        or re.search(
            rf"\b(?:already|previously)\s+(?:successfully\s+)?{completed}\b",
            statement,
            flags=re.IGNORECASE,
        )
    )


def _recipient_terminal_no_action(email: dict) -> bool:
    """Honor an explicit current-turn recipient no-action state.

    Generic ``no action required`` is authoritative only when it is not scoped
    to another named actor, and only until a later direct recipient request.
    """
    raw = str(email.get("body_text") or email.get("snippet") or "")
    turn = _phase1g_effective_turn_text(raw)
    pattern = re.compile(
        r"\b(?:"
        r"no (?:further|other|additional)?\s*action (?:is )?(?:needed|required) from you|"
        r"nothing (?:is )?required from you|"
        r"you (?:do not|don't|dont) need to (?:do|take) anything|"
        r"no (?:further|other|additional)?\s*action (?:is )?(?:needed|required)"
        r"(?!\s+from\b)"
        r")\b",
        flags=re.IGNORECASE,
    )
    matches = list(pattern.finditer(turn))
    if not matches:
        return False
    trailing = turn[matches[-1].end():]
    sentences = [
        item.strip()
        for item in re.split(r"(?<=[.!?])\s+|[\r\n]+", trailing)
        if item.strip()
    ]
    return not any(_phase1b_recipient_request_signal(item) for item in sentences)


def _canonical_initial_actions(summary: dict, email: dict) -> list[str]:
    """Apply final provider-neutral Action Item invariants before persistence."""
    if _recipient_terminal_no_action(email):
        return []

    source = _phase1g_effective_turn_text(
        str(email.get("body_text") or email.get("snippet") or "")
    )
    raw_actions = [
        str(value or "").strip()
        for value in (summary.get("action_items") or [])
        if str(value or "").strip()
    ]
    actions: list[str] = []
    for action in raw_actions:
        if _completed_status_label(action):
            continue
        if _action_introduces_unsupported_script(action, source):
            continue
        duplicate_index = next((
            index for index, current in enumerate(actions)
            if _action_similarity(action, current) >= 0.90
        ), None)
        if duplicate_index is None:
            actions.append(action)
        elif len(action.split()) > len(actions[duplicate_index].split()):
            actions[duplicate_index] = action
    return actions


def _parse_due_date(value: str, reference: date) -> date | None:
    text = str(value or "").strip()
    for match in re.findall(r"\b(20\d{2})-(\d{2})-(\d{2})\b", text):
        try:
            return date(*(int(part) for part in match))
        except ValueError:
            pass
    for fmt in ("%m/%d/%Y", "%m-%d-%Y", "%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    lowered = text.casefold()
    if re.search(r"\btoday\b|\bend of day\b|\beod\b", lowered):
        return reference
    if re.search(r"\btomorrow\b", lowered):
        return reference + timedelta(days=1)
    return None


def _deadline_identity(value: str, reference: date) -> str:
    """Canonical identity for de-duplicating equivalent deadline wording.

    Presentation variants such as ``by 2026-09-11`` and ``2026-09-11`` are one
    deadline.  Preserve distinct clock times on the same day so two genuinely
    different timed deadlines are not collapsed.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""
    parsed = _parse_due_date(text, reference)
    if parsed is not None:
        lowered = text.casefold()
        time_match = re.search(
            r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s*[ap]\.?m\.?)?\b|"
            r"\b(?:1[0-2]|0?\d)(?:[:.]?[0-5]\d)?\s*[ap]\.?m\.?\b",
            lowered,
            flags=re.IGNORECASE,
        )
        time_key = re.sub(r"[^0-9apm:]", "", time_match.group(0).casefold()) if time_match else ""
        return f"date:{parsed.isoformat()}|time:{time_key}"

    normalized = text.casefold()
    normalized = re.sub(
        r"^(?:important\s+)?(?:deadline|due\s+date)\s*(?::|=|-|\bis\b)?\s*",
        "",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = re.sub(r"^(?:by|due|before|on)\s+", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized).strip()
    return f"text:{normalized}"


def _reference_date(thread_email: dict) -> date:
    raw = str(thread_email.get("date") or thread_email.get("date_display") or "").strip()
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return date.today()


def _priority_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(
        str(value or "").strip().casefold(), 0
    )


def _incremental_priority_material_change(
    existing: dict, added: dict, replaced_due_dates: set[str],
    introduced_open_work: bool, thread_email: dict,
) -> bool:
    # Do not let a generic acknowledgement silently downgrade a saved task.
    # Priority is recalculated only when the newest turn actually changes active
    # work/a deadline or contains an explicit urgency signal. Overall workflow
    # Status is manual-only and therefore cannot make an email turn material.
    if introduced_open_work or replaced_due_dates:
        return True
    for update in added.get("task_updates") or []:
        if not isinstance(update, dict):
            continue
        state = str(update.get("state") or "").strip().casefold()
        if state in {"new", "updated", "completed", "cancelled", "reopened"}:
            # A genuine task update is a material active-work change even when
            # the due date itself is unchanged. Generic acknowledgements should
            # be emitted by the incremental model as ``unchanged`` and therefore
            # preserve the saved priority.
            return True

    old_priority = str(existing.get("priority") or "Low").title()
    new_priority = str(added.get("priority") or old_priority).title()
    if new_priority == old_priority:
        return False
    body = str(thread_email.get("body_text") or thread_email.get("snippet") or "").casefold()
    urgency_signal = bool(re.search(
        r"\b(?:urgent|urgently|asap|immediately|critical|high[ -]?priority|"
        r"time[ -]?sensitive|please prioritize|priority request|end of day|eod)\b",
        body,
    ))
    return urgency_signal


def _recompute_priority(
    details: list[dict], added_priority: str, thread_email: dict, *,
    existing_priority: str = "Low", material_change: bool = True,
) -> str:
    open_rows = [row for row in details if not row.get("completed") and not row.get("cancelled")]
    if not open_rows:
        return "Low"
    if not material_change:
        return str(existing_priority or "Low").title()

    due_values = [
        str(row.get("due_date") or "").strip()
        for row in open_rows if str(row.get("due_date") or "").strip()
    ]
    added_value = str(added_priority or existing_priority or "Low").title()
    if not due_values:
        return added_value

    today = date.today()
    reference = _reference_date(thread_email)
    resolved = [parsed for parsed in (_parse_due_date(value, reference) for value in due_values) if parsed is not None]
    if resolved:
        nearest = min(resolved)
        days = (nearest - today).days
        if days < 0:
            deadline_priority = "Critical"
        elif days <= 1:
            deadline_priority = "High"
        elif days <= 7:
            deadline_priority = "Medium"
        else:
            deadline_priority = "Low"
    else:
        deadline_priority = "Low"
    candidates = [deadline_priority, added_value]
    return max(candidates, key=_priority_rank)


def _ensure_initial_task_metadata(summary: dict, email: dict) -> dict:
    # Initial summaries get durable action identities immediately. Later thread
    # updates can rename/split actions without losing checkbox history.
    result = dict(summary)
    # One canonical list feeds both Summary and To-Do metadata. This final
    # provider-neutral boundary prevents model/audit variants from surviving in
    # ``action_items`` after the durable detail rows have already been cleaned.
    actions = _canonical_initial_actions(result, email)
    result["action_items"] = actions
    if not actions:
        result["task_title"] = ""
        result["deadlines"] = []
        result["priority"] = "Low"
    elif _completed_status_label(result.get("task_title", "")) or _action_introduces_unsupported_script(
        result.get("task_title", ""),
        _phase1g_effective_turn_text(str(email.get("body_text") or email.get("snippet") or "")),
    ):
        result["task_title"] = actions[0]

    raw_details = [dict(value) for value in (result.get("action_item_details") or []) if isinstance(value, dict)]
    by_action = {
        _normalized_action_key(value.get("action")): value
        for value in raw_details if str(value.get("action") or "").strip()
    }
    seed = str(email.get("canonical_thread_id") or email.get("uid") or email.get("message_id") or "email")
    details = []
    for index, action in enumerate(actions):
        detail = dict(by_action.get(_normalized_action_key(action)) or (raw_details[index] if index < len(raw_details) else {}))
        due = str(detail.get("due_date") or detail.get("deadline") or "").strip()
        details.append({
            **detail,
            "action": action,
            "action_id": str(detail.get("action_id") or _stable_action_id(seed, action, index)),
            "due_date": due,
            "deadline_state": str(detail.get("deadline_state") or ("explicit" if due else "unspecified")),
            "completed": bool(detail.get("completed")),
            "cancelled": bool(detail.get("cancelled")),
            "completion_source": str(detail.get("completion_source") or "email"),
            "cancellation_source": str(detail.get("cancellation_source") or "email"),
        })
    result["action_item_details"] = details
    # Workflow Status is user-owned. AI may describe lifecycle language in the
    # email content, but a generated summary must never silently move the task.
    # Every newly created task therefore starts at the neutral manual baseline.
    result["status"] = "Not Started"
    result["status_source"] = "manual"
    result["task_title_source"] = str(result.get("task_title_source") or "generated")
    result["task_revision"] = int(result.get("task_revision") or 0)
    result["task_change_history"] = list(result.get("task_change_history") or [])
    result["deadline_mode"] = _deadline_mode(details)
    return result


def create_summary(email: dict) -> dict:
    # Build a display-ready summary while preserving email metadata.
    attachments = [{
        "filename": item.get("filename") or "Attachment",
        "size": int(item.get("size") or 0),
        "content_type": item.get("content_type") or "application/octet-stream",
    } for item in (email.get("attachments") or [])]
    summary = {
        "uid": str(email.get("uid", "")),
        "from": email.get("from", ""),
        "to": email.get("to", ""),
        "cc": email.get("cc", ""),
        "subject": email.get("subject") or "(No Subject)",
        "date": email.get("date", ""),
        "date_display": email.get("date_display", "Unknown"),
        "snippet": email.get("snippet", ""),
        "message_id": email.get("message_id", ""),
        "attachments": attachments,
        "source_uids": list(email.get("source_uids") or [str(email.get("uid", ""))]),
        "thread_count": int(email.get("thread_count") or 1),
        "canonical_thread_id": str(email.get("canonical_thread_id") or ""),
        **summarize_email(email),
    }
    trace_summary_pipeline("SUMMARY_SERVICE_MERGED", email=email, summary=summary)
    prepared = _ensure_initial_task_metadata(summary, email)
    stamped = _stamp_new_summary(prepared)
    trace_summary_pipeline("SUMMARY_SERVICE_READY", email=email, summary=stamped)
    return stamped


def create_incremental_summary(email: dict, existing: dict) -> dict:
    # Build one new-turn summary plus structured task reconciliation metadata.
    attachments = [{
        "filename": item.get("filename") or "Attachment",
        "size": int(item.get("size") or 0),
        "content_type": item.get("content_type") or "application/octet-stream",
    } for item in (email.get("attachments") or [])]
    incremental = {
        "uid": str(email.get("uid", "")),
        "from": email.get("from", ""),
        "to": email.get("to", ""),
        "cc": email.get("cc", ""),
        "subject": email.get("subject") or "(No Subject)",
        "date": email.get("date", ""),
        "date_display": email.get("date_display", "Unknown"),
        "snippet": email.get("snippet", ""),
        "message_id": email.get("message_id", ""),
        "attachments": attachments,
        "source_uids": list(email.get("source_uids") or [str(email.get("uid", ""))]),
        "thread_count": int(email.get("thread_count") or 1),
        "canonical_thread_id": str(email.get("canonical_thread_id") or ""),
        **summarize_incremental_email(email, existing),
    }
    trace_summary_pipeline("THREAD_SUMMARY_SERVICE_MERGED", email=email, summary=incremental)
    return incremental


def _saved_action_rows(item: dict) -> list[dict]:
    # Durable detail rows are the authoritative action ledger. ``action_items``
    # is the current OPEN-work projection and may intentionally omit actions
    # closed by a later email reply. Retaining closed detail rows prevents a
    # future thread update from resurrecting cancelled/completed work.
    actions = [str(value or "").strip() for value in (item.get("action_items") or []) if str(value or "").strip()]
    raw_details = [dict(value) for value in (item.get("action_item_details") or []) if isinstance(value, dict)]
    seed = str(item.get("canonical_thread_id") or item.get("uid") or "saved")
    rows = []
    seen = set()

    for index, detail in enumerate(raw_details):
        action = str(detail.get("action") or "").strip()
        if not action:
            continue
        key = _normalized_action_key(action)
        if key in seen:
            continue
        seen.add(key)
        due = str(detail.get("due_date") or detail.get("deadline") or "").strip()
        rows.append({
            **detail,
            "action": action,
            "action_id": str(detail.get("action_id") or _stable_action_id(seed, action, index)),
            "due_date": due,
            "deadline_state": str(detail.get("deadline_state") or ("explicit" if due else "unspecified")),
            "completed": bool(detail.get("completed")),
            "cancelled": bool(detail.get("cancelled")),
            "completion_source": str(detail.get("completion_source") or "email"),
            "cancellation_source": str(detail.get("cancellation_source") or "email"),
        })

    # Compatibility for legacy rows that predate action_item_details.
    for index, action in enumerate(actions):
        key = _normalized_action_key(action)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "action": action,
            "action_id": _stable_action_id(seed, action, len(rows) + index),
            "due_date": "",
            "deadline_state": "unspecified",
            "completed": False,
            "cancelled": False,
            "completion_source": "email",
            "cancellation_source": "email",
        })
    return rows

def _collapse_thread_cancelled_action_aliases(rows: list[dict]) -> list[dict]:
    """Collapse duplicate cancelled aliases created during thread reconciliation only.

    Thread replay and incremental generation can describe the same cancelled work
    with harmless verb variants (for example, ``write`` vs ``prepare``).  The
    active projection is already correct, but keeping both aliases makes the
    durable historical ledger depend on model wording/provider order.  Collapse
    only cancelled rows that have the same saved due date and are semantically
    the same task.  Distinct sibling identities (Proposal A/B, version 3/4,
    etc.) remain separate because the shared thread identity matcher preserves
    those discriminators.  Normal/single-email summaries never call this path.
    """
    kept: list[dict] = []
    for raw in rows or []:
        row = dict(raw)
        if not bool(row.get("cancelled")):
            kept.append(row)
            continue

        due = str(row.get("due_date") or "").strip()
        duplicate_index = None
        for index, prior in enumerate(kept):
            if not bool(prior.get("cancelled")):
                continue
            if str(prior.get("due_date") or "").strip() != due:
                continue
            if _incremental_actions_semantically_same(
                str(prior.get("action") or ""),
                str(row.get("action") or ""),
            ):
                duplicate_index = index
                break

        if duplicate_index is None:
            kept.append(row)
            continue

        # Keep the older durable identity/action wording, but retain any useful
        # metadata that only exists on the later alias.  Lifecycle state stays
        # cancelled by construction.
        prior = kept[duplicate_index]
        for field in (
            "completion_source", "cancellation_source",
            "deadline_state", "reactivated_by_update",
        ):
            if not prior.get(field) and row.get(field):
                prior[field] = row.get(field)

    return kept


def _reconcile_incremental_tasks(existing: dict, added: dict) -> tuple[list[str], list[dict], set[str], bool, bool]:
    rows = _saved_action_rows(existing)
    replaced_due_dates = set()
    introduced_open_work = False
    cancelled_by_this_turn = False
    normalized_seen = {_normalized_action_key(row["action"]): index for index, row in enumerate(rows)}
    seed = str(added.get("canonical_thread_id") or added.get("uid") or existing.get("canonical_thread_id") or "incremental")

    for update_index, update in enumerate(added.get("task_updates") or []):
        if not isinstance(update, dict):
            continue
        state = str(update.get("state") or "").strip().casefold()
        index = update.get("previous_index")
        try:
            index = int(index)
        except (TypeError, ValueError):
            index = None

        if state == "new":
            action = str(update.get("action") or "").strip()
            if not action:
                continue
            key = _normalized_action_key(action)
            duplicate_index = normalized_seen.get(key)
            if duplicate_index is None:
                similar = [
                    (candidate_index, _action_similarity(action, row.get("action", "")))
                    for candidate_index, row in enumerate(rows)
                ]
                if similar:
                    best_index, best_score = max(similar, key=lambda pair: pair[1])
                    if best_score >= 0.78:
                        duplicate_index = best_index
            if duplicate_index is not None:
                existing_row = rows[duplicate_index]
                # For an already-open highly-similar action, treat model-side
                # "new" as an update to avoid duplicates. A closed historical
                # action must NOT suppress genuinely new work from the newest
                # reply; in that case fall through and append a new open row so
                # the old Completed/Cancelled history remains intact.
                if not existing_row.get("completed") and not existing_row.get("cancelled"):
                    due = str(update.get("due_date") or "").strip()
                    if due:
                        old_due = str(existing_row.get("due_date") or "").strip()
                        if old_due and old_due != due:
                            replaced_due_dates.add(old_due)
                        existing_row["due_date"] = due
                        existing_row["deadline_state"] = "explicit"
                    if _action_similarity(action, existing_row.get("action", "")) >= 0.78:
                        existing_row["action"] = action
                    normalized_seen[_normalized_action_key(existing_row["action"])] = duplicate_index
                    continue
            due = str(update.get("due_date") or "").strip()
            rows.append({
                "action": action,
                "action_id": _stable_action_id(seed, action, update_index),
                "due_date": due,
                "deadline_state": "explicit" if due else "unspecified",
                "completed": False,
                "cancelled": False,
                "completion_source": "email",
                "cancellation_source": "email",
            })
            normalized_seen[key] = len(rows) - 1
            introduced_open_work = True
            continue

        if index is None or not 0 <= index < len(rows):
            continue
        row = rows[index]
        if state == "unchanged":
            continue
        if state == "completed":
            row["completed"] = True
            row["cancelled"] = False
            row["completion_source"] = "email"
            row["cancellation_source"] = "email"
            continue
        if state == "cancelled":
            if not row.get("completed"):
                was_cancelled = bool(row.get("cancelled"))
                row["cancelled"] = True
                row["cancellation_source"] = "email"
                if not was_cancelled:
                    cancelled_by_this_turn = True
            continue
        if state == "reassigned":
            # Recipient ownership ended, but the underlying work still exists
            # under another named owner. Represent it as an inactive durable
            # row without treating the turn as a cancellation of all work; that
            # distinction prevents the cancelled-snapshot UI from keeping the
            # reassigned task in the user's live Action Items/To-Do.
            if not row.get("completed"):
                row["cancelled"] = True
                row["cancellation_source"] = "reassigned"
            continue

        if state in {"updated", "reopened"}:
            old_action = str(row.get("action") or "").strip()
            old_key = _normalized_action_key(old_action)
            latest_action = str(update.get("action") or "").strip()
            action_changed = bool(
                latest_action
                and _normalized_action_key(latest_action) != old_key
            )
            if latest_action:
                row["action"] = latest_action
                normalized_seen.pop(old_key, None)
                normalized_seen[_normalized_action_key(latest_action)] = index
            if bool(update.get("due_date_changed")):
                old_due = str(row.get("due_date") or "").strip()
                new_due = str(update.get("due_date") or "").strip()
                if old_due and old_due != new_due:
                    replaced_due_dates.add(old_due)
                row["due_date"] = new_due
                row["deadline_state"] = "explicit" if new_due else "none"

            # Durable completion belongs to the exact work the user completed.
            # If a later reply materially changes that same action, only that
            # action becomes open again; unrelated completed actions keep their
            # progress. A deadline-only update does not reopen completed work.
            materially_updated_closed_action = (
                state == "updated"
                and action_changed
                and (bool(row.get("completed")) or bool(row.get("cancelled")))
            )
            if state == "reopened" or materially_updated_closed_action:
                row["completed"] = False
                row["cancelled"] = False
                row["completion_source"] = "email_update" if materially_updated_closed_action else "email"
                row["cancellation_source"] = "email_update" if materially_updated_closed_action else "email"
                row["reactivated_by_update"] = bool(materially_updated_closed_action)
                introduced_open_work = True

    global_deadline = str(added.get("_global_deadline") or "").strip()
    global_deadline_removed = bool(added.get("_global_deadline_removed"))
    if global_deadline or global_deadline_removed:
        for row in rows:
            if row.get("cancelled") or row.get("completed"):
                continue
            old_due = str(row.get("due_date") or "").strip()
            new_due = "" if global_deadline_removed else global_deadline
            if old_due == new_due:
                continue
            if old_due:
                replaced_due_dates.add(old_due)
            row["due_date"] = new_due
            row["deadline_state"] = "none" if global_deadline_removed else "explicit"

    # Thread-only deterministic history normalization: a cancellation may be
    # paraphrased into multiple aliases by different replay/provider passes.
    # Collapse those aliases before projecting current actions/history.
    rows = _collapse_thread_cancelled_action_aliases(rows)

    active_rows = [row for row in rows if not row.get("cancelled")]
    open_rows = [row for row in active_rows if not row.get("completed")]
    completed_rows = [row for row in active_rows if row.get("completed")]
    # Per-action cancellation is email content, not authority over the user's
    # workflow Status. The saved manual Status is consulted only to preserve the
    # display snapshot of a task the user already marked Cancelled.
    old_status = normalize_task_status(existing.get("status"))
    cancelled_all_work_by_email = bool(rows) and not open_rows and cancelled_by_this_turn
    cancelled_snapshot = bool(rows) and not open_rows and (
        old_status == "Cancelled" or cancelled_all_work_by_email
    )

    # Keep the cancelled task's last action snapshot visible for history, just
    # like a task cancelled manually in To-Do. For partial cancellation, only
    # still-current open work remains in the live Summary; the cancelled detail
    # rows stay durable in action_item_details/Recent Activity.
    if cancelled_snapshot:
        actions = [row["action"] for row in rows if row.get("action")]
    else:
        actions = [
            row["action"] for row in rows
            if row.get("action") and not row.get("completed") and not row.get("cancelled")
        ]
    details = [
        {
            "action": row["action"],
            "action_id": str(row.get("action_id") or ""),
            "due_date": str(row.get("due_date") or ""),
            "deadline_state": str(row.get("deadline_state") or "unspecified"),
            "completed": bool(row.get("completed")),
            "cancelled": bool(row.get("cancelled")),
            "completion_source": str(row.get("completion_source") or "email"),
            "cancellation_source": str(row.get("cancellation_source") or "email"),
            "reactivated_by_update": bool(row.get("reactivated_by_update")),
        }
        for row in rows if row.get("action")
    ]
    return actions, details, replaced_due_dates, introduced_open_work, cancelled_all_work_by_email


def _clean_incremental_key_point(value: str, thread_subject: str = "") -> str:
    """Remove reader/LLM wrapper text from one current Key Point only.

    This is deliberately field-local: it does not rewrite Summary text, task
    rows, Recent Activity, provider content, or stored thread bodies.
    """
    point = re.sub(r"\s+", " ", str(value or "")).strip(" \t\r\n-–—:;,.\"'")
    if not point:
        return ""

    subject = re.sub(
        r"^(?:(?:re|fw|fwd)\s*:\s*)+",
        "",
        str(thread_subject or "").strip(),
        flags=re.IGNORECASE,
    ).strip(" \t\r\n-–—:;,.\"'")
    if subject and point.casefold() == subject.casefold():
        return ""

    # Keep the fact after a generic delta wrapper, never the wrapper itself.
    point = re.sub(
        r"^(?:latest\s+)?(?:thread\s+)?update(?:\s+for\s+(?:this|the)\s+thread)?\s*:\s*",
        "",
        point,
        flags=re.IGNORECASE,
    ).strip(" \t\r\n-–—:;,.\"'")
    return point


def _thread_keypoint_is_quoted_history_artifact(value: str) -> bool:
    """Reject provider reply-history wrapper text from current thread Key Points.

    Incremental provider bodies can flatten a reply delimiter and part of the
    quoted message into one model Key Point (for example ``On ... wrote: ...``).
    That text is useful as thread history, but it is never a current-state fact.
    Keep this guard thread-only so normal/single-email Key Point behavior remains
    unchanged.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return False
    return bool(re.match(
        r"^(?:on\s+.+?\s+wrote\s*:|from\s*:|sent\s*:|to\s*:|cc\s*:|"
        r"subject\s*:|-{2,}\s*(?:original|forwarded)\s+message(?:\s*-{2,})?)",
        text, flags=re.IGNORECASE,
    ))


def _thread_recipient_assignment_summary_cleanup(
    candidate: str, thread_email: dict, details: list[dict]
) -> str:
    """Remove stale no-action prose after work is explicitly assigned to the recipient.

    The incremental LLM/field validator operates before durable task reconciliation,
    so a reply that transfers ownership *to the recipient* can temporarily carry
    forward an earlier ``No action is required`` sentence even though reconciliation
    correctly creates an active recipient Action Item.  Repair that contradiction
    only when the newest authored turn explicitly assigns ownership/work to ``you``
    and the reconciled ledger contains open work.  Normal/single-email summaries and
    third-party reassignment summaries never pass through this helper.
    """
    text = re.sub(r"\s+", " ", str(candidate or "")).strip()
    latest = _incremental_current_turn_text(thread_email)
    if not text or not latest:
        return text

    has_open_work = any(
        isinstance(row, dict)
        and str(row.get("action") or "").strip()
        and not bool(row.get("completed"))
        and not bool(row.get("cancelled"))
        for row in (details or [])
    )
    if not has_open_work:
        return text

    assignment_to_recipient = bool(re.search(
        r"\b(?:"
        r"(?:reassigned|assigned|transferred|handed\s+off)\s+(?:this\s+)?(?:task|work|item|request)?\s*to\s+you|"
        r"(?:this\s+)?(?:task|work|item|request)\s+is\s+now\s+assigned\s+to\s+you|"
        r"ownership\s+(?:is\s+)?(?:now\s+)?(?:transferred|assigned|moved|given)\s+to\s+you|"
        r"you\s+(?:now\s+)?(?:own|owning|are\s+responsible\s+for|will\s+take\s+over|take\s+over)\b|"
        r"(?:this\s+)?(?:task|work|item|request)\s+is\s+now\s+yours"
        r")",
        latest, flags=re.IGNORECASE,
    ))
    if not assignment_to_recipient:
        return text

    # Remove only complete no-action sentences/clauses; preserve the ownership
    # transfer and deadline/current-state content generated by the model.
    no_action_sentence = re.compile(
        r"(?:^|(?<=[.!?])\s+)"
        r"(?:no\s+(?:further\s+|other\s+)?action\s+(?:is\s+)?required(?:\s+from\s+you)?|"
        r"no\s+action\s+(?:is\s+)?required\s+from\s+you)"
        r"(?=\s*(?:[.!?](?:\s|$)|$))\s*[.!?]?\s*",
        flags=re.IGNORECASE,
    )
    cleaned = no_action_sentence.sub(" ", text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .")
    if cleaned:
        return cleaned + ("." if text.endswith(".") else "")
    return text


def _thread_keypoint_is_action_restatement(point: str, actions) -> bool:
    """Thread-only guard for lifecycle/deadline wording around an Action Item.

    Normal single-email Key Point validation is deliberately untouched. A
    thread delta may phrase task state as "Reopen X...", "X done", or
    "X cancelled". Those are lifecycle facts already represented by the
    durable Action Item row, not independent Key Points.
    """
    text = re.sub(r"\s+", " ", str(point or "")).strip()
    if not text:
        return False
    if _phase1b_keypoint_is_action_restatement(text, actions):
        return True

    lifecycle_wording = bool(re.search(
        r"\b(?:reopen|re-open|reopened|resume|resumed|restart|redo|repeat|"
        r"done|complete|completed|finished|approved|cancelled|canceled|"
        r"no\s+longer\s+(?:needed|required))\b",
        text, flags=re.IGNORECASE,
    ))
    if not lifecycle_wording:
        return False

    def payload_terms(value: str) -> set[str]:
        marker_terms = {
            f"marker:{match.group(1).casefold()}:{match.group(2).casefold()}"
            for match in re.finditer(
                r"\b(proposal|option|variant|phase|version|revision|rev|draft)\s+"
                r"([A-Za-z0-9][A-Za-z0-9._-]{0,15})\b",
                value, flags=re.IGNORECASE,
            )
        }
        value = re.sub(r"\b20\d{2}-\d{2}-\d{2}(?:[T\s]+\d{1,2}:\d{2}(?::\d{2})?)?\b", " ", value)
        value = re.sub(r"\b\d{1,2}(?::\d{2})?\s*(?:am|pm)\b", " ", value, flags=re.IGNORECASE)
        ignored = {
            "a", "an", "and", "at", "be", "before", "by",
            "approve", "approved", "cancel", "cancelled", "canceled",
            "complete", "completed", "confirm", "done", "deadline", "due",
            "finish", "finished", "for", "it", "new", "needed", "on",
            "please", "prepare", "provide", "reopen", "reopened", "required",
            "restart", "resume", "resumed", "redo", "repeat", "review",
            "send", "submit", "the", "this", "that", "to", "updated",
            "upload", "again", "is", "was", "with", "of", "request",
            "task", "action", "no", "longer",
        }
        return marker_terms | {
            token for token in re.findall(r"[a-z0-9]+", value.casefold())
            if token and token not in ignored
        }

    point_terms = payload_terms(text)
    if not point_terms:
        return False
    for action in actions or []:
        action_terms = payload_terms(str(action or ""))
        if action_terms and point_terms == action_terms:
            return True
    return False


def _thread_keypoint_is_event_schedule_restatement(point: str, summary_text: str) -> bool:
    """Drop a thread-only event-schedule fact already stated in Summary.

    Incremental LLM passes can sometimes emit a Key Point such as "Meeting date
    is now 2026-09-18" even when the same current event date/time is already
    fully present in the merged Summary.  That creates provider/cold-vs-live
    variance without adding information.  Keep the guard intentionally narrow:
    it only applies to event scheduling language (meeting/call/session/etc.),
    requires an explicit ISO date in the Key Point, and requires that same date
    plus the same event identity be present in Summary.  Task/deadline change
    Key Points (for example version delivery changes) and non-schedule facts are
    left untouched.
    """
    text = re.sub(r"\s+", " ", str(point or "")).strip()
    summary = re.sub(r"\s+", " ", str(summary_text or "")).strip()
    if not text or not summary:
        return False

    dates = set(re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", text))
    if not dates or not any(date in summary for date in dates):
        return False

    event_pattern = re.compile(
        r"\b(?:meeting|call|session|appointment|interview|conference|presentation|"
        r"workshop|webinar|hearing|demo)\b",
        flags=re.IGNORECASE,
    )
    if not event_pattern.search(text):
        return False
    if not re.search(
        r"\b(?:date|time|schedule|scheduled|rescheduled|set|confirmed|now)\b",
        text, flags=re.IGNORECASE,
    ):
        return False

    # Require overlap on the event phrase itself, not just on the date.  This
    # prevents an unrelated event Key Point from being removed merely because
    # two facts happen to share a calendar date.
    event_terms = {
        token for token in re.findall(r"[a-z0-9]+", text.casefold())
        if token in {
            "meeting", "call", "session", "appointment", "interview",
            "conference", "presentation", "workshop", "webinar", "hearing", "demo",
            "steering", "project", "customer", "client", "team", "review",
        }
    }
    summary_terms = set(re.findall(r"[a-z0-9]+", summary.casefold()))
    core_events = {
        "meeting", "call", "session", "appointment", "interview",
        "conference", "presentation", "workshop", "webinar", "hearing", "demo",
    }
    if not (event_terms & core_events & summary_terms):
        return False

    # Scheduling-only Key Points may contain connective/status words but should
    # not carry an independent factual payload absent from Summary.
    ignored = {
        "a", "an", "and", "at", "by", "date", "is", "now", "of", "on", "the",
        "time", "to", "set", "scheduled", "schedule", "rescheduled", "confirmed",
        "for", "has", "been", "will", "be",
    }
    payload = {
        token for token in re.findall(r"[a-z0-9]+", text.casefold())
        if token not in ignored and not re.fullmatch(r"20\d{2}|\d{1,2}", token)
    }
    return payload.issubset(summary_terms | core_events)


def _thread_keypoint_is_deadline_state_restatement(point: str, actions) -> bool:
    """Drop thread-only deadline-state prose already carried by an Action row.

    Incremental model passes may promote phrases such as "no separate fixed
    deadline for reading" into Key Points even though deadline state belongs to
    the durable action/deadline projection.  Keeping that prose makes Cold and
    Incremental/provider output depend on model wording rather than current
    thread state.  This guard is intentionally narrow and does not touch normal
    single-email summaries or independent date/context facts.
    """
    text = re.sub(r"\s+", " ", str(point or "")).strip()
    if not text or not (actions or []):
        return False
    if not re.search(
        r"\b(?:no|without)\s+(?:a\s+)?(?:separate\s+)?(?:fixed|explicit)?\s*deadline\b|"
        r"\bdeadline\s+(?:is\s+)?(?:not\s+fixed|unspecified|tbd|to\s+be\s+determined)\b",
        text, flags=re.IGNORECASE,
    ):
        return False

    ignored = {
        "a", "an", "and", "for", "fixed", "explicit", "deadline", "is", "no",
        "not", "separate", "the", "to", "without", "unspecified", "tbd", "be",
        "determined", "of", "on", "by", "reading", "reviewing",
    }
    point_terms = {
        token for token in re.findall(r"[a-z0-9]+", text.casefold())
        if token not in ignored
    }
    if not point_terms:
        # A generic "no fixed deadline" statement is itself structured task
        # metadata when the thread has active work; it is not an independent
        # contextual fact.
        return True

    for action in actions or []:
        action_terms = {
            token for token in re.findall(r"[a-z0-9]+", str(action or "").casefold())
            if token not in {"a", "an", "and", "for", "the", "to", "please"}
        }
        if action_terms and (point_terms & action_terms):
            return True
    return False


def _thread_source_clauses(thread_email: dict) -> list[str]:
    """Return authored thread clauses in chronological order, excluding quotes.

    Only narrow deterministic recovery helpers consume this.  We intentionally
    do not feed these clauses back through the general Summary extractor.
    """
    turns = [dict(item) for item in (thread_email.get("thread_messages") or []) if isinstance(item, dict)]
    if not turns:
        body = str(thread_email.get("body_text") or thread_email.get("snippet") or "").strip()
        turns = [{"body_text": body}] if body else []

    result: list[str] = []
    for turn in turns:
        body = str(turn.get("body_text") or turn.get("snippet") or "")
        if not body:
            continue
        # Quoted history is lifecycle evidence only when explicitly processed by
        # the threading layer; never recover Key Points from quote/footer lines.
        authored_lines = []
        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(">"):
                continue
            if re.match(r"^(?:on\s+.+wrote:|from:|sent:|to:|subject:|-{2,}\s*(?:original|forwarded))", line, flags=re.IGNORECASE):
                continue
            authored_lines.append(line)
        authored = " ".join(authored_lines)
        for clause in re.split(r"(?<=[.!?])\s+|[;]+", authored):
            clean = re.sub(r"\s+", " ", clause).strip(" \t\r\n-–—:;,.")
            if clean:
                result.append(clean)
    return result


def _constraint_tokens(value: str) -> set[str]:
    ignored = {
        "a", "an", "and", "any", "are", "as", "at", "be", "before", "by",
        "cannot", "for", "from", "is", "it", "must", "of", "on", "or", "required",
        "the", "to", "until", "without", "will", "need", "needs", "needed",
    }
    tokens = set()
    for token in re.findall(r"[a-z0-9]+", str(value or "").casefold()):
        if token in ignored:
            continue
        if len(token) > 4 and token.endswith("s"):
            token = token[:-1]
        tokens.add(token)
    return tokens


def _looks_like_prerequisite_constraint(value: str) -> bool:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text or re.match(r"^(?:please|kindly)\b", text, flags=re.IGNORECASE):
        return False
    return bool(
        re.search(r"\b(?:is|are)\s+(?:still\s+)?required\s+before\b", text, flags=re.IGNORECASE)
        or re.search(r"\bcannot\b.+\b(?:until|without)\b", text, flags=re.IGNORECASE)
        or re.search(r"\bmust\b.+\bbefore\b", text, flags=re.IGNORECASE)
        or re.search(r"\b(?:depends?|dependent)\s+on\b", text, flags=re.IGNORECASE)
        or re.search(r"\bprerequisite\b", text, flags=re.IGNORECASE)
    )


def _looks_like_context_location(value: str) -> bool:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text or re.match(r"^(?:please|kindly)\b", text, flags=re.IGNORECASE):
        return False
    return bool(re.search(
        r"\b(?:meeting|call|session|appointment|interview|conference|presentation|"
        r"workshop|webinar|hearing|demo|event)?\s*location\s+(?:is|remains|will\s+be)\b",
        text, flags=re.IGNORECASE,
    ))


def _canonicalize_thread_source_key_points(points, thread_email: dict, actions) -> tuple[list[str], list[str]]:
    """Stabilize a narrow set of source-grounded thread context facts.

    Cold reconstruction and a later Incremental pass can disagree on whether a
    prerequisite or event-location fact deserves a Key Point.  These facts are
    deterministic in the authored source and are independent from action/deadline
    state, so recover a canonical source clause rather than trusting a random
    model paraphrase.  Stale lifecycle/deadline prose remains handled elsewhere.
    """
    current = [str(value or "").strip() for value in (points or []) if str(value or "").strip()]
    source_candidates: list[str] = []
    for clause in _thread_source_clauses(thread_email):
        # These two grammars are declarative context by construction.  Do not
        # reuse the broad action-restatement heuristic here: phrases such as
        # "Legal review is required before ..." legitimately contain an action
        # verb while describing a process prerequisite rather than recipient work.
        if _looks_like_prerequisite_constraint(clause) or _looks_like_context_location(clause):
            source_candidates.append(clause)
    source_candidates = list(dict.fromkeys(source_candidates))
    if not source_candidates:
        return current, []

    recovered: list[str] = []
    for canonical in source_candidates:
        canonical_terms = _constraint_tokens(canonical)
        best_index = None
        best_score = 0.0
        canonical_kind_prereq = _looks_like_prerequisite_constraint(canonical)
        canonical_kind_location = _looks_like_context_location(canonical)
        for index, point in enumerate(current):
            same_kind = (
                canonical_kind_prereq and _looks_like_prerequisite_constraint(point)
            ) or (
                canonical_kind_location and _looks_like_context_location(point)
            )
            if not same_kind:
                continue
            point_terms = _constraint_tokens(point)
            overlap = len(canonical_terms & point_terms) / max(1, min(len(canonical_terms), len(point_terms)))
            if overlap > best_score:
                best_index, best_score = index, overlap
        if best_index is not None and best_score >= 0.34:
            if current[best_index].casefold() != canonical.casefold():
                current[best_index] = canonical
                recovered.append(canonical)
            continue
        current.append(canonical)
        recovered.append(canonical)

    return list(dict.fromkeys(current)), list(dict.fromkeys(recovered))


def _recover_thread_unchanged_value_key_points(points, thread_email: dict, actions) -> tuple[list[str], list[str]]:
    """Recover source-grounded unchanged quantitative facts on the newest turn.

    Thread reconstruction and incremental generation can phrase the same stable
    fact differently—or one LLM pass can omit it entirely. When the newest
    authored turn explicitly says a quantitative fact is unchanged, preserve
    that fact as a current Key Point in both paths.

    The guard is intentionally narrow: it requires an unchanged/same-state cue
    plus a currency or percentage value, rejects deadline/date clauses, and
    never promotes Action Item lifecycle wording into Key Points.
    """
    latest = _incremental_current_turn_text(thread_email)
    current = [str(value or "").strip() for value in (points or []) if str(value or "").strip()]
    if not latest:
        return current, []

    clauses = [
        re.sub(r"\s+", " ", clause).strip(" \t\r\n-–—:;,.")
        for clause in re.split(r"(?:[;\n]+|(?<=[.!?])\s+)", latest)
    ]
    recovered: list[str] = []
    for clause in clauses:
        if not clause:
            continue
        if not re.search(
            r"\b(?:unchanged|remains?\s+(?:the\s+)?same|is\s+(?:still\s+)?the\s+same|"
            r"stays?\s+(?:the\s+)?same)\b",
            clause, flags=re.IGNORECASE,
        ):
            continue
        if not re.search(r"(?:[$€£]\s*\d|\b\d+(?:[.,]\d+)?\s*%)", clause):
            continue
        if re.search(r"\b(?:deadline|due|by\s+20\d{2}-\d{2}-\d{2})\b", clause, flags=re.IGNORECASE):
            continue
        if _thread_keypoint_is_action_restatement(clause, actions):
            continue

        # Normalize the common source form "the $18,400 quote amount is
        # unchanged" into a fact-first Key Point. This is generic to any
        # currency/percentage value and noun phrase, not tied to a test case.
        leading_value = re.match(
            r"^(?:the\s+)?(?P<value>(?:[$€£]\s*\d[\d,]*(?:\.\d+)?|"
            r"\d+(?:[.,]\d+)?\s*%))\s+"
            r"(?P<label>[A-Za-z][A-Za-z0-9 /_\-]{1,80}?)\s+"
            r"(?:is|remains?)\s+unchanged$",
            clause, flags=re.IGNORECASE,
        )
        if leading_value:
            label = re.sub(r"\s+", " ", leading_value.group("label")).strip()
            value = re.sub(r"\s+", "", leading_value.group("value")).strip()
            clause = f"{label[:1].upper() + label[1:]} remains {value}"

        def _same_stable_value_fact(left: str, right: str) -> bool:
            def values(value: str) -> set[str]:
                return {
                    re.sub(r"[^0-9.%]", "", match.group(0))
                    for match in re.finditer(
                        r"(?:[$€£]\s*\d[\d,]*(?:\.\d+)?|\b\d+(?:[.,]\d+)?\s*%)",
                        value,
                    )
                }
            left_values = values(left)
            right_values = values(right)
            if not (left_values & right_values):
                return False
            ignored = {
                "a", "an", "at", "is", "the", "this", "that", "remains",
                "remain", "unchanged", "same", "still", "stays", "stay",
                "value", "amount",  # "amount" alone is too generic.
            }
            left_terms = {
                token for token in re.findall(r"[a-z]+", left.casefold())
                if token not in ignored
            }
            right_terms = {
                token for token in re.findall(r"[a-z]+", right.casefold())
                if token not in ignored
            }
            return bool(left_terms & right_terms)

        if any(
            _action_similarity(clause, prior) >= 0.68
            or _same_stable_value_fact(clause, prior)
            for prior in current
        ):
            continue

        current.append(clause)
        recovered.append(clause)

    return list(dict.fromkeys(current)), list(dict.fromkeys(recovered))


def _reconcile_incremental_key_points(existing_points, added_points) -> tuple[list[str], list[str], list[dict]]:
    # Key-point deltas follow the same user-facing rule as task updates:
    # genuinely added facts append to the current list, while a reworded/updated
    # version of the same fact replaces only that specific prior point.
    current = [str(value or "").strip() for value in (existing_points or []) if str(value or "").strip()]
    changed: list[str] = []
    changes: list[dict] = []
    for raw in added_points or []:
        point = str(raw or "").strip()
        if not point:
            continue
        exact = next((i for i, value in enumerate(current) if value.casefold() == point.casefold()), None)
        if exact is not None:
            continue
        best_index = None
        best_score = 0.0
        for index, value in enumerate(current):
            score = _action_similarity(point, value)
            if score > best_score:
                best_index, best_score = index, score
        # A strong semantic/text overlap means the newest point is an update to
        # one existing fact. Lower-overlap points are genuinely additive.
        if best_index is not None and best_score >= 0.72:
            old_value = current[best_index]
            current[best_index] = point
            changes.append({"type": "key_point_updated", "from": old_value, "to": point})
        else:
            current.append(point)
            changes.append({"type": "key_point_added", "to": point})
        changed.append(point)
    return current, list(dict.fromkeys(changed)), changes



def _thread_quantitative_value_tokens(value: str) -> set[str]:
    """Return stable numeric/currency/percentage identities from one fact string."""
    tokens: set[str] = set()
    for match in re.finditer(
        r"(?:[$€£]\s*\d[\d,]*(?:\.\d+)?|\b\d+(?:[.,]\d+)?\s*%)",
        str(value or ""),
    ):
        token = re.sub(r"\s+|,", "", match.group(0)).casefold()
        if token:
            tokens.add(token)
    return tokens


def _thread_correction_replacements(latest: str) -> list[tuple[str, str, set[str]]]:
    """Extract explicit newest-turn quantitative replacements.

    Each tuple is ``(old_value, new_value, topic_tokens)``.  This is intentionally
    thread/current-state only: it requires explicit correction/replacement grammar,
    so an email that merely mentions two amounts does not invalidate either fact.
    """
    text = re.sub(r"\s+", " ", str(latest or "")).strip()
    if not text:
        return []

    value = r"(?:[$€£]\s*\d[\d,]*(?:\.\d+)?|\b\d+(?:[.,]\d+)?\s*%)"
    patterns = (
        rf"(?P<new>{value})\s+(?:instead\s+of|rather\s+than)\s+(?P<old>{value})",
        rf"(?P<new>{value})\s*,?\s*not\s+(?P<old>{value})",
        rf"(?:change(?:d)?|update(?:d)?|revise(?:d)?|correct(?:ed)?)\s+from\s+(?P<old>{value})\s+to\s+(?P<new>{value})",
        rf"replace\s+(?P<old>{value})\s+with\s+(?P<new>{value})",
    )
    stop = {
        "a", "an", "and", "are", "as", "at", "be", "by", "change", "changed",
        "correction", "corrected", "for", "from", "instead", "is", "new", "not",
        "of", "old", "on", "rather", "replace", "replaced", "revised", "revision",
        "same", "than", "the", "this", "to", "update", "updated", "use", "using",
        "value", "amount", "with",
    }
    replacements: list[tuple[str, str, set[str]]] = []
    for sentence in re.split(r"(?<=[.!?])\s+|[\r\n]+", text):
        sentence = sentence.strip()
        if not sentence:
            continue
        for pattern in patterns:
            for match in re.finditer(pattern, sentence, flags=re.IGNORECASE):
                old_value = re.sub(r"\s+|,", "", match.group("old")).casefold()
                new_value = re.sub(r"\s+|,", "", match.group("new")).casefold()
                if not old_value or not new_value or old_value == new_value:
                    continue
                topic_tokens = {
                    token for token in re.findall(r"[a-z]+", sentence.casefold())
                    if len(token) >= 3 and token not in stop
                }
                replacements.append((old_value, new_value, topic_tokens))
    return replacements


def _prune_thread_stale_key_points(points, thread_email: dict) -> list[str]:
    """Remove narrow current-state facts explicitly superseded by the newest turn.

    This is thread-only reconciliation and never rewrites normal single-email Key
    Points.  Two source-proven stale shapes are handled: an old unscheduled-state
    fact after a later schedule is supplied, and an old quantitative value after
    the newest authored turn explicitly replaces it with another value.  The
    correction Key Point itself is retained because it documents the current value
    and its provenance; only the separate stale prior-value bullet is removed.
    """
    latest = _incremental_current_turn_text(thread_email)
    current = [str(value or "").strip() for value in (points or []) if str(value or "").strip()]
    if not latest:
        return current

    latest_tokens = set(re.findall(r"[a-z0-9]+", latest.casefold()))
    # Reconcile against the authored thread history, not only the newest turn.
    # This self-heals a stale value bullet that may already have been persisted
    # before this guard existed, while keeping quote/footer text excluded.
    authored_history = ". ".join(_thread_source_clauses(thread_email)) or latest
    replacements = _thread_correction_replacements(authored_history)
    has_concrete_schedule = bool(re.search(r"\b20\d{2}-\d{2}-\d{2}\b", latest))
    result = []
    for point in current:
        point_tokens = set(re.findall(r"[a-z0-9]+", point.casefold()))

        stale_schedule = has_concrete_schedule and bool(re.search(
            r"\b(?:not\s+(?:yet\s+)?scheduled|date\s+(?:is\s+)?not\s+scheduled|"
            r"no\s+(?:scheduled|confirmed)\s+(?:meeting\s+)?(?:date|time|schedule)|"
            r"no\s+(?:meeting\s+)?(?:date|time|schedule)\s+(?:is\s+)?(?:scheduled|confirmed)|"
            r"schedule\s+(?:is\s+)?(?:tbd|unknown)|date\s+(?:is\s+)?(?:tbd|unknown)|"
            r"not\s+(?:yet\s+)?confirmed)\b",
            point, flags=re.IGNORECASE,
        ))
        if stale_schedule:
            shared = (point_tokens & latest_tokens) - {
                "date", "time", "scheduled", "schedule", "not", "yet", "is",
                "the", "a", "an", "on", "at", "for", "remains", "remain",
            }
            if shared:
                continue

        point_values = _thread_quantitative_value_tokens(point)
        stale_replaced_value = False
        for replacement_index, (old_value, new_value, topic_tokens) in enumerate(replacements):
            if old_value not in point_values or new_value in point_values:
                continue
            # Require shared business/topic wording when available.  This keeps a
            # correction to one amount from deleting an unrelated old-value fact
            # elsewhere in the same thread.
            if topic_tokens and not (topic_tokens & point_tokens):
                continue
            # A later explicit correction can legitimately restore an earlier
            # value (A -> B -> A).  In that case the earlier A is current again
            # and must not be pruned merely because it was once superseded.
            restored_later = any(
                later_new == old_value
                and (
                    not topic_tokens
                    or not later_topic
                    or bool(topic_tokens & later_topic)
                )
                for _, later_new, later_topic in replacements[replacement_index + 1:]
            )
            if restored_later:
                continue
            stale_replaced_value = True
            break
        if stale_replaced_value:
            continue

        result.append(point)
    return result




def _prune_thread_superseded_ownership_key_points(
    points, thread_email: dict, details: list[dict]
) -> list[str]:
    """Drop stale current-owner Key Points after an explicit thread handoff.

    This is intentionally thread-only.  A previous provider turn can persist a
    compact fact such as ``Alex is responsible``.  If a later authored reply
    explicitly transfers that same work away from Alex (to the recipient or to
    another named person), ordinary semantic Key-Point reconciliation may keep
    both facts because the new handoff sentence has little textual overlap with
    the old compact owner fact.  Remove only the superseded owner assertion;
    retain the handoff fact itself and any unrelated ownership facts.

    Generic owner-only bullets are pruned only when the reconciled ledger has a
    single task identity, so multi-task threads are never guessed.  Topic-bearing
    owner bullets additionally require overlap with the transferred task.
    """
    latest = _incremental_current_turn_text(thread_email)
    current = [str(value or "").strip() for value in (points or []) if str(value or "").strip()]
    if not latest or not current:
        return current

    name = r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2}"
    # Provider replies are often soft-wrapped inside one authored sentence
    # (for example ``take over the quarterly review\nfrom Alex``).  Ownership
    # evidence must treat those visual line wraps as whitespace; otherwise the
    # handoff verb and ``from <old owner>`` land in different fragments and the
    # prior owner Key Point survives.  Fold only inside this thread-specific
    # ownership reconciler instead of changing the global sentence parser.
    folded_latest = re.sub(r"[ \t]*[\r\n]+[ \t]*", " ", latest).strip()
    transfer_sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", folded_latest)
        if part.strip()
    ]

    evidence: list[tuple[str, str]] = []
    patterns = (
        re.compile(
            rf"(?i:\b(?:take|takes|taking|took)\s+over\b).*?"
            rf"(?i:\bfrom\b)\s+(?P<old>{name}|you|the\s+recipient)\b"
        ),
        re.compile(
            rf"(?i:\b(?:ownership|task|work|item|request)\b).*?"
            rf"(?i:\b(?:reassigned|assigned|transferred|handed\s+off|moved)\b).*?"
            rf"(?i:\bfrom\b)\s+(?P<old>{name}|you|the\s+recipient)\b"
        ),
        re.compile(
            rf"(?i:\bfrom\b)\s+(?P<old>{name}|you|the\s+recipient)\s+"
            rf"(?i:\bto\b)\s+(?:{name}|you|the\s+recipient)\b"
        ),
        re.compile(
            rf"(?i:\b(?:owns?|ownership|responsible|assigned|take\s+over)\b).*?"
            rf"(?i:\binstead\s+of\b)\s+(?P<old>{name}|you|the\s+recipient)\b"
        ),
    )
    for sentence in transfer_sentences:
        if not re.search(
            r"\b(?:ownership|own|owns|responsible|assigned|reassigned|transferred|"
            r"handed\s+off|take\s+over|takes\s+over|taking\s+over|moved)\b",
            sentence,
            flags=re.IGNORECASE,
        ):
            continue
        for pattern in patterns:
            match = pattern.search(sentence)
            if not match:
                continue
            old_owner = re.sub(r"\s+", " ", str(match.group("old") or "")).strip()
            if old_owner:
                evidence.append((old_owner, sentence))
                break
    if not evidence:
        return current

    # If the newest turn explicitly says the old owner still owns/is responsible
    # for something, an owner-only prior bullet is ambiguous and must be kept.
    def _latest_keeps_owner(owner: str) -> bool:
        alias = r"(?:you|the\s+recipient)" if owner.casefold() in {"you", "the recipient"} else re.escape(owner)
        return bool(re.search(
            rf"\b{alias}\b[^.!?]{{0,80}}\b(?:still|remains?|continues?\s+to)\b"
            rf"[^.!?]{{0,40}}\b(?:owns?|owner|responsible|assigned)\b|"
            rf"\b(?:still|remains?)\b[^.!?]{{0,40}}\b{alias}\b"
            rf"[^.!?]{{0,40}}\b(?:owns?|owner|responsible|assigned)\b",
            latest,
            flags=re.IGNORECASE,
        ))

    active_or_inactive_tasks = [
        str(row.get("action") or "").strip()
        for row in (details or [])
        if isinstance(row, dict) and str(row.get("action") or "").strip()
    ]
    task_identities = {
        _normalized_action_key(action) for action in active_or_inactive_tasks if _normalized_action_key(action)
    }
    single_task_context = len(task_identities) == 1

    ignored = {
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has",
        "is", "it", "now", "of", "on", "or", "the", "this", "to", "will", "with",
        "owner", "owns", "ownership", "responsible", "responsibility", "assignee",
        "assigned", "reassigned", "transferred", "moved", "handoff", "handed", "off",
        "take", "takes", "taking", "over",
        "instead", "recipient", "you", "your", "task", "work", "item", "request",
    }

    def _terms(value: str, owner: str) -> set[str]:
        text = re.sub(re.escape(owner), " ", str(value or ""), flags=re.IGNORECASE)
        return {
            token for token in re.findall(r"[a-z0-9]+", text.casefold())
            if len(token) >= 3 and token not in ignored
        }

    def _asserts_current_ownership(point: str, owner: str) -> bool:
        text = re.sub(r"\s+", " ", str(point or "")).strip()
        if not text:
            return False
        if owner.casefold() in {"you", "the recipient"}:
            owner_pattern = r"(?:you|the\s+recipient|recipient)"
        else:
            owner_pattern = re.escape(owner)
        return bool(re.search(
            rf"(?:^|\b){owner_pattern}\b[^.!?]{{0,80}}"
            rf"\b(?:owns?|is\s+(?:the\s+)?owner|is\s+responsible|"
            rf"remains?\s+responsible|assigned\s+to|will\s+handle|will\s+own|"
            rf"will\s+(?:now\s+)?take\s+over|takes?\s+over)\b|"
            rf"\b(?:owner|responsible\s+party|assignee)\s*[:=-]\s*{owner_pattern}\b|"
            # Provider/model aliases can put the state verb before the owner
            # (``Ownership transferred to the recipient``, or ``Task assigned to
            # <named owner>``). Treat those as current-owner assertions too so a later
            # explicit handoff can retire them instead of leaving stale history
            # beside the new owner.  This stays inside thread-only reconciliation.
            rf"\b(?:ownership|responsibility|assignee|task|work|item|request)\b"
            rf"[^.!?]{{0,70}}\b(?:assigned|reassigned|transferred|handed\s+off|moved)\b"
            rf"[^.!?]{{0,35}}\bto\s+{owner_pattern}\b|"
            rf"\b(?:assigned|reassigned|transferred|handed\s+off|moved)\b"
            rf"[^.!?]{{0,35}}\bto\s+{owner_pattern}\b",
            text,
            flags=re.IGNORECASE,
        ))

    result = []
    for point in current:
        remove = False
        for owner, sentence in evidence:
            if _latest_keeps_owner(owner) or not _asserts_current_ownership(point, owner):
                continue
            point_terms = _terms(point, owner)
            sentence_terms = _terms(sentence, owner)
            action_terms = set()
            for action in active_or_inactive_tasks:
                action_terms |= _terms(action, owner)

            # ``Alex is responsible`` carries no task noun.  Only prune that
            # compact provider artifact when there is exactly one task identity.
            if not point_terms:
                if single_task_context:
                    remove = True
                    break
                continue

            # In multi-task threads, the transfer sentence itself must identify
            # the same task as the stale ownership bullet.  Do not let the union
            # of unrelated durable action terms create a false match.  The action
            # ledger is only a fallback when there is exactly one task identity.
            if point_terms & sentence_terms:
                remove = True
                break
            if single_task_context and point_terms & action_terms:
                remove = True
                break
        if not remove:
            result.append(point)
    return result


def _thread_reassignment_current_state_summary(
    candidate: str, thread_email: dict, details: list[dict]
) -> str:
    """Canonicalize an explicit thread reassignment from durable current state.

    Incremental and cold-replay model calls can legitimately paraphrase the same
    reassignment very differently (for example, "X owns the report" versus
    "report preparation is under X's ownership").  When the newest turn
    explicitly assigns existing work to another named person, use that source
    evidence plus the reconciled action ledger to produce one stable current
    state sentence.  This is deliberately thread-only and activates only when a
    reassigned/inactive row can be matched unambiguously; ordinary summaries and
    generic cancellations are untouched.
    """
    latest = _incremental_current_turn_text(thread_email)
    if not latest:
        return str(candidate or "").strip()

    assignment_re = re.compile(
        r"\b(?:"
        r"(?P<lead>[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+"
        r"(?:will|now\s+will|will\s+now|is\s+going\s+to|owns?|has\s+ownership|"
        r"confirmed\s+ownership|has\s+confirmed\s+ownership|will\s+take\s+over)|"
        r"(?:reassigned|assigned|transferred|handed\s+off)\s+to\s+"
        r"(?P<to>[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})"
        r")\b",
        flags=re.IGNORECASE,
    )
    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+|[\r\n]+", latest)
        if part.strip()
    ]
    evidence = []
    for sentence in sentences:
        match = assignment_re.search(sentence)
        if not match:
            continue
        assignee = str(match.group("lead") or match.group("to") or "").strip()
        if assignee:
            evidence.append((assignee, sentence))
    if not evidence:
        return str(candidate or "").strip()

    cancelled = [
        dict(item) for item in (details or [])
        if isinstance(item, dict)
        and bool(item.get("cancelled"))
        and str(item.get("action") or "").strip()
    ]
    active = [
        dict(item) for item in (details or [])
        if isinstance(item, dict)
        and not bool(item.get("completed"))
        and not bool(item.get("cancelled"))
        and str(item.get("action") or "").strip()
    ]
    if not cancelled or not active:
        return str(candidate or "").strip()

    stop = {
        "the", "a", "an", "to", "for", "from", "with", "and", "or", "of",
        "prepare", "review", "send", "submit", "upload", "confirm", "approve",
        "write", "read", "complete", "provide", "update", "create", "finish",
        "task", "work", "item", "request",
    }

    def _terms(value: str) -> set[str]:
        return {
            token for token in re.findall(r"[a-z0-9]+", str(value or "").casefold())
            if len(token) >= 3 and token not in stop
        }

    chosen = None
    chosen_assignee = ""
    best_score = 0
    tied = False
    for assignee, sentence in evidence:
        sentence_terms = _terms(sentence)
        ranked = []
        for item in cancelled:
            action_terms = _terms(item.get("action") or "")
            overlap = len(action_terms & sentence_terms)
            if overlap:
                ranked.append((overlap, item))
        ranked.sort(key=lambda pair: pair[0], reverse=True)
        if not ranked:
            continue
        score = ranked[0][0]
        local_tied = len(ranked) > 1 and ranked[1][0] == score
        if local_tied:
            continue
        if score > best_score:
            best_score = score
            chosen = ranked[0][1]
            chosen_assignee = assignee
            tied = False
        elif score == best_score and score > 0 and chosen is not ranked[0][1]:
            tied = True
    if not chosen or tied or best_score <= 0:
        return str(candidate or "").strip()

    reassigned_action = re.sub(r"\s+", " ", str(chosen.get("action") or "")).strip(" .")
    if not reassigned_action:
        return str(candidate or "").strip()

    object_phrase = re.sub(
        r"^(?:prepare|review|send|submit|upload|confirm|approve|write|read|complete|"
        r"provide|update|create|finish)\s+",
        "",
        reassigned_action,
        flags=re.IGNORECASE,
    ).strip()
    if not object_phrase:
        object_phrase = reassigned_action
    if not re.match(r"^(?:the|a|an)\b", object_phrase, flags=re.IGNORECASE):
        object_phrase = "the " + object_phrase

    def _recipient_clause(item: dict) -> str:
        action = re.sub(r"\s+", " ", str(item.get("action") or "")).strip(" .")
        if not action:
            return ""
        action = action[:1].lower() + action[1:]
        due = re.sub(r"\s+", " ", str(item.get("due_date") or "")).strip(" .")
        if due:
            return f"{action} by {due}"
        return action

    recipient_parts = [part for part in (_recipient_clause(item) for item in active) if part]
    if not recipient_parts:
        return str(candidate or "").strip()
    if len(recipient_parts) == 1:
        recipient_work = recipient_parts[0]
    else:
        recipient_work = ", ".join(recipient_parts[:-1]) + f", and {recipient_parts[-1]}"

    return (
        f"{chosen_assignee} owns {object_phrase}; "
        f"the recipient still needs to {recipient_work}."
    )


def _thread_closed_no_action_summary(existing: dict, candidate: str, thread_email: dict, details: list[dict]) -> str:
    """Preserve a proven closed-state summary across reference-only replies.

    A newest FYI/no-action turn may quote an old request.  If all durable actions
    are already closed and the new candidate fails to mention that closed state,
    keep the prior current-state summary rather than resurrecting old deadline
    language from quoted history.
    """
    current = _incremental_current_turn_text(thread_email)
    if not current:
        return candidate
    no_action = bool(re.search(
        r"\b(?:no\s+(?:further\s+|other\s+)?action\s+(?:is\s+)?required|"
        r"no\s+action\s+(?:is\s+)?required\s+from\s+you|"
        r"fyi\s+only|reference[- ]only|for\s+reference\s+only)\b",
        current, flags=re.IGNORECASE,
    ))
    if not no_action:
        return candidate
    if any(not bool(row.get("completed")) and not bool(row.get("cancelled")) for row in details):
        return candidate
    closed_signal = re.compile(
        r"\b(?:cancelled|canceled|completed|finished|approved|resolved|closed|"
        r"no\s+(?:further\s+|other\s+)?action\s+(?:is\s+)?required|"
        r"no\s+action\s+(?:is\s+)?required)\b",
        flags=re.IGNORECASE,
    )
    if closed_signal.search(candidate or ""):
        return candidate
    previous = str(existing.get("summary") or "").strip()
    if previous and closed_signal.search(previous):
        return previous
    return candidate


def _primary_open_action(details: list[dict]) -> dict | None:
    return next(
        (item for item in details if not bool(item.get("completed")) and not bool(item.get("cancelled"))),
        None,
    )


def _refreshed_task_title(existing: dict, old_details: list[dict], new_details: list[dict]) -> str:
    saved = str(existing.get("task_title") or "").strip()
    # A title explicitly edited in To-Do is a user-owned label. New email
    # content may update the task facts underneath it, but must not rename it.
    if str(existing.get("task_title_source") or "generated").strip().casefold() == "user":
        return saved
    old_primary = _primary_open_action(old_details)
    new_primary = _primary_open_action(new_details)
    if new_primary is None:
        return saved
    if not saved:
        return " ".join(str(new_primary.get("action") or "").split()[:10]).rstrip(" ,;:-")
    if old_primary is None or str(old_primary.get("action_id") or "") != str(new_primary.get("action_id") or ""):
        return " ".join(str(new_primary.get("action") or "").split()[:10]).rstrip(" ,;:-")

    old_action = str(old_primary.get("action") or "").strip()
    new_action = str(new_primary.get("action") or "").strip()
    # A generated title should follow explicit discriminator changes on the same
    # durable task (version/revision/phase/etc.).  Similarity stays high for
    # "version 3" -> "version 4", so a similarity-only guard leaves a stale
    # To-Do title even though the action ledger is correct. User-edited titles
    # were already protected above.
    marker_pattern = re.compile(
        r"\b(version|revision|rev|phase|option|variant|draft|proposal)\s+"
        r"([A-Za-z0-9][A-Za-z0-9._-]{0,15})\b",
        flags=re.IGNORECASE,
    )
    old_markers = {(m.group(1).casefold(), m.group(2).casefold()) for m in marker_pattern.finditer(old_action)}
    new_markers = {(m.group(1).casefold(), m.group(2).casefold()) for m in marker_pattern.finditer(new_action)}
    if old_markers and new_markers and old_markers != new_markers:
        return " ".join(new_action.split()[:10]).rstrip(" ,;:-")

    if _action_similarity(old_action, new_action) < 0.62:
        return " ".join(new_action.split()[:10]).rstrip(" ,;:-")
    return saved


def _task_change_records(existing: dict, new_details: list[dict], *, priority: str,
                         task_title: str, deadline_mode: str) -> list[dict]:
    old_details = _saved_action_rows(existing)
    old_by_id = {str(item.get("action_id") or ""): item for item in old_details if str(item.get("action_id") or "")}
    new_by_id = {str(item.get("action_id") or ""): item for item in new_details if str(item.get("action_id") or "")}
    changes = []
    for action_id, item in new_by_id.items():
        old = old_by_id.get(action_id)
        if old is None:
            changes.append({"type": "action_added", "action_id": action_id, "action": item.get("action", "")})
            continue
        if str(old.get("action") or "") != str(item.get("action") or ""):
            changes.append({
                "type": "action_reworded", "action_id": action_id,
                "from": old.get("action", ""), "to": item.get("action", ""),
            })
        old_due, new_due = str(old.get("due_date") or ""), str(item.get("due_date") or "")
        if old_due != new_due:
            changes.append({
                "type": "deadline_changed" if new_due else "deadline_removed",
                "action_id": action_id, "action": item.get("action", ""),
                "from": old_due, "to": new_due,
            })
        if bool(old.get("completed")) != bool(item.get("completed")):
            changes.append({
                "type": "action_completed" if item.get("completed") else "action_reopened",
                "action_id": action_id, "action": item.get("action", ""),
            })
        if bool(old.get("cancelled")) != bool(item.get("cancelled")):
            changes.append({
                "type": "action_cancelled" if item.get("cancelled") else "action_reopened",
                "action_id": action_id, "action": item.get("action", ""),
            })
    for action_id, item in old_by_id.items():
        if action_id not in new_by_id:
            changes.append({"type": "action_archived", "action_id": action_id, "action": item.get("action", "")})

    old_priority = str(existing.get("priority") or "Low").title()
    if old_priority != priority:
        changes.append({"type": "priority_changed", "from": old_priority, "to": priority})
    old_title = str(existing.get("task_title") or "").strip()
    if old_title and task_title and old_title != task_title:
        changes.append({"type": "title_changed", "from": old_title, "to": task_title})
    old_deadline_mode = str(existing.get("deadline_mode") or "auto")
    if old_deadline_mode != deadline_mode and deadline_mode == "explicit_none":
        changes.append({"type": "task_deadline_removed"})
    return changes


def _notice_details(changes: list[dict]) -> list[str]:
    lines = []
    for change in changes:
        kind = str(change.get("type") or "")
        action = str(change.get("action") or "").strip()
        if kind == "action_added":
            lines.append(f"New action: {action}")
        elif kind == "deadline_changed":
            lines.append(f"Deadline: {change.get('from') or 'none'} → {change.get('to') or 'none'}")
        elif kind in {"deadline_removed", "task_deadline_removed"}:
            lines.append(
                f"Explicit deadline removed{f' for {action}' if action else ''}; "
                "planned deadline reset to 14 days from the latest update."
            )
        elif kind == "action_completed":
            lines.append(f"Completed by email update: {action}")
        elif kind == "action_cancelled":
            lines.append(f"No longer required: {action}")
        elif kind == "action_reopened":
            lines.append(f"Reopened: {action}")
        elif kind == "priority_changed":
            lines.append(f"Priority: {change.get('from')} → {change.get('to')}")
    return list(dict.fromkeys(line for line in lines if line))[:6]


def merge_incremental_summary(existing: dict, added: dict, thread_email: dict) -> dict:
    # Merge a new thread turn while synchronizing To-Do state safely.
    old_text = str(existing.get("summary") or "").strip()
    new_text = str(added.get("summary") or "").strip()
    source_uids = list(dict.fromkeys(
        str(value)
        for value in (
            list(existing.get("source_uids") or [])
            + list(thread_email.get("source_uids") or [])
            + list(added.get("source_uids") or [])
        )
        if str(value)
    ))
    old_details = _saved_action_rows(existing)
    current_key_points, changed_key_points, key_point_changes = _reconcile_incremental_key_points(
        existing.get("key_points"), added.get("key_points")
    )
    actions, action_details, replaced_due_dates, introduced_open_work, cancelled_all_work_by_email = _reconcile_incremental_tasks(existing, added)
    # Re-apply Summary-vs-Key Point-vs-Action separation to the merged current
    # state as well. Older thread turns may have left noun-phrase task fragments
    # in Key Points; once the final Action Items are known, remove those current
    # duplicates without rewriting Recent Activity history. Completed/cancelled
    # rows remain valid ownership context for this dedupe even though they are not
    # live To-Do rows.
    thread_subject = str(
        thread_email.get("thread_subject")
        or thread_email.get("subject")
        or existing.get("subject")
        or ""
    )
    action_keypoint_context = [
        str(detail.get("action") or "").strip()
        for detail in action_details
        if str(detail.get("action") or "").strip()
    ]

    def _clean_current_points(values):
        cleaned = []
        for raw_point in values or []:
            point = _clean_incremental_key_point(raw_point, thread_subject)
            if not point:
                continue
            if _thread_keypoint_is_quoted_history_artifact(point):
                continue
            if _thread_keypoint_is_action_restatement(point, action_keypoint_context):
                continue
            if _thread_keypoint_is_deadline_state_restatement(point, action_keypoint_context):
                continue
            if _thread_keypoint_is_event_schedule_restatement(point, new_text):
                continue
            cleaned.append(point)
        return list(dict.fromkeys(cleaned))

    current_key_points = _clean_current_points(current_key_points)
    changed_key_points = _clean_current_points(changed_key_points)
    current_key_points = _prune_thread_stale_key_points(current_key_points, thread_email)
    changed_key_points = _prune_thread_stale_key_points(changed_key_points, thread_email)
    current_key_points = _prune_thread_superseded_ownership_key_points(
        current_key_points, thread_email, action_details
    )
    changed_key_points = _prune_thread_superseded_ownership_key_points(
        changed_key_points, thread_email, action_details
    )
    current_key_points, recovered_context_key_points = _canonicalize_thread_source_key_points(
        current_key_points, thread_email, action_keypoint_context
    )
    if recovered_context_key_points:
        changed_key_points = list(dict.fromkeys(changed_key_points + recovered_context_key_points))
    current_key_points, recovered_key_points = _recover_thread_unchanged_value_key_points(
        current_key_points, thread_email, action_keypoint_context
    )
    if recovered_key_points:
        changed_key_points = list(dict.fromkeys(changed_key_points + recovered_key_points))
    deadline_mode = _deadline_mode(action_details)
    old_status = normalize_task_status(existing.get("status"))
    old_status_source = str(existing.get("status_source") or "manual").strip().casefold()
    priority_material_change = _incremental_priority_material_change(
        existing, added, replaced_due_dates, introduced_open_work, thread_email
    )
    explicit_priority = str(added.get("_explicit_priority") or "").strip().title()
    # Email-confirmed cancellation may close action rows, but it does not own the
    # workflow Status. Preserve historical urgency instead of collapsing priority
    # to Low merely because no active action rows remain.
    if cancelled_all_work_by_email:
        priority = str(existing.get("priority") or "Low").title()
    else:
        priority = explicit_priority or _recompute_priority(
            action_details, str(added.get("priority") or existing.get("priority") or "Low"),
            thread_email, existing_priority=str(existing.get("priority") or "Low"),
            material_change=priority_material_change,
        )
    task_title = _refreshed_task_title(existing, old_details, action_details)
    new_text = _thread_closed_no_action_summary(existing, new_text, thread_email, action_details)
    new_text = _thread_reassignment_current_state_summary(new_text, thread_email, action_details)
    new_text = _thread_recipient_assignment_summary_cleanup(new_text, thread_email, action_details)

    # Workflow Status is manual-only. A new email reply is a content/task delta,
    # never authority to move the user-owned workflow state. Lifecycle language
    # (start/resume, hold/pause, complete, cancel, reopen) may still be summarized
    # as email content, but Status itself stays exactly as saved until the user
    # changes it in To-Do. This also makes incremental and cold-replay behavior
    # deterministic: replaying email history cannot fabricate workflow changes.
    task_status = old_status
    status_source = old_status_source or "manual"

    deadlines = []
    seen_deadlines = set()
    deadline_reference = _reference_date(thread_email)
    # Current per-action due dates are the source of truth. Active tasks show
    # only current work. A Cancelled task intentionally retains its last known
    # deadlines as historical context, matching manual cancellation behavior.
    preserve_cancelled_history = task_status == "Cancelled" and bool(actions)
    for detail in action_details:
        if not preserve_cancelled_history and (bool(detail.get("completed")) or bool(detail.get("cancelled"))):
            continue
        due = str(detail.get("due_date") or "").strip()
        due_identity = _deadline_identity(due, deadline_reference)
        if due and due_identity and due_identity not in seen_deadlines:
            seen_deadlines.add(due_identity)
            deadlines.append(due)

    has_open_work = any(
        not bool(detail.get("completed")) and not bool(detail.get("cancelled"))
        for detail in action_details
    )
    if not deadlines and (has_open_work or preserve_cancelled_history):
        fallback_values = (
            list(existing.get("deadlines") or []) + list(added.get("deadlines") or [])
            if preserve_cancelled_history
            else list(added.get("deadlines") or []) + list(existing.get("deadlines") or [])
        )
        for value in fallback_values:
            text = str(value or "").strip()
            superseded = (
                False
                if preserve_cancelled_history
                else any(
                    old_due.casefold() in text.casefold()
                    for old_due in replaced_due_dates if old_due
                )
            )
            identity = _deadline_identity(text, deadline_reference)
            if not text or superseded or not identity or identity in seen_deadlines:
                continue
            seen_deadlines.add(identity)
            deadlines.append(text)

    changes = _task_change_records(
        existing,
        action_details,
        priority=priority,
        task_title=task_title,
        deadline_mode=deadline_mode,
    )
    history = list(existing.get("task_change_history") or [])[-99:]
    task_change_types = {
        "action_added", "action_reworded", "deadline_changed", "deadline_removed",
        "action_completed", "action_reopened", "action_cancelled", "action_archived",
        "priority_changed", "title_changed", "task_deadline_removed",
    }
    thread_task_updated = any(
        str(change.get("type") or "").strip().casefold() in task_change_types
        for change in changes if isinstance(change, dict)
    )

    if changes:
        # Bind each durable change-history entry to the incremental turn that
        # actually produced the delta. ``thread_email`` represents the full
        # conversation and can carry the whole thread's source set/metadata;
        # using it here made a later reply accidentally match older history.
        # ``added`` is generated from ``build_incremental_thread_email`` and is
        # therefore the authoritative newest unseen turn for this merge.
        history.append({
            # Explicit provenance lets To-Do Recent Activity distinguish a
            # thread-driven change from a manual user edit at a glance.
            "source": "email_reply",
            "source_uid": str(added.get("uid") or thread_email.get("uid") or ""),
            "message_id": str(added.get("message_id") or thread_email.get("message_id") or ""),
            "date": str(added.get("date") or thread_email.get("date") or ""),
            "date_display": str(added.get("date_display") or thread_email.get("date_display") or ""),
            "changes": changes,
        })
    notice_lines = _notice_details(changes)

    incremental_updates = list(existing.get("incremental_updates") or [])
    summary_changed = bool(
        new_text
        and re.sub(r"\s+", " ", new_text).strip().casefold()
        != re.sub(r"\s+", " ", old_text).strip().casefold()
    )
    incremental_updates.append({
        # ``source_uid`` is the exact turn represented by this update. Keep the
        # broader source_uids list for compatibility/batched unseen turns, but
        # UI history/highlighting must key from this exact turn first.
        "source_uid": str(added.get("uid") or thread_email.get("uid") or ""),
        "message_id": str(added.get("message_id") or thread_email.get("message_id") or ""),
        "summary": new_text,
        "summary_changed": summary_changed,
        "summary_scope": "full_thread",
        "key_points": list(added.get("key_points") or []),
        "changed_key_points": changed_key_points,
        "key_point_changes": key_point_changes,
        "deadlines": list(added.get("deadlines") or []),
        "action_items": [
            str(update.get("action") or "").strip()
            for update in (added.get("task_updates") or [])
            if isinstance(update, dict) and str(update.get("state") or "").casefold() in {"new", "updated", "reopened"}
            and str(update.get("action") or "").strip()
        ],
        "task_updates": list(added.get("task_updates") or []),
        "source_uids": list(added.get("source_uids") or []),
        "date_display": str(added.get("date_display") or thread_email.get("date_display") or ""),
    })
    merged = dict(existing)
    merged.update({
        "uid": str(thread_email.get("uid") or added.get("uid") or existing.get("uid") or ""),
        "from": thread_email.get("from", existing.get("from", "")),
        "to": thread_email.get("to", existing.get("to", "")),
        "cc": thread_email.get("cc", existing.get("cc", "")),
        "subject": thread_email.get("thread_subject") or thread_email.get("subject") or existing.get("subject", ""),
        "date": thread_email.get("date", existing.get("date", "")),
        "date_display": thread_email.get("date_display", existing.get("date_display", "Unknown")),
        "snippet": thread_email.get("snippet", existing.get("snippet", "")),
        "message_id": thread_email.get("message_id", added.get("message_id", existing.get("message_id", ""))),
        # The incremental LLM now returns a concise CURRENT whole-thread
        # summary, so replace the prior snapshot instead of appending a delta.
        "summary": new_text or old_text,
        "key_points": current_key_points,
        "deadlines": deadlines,
        "action_items": actions,
        "action_item_details": action_details,
        "task_title": task_title,
        "task_title_source": str(existing.get("task_title_source") or "generated"),
        "status": task_status,
        "status_source": status_source,
        "deadline_mode": deadline_mode,
        "task_change_history": history,
        "task_revision": int(existing.get("task_revision") or 0),
        "attachments": list(thread_email.get("attachments") or []),
        "source_uids": source_uids,
        "incremental_updates": incremental_updates,
        "thread_count": int(thread_email.get("thread_count") or len(source_uids) or 1),
        "canonical_thread_id": str(thread_email.get("canonical_thread_id") or existing.get("canonical_thread_id") or ""),
        "priority": priority,
        "record_type": existing.get("record_type", "manual"),
        "generation_source": existing.get("generation_source", "manual"),
        "generation_mode": existing.get("generation_mode", "individual"),
        "_thread_summary_updated": True,
        "_thread_task_updated": thread_task_updated,
    })
    if notice_lines:
        merged["todo_update_notice"] = {
            "title": "Task updated from new reply",
            "message": "The existing To-Do was synchronized with the latest thread reply.",
            "details": notice_lines,
            "entity_id": str(merged.get("uid") or ""),
        }
    return _stamp_content_update(merged, existing)


def _is_trusted_sent_turn(turn: dict) -> bool:
    return str(turn.get("_mailmind_summary_context") or "").strip().casefold() == "trusted_sent"


def _thread_delta_groups(turns: list[dict]) -> tuple[list[list[dict]], list[dict]]:
    # Keep trusted Sent context attached to the next inbound safe reply instead
    # of treating the user's own outbound mail as a standalone incoming task
    # update. This preserves the established Summary direction boundary while
    # still letting the next legitimate reply see the conversation context.
    groups: list[list[dict]] = []
    pending_sent: list[dict] = []
    for raw in turns:
        turn = dict(raw)
        if _is_trusted_sent_turn(turn):
            pending_sent.append(turn)
            continue
        groups.append(pending_sent + [turn])
        pending_sent = []
    return groups, pending_sent


def _thread_group_email(thread_email: dict, turns: list[dict]) -> dict:
    ordered = [dict(item) for item in turns]
    ordered.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))
    latest = dict(ordered[-1])
    sections = []
    attachments = []
    for item in ordered:
        body = str(item.get("body_text") or item.get("snippet") or "").strip()
        sections.append(
            f"[{item.get('date_display') or 'Unknown date'} | "
            f"{item.get('from') or 'Unknown sender'} -> {item.get('to') or 'Unknown recipient'}]\n"
            f"Subject: {item.get('subject') or '(No Subject)'}\n{body}"
        )
        for attachment in item.get("attachments") or []:
            attachments.append({**attachment, "message_uid": str(item.get("uid") or "")})
    latest["body_text"] = (
        "\n\n--- New conversation turn ---\n\n".join(sections)
        if len(ordered) > 1
        else str(ordered[-1].get("body_text") or ordered[-1].get("snippet") or "")
    )
    latest["body_html"] = ""
    latest["attachments"] = attachments
    latest["source_uids"] = [str(item.get("uid") or "") for item in ordered if str(item.get("uid") or "")]
    latest["thread_count"] = len(latest["source_uids"]) or len(ordered) or 1
    latest["canonical_thread_id"] = str(thread_email.get("canonical_thread_id") or latest.get("canonical_thread_id") or "")
    latest["thread_subject"] = str(thread_email.get("thread_subject") or latest.get("thread_subject") or latest.get("subject") or "")
    identity = str(thread_email.get("_mailmind_recipient_identity") or "").strip()
    if identity:
        latest["_mailmind_recipient_identity"] = identity
    return latest


def _cumulative_thread_email(thread_email: dict, turns: list[dict]) -> dict:
    # Build current thread metadata through one exact inbound reply. The newest
    # body is used for materiality/priority checks; historical facts already
    # live in the saved current-state Summary.
    ordered = [dict(item) for item in turns]
    ordered.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))
    latest = dict(ordered[-1])
    latest["thread_messages"] = ordered
    latest["source_uids"] = [str(item.get("uid") or "") for item in ordered if str(item.get("uid") or "")]
    latest["thread_count"] = len(latest["source_uids"]) or len(ordered) or 1
    latest["canonical_thread_id"] = str(thread_email.get("canonical_thread_id") or "")
    latest["thread_subject"] = str(thread_email.get("thread_subject") or latest.get("subject") or "")
    latest["body_text"] = str(ordered[-1].get("body_text") or ordered[-1].get("snippet") or "")
    latest["body_html"] = ""
    identity = str(thread_email.get("_mailmind_recipient_identity") or "").strip()
    if identity:
        latest["_mailmind_recipient_identity"] = identity
    return latest


def _record_trailing_sent_sources(summary: dict, trailing_sent: list[dict]) -> dict:
    if not trailing_sent:
        return summary
    result = dict(summary)
    sources = [str(value or "").strip() for value in (result.get("source_uids") or []) if str(value or "").strip()]
    sources.extend(str(item.get("uid") or "").strip() for item in trailing_sent if str(item.get("uid") or "").strip())
    result["source_uids"] = list(dict.fromkeys(sources))
    result["thread_count"] = max(int(result.get("thread_count") or 0), len(result["source_uids"]))
    return result


def reconstruct_thread_summary(thread_email: dict) -> dict:
    # First-time summary of an existing provider thread must reconstruct ALL
    # eligible safe inbound turns chronologically. A single flat whole-thread
    # extraction can over-focus on the latest reply and lose still-active older
    # work. Replay uses the same incremental merge engine used for future replies,
    # so fresh DB, Manual/Automatic, and Individual/Batch semantics stay aligned.
    turns = [dict(item) for item in (thread_email.get("thread_messages") or []) if isinstance(item, dict)]
    if len(turns) <= 1:
        return create_summary(thread_email)
    turns.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))
    groups, trailing_sent = _thread_delta_groups(turns)
    if not groups:
        return create_summary(thread_email)

    first_group = groups[0]
    current = create_summary(_thread_group_email(thread_email, first_group))
    cumulative = list(first_group)
    for group in groups[1:]:
        incremental = _thread_group_email(thread_email, group)
        generated = create_incremental_summary(incremental, current)
        cumulative.extend(group)
        current = merge_incremental_summary(
            current, generated, _cumulative_thread_email(thread_email, cumulative)
        )

    # Historical provider turns are reconstruction input, not user-visible
    # "Recent Activity". The Summary did not exist when those replies happened,
    # so the first persisted card must look like a newly created current-state
    # snapshot: no blue latest-update styling, no update banner/notification,
    # and no Recent Activity rows. Keep the merged current fields/action IDs,
    # then discard only the replay bookkeeping. A genuinely NEW safe reply that
    # arrives after this card exists will create the first incremental/history
    # entry through the normal merge path.
    current["incremental_updates"] = []
    current["task_change_history"] = []
    current.pop("_thread_summary_updated", None)
    current.pop("todo_update_notice", None)
    created_at = str(current.get("summary_created_at") or _summary_now_utc())
    current["summary_created_at"] = created_at
    current["summary_activity_at"] = created_at
    return _record_trailing_sent_sources(current, trailing_sent)


def merge_unseen_thread_updates(existing: dict, thread_email: dict, known_uids=None) -> tuple[dict, int]:
    # Apply each unseen safe inbound reply as its own delta. This is critical when
    # two or more replies arrive before the next Summary pass: each gets independent
    # Recent Activity attribution and only the latest reply remains blue. Trusted
    # Sent turns are carried with the next inbound delta as context, not as tasks.
    known = {str(value or "").strip() for value in (known_uids or existing.get("source_uids") or []) if str(value or "").strip()}
    all_turns = [dict(item) for item in (thread_email.get("thread_messages") or []) if isinstance(item, dict)]
    all_turns.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))
    unseen = [item for item in all_turns if str(item.get("uid") or "").strip() not in known]
    groups, trailing_sent = _thread_delta_groups(unseen)
    if not groups:
        result = _record_trailing_sent_sources(dict(existing), trailing_sent)
        return result, 0

    current = dict(existing)
    cumulative = [item for item in all_turns if str(item.get("uid") or "").strip() in known]
    applied = 0
    for group in groups:
        incremental = _thread_group_email(thread_email, group)
        generated = create_incremental_summary(incremental, current)
        cumulative.extend(group)
        current = merge_incremental_summary(
            current, generated, _cumulative_thread_email(thread_email, cumulative)
        )
        applied += 1
    current = _record_trailing_sent_sources(current, trailing_sent)
    return current, applied


def update_batch_breakdown(batch: dict, updated_email: dict) -> dict:
    # Replace one batch-owned email and refresh derived batch metadata in place.
    canonical_id = str(updated_email.get("canonical_thread_id") or "").strip()
    breakdowns = [dict(item) for item in (batch.get("email_breakdowns") or [])]
    match_index = next((i for i, item in enumerate(breakdowns) if canonical_id and str(item.get("canonical_thread_id") or "").strip() == canonical_id), None)
    if match_index is None:
        return dict(batch)
    updated_copy = dict(updated_email)
    notice = updated_copy.pop("todo_update_notice", None)
    was_thread_update = bool(updated_copy.pop("_thread_summary_updated", False))
    breakdowns[match_index] = updated_copy
    sender_counts, attachments = Counter(), []
    for item in breakdowns:
        name, address = parseaddr(str(item.get("from") or "")); sender_counts[name or address or "Unknown sender"] += 1
        attachments.extend({**attachment, "subject": item.get("subject", "")} for attachment in (item.get("attachments") or []))
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    priority = max((str(item.get("priority") or "Low").title() for item in breakdowns), key=lambda v: rank.get(v.casefold(), 0), default="Low")
    latest = max(breakdowns, key=lambda item: str(item.get("date") or ""), default={})
    refreshed = dict(batch)
    refreshed.update({
        "email_breakdowns": breakdowns, "email_count": len(breakdowns),
        "action_items": [str(v).strip() for item in breakdowns for v in (item.get("action_items") or []) if str(v).strip()],
        "deadlines": _dedupe_batch_deadlines([
            str(v).strip()
            for item in breakdowns
            for v in _phase1c_dedupe_deadlines(item.get("deadlines") or [])
            if str(v).strip()
        ]),
        "priority": priority, "status": aggregate_task_status(item.get("status") for item in breakdowns),
        "top_senders": [{"sender": sender, "count": count} for sender, count in sender_counts.most_common()],
        "attachments": attachments,
        "source_uids": sorted({str(uid) for item in breakdowns for uid in (item.get("source_uids") or [item.get("uid")]) if str(uid)}),
        "date": latest.get("date", batch.get("date", "")), "date_display": latest.get("date_display", batch.get("date_display", "Unknown")),
        "absorbed_canonical_thread_ids": sorted({str(item.get("canonical_thread_id") or "").strip() for item in breakdowns if str(item.get("canonical_thread_id") or "").strip()}),
    })

    # A one-conversation Batch card is only a wrapper around that same thread.
    # When a new reply updates the breakdown, mirror its current narrative fields
    # too; otherwise the card keeps the pre-reply Summary/Key Points while its
    # nested breakdown and To-Do already show the new state.  Multi-email Batch
    # aggregation remains untouched, preserving the locked normal Batch path.
    if len(breakdowns) == 1:
        only = breakdowns[0]
        refreshed["summary"] = str(only.get("summary") or "")
        refreshed["snippet"] = str(only.get("summary") or only.get("snippet") or "")
        refreshed["key_points"] = list(only.get("key_points") or [])
    notices = [item for item in (batch.get("todo_update_notices") or []) if isinstance(item, dict)]
    if isinstance(notice, dict):
        notices.append(notice)
    if notices:
        refreshed["todo_update_notices"] = notices
    if was_thread_update:
        refreshed["_thread_summary_updated"] = True
        # Temporary UI-commit metadata: a Batch card owns drafts per source UID,
        # not by the synthetic batch UID. Accumulate every source that changed
        # during this generation job so only those drafts are invalidated.
        refreshed["_reply_draft_updated_uids"] = list(dict.fromkeys(
            [str(value) for value in (batch.get("_reply_draft_updated_uids") or []) if str(value)]
            + [str(updated_copy.get("uid") or "")]
        ))
    return _stamp_content_update(refreshed, batch)


def create_single_email_batch_summary(summary: dict) -> dict:
    # Wrap one existing analysis as a one-email Batch record without another LLM call.
    name, address = parseaddr(str(summary.get("from") or ""))
    sender = name or address or "Unknown sender"
    subject = summary.get("subject") or "(No Subject)"
    attachments = [
        {**item, "subject": subject}
        for item in (summary.get("attachments") or [])
    ]
    return _stamp_new_summary({
        "uid": f"batch:{uuid4().hex}",
        "record_type": "batch",
        "email_count": 1,
        "from": summary.get("from", ""),
        "to": summary.get("to", ""),
        "cc": summary.get("cc", ""),
        "subject": subject,
        "date": summary.get("date", ""),
        "date_display": summary.get("date_display", "Unknown"),
        "snippet": summary.get("summary") or summary.get("snippet", ""),
        "summary": summary.get("summary", ""),
        "key_points": list(summary.get("key_points") or []),
        "action_items": list(summary.get("action_items") or []),
        # Batch wrappers must preserve the same semantic deadline identity rules
        # as individual summaries instead of reintroducing formatting duplicates.
        "deadlines": _phase1c_dedupe_deadlines(summary.get("deadlines") or []),
        "priority": summary.get("priority") or "Low",
        "status": summary.get("status") or "Not Started",
        "top_senders": [{"sender": sender, "count": 1}],
        "attachments": attachments,
        "email_breakdowns": [summary],
        "source_uids": sorted({str(uid) for uid in (summary.get("source_uids") or [summary.get("uid")]) if str(uid)}),
    })


def create_batch_summary(summaries: list[dict]) -> dict:
    # Build one list card with aggregate and per-email reader data.
    aggregate = summarize_email_batch(summaries)
    sender_counts = Counter()
    for item in summaries:
        name, address = parseaddr(str(item.get("from") or ""))
        sender_counts[name or address or "Unknown sender"] += 1
    all_attachments = []
    for item in summaries:
        for attachment in item.get("attachments", []):
            all_attachments.append({**attachment, "subject": item.get("subject", "")})
    action_items = [
        str(action).strip()
        for item in summaries
        for action in (item.get("action_items") or [])
        if str(action).strip()
    ]
    deadlines = _dedupe_batch_deadlines([
        str(deadline).strip()
        for item in summaries
        for deadline in _phase1c_dedupe_deadlines(item.get("deadlines") or [])
        if str(deadline).strip()
    ])
    priority_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    priority = max(
        (str(item.get("priority") or "Low").strip().title() for item in summaries),
        key=lambda value: priority_rank.get(value.casefold(), 0),
        default="Low",
    )
    status = aggregate_task_status(item.get("status") for item in summaries)
    absorbed_canonical_thread_ids = sorted({str(item.get("canonical_thread_id") or "").strip() for item in summaries if str(item.get("canonical_thread_id") or "").strip()})
    return _stamp_new_summary({
        "uid": f"batch:{uuid4().hex}",
        "record_type": "batch",
        "email_count": len(summaries),
        "from": "Multiple senders",
        "to": summaries[0].get("to", "") if summaries else "",
        "cc": "",
        "subject": aggregate.get("title") or "Selected Email Highlights",
        "date": max((str(item.get("date") or "") for item in summaries), default=""),
        "date_display": max(summaries, key=lambda item: str(item.get("date") or "")).get("date_display", "Unknown") if summaries else "Unknown",
        "snippet": aggregate["summary"],
        "summary": aggregate["summary"],
        "key_points": aggregate["key_points"],
        # Per-email grounded values are canonical. The second AI pass provides
        # prose and takeaways only, preventing cross-tab count mismatches.
        "action_items": action_items,
        "deadlines": deadlines,
        "priority": priority,
        "status": status,
        "top_senders": [{"sender": sender, "count": count} for sender, count in sender_counts.most_common()],
        "attachments": all_attachments,
        "email_breakdowns": summaries,
        "absorbed_canonical_thread_ids": absorbed_canonical_thread_ids,
        "source_uids": sorted({uid for item in summaries for uid in item.get("source_uids", [str(item.get("uid", ""))]) if uid}),
    })
