# To-Do business and persistence helpers shared by the To-Do workspace.
from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta
from email.utils import parsedate_to_datetime

from storage.summary_store import SUMMARY_FOLDER
from email_handler.display_time import display_now, to_display_datetime
from ui.summary_metrics import is_task_ready
from services.task_status import (
    CLOSED_TASK_STATUSES,
    normalize_task_status,
)


_FOLDER = SUMMARY_FOLDER

_PRIORITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

ACTIVE_TASK_STATUSES = frozenset({"Not Started", "In Progress", "On Hold"})

ACTION_NEEDED_STATUSES = frozenset({"Not Started", "In Progress"})

_EMPTY_ITEM_MARKERS = {
    "",
    "none",
    "none identified",
    "none identified.",
    "n/a",
    "na",
    "no action required",
    "no action required.",
}

def _clean_list(value) -> list[str]:
    if value in (None, ""):
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    cleaned: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if text and text.casefold() not in _EMPTY_ITEM_MARKERS:
            cleaned.append(text)
    return cleaned

def _status(value) -> str:
    return normalize_task_status(value)

def _priority(value) -> str:
    key = str(value or "Medium").strip().casefold()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(key, "Medium")

def _normalize_task_record(item: dict) -> dict:
    record = dict(item)
    record["action_items"] = _clean_list(item.get("action_items"))
    record["deadlines"] = _clean_list(item.get("deadlines"))
    raw_details = item.get("action_item_details")
    record["action_item_details"] = [
        {
            "action": str(detail.get("action") or "").strip(),
            "action_id": str(detail.get("action_id") or "").strip(),
            "due_date": str(detail.get("due_date") or detail.get("deadline") or "").strip(),
            "deadline_state": str(detail.get("deadline_state") or "").strip(),
            "completed": bool(detail.get("completed")),
            "cancelled": bool(detail.get("cancelled")),
            "completion_source": str(detail.get("completion_source") or "").strip(),
            "cancellation_source": str(detail.get("cancellation_source") or "").strip(),
        }
        for detail in (raw_details if isinstance(raw_details, list) else [])
        if isinstance(detail, dict) and str(detail.get("action") or "").strip()
    ]
    record["task_due_date"] = str(item.get("task_due_date") or "").strip()
    record["task_title"] = str(item.get("task_title") or "").strip()
    record["deadline_mode"] = str(item.get("deadline_mode") or "auto").strip()
    record["status_source"] = str(item.get("status_source") or "email").strip()
    record["task_revision"] = int(item.get("task_revision") or 0)
    record["task_change_history"] = [
        dict(entry) for entry in (item.get("task_change_history") or [])
        if isinstance(entry, dict)
    ]
    record["task_is_read"] = bool(item.get("task_is_read", True))
    record["task_update_is_read"] = bool(item.get("task_update_is_read", True))
    # Task list ordering is independent from the AI Summary list. These
    # private fields preserve the task's own creation baseline while Recent
    # Activity supplies later meaningful task changes.
    record["_task_created_at"] = str(
        item.get("_task_created_at")
        or item.get("summary_created_at")
        or item.get("generated_at")
        or ""
    ).strip()
    record["status"] = _status(item.get("status"))
    record["priority"] = _priority(item.get("priority"))
    return record

def _task_records(summaries: list[dict]) -> list[dict]:
    # Return one To-Do row per source email, even for batch summaries.
    #
    # A batch remains one card in AI Summary, but its source emails are expanded
    # here so each email keeps its own action items, sender, priority, status,
    # and due date in the To-Do workspace.
    records: list[dict] = []
    for summary in summaries:
        is_batch = str(summary.get("record_type") or "manual").strip().casefold() == "batch"
        breakdowns = summary.get("email_breakdowns") or []

        if is_batch and breakdowns:
            parent_uid = str(summary.get("uid") or "")
            for index, email_item in enumerate(breakdowns):
                if not isinstance(email_item, dict) or not is_task_ready(email_item):
                    continue
                source_uid = str(email_item.get("uid") or "").strip()
                record = _normalize_task_record(email_item)
                # Keep a stable UI key while retaining the parent batch row that
                # owns this nested email_breakdowns entry in SQLite.
                record["uid"] = source_uid or f"{parent_uid}:source:{index}"
                record["_batch_parent_uid"] = parent_uid
                record["_batch_source_uid"] = source_uid
                record["_batch_source_index"] = index
                record["_task_created_at"] = str(
                    summary.get("summary_created_at")
                    or summary.get("generated_at")
                    or record.get("_task_created_at")
                    or ""
                ).strip()
                records.append(record)
            continue

        if not is_task_ready(summary):
            continue
        record = _normalize_task_record(summary)
        record["_task_created_at"] = str(
            summary.get("summary_created_at")
            or summary.get("generated_at")
            or record.get("_task_created_at")
            or ""
        ).strip()
        records.append(record)
    return records

def _search_text(task: dict) -> str:
    fields = [
        task.get("subject", ""),
        task.get("from", ""),
        task.get("summary", ""),
        task.get("task_title", ""),
        " ".join(task.get("action_items", [])),
        " ".join(task.get("deadlines", [])),
        " ".join(
            f"{item.get('action', '')} {item.get('due_date', '')}"
            for item in task.get("action_item_details", [])
            if isinstance(item, dict)
        ),
        task.get("task_due_date", ""),
        task.get("priority", ""),
        task.get("status", ""),
    ]
    return " ".join(str(field or "") for field in fields).casefold()

def _parse_clock(text: str) -> time:
    match = re.search(r"\b(\d{1,2}(?::\d{2})?\s*(?:AM|PM))\b", text, re.IGNORECASE)
    if not match:
        return time.min
    value = re.sub(r"\s+", " ", match.group(1).upper()).strip()
    for fmt in ("%I:%M %p", "%I %p"):
        try:
            return datetime.strptime(value, fmt).time()
        except ValueError:
            continue
    return time.min

def _email_reference_date(task: dict) -> date | None:
    # Return the email's calendar date for resolving exact Today/Tomorrow notes.
    candidates = [task.get("date"), task.get("date_display")]
    for candidate in candidates:
        raw = str(candidate or "").strip()
        if not raw:
            continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
        except ValueError:
            pass
        for fmt in (
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%b %d, %Y %I:%M %p",
            "%B %d, %Y %I:%M %p",
            "%b %d, %Y",
            "%B %d, %Y",
        ):
            try:
                return datetime.strptime(raw, fmt).date()
            except ValueError:
                continue
    return None

def _parse_deadline_text(value: str, reference_date: date | None = None) -> datetime:
    # Parse only real calendar deadlines; reject instructions masquerading as dates.
    raw = re.sub(r"\s+", " ", str(value or "").strip())
    if not raw:
        return datetime.max

    # Resolve source-preserving advanced relative constraints against the email
    # date. Summary keeps the original wording while To-Do still gets a sortable
    # calendar value. Holidays are intentionally not guessed for business days.
    lowered = raw.casefold()
    if reference_date is not None:
        word_numbers = {
            "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
            "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
        }
        # General calendar-day/hour durations. These are distinct from business
        # days and must not fall through to the generic +14-day plan.
        duration = re.search(
            r"\bwithin\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
            r"(hours?|days?)\b",
            lowered,
        )
        if duration and "business" not in duration.group(0):
            token, unit = duration.groups()
            count = int(token) if token.isdigit() else word_numbers.get(token, 0)
            if count > 0:
                base = datetime.combine(reference_date, time.min)
                return base + (timedelta(hours=count) if unit.startswith("hour") else timedelta(days=count))

        # Filipino relative-day wording is intentionally preserved by Summary but
        # resolved here for sortable To-Do dates.
        if re.search(r"\bbukas\b", lowered):
            return datetime.combine(reference_date + timedelta(days=1), _parse_clock(raw))

        # EOD is a same-day cutoff. Use end-of-day rather than the system's
        # estimated deadline.
        if re.search(r"\b(?:by\s+)?eod\b", lowered):
            return datetime.combine(reference_date, time(23, 59))

        # Midnight tonight is the boundary at the end of the reference day.
        if re.search(r"\b(?:12\s*am\s+)?midnight\s+tonight\b", lowered):
            return datetime.combine(reference_date + timedelta(days=1), time.min)

        # Time-only cutoffs inherit the email's calendar date.
        time_only = re.search(
            r"\b(?:by|before|no later than)\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm))\b",
            lowered,
        )
        if time_only and not re.search(r"\b(?:today|tomorrow|tonight)\b", lowered):
            return datetime.combine(reference_date, _parse_clock(time_only.group(1)))

        # Named weekday deadlines resolve to the next occurrence, including the
        # reference day itself when the message is sent on that weekday.
        weekday_match = re.search(
            r"\b(?:by|before|on)\s+(?:this\s+|next\s+)?"
            r"(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
            lowered,
        )
        if weekday_match:
            weekday_map = {
                "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
                "friday": 4, "saturday": 5, "sunday": 6,
            }
            target = weekday_map[weekday_match.group(1)]
            delta = (target - reference_date.weekday()) % 7
            if re.search(r"\bnext\s+" + weekday_match.group(1) + r"\b", lowered):
                delta = delta or 7
            return datetime.combine(reference_date + timedelta(days=delta), _parse_clock(raw))

        # Recurring monthly rule: expose the next concrete occurrence for sorting
        # while leaving the original recurrence text stored in action details.
        if re.search(r"\blast\s+business\s+day\s+of\s+every\s+month\b", lowered):
            year, month = reference_date.year, reference_date.month
            if month == 12:
                next_month = date(year + 1, 1, 1)
            else:
                next_month = date(year, month + 1, 1)
            current = next_month - timedelta(days=1)
            while current.weekday() >= 5:
                current -= timedelta(days=1)
            if current < reference_date:
                if next_month.month == 12:
                    after = date(next_month.year + 1, 1, 1)
                else:
                    after = date(next_month.year, next_month.month + 1, 1)
                current = after - timedelta(days=1)
                while current.weekday() >= 5:
                    current -= timedelta(days=1)
            return datetime.combine(current, time.min)

        # Quarterly recurrence: next Nth business day after a quarter end.
        quarter = re.search(
            r"\b(first|second|third|fourth|fifth)\s+business\s+day\s+after\s+each\s+quarter(?:\s+ends?)?\b",
            lowered,
        )
        if quarter:
            ordinal = {"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5}[quarter.group(1)]
            quarter_ends = [
                date(reference_date.year, 3, 31), date(reference_date.year, 6, 30),
                date(reference_date.year, 9, 30), date(reference_date.year, 12, 31),
                date(reference_date.year + 1, 3, 31),
            ]
            for qend in quarter_ends:
                current = qend
                remaining = ordinal
                while remaining > 0:
                    current += timedelta(days=1)
                    if current.weekday() < 5:
                        remaining -= 1
                if current >= reference_date:
                    return datetime.combine(current, time.min)

        business = re.search(
            r"\bwithin\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+business\s+days?\b",
            lowered,
        )
        if business:
            token = business.group(1)
            count = int(token) if token.isdigit() else word_numbers.get(token, 0)
            current = reference_date
            remaining = count
            while remaining > 0:
                current += timedelta(days=1)
                if current.weekday() < 5:
                    remaining -= 1
            return datetime.combine(current, time.min)

        if re.search(r"\bclose of business(?:\s+today)?\b", lowered):
            return datetime.combine(reference_date, time(17, 0))

        end_week = re.search(r"\bend of\s+(?:(this|next)\s+)?week\b", lowered)
        if end_week:
            modifier = str(end_week.group(1) or "this").casefold()
            days_to_friday = (4 - reference_date.weekday()) % 7
            if modifier == "next":
                days_to_friday += 7
            return datetime.combine(reference_date + timedelta(days=days_to_friday), time.min)

        end_month = re.search(r"\bend of\s+(?:(this|next)\s+)?month\b", lowered)
        if end_month:
            base = reference_date
            if str(end_month.group(1) or "this").casefold() == "next":
                if base.month == 12:
                    base = date(base.year + 1, 1, 1)
                else:
                    base = date(base.year, base.month + 1, 1)
            next_month = (base.replace(day=28) + timedelta(days=4)).replace(day=1)
            return datetime.combine(next_month - timedelta(days=1), time.min)

        recurring = re.search(
            r"\b(?:every|each)\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
            lowered,
        )
        if recurring:
            weekday_map = {
                "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
                "friday": 4, "saturday": 5, "sunday": 6,
            }
            target = weekday_map[recurring.group(1)]
            delta = (target - reference_date.weekday()) % 7
            return datetime.combine(reference_date + timedelta(days=delta), time.min)

    # Explicit ISO dates are authoritative even when surrounded by model wording,
    # e.g. "Today (2026-07-28)" or "finish by 2026-08-10".
    iso_match = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", raw)
    if iso_match:
        try:
            parsed_date = datetime.strptime(iso_match.group(1), "%Y-%m-%d").date()
            return datetime.combine(parsed_date, _parse_clock(raw))
        except ValueError:
            pass

    month_names = (
        "January|February|March|April|May|June|July|August|September|"
        "October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
    )

    # Accept an explicit month/day/year embedded in a sentence such as
    # "Finish by August 10, 2026". The surrounding instruction is not used.
    month_year_match = re.search(
        rf"\b({month_names})\s+(\d{{1,2}})(?:st|nd|rd|th)?(?:,\s*|\s+)(\d{{4}})"
        rf"(?:\s+(?:at\s+)?(\d{{1,2}}(?::\d{{2}})?\s*(?:AM|PM)))?\b",
        raw,
        re.IGNORECASE,
    )
    if month_year_match:
        month, day_value, year_value, clock_value = month_year_match.groups()
        normalized = f"{month} {day_value}, {year_value}"
        if clock_value:
            normalized += f" {clock_value}"
        for fmt in (
            "%B %d, %Y %I:%M %p", "%b %d, %Y %I:%M %p",
            "%B %d, %Y %I %p", "%b %d, %Y %I %p",
            "%B %d, %Y", "%b %d, %Y",
        ):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue

    numeric_match = re.search(
        r"\b(\d{1,2}/\d{1,2}/\d{4})(?:\s+(?:at\s+)?(\d{1,2}(?::\d{2})?\s*(?:AM|PM)))?\b",
        raw,
        re.IGNORECASE,
    )
    if numeric_match:
        normalized = numeric_match.group(1)
        if numeric_match.group(2):
            normalized += f" {numeric_match.group(2)}"
        for fmt in ("%m/%d/%Y %I:%M %p", "%m/%d/%Y %I %p", "%m/%d/%Y"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue

    normalized = raw.strip(" .")

    # Resolve relative wording against the date the email was sent, never the
    # day the app happens to be opened. This supports model output such as
    # "today", "finish today", "tomorrow at 3:00 PM", and "tomorrow afternoon".
    relative_match = re.search(
        r"\b(today|tomorrow)\b"
        r"(?:\s+(?:(?:at|by|before)\s+)?(\d{1,2}(?::\d{2})?\s*(?:AM|PM)))?"
        r"(?:\s+(morning|afternoon|evening|tonight|noon))?",
        normalized,
        re.IGNORECASE,
    )
    if relative_match and reference_date is not None:
        target = reference_date
        if relative_match.group(1).casefold() == "tomorrow":
            target += timedelta(days=1)

        clock = time.min
        clock_value = relative_match.group(2)
        daypart = str(relative_match.group(3) or "").casefold()
        if clock_value:
            try:
                clock = _parse_clock(clock_value)
                if clock == time.min and not re.search(r"12(?::00)?\s*AM", clock_value, re.IGNORECASE):
                    return datetime.max
            except ValueError:
                return datetime.max
        elif daypart:
            clock = {
                "morning": time(8, 0),
                "noon": time(12, 0),
                "afternoon": time(15, 0),
                "evening": time(19, 0),
                "tonight": time(19, 0),
            }[daypart]
        return datetime.combine(target, clock)

    # Month/day without a year can only be resolved when the email date gives a
    # reliable year reference. Roll to the following year when needed.
    month_day_match = re.search(
        rf"\b({month_names})\s+(\d{{1,2}})(?:st|nd|rd|th)?(?:\s+(?:at\s+)?(\d{{1,2}}(?::\d{{2}})?\s*(?:AM|PM)))?\b",
        normalized,
        re.IGNORECASE,
    )
    if month_day_match and reference_date is not None:
        month, day_value, clock_value = month_day_match.groups()
        normalized_date = f"{month} {day_value}, {reference_date.year}"
        if clock_value:
            normalized_date += f" {clock_value}"
        parsed = datetime.max
        for fmt in (
            "%B %d, %Y %I:%M %p", "%b %d, %Y %I:%M %p",
            "%B %d, %Y %I %p", "%b %d, %Y %I %p",
            "%B %d, %Y", "%b %d, %Y",
        ):
            try:
                parsed = datetime.strptime(normalized_date, fmt)
                break
            except ValueError:
                continue
        # Keep a recently passed month/day in the message year. Rolling every
        # past named date forward one year turns overdue deadlines into future
        # work. Only roll when the candidate is more than 30 days before the
        # message date, matching the Summary deadline resolver's bounded rule.
        if parsed != datetime.max and parsed.date() < reference_date - timedelta(days=30):
            try:
                parsed = parsed.replace(year=parsed.year + 1)
            except ValueError:
                return datetime.max
        return parsed

    return datetime.max

def _deadline_candidates(task: dict) -> list[tuple[datetime, str]]:
    # Return all parseable email-level deadlines, sorted chronologically.
    reference_date = _email_reference_date(task)
    candidates = []
    seen = set()
    for value in task.get("deadlines") or []:
        raw = str(value or "").strip()
        parsed = _parse_deadline_text(raw, reference_date)
        if parsed == datetime.max:
            continue
        key = parsed.isoformat()
        if key in seen:
            continue
        seen.add(key)
        candidates.append((parsed, raw))
    return sorted(candidates, key=lambda item: item[0])

_DEADLINE_MATCH_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "must", "should",
    "please", "need", "needs", "required", "require", "before", "after", "by",
    "due", "deadline", "today", "tomorrow", "monday", "tuesday", "wednesday",
    "thursday", "friday", "saturday", "sunday", "january", "february", "march",
    "april", "may", "june", "july", "august", "september", "october", "november",
    "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept",
    "oct", "nov", "dec", "am", "pm",
}

def _deadline_match_tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", str(value or "").casefold())
        if len(token) >= 3 and not token.isdigit() and token not in _DEADLINE_MATCH_STOPWORDS
    }

def _action_item_rows(task: dict) -> list[dict]:
    # Pair each action with its own deadline while preserving one task per email.
    actions = _clean_list(task.get("action_items"))
    details = [
        item for item in (task.get("action_item_details") or [])
        if isinstance(item, dict)
    ]
    detail_by_action = {
        re.sub(r"\s+", " ", str(item.get("action") or "").strip()).casefold(): item
        for item in details
        if str(item.get("action") or "").strip()
    }
    candidates = _deadline_candidates(task)
    reference_date = _email_reference_date(task)
    used_candidate_indexes = set()
    rows = []

    for index, action in enumerate(actions):
        normalized_action = re.sub(r"\s+", " ", action).casefold()
        detail = detail_by_action.get(normalized_action)
        if detail is None and index < len(details):
            candidate_detail = details[index]
            detail_action = re.sub(
                r"\s+", " ", str(candidate_detail.get("action") or "").strip()
            ).casefold()
            if not detail_action or detail_action == normalized_action:
                detail = candidate_detail

        due_raw = str((detail or {}).get("due_date") or "").strip()
        deadline_state = str((detail or {}).get("deadline_state") or "").strip().casefold()
        parsed = _parse_deadline_text(due_raw, reference_date) if due_raw else datetime.max

        # Legacy summaries often kept the deadline directly inside the action text.
        if parsed == datetime.max and deadline_state not in {"none", "unspecified"}:
            # A persisted ``unspecified`` state is an explicit statement that this
            # action has no sender-owned due date. Do not re-parse calendar words
            # inside the action itself (for example, alternatives in an ambiguous
            # date-confirmation task) as a hidden deadline. Legacy rows with a
            # blank state still keep the older action-text recovery path.
            parsed_from_action = _parse_deadline_text(action, reference_date)
            if parsed_from_action != datetime.max:
                parsed = parsed_from_action
                due_raw = action

        # Older saved summaries have separate action/deadline arrays. Pair a
        # descriptive deadline to its matching action using local word overlap.
        if parsed == datetime.max and deadline_state not in {"none", "unspecified"} and candidates:
            action_tokens = _deadline_match_tokens(action)
            best = None
            for candidate_index, (candidate_date, candidate_raw) in enumerate(candidates):
                if candidate_index in used_candidate_indexes:
                    continue
                deadline_tokens = _deadline_match_tokens(candidate_raw)
                common = action_tokens & deadline_tokens
                if len(common) < 2:
                    continue
                score = len(common) / max(1, min(len(action_tokens), len(deadline_tokens)))
                if best is None or score > best[0]:
                    best = (score, candidate_index, candidate_date, candidate_raw)
            if best is not None and best[0] >= 0.45:
                _, candidate_index, parsed, due_raw = best
                used_candidate_indexes.add(candidate_index)

        rows.append({
            "action": action,
            "due_date": due_raw,
            "parsed_due": parsed,
            "completed": bool((detail or {}).get("completed")),
            "cancelled": bool((detail or {}).get("cancelled")),
            "action_id": str((detail or {}).get("action_id") or ""),
            "deadline_state": deadline_state,
        })

    return rows

def _action_deadline_entries(task: dict) -> list[dict]:
    # Return every action-item deadline with its action and completion state.
    entries = []
    for index, row in enumerate(_action_item_rows(task)):
        parsed = row.get("parsed_due", datetime.max)
        if parsed == datetime.max:
            continue
        entries.append({
            "parsed": parsed,
            "raw": str(row.get("due_date") or "").strip(),
            "action": str(row.get("action") or "").strip(),
            "completed": bool(row.get("completed")),
            "cancelled": bool(row.get("cancelled")),
            "index": index,
            "source": "action",
        })
    return sorted(entries, key=lambda item: (item["parsed"], item["index"]))

def _dedupe_deadline_entries(entries: list[dict]) -> list[dict]:
    # A single task/thread deadline may be inherited by several action items.
    # The To-Do workspace must present that effective date/time once, not once
    # per action.  Genuinely different dates/times remain separate entries.
    grouped: dict[str, list[dict]] = {}
    order: list[str] = []
    for raw_entry in entries:
        entry = dict(raw_entry)
        parsed = entry.get("parsed", datetime.max)
        if parsed == datetime.max:
            continue
        key = parsed.isoformat()
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(entry)

    deduped: list[dict] = []
    for key in order:
        group = grouped[key]
        # Prefer an active action as the representative so a shared deadline
        # does not look completed merely because one sibling action is done.
        representative = next(
            (entry for entry in group if not entry.get("completed") and not entry.get("cancelled")),
            next((entry for entry in group if not entry.get("cancelled")), group[0]),
        )
        merged = dict(representative)
        actions = list(dict.fromkeys(
            str(entry.get("action") or "").strip()
            for entry in group
            if str(entry.get("action") or "").strip()
        ))
        merged["shared_action_count"] = len(actions)
        merged["actions"] = actions
        if len(actions) > 1:
            merged["action"] = f"Shared by {len(actions)} action items"
        merged["completed"] = bool(group) and all(
            bool(entry.get("completed")) or bool(entry.get("cancelled"))
            for entry in group
        )
        merged["cancelled"] = bool(group) and all(bool(entry.get("cancelled")) for entry in group)
        merged["index"] = min(int(entry.get("index") or 0) for entry in group)
        deduped.append(merged)

    return sorted(deduped, key=lambda item: (item["parsed"], item.get("index", 0)))


def _deadline_entries(task: dict, *, include_completed: bool = False) -> list[dict]:
    # Return effective deadlines used by the To-Do UI.
    #
    # Action-item deadlines are authoritative when available. A shared
    # task/thread deadline can legitimately appear on multiple action-detail
    # rows; collapse identical effective date/times to one To-Do deadline while
    # preserving genuinely different per-item deadlines.
    action_entries = _action_deadline_entries(task)
    if action_entries:
        eligible = (
            action_entries
            if include_completed
            else [
                entry for entry in action_entries
                if not entry["completed"] and not entry.get("cancelled")
            ]
        )
        return _dedupe_deadline_entries(eligible)

    return _dedupe_deadline_entries([
        {
            "parsed": parsed,
            "raw": raw,
            "action": "",
            "completed": False,
            "cancelled": False,
            "index": index,
            "source": "email",
        }
        for index, (parsed, raw) in enumerate(_deadline_candidates(task))
    ])

def _valid_extracted_deadline(task: dict) -> tuple[datetime, str]:
    entries = _deadline_entries(task, include_completed=False)
    if not entries:
        return datetime.max, ""
    first = entries[0]
    return first["parsed"], first["raw"]

def _invalid_extracted_deadline_note(task: dict) -> str:
    reference_date = _email_reference_date(task)
    for value in task.get("deadlines") or []:
        raw = str(value or "").strip()
        if raw and _parse_deadline_text(raw, reference_date) == datetime.max:
            return raw
    return ""

def _estimated_deadline_reference_date(task: dict) -> date:
    """Resolve the local processing/activity date used by the +14-day plan.

    Generated summary timestamps are stored in UTC, so convert them to the app's
    display timezone before taking the calendar date. This prevents an email
    processed after local midnight from receiving a deadline one day early.
    """
    for value in (
        task.get("summary_activity_at"),
        task.get("_task_created_at"),
        task.get("summary_created_at"),
        task.get("generated_at"),
    ):
        raw = str(value or "").strip()
        if not raw:
            continue
        try:
            converted = to_display_datetime(raw)
        except Exception:
            converted = None
        if converted is not None:
            return converted.date()
        parsed = _parse_task_activity_datetime(raw)
        if parsed is not None:
            return parsed.date()

    # Legacy summaries may predate processing timestamps. Preserve their old
    # behavior as a compatibility fallback, then fall back to the local today.
    return _email_reference_date(task) or display_now().date()


_UPPER_BOUND_MARKER_RE = re.compile(
    r"\b(?:beforehand|before|prior\s+to|ahead\s+of|no\s+later\s+than)\b",
    re.IGNORECASE,
)
_UPPER_BOUND_GENERIC_EVENT_WORDS = frozenset({
    "meeting", "call", "review", "session", "appointment", "interview",
    "presentation", "demo", "launch", "release", "deployment", "event",
    "workshop", "training", "hearing", "visit", "trip", "departure",
    "arrival", "checkin", "check-in", "cutover", "go-live", "golive",
})


def _planned_deadline_context_texts(task: dict) -> list[str]:
    """Return grounded text that may constrain a fallback planned deadline.

    The saved Summary record does not retain the raw email body, so use only the
    source-grounded fields that survive the summary pipeline.  This keeps the
    To-Do resolver deterministic and makes Summary/To-Do display share one rule.
    """
    values: list[str] = []
    for value in (
        task.get("summary"),
        task.get("task_title"),
        *(task.get("key_points") or []),
        *(task.get("action_items") or []),
    ):
        text = re.sub(r"\s+", " ", str(value or "").strip())
        if text and text not in values:
            values.append(text)
    return values


def _context_sentences(task: dict) -> list[str]:
    sentences: list[str] = []
    for text in _planned_deadline_context_texts(task):
        parts = re.split(r"(?<=[.!?;])\s+|\n+", text)
        for part in parts:
            cleaned = re.sub(r"\s+", " ", str(part or "").strip())
            if cleaned and cleaned not in sentences:
                sentences.append(cleaned)
    return sentences


def _upper_bound_anchor_tokens(text: str) -> set[str]:
    """Extract useful event words from a relational phrase such as 'before meeting'."""
    normalized = re.sub(r"\s+", " ", str(text or "").casefold())
    match = _UPPER_BOUND_MARKER_RE.search(normalized)
    if not match:
        return set()
    tail = normalized[match.end():]
    # Only inspect the short phrase immediately after the relation marker.
    tail = re.split(r"[,.!?;:]", tail, maxsplit=1)[0]
    tokens = {
        token for token in re.findall(r"[a-z][a-z0-9-]*", tail)[:8]
        if token not in {
            "the", "a", "an", "our", "your", "my", "their", "this", "that",
            "joining", "attending", "starting", "beginning", "going", "it",
        }
    }
    return tokens


def _planned_deadline_upper_bound(task: dict) -> datetime | None:
    """Resolve a known contextual upper bound for an otherwise undated task.

    Examples include "read this before the meeting" when the same summary also
    contains the meeting date.  A contextual event date is *not* promoted to an
    explicit sender deadline; it only caps the system's +14-day fallback.

    Conservative rules:
    - require an explicit upper-bound relation (before/prior to/ahead of/etc.);
    - prefer a date in the same sentence as that relation;
    - otherwise match an event noun (meeting/call/launch/...) to a dated sentence;
    - if there is exactly one grounded contextual date, allow it as the bound;
    - never guess among multiple unrelated dates.
    """
    sentences = _context_sentences(task)
    relation_sentences = [s for s in sentences if _UPPER_BOUND_MARKER_RE.search(s)]
    if not relation_sentences:
        return None

    reference_date = _email_reference_date(task) or _estimated_deadline_reference_date(task)

    dated: list[tuple[datetime, str]] = []
    seen_dates: set[str] = set()
    for sentence in sentences:
        parsed = _parse_deadline_text(sentence, reference_date)
        if parsed == datetime.max:
            continue
        key = parsed.isoformat()
        if key in seen_dates:
            continue
        seen_dates.add(key)
        dated.append((parsed, sentence))

    if not dated:
        return None

    # Strongest evidence: the relation and date occur together.
    same_sentence = []
    for sentence in relation_sentences:
        parsed = _parse_deadline_text(sentence, reference_date)
        if parsed != datetime.max:
            same_sentence.append(parsed)
    if same_sentence:
        return min(same_sentence)

    # Next strongest: the relation names a recognizable event and one dated
    # sentence names that same event.
    for relation in relation_sentences:
        anchors = _upper_bound_anchor_tokens(relation)
        event_anchors = anchors & _UPPER_BOUND_GENERIC_EVENT_WORDS
        if not event_anchors:
            continue
        matches = [
            parsed for parsed, sentence in dated
            if event_anchors & set(re.findall(r"[a-z][a-z0-9-]*", sentence.casefold()))
        ]
        if len({item.isoformat() for item in matches}) == 1:
            return matches[0]

    # "before joining" / "before attending" may not repeat the event noun.
    # When there is only one contextual date in all grounded text, it is
    # unambiguous enough to cap the fallback without inventing a new date.
    if len(dated) == 1:
        return dated[0][0]

    return None


def _estimated_deadline(task: dict) -> datetime:
    # Active work with no explicit due date uses processing/activity date +14
    # calendar days as a fallback candidate.  If the email context says the work
    # must happen before a known event/date, cap the plan at that grounded upper
    # bound instead of scheduling work after the event that requires it.
    reference_date = _estimated_deadline_reference_date(task)
    fallback = datetime.combine(reference_date + timedelta(days=14), time.min)
    upper_bound = _planned_deadline_upper_bound(task)
    if upper_bound is not None and upper_bound < fallback:
        return upper_bound
    return fallback

def _resolved_deadline(task: dict) -> tuple[datetime, str]:
    extracted, _ = _valid_extracted_deadline(task)
    if extracted != datetime.max:
        return extracted, "extracted"

    action_entries = _action_deadline_entries(task)
    if action_entries:
        # Completed action-item dates normally stop being "upcoming". However,
        # an explicit reactivation/reopen means the TASK itself is active again.
        # In that state, keep the action checks as history but restore the
        # original extracted due date at task level so Due Today / Overdue and
        # the table's Deadline cell become active again.
        if _status(task.get("status")) in ACTIVE_TASK_STATUSES:
            return min(entry["parsed"] for entry in action_entries), "extracted"
        return datetime.max, "none"

    manual_due = str(task.get("task_due_date") or "").strip()
    if manual_due:
        parsed = _parse_deadline_text(manual_due)
        if parsed != datetime.max:
            return parsed, "manual"

    if _status(task.get("status")) in CLOSED_TASK_STATUSES:
        return datetime.max, "none"

    # Active tasks with no current explicit calendar date use the standard
    # planned deadline. This also upgrades records saved by older versions as
    # deadline_mode="explicit_none": they now receive +14 days from the latest
    # email/thread update instead of staying open-ended.
    return _estimated_deadline(task), "estimated"

def _parse_deadline(task: dict) -> datetime:
    return _resolved_deadline(task)[0]

def _is_action_needed(task: dict, today: date | None = None) -> bool:
    # Return True for one urgent active task shown by the sidebar shortcut.
    #
    # Action Needed is intentionally an OR rule evaluated once per task, so a
    # Critical + Overdue task still contributes exactly one task/count.
    if _status(task.get("status")) not in ACTION_NEEDED_STATUSES:
        return False

    if _priority(task.get("priority")) == "Critical":
        return True

    deadline = _parse_deadline(task)
    if deadline == datetime.max:
        return False

    today = today or date.today()
    due_day = deadline.date()
    week_end = today + timedelta(days=6 - today.weekday())

    # All overdue dates are urgent, and current-week dates include Due Today.
    # This Month by itself is deliberately not included.
    return due_day < today or today <= due_day <= week_end

def todo_action_needed_count(summaries: list[dict]) -> int:
    # Count unique task rows that currently satisfy Action Needed.
    return sum(1 for task in _task_records(summaries or []) if _is_action_needed(task))

def _deadline_timezone_label(raw: str) -> str:
    # Preserve a source-written timezone abbreviation as a display qualifier.
    # Do not convert it: abbreviations such as CST can be region-ambiguous, and
    # the source may explicitly require the original clock/timezone to remain.
    match = re.search(
        r"\b\d{1,2}(?::\d{2})?\s*(?:AM|PM)\s+([A-Z]{2,5})\b",
        str(raw or ""),
        flags=re.IGNORECASE,
    )
    return match.group(1).upper() if match else ""


def _format_deadline(parsed: datetime, raw: str = "") -> str:
    label = f"{parsed.strftime('%b')} {parsed.day}, {parsed.year}"
    if parsed.time() != time.min:
        clock = parsed.strftime("%I:%M %p").lstrip("0")
        label += f" at {clock}"
        timezone_label = _deadline_timezone_label(raw)
        if timezone_label:
            label += f" {timezone_label}"
    return label

def _due_label(task: dict) -> str:
    parsed, source = _resolved_deadline(task)
    if parsed == datetime.max:
        return ""
    raw = ""
    if source == "extracted":
        _, raw = _valid_extracted_deadline(task)
    elif source == "manual":
        raw = str(task.get("task_due_date") or "").strip()
    return _format_deadline(parsed, raw)

def _due_source(task: dict) -> str:
    return _resolved_deadline(task)[1]

def _due_state_class(task: dict) -> str:
    deadline = _parse_deadline(task)
    if deadline == datetime.max:
        return ""
    if deadline.date() < date.today():
        return " is-overdue"
    if deadline.date() == date.today():
        return " is-today"
    return ""

def _email_reference_datetime(task: dict) -> datetime | None:
    candidates = [task.get("date"), task.get("date_display")]
    for candidate in candidates:
        raw = str(candidate or "").strip()
        if not raw:
            continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass
        for fmt in (
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%b %d, %Y %I:%M %p",
            "%B %d, %Y %I:%M %p",
            "%b %d, %Y",
            "%B %d, %Y",
        ):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None

def _format_created_datetime(task: dict) -> str:
    parsed = _email_reference_datetime(task)
    if parsed is None:
        return "—"
    label = f"{parsed.strftime('%b')} {parsed.day}, {parsed.year}"
    if parsed.time() != time.min:
        label += f" at {parsed.strftime('%I:%M %p').lstrip('0')}"
    return label

def _deadline_matches_filter(task: dict, filter_key: str | None) -> bool:
    if not filter_key:
        return True

    # Closed tasks remain visible in history/status filters, but they no longer
    # participate in active deadline views. This keeps Completed/Cancelled out
    # of Due Today, This Week, This Month, and Overdue consistently.
    if _status(task.get("status")) in CLOSED_TASK_STATUSES:
        return False

    deadline = _parse_deadline(task)
    if deadline == datetime.max:
        return False

    due_day = deadline.date()
    today = date.today()
    if filter_key == "due_today":
        return due_day == today
    if filter_key == "this_week":
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        return week_start <= due_day <= week_end
    if filter_key == "this_month":
        return due_day.year == today.year and due_day.month == today.month
    if filter_key == "overdue":
        return _status(task.get("status")) not in CLOSED_TASK_STATUSES and due_day < today
    return True

def todo_active_deadline_count(summaries: list[dict], filter_key: str) -> int:
    # Sidebar Due Today / Overdue counters show only tasks that can be acted on
    # now. On Hold, Completed, and Cancelled are deliberately excluded.
    if filter_key not in {"due_today", "overdue"}:
        return 0
    return sum(
        1
        for task in _task_records(summaries or [])
        if _status(task.get("status")) in ACTION_NEEDED_STATUSES
        and _deadline_matches_filter(task, filter_key)
    )

def _parse_task_activity_datetime(value) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        # Keep the wall-clock value already chosen by the app/provider. Task
        # activity is primarily used for relative ordering and compact labels.
        return parsed.replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in (
        "%b %d, %Y at %I:%M %p",
        "%B %d, %Y at %I:%M %p",
        "%b %d, %Y %I:%M %p",
        "%B %d, %Y %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    try:
        parsed = parsedate_to_datetime(raw)
        return parsed.replace(tzinfo=None) if parsed is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _task_created_datetime(task: dict) -> datetime | None:
    # Summary-generated timestamps are stored in UTC (SQLite CURRENT_TIMESTAMP /
    # summary_created_at). Convert them to MailMind's display timezone before
    # rendering labels. This prevents UTC values such as 10:50 AM from being
    # shown as local time when the actual Manila time is 6:50 PM.
    for value in (
        task.get("_task_created_at"),
        task.get("summary_created_at"),
        task.get("generated_at"),
    ):
        raw = str(value or "").strip()
        if not raw:
            continue
        try:
            converted = to_display_datetime(raw)
        except Exception:
            converted = None
        if converted is not None:
            return converted.replace(tzinfo=None)
        parsed = _parse_task_activity_datetime(raw)
        if parsed is not None:
            return parsed
    # Legacy fallback only: old stored tasks may predate explicit summary
    # creation timestamps. Their email reference time is the safest baseline.
    return _email_reference_datetime(task)


def _task_activity_datetime(task: dict) -> datetime | None:
    created = _task_created_datetime(task)
    candidates = [created] if created is not None else []
    for entry in (task.get("task_change_history") or []):
        if not isinstance(entry, dict):
            continue
        parsed = None
        # date_display is normally already normalized for the user's UI; use it
        # before raw provider timestamps when both are available.
        for value in (entry.get("date_display"), entry.get("date")):
            parsed = _parse_task_activity_datetime(value)
            if parsed is not None:
                break
        if parsed is not None:
            candidates.append(parsed)
    return max(candidates) if candidates else None


def _task_datetime_sort_number(value: datetime | None) -> int:
    if value is None:
        return -1
    return (
        value.toordinal() * 86_400
        + value.hour * 3_600
        + value.minute * 60
        + value.second
    )


def _task_has_update_history(task: dict) -> bool:
    return any(
        isinstance(entry, dict) and list(entry.get("changes") or [])
        for entry in (task.get("task_change_history") or [])
    )


def _task_latest_activity_key(task: dict) -> tuple[int, int, int]:
    activity = _task_datetime_sort_number(_task_activity_datetime(task))
    created = _task_datetime_sort_number(_task_created_datetime(task))
    # Latest Activity is a true chronological stream. A newly created task is
    # activity too, so a task created at 8:03 PM must sort above a thread that
    # was last updated at 6:09 PM. Updated threads still rise whenever their
    # actual update timestamp is the newest event.
    return -activity, -created, _PRIORITY_RANK[task["priority"]]


def _task_oldest_activity_key(task: dict) -> tuple[int, int, int]:
    activity = _task_datetime_sort_number(_task_activity_datetime(task))
    created = _task_datetime_sort_number(_task_created_datetime(task))
    # Unknown legacy timestamps sort after known tasks in either direction.
    return (activity < 0), activity if activity >= 0 else 0, created if created >= 0 else 0


def _task_newest_created_key(task: dict) -> tuple[int, int]:
    created = _task_datetime_sort_number(_task_created_datetime(task))
    return (created < 0), -created if created >= 0 else 0


def _task_oldest_created_key(task: dict) -> tuple[int, int]:
    created = _task_datetime_sort_number(_task_created_datetime(task))
    return (created < 0), created if created >= 0 else 0


def _task_activity_label(task: dict) -> str:
    activity = _task_activity_datetime(task)
    if activity is None:
        return ""
    prefix = "Updated" if _task_has_update_history(task) else "Created"
    try:
        today = display_now().date()
    except Exception:
        today = date.today()
    if activity.date() == today:
        stamp = activity.strftime("%I:%M %p").lstrip("0")
    elif activity.year == today.year:
        stamp = f"{activity.strftime('%b')} {activity.day}"
    else:
        stamp = f"{activity.strftime('%b')} {activity.day}, {activity.year}"
    return f"{prefix} {stamp}"


def _deadline_sort_number(task: dict) -> tuple[int, int]:
    deadline = _parse_deadline(task)
    if deadline == datetime.max:
        return 1, 0
    seconds = (
        deadline.toordinal() * 86_400
        + deadline.hour * 3_600
        + deadline.minute * 60
        + deadline.second
    )
    return 0, seconds

def _due_soonest_key(task: dict) -> tuple[int, int, int]:
    no_due, value = _deadline_sort_number(task)
    return no_due, value, _PRIORITY_RANK[task["priority"]]

def _due_latest_key(task: dict) -> tuple[int, int, int]:
    no_due, value = _deadline_sort_number(task)
    return no_due, -value, _PRIORITY_RANK[task["priority"]]

def _persist_status(store, task: dict, status: str) -> None:
    parent_uid = str(task.get("_batch_parent_uid") or "").strip()
    source_uid = str(task.get("_batch_source_uid") or "").strip()
    source_index = task.get("_batch_source_index")
    if parent_uid:
        store.update_breakdown_status(
            _FOLDER, parent_uid, source_uid, status, source_index=source_index
        )
    else:
        store.update_status(_FOLDER, str(task.get("uid") or ""), status)

def _append_task_change_history(store, task: dict, changes, *, source: str = "user") -> bool:
    # Persist one history group to either an individual task or a Batch-owned source task.
    parent_uid = str(task.get("_batch_parent_uid") or "").strip()
    source_uid = str(task.get("_batch_source_uid") or "").strip()
    source_index = task.get("_batch_source_index")
    if parent_uid:
        return bool(store.append_breakdown_task_change_history(
            _FOLDER, parent_uid, source_uid, changes,
            source_index=source_index, source=source,
        ))
    return bool(store.append_task_change_history(
        _FOLDER, str(task.get("uid") or ""), changes, source=source
    ))


def _persist_action_item_completion(store, task: dict, action_index: int, completed: bool) -> bool:
    parent_uid = str(task.get("_batch_parent_uid") or "").strip()
    source_uid = str(task.get("_batch_source_uid") or "").strip()
    source_index = task.get("_batch_source_index")
    if parent_uid:
        return bool(store.update_breakdown_action_item_completion(
            _FOLDER,
            parent_uid,
            source_uid,
            action_index,
            completed,
            source_index=source_index,
        ))
    return bool(store.update_action_item_completion(
        _FOLDER, str(task.get("uid") or ""), action_index, completed
    ))

def _persist_all_action_items_completion(store, task: dict, completed_flags) -> bool:
    parent_uid = str(task.get("_batch_parent_uid") or "").strip()
    source_uid = str(task.get("_batch_source_uid") or "").strip()
    source_index = task.get("_batch_source_index")
    flags = [bool(value) for value in (completed_flags or [])]
    if parent_uid:
        return bool(store.update_breakdown_action_items_completion(
            _FOLDER,
            parent_uid,
            source_uid,
            flags,
            source_index=source_index,
        ))
    return bool(store.update_action_items_completion(
        _FOLDER, str(task.get("uid") or ""), flags
    ))

def _auto_status_for_action_progress(current_status: str, states: list[bool]) -> str:
    # Workflow Status is manual-only. Checkbox progress is still saved, but it
    # must not silently move Not Started/In Progress/Completed behind the user's
    # back. The Status picker remains the single authority for workflow state.
    return _status(current_status)

def _requires_cancel_confirmation(current_status: str, requested_status: str) -> bool:
    # Confirm every real status transition either to or from Cancelled.
    current = _status(current_status)
    requested = _status(requested_status)
    return current != requested and "Cancelled" in {current, requested}

def _requires_reopen_confirmation(current_status: str, requested_status: str) -> bool:
    # Confirm when a completed task is reopened into an active workflow state.
    current = _status(current_status)
    requested = _status(requested_status)
    return current == "Completed" and requested in ACTIVE_TASK_STATUSES

def _reopen_deadline_preview(
    task: dict, action_states: list[bool] | None = None
) -> datetime:
    # Return the deadline that would be active after reopening without changing it.
    #
    # Completed action items stay completed when a task is reopened. Their dates do
    # not become active again unless the user explicitly unchecks those items.
    action_entries = _action_deadline_entries(task)
    if action_entries:
        states = None
        if isinstance(action_states, list):
            states = [bool(value) for value in action_states]

        active_entries = []
        for entry in action_entries:
            index = int(entry.get("index", -1))
            completed = bool(entry.get("completed"))
            if states is not None and 0 <= index < len(states):
                completed = states[index]
            if not completed:
                active_entries.append(entry)

        if active_entries:
            return min(entry["parsed"] for entry in active_entries)

        # Reopening an explicitly closed task reactivates its original task-level
        # due date even when every action item remains checked. The checks are
        # preserved as completion history; only the task workflow is reopened.
        return min(entry["parsed"] for entry in action_entries)

    # Email/manual/estimated task deadlines are already display-only and are
    # never rewritten by a status transition, so the existing resolved value is
    # exactly the value that becomes active again after reopening.
    return _parse_deadline(task)

def _metric_counts(tasks: list[dict]) -> dict[str, int]:
    # Status is a complete breakdown of every task, including closed tasks.
    not_started = sum(task["status"] == "Not Started" for task in tasks)
    in_progress = sum(task["status"] == "In Progress" for task in tasks)
    on_hold = sum(task["status"] == "On Hold" for task in tasks)
    completed = sum(task["status"] == "Completed" for task in tasks)
    cancelled = sum(task["status"] == "Cancelled" for task in tasks)

    # Priority and Deadline dashboard metrics describe active workload only.
    # Completed/Cancelled tasks stay visible in Status counts but must not
    # inflate active priority or deadline counters.
    active_tasks = [
        task
        for task in tasks
        if _status(task.get("status")) in ACTIVE_TASK_STATUSES
    ]

    critical_priority = sum(task["priority"] == "Critical" for task in active_tasks)
    high_priority = sum(task["priority"] == "High" for task in active_tasks)
    medium_priority = sum(task["priority"] == "Medium" for task in active_tasks)
    low_priority = sum(task["priority"] == "Low" for task in active_tasks)
    today = date.today()
    due_today = sum(
        (deadline := _parse_deadline(task)) != datetime.max
        and deadline.date() == today
        for task in active_tasks
    )
    overdue = sum(
        (deadline := _parse_deadline(task)) != datetime.max
        and deadline.date() < today
        for task in active_tasks
    )

    # Upcoming deadline counters. "This week" ends on Sunday, while
    # "This month" covers the remaining upcoming dates in the current month.
    week_end = today + timedelta(days=6 - today.weekday())
    if today.month == 12:
        next_month = date(today.year + 1, 1, 1)
    else:
        next_month = date(today.year, today.month + 1, 1)
    month_end = next_month - timedelta(days=1)

    this_week = sum(
        (deadline := _parse_deadline(task)) != datetime.max
        and today < deadline.date() <= week_end
        for task in active_tasks
    )
    this_month = sum(
        (deadline := _parse_deadline(task)) != datetime.max
        and today < deadline.date() <= month_end
        for task in active_tasks
    )

    return {
        "not_started": not_started,
        "in_progress": in_progress,
        "on_hold": on_hold,
        "completed": completed,
        "cancelled": cancelled,
        "critical": critical_priority,
        "high": high_priority,
        "medium": medium_priority,
        "low": low_priority,
        "due_today": due_today,
        "this_week": this_week,
        "this_month": this_month,
        "overdue": overdue,
    }
