# Deadline and task helpers used by the AI Summary list.
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime
import re

_MONTHS = {
    name: number
    for number, names in enumerate([
        (),
        ("january", "jan"), ("february", "feb"), ("march", "mar"),
        ("april", "apr"), ("may",), ("june", "jun"),
        ("july", "jul"), ("august", "aug"), ("september", "sep", "sept"),
        ("october", "oct"), ("november", "nov"), ("december", "dec"),
    ])
    for name in names
}
_MONTH_PATTERN = "|".join(sorted(_MONTHS, key=len, reverse=True))
_WEEKDAYS = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
}
_EMPTY_ITEM_MARKERS = {
    "", "none", "none identified", "none identified.", "n/a", "na",
    "no action required", "no action required.",
}

def _has_real_values(values) -> bool:
    if not values:
        return False
    if isinstance(values, str):
        values = [values]
    return any(
        (text := str(value or "").strip().casefold())
        and text not in _EMPTY_ITEM_MARKERS
        for value in values
    )

def is_task_ready(summary: dict) -> bool:
    return _has_real_values(summary.get("action_items"))


def todo_task_count(summaries: list[dict]) -> int:
    # Count To-Do rows, expanding batch summaries into source-email tasks.
    count = 0
    for item in summaries or []:
        is_batch = str(item.get("record_type") or "manual").strip().casefold() == "batch"
        breakdowns = item.get("email_breakdowns") or []
        if is_batch and breakdowns:
            count += sum(
                1 for email_item in breakdowns
                if isinstance(email_item, dict) and is_task_ready(email_item)
            )
        elif is_task_ready(item):
            count += 1
    return count

def _summary_email_date(summary: dict, fallback: date) -> date:
    raw = summary.get("date") or summary.get("date_display") or ""
    if isinstance(raw, datetime):
        return raw.date()
    if isinstance(raw, date):
        return raw
    text = str(raw).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(text).date()
    except (TypeError, ValueError, OverflowError):
        return fallback

def _append_date(found: list[date], value: date) -> None:
    if value not in found:
        found.append(value)

def _deadline_dates(summary: dict, today: date | None = None) -> list[date]:
    today = today or datetime.now().date()
    email_date = _summary_email_date(summary, today)
    values = summary.get("deadlines") or []
    if isinstance(values, str):
        values = [values]
    found: list[date] = []
    for value in values:
        text = str(value or "")
        for match in re.findall(r"\b(20\d{2})-(\d{2})-(\d{2})\b", text):
            try:
                _append_date(found, date(*(int(part) for part in match)))
            except ValueError:
                pass
        for month_name, day_text, year_text in re.findall(
            rf"\b({_MONTH_PATTERN})\.?\s+(\d{{1,2}})(?:st|nd|rd|th)?"
            rf"(?:,?\s+(20\d{{2}}))?\b", text, flags=re.IGNORECASE
        ):
            year = int(year_text) if year_text else email_date.year
            try:
                candidate = date(year, _MONTHS[month_name.casefold()], int(day_text))
                if not year_text and candidate < email_date - timedelta(days=180):
                    candidate = candidate.replace(year=year + 1)
                _append_date(found, candidate)
            except ValueError:
                pass
        for month_text, day_text, year_text in re.findall(
            r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})\b", text
        ):
            year = int(year_text)
            if year < 100:
                year += 2000
            try:
                _append_date(found, date(year, int(month_text), int(day_text)))
            except ValueError:
                pass
        lowered = text.casefold()
        if re.search(r"\b(today|end of day|eod)\b", lowered):
            _append_date(found, email_date)
        if re.search(r"\btomorrow\b", lowered):
            _append_date(found, email_date + timedelta(days=1))
        weekday_match = re.search(
            r"\b(this|next)\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
            lowered,
        )
        if weekday_match:
            target = _WEEKDAYS[weekday_match.group(2)]
            days_ahead = (target - email_date.weekday()) % 7
            if weekday_match.group(1) == "next" or days_ahead == 0:
                days_ahead += 7
            _append_date(found, email_date + timedelta(days=days_ahead))
    return found

def deadline_matches(summary: dict, window: str, today: date | None = None) -> bool:
    today = today or datetime.now().date()
    dates = [value for value in _deadline_dates(summary, today=today) if value >= today]
    if window == "today" and any(value == today for value in dates):
        return True
    if window == "week" and any(value <= today + timedelta(days=7) for value in dates):
        return True
    if window == "month" and any(
        value.year == today.year and value.month == today.month for value in dates
    ):
        return True
    values = summary.get("deadlines") or []
    if isinstance(values, str):
        values = [values]
    text = " ".join(str(value or "").casefold() for value in values)
    if window == "today":
        return bool(re.search(r"\b(today|end of day|eod)\b", text))
    if window == "week":
        return bool(re.search(r"\b(today|tomorrow|this week|end of week|eow)\b", text))
    if window == "month":
        return bool(re.search(r"\b(today|tomorrow|this week|this month|end of month|eom)\b", text))
    return False
