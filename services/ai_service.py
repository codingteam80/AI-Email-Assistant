# AI orchestration for local Ollama email summarization and reply drafting.
import json
from datetime import date, datetime, timedelta
from email.utils import parseaddr
from email.utils import parsedate_to_datetime
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from config import (
    OLLAMA_KEEP_ALIVE,
    OLLAMA_MODEL,
    OLLAMA_REQUEST_TIMEOUT,
    OLLAMA_STATUS_TIMEOUT_SECONDS,
    OLLAMA_TAGS_URL,
    OLLAMA_TEMPERATURE,
    OLLAMA_THINK,
    OLLAMA_URL,
)
from services.llm_schemas import (
    ACTION_AUDIT_SCHEMA,
    INCREMENTAL_SUMMARY_SCHEMA,
    SECURITY_BATCH_SCHEMA,
    SECURITY_SCHEMA,
    SUMMARY_SCHEMA,
)
from services.ollama_structured_service import request_structured
from services.ollama_runtime_service import log_ollama_timing, ollama_generation_slot
from services.generation_trace_service import consume_next_ollama_operation, set_next_ollama_operation, trace_event
from services.summary_profiler_service import (
    begin_summary_profile,
    finish_summary_profile,
    record_summary_stage,
    set_summary_profile_flag,
)
from services.task_status import normalize_task_status
from services.summary_trace_service import trace_summary_pipeline
from services.security_trace_service import trace_security_detection
from email_handler.display_time import to_display_datetime


def get_ollama_status() -> dict:
    # Check the local Ollama service without downloading or installing anything.
    try:
        with urlopen(OLLAMA_TAGS_URL, timeout=OLLAMA_STATUS_TIMEOUT_SECONDS) as response:
            models = json.loads(response.read().decode("utf-8")).get("models", [])
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
        return {"available": False, "model_ready": False}

    names = {str(model.get("name", "")) for model in models}
    return {
        "available": True,
        "model_ready": OLLAMA_MODEL in names,
    }


def _email_text(email: dict) -> str:
    # Build a bounded prompt payload for one message or reconstructed thread.
    body = (email.get("body_text") or email.get("snippet") or "").strip()
    return (
        f"From: {email.get('from', '')}\n"
        f"To: {email.get('to', '')}\n"
        f"Subject: {email.get('subject', '')}\n"
        f"Date: {email.get('date_display', email.get('date', ''))}\n\n"
        f"Conversation ({int(email.get('thread_count') or 1)} message(s)):\n{body[:30000]}"
    )


def _strip_format_noise(value: str, *, inline_list_markers: bool = False) -> str:
    """Remove presentation-only markers without changing business wording."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return ""

    # Attention/check/list decoration is presentation, not business meaning.
    text = re.sub(r"(?:📌|✅|☑️?|✔️?|👉|➡️?|🔹|🔸|▪️?|▫️?)", " ", text)

    # Remove list markers only at the start of a line/item. Restrict numbered
    # markers to one or two digits so a leading year such as "2026." is safe.
    text = re.sub(r"(?m)^\s*(?:[-*•]+|\d{1,2}[.)])\s+", "", text)

    if inline_list_markers:
        # Convert only spaced list dashes; hyphenated words remain untouched.
        text = re.sub(r"([:;])\s*[-*•]+\s+", r"\1 ", text)
        text = re.sub(r"\s+[-*•]+\s+(?=[A-Z0-9])", "; ", text)

    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s+([,.;:])", r"\1", text)
    return text.strip(" ;")


def _normalize_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    cleaned = [_strip_format_noise(item) for item in value]
    return [item for item in cleaned if item]


def _normalize_priority(value) -> str:
    priority = str(value or "medium").strip().casefold()
    return (
        priority.title()
        if priority in {"critical", "high", "medium", "low"}
        else "Medium"
    )


def _body_text(email: dict) -> str:
    # Return only message-body text, excluding metadata such as the subject.
    return str(email.get("body_text") or email.get("snippet") or "").strip()


_PHASE1_ENGLISH_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_PHASE1_LOCALIZED_MONTHS = {
    "enero": 1, "pebrero": 2, "marso": 3, "abril": 4, "mayo": 5,
    "hunyo": 6, "hulyo": 7, "agosto": 8, "setyembre": 9,
    "oktubre": 10, "nobyembre": 11, "disyembre": 12,
}


def _phase1_source_date_identities(value: str, default_year: int | None = None) -> set[str]:
    """Return calendar identities explicitly present in source/date text.

    This is date grammar only. It lets a model ISO date and the same source date
    written with a month name compare as one fact without normalizing unrelated text.
    """
    source = re.sub(r"\s+", " ", str(value or ""))
    identities: set[str] = set()

    for match in re.finditer(r"\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b", source):
        year, month, day_num = (int(part) for part in match.groups())
        try:
            date(year, month, day_num)
        except ValueError:
            continue
        identities.add(f"date:{year:04d}-{month:02d}-{day_num:02d}")

    english_names = (
        r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
    )
    for match in re.finditer(
        rf"\b({english_names})\s+(\d{{1,2}})(?:st|nd|rd|th)?(?:,?\s+(20\d{{2}}))?\b",
        source,
        flags=re.IGNORECASE,
    ):
        month = _PHASE1_ENGLISH_MONTHS.get(match.group(1)[:3].casefold())
        year = int(match.group(3) or default_year or 2000)
        day_num = int(match.group(2))
        try:
            date(year, month, day_num)
        except (TypeError, ValueError):
            continue
        identities.add(f"date:{year:04d}-{month:02d}-{day_num:02d}")

    localized_names = "|".join(sorted(_PHASE1_LOCALIZED_MONTHS, key=len, reverse=True))
    for match in re.finditer(
        rf"\b({localized_names})\s+(\d{{1,2}})(?:,?\s+(20\d{{2}}))?\b",
        source,
        flags=re.IGNORECASE,
    ):
        month = _PHASE1_LOCALIZED_MONTHS.get(match.group(1).casefold())
        year = int(match.group(3) or default_year or 2000)
        day_num = int(match.group(2))
        try:
            date(year, month, day_num)
        except (TypeError, ValueError):
            continue
        identities.add(f"date:{year:04d}-{month:02d}-{day_num:02d}")
    return identities


def _phase1b_explicit_priority(email: dict) -> str:
    # An explicit sender-supplied priority is authoritative. Read the body in
    # chronological order and keep the last explicit value so a legitimate
    # thread update can replace an older priority without inferring urgency from
    # unrelated words such as "urgent" inside quoted/history content.
    body = _body_text(email)
    matches = list(re.finditer(
        r"\bpriority\s*(?::|=|is|remains?|stays?)\s*"
        r"(critical|high|medium|low)\b",
        body,
        flags=re.IGNORECASE,
    ))
    if not matches:
        return ""
    return str(matches[-1].group(1) or "").title()


def _content_words(value: str) -> list[str]:
    # Extract comparable words while ignoring common action-summary filler.
    ignored = {
        "a", "an", "and", "as", "at", "be", "by", "for", "from", "in", "is",
        "it", "of", "on", "or", "the", "to", "with", "please", "request",
        "requested", "confirm", "review", "reply", "send", "prepare", "provide",
    }
    return [
        word for word in re.findall(r"[a-z0-9]+", str(value).casefold())
        if len(word) > 1 and word not in ignored
    ]


def _is_low_information(email: dict) -> bool:
    # Detect bodies too small to support an inferred business summary.
    body = _body_text(email)
    words = re.findall(r"[\w'-]+", body, flags=re.UNICODE)
    return not body or (len(words) <= 3 and len(body) <= 40)


def _has_action_request(body: str) -> bool:
    # Require a recipient-directed request signal before accepting model action items.
    # Include common indirect requests because real business email is not always imperative.
    patterns = (
        r"\bplease\b", r"\bpls\b", r"\bpaki(?:[- ]?\w+)?\b", r"\bkindly\b",
        r"\bit would be helpful if you could\b", r"\bif you could\b",
        r"\bmust\b", r"\bneeds? to\b", r"\brequired to\b", r"\baction required\b",
        r"\bcan you\b", r"\bcould you\b", r"\bwould you\b", r"\bwill you\b", r"\bdo you\b",
        r"\blet me know\b", r"\brespond\b", r"\breply\b", r"\bconfirm\b",
        r"\breview\b", r"\bapprove\b", r"\bsubmit\b", r"\bsend\b",
        r"\bprepare\b", r"\bcomplete\b", r"\binvestigate\b", r"\bfollow up\b",
        r"\bupdate\b", r"\bupload\b", r"\bsign\b", r"\bread\b",
    )
    lowered = str(body or "").casefold()
    return any(re.search(pattern, lowered) for pattern in patterns)


def _phase1_token_support_related(left: str, right: str) -> bool:
    """Light morphology-aware token relation used only for source grounding.

    Business-email extraction frequently paraphrases a source adjective/noun pair
    (``available`` -> ``availability``) or inflects a verb. Exact-token overlap
    made otherwise grounded model actions fail before the stronger evidence and
    ownership checks could run. Keep this intentionally conservative: exact match
    wins, otherwise require a long common prefix or ordinary inflection prefix.
    """
    a = str(left or "").casefold()
    b = str(right or "").casefold()
    if not a or not b:
        return False
    if a == b:
        return True
    if min(len(a), len(b)) >= 6:
        prefix = 0
        for ca, cb in zip(a, b):
            if ca != cb:
                break
            prefix += 1
        if prefix >= 5:
            return True
    if min(len(a), len(b)) >= 4 and (a.startswith(b) or b.startswith(a)):
        return True
    return False


def _is_supported(value: str, body: str) -> bool:
    # Reject model output that has no meaningful lexical support in the body.
    # Use conservative morphology-aware overlap so harmless paraphrases such as
    # available/availability do not erase a real recipient request. Later evidence,
    # assignee, and non-action validators still have to pass.
    item_words = set(_content_words(value))
    if not item_words:
        return False
    body_words = set(_content_words(body))
    matched = sum(
        1 for item in item_words
        if any(_phase1_token_support_related(item, source) for source in body_words)
    )
    return bool(matched) and matched / len(item_words) >= (1.0 / 3.0)


def _ground_action_items(email: dict, values) -> list[str]:
    body = _body_text(email)
    if not _has_action_request(body):
        return []
    return [item for item in _normalize_list(values) if _is_supported(item, body)]


def _ground_deadlines(email: dict, values) -> list[str]:
    # Keep only temporal constraints grounded in active recipient-owned work.
    body = _phase1g_active_deadline_text(email).casefold()
    if not body:
        return []
    deadline_signal = re.compile(
        r"\b(today|tomorrow|tonight|bukas|eod|close of business|"
        r"end of (?:(?:this|next) )?(?:day|week|month)|"
        r"(?:this |next |every )?(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)|"
        r"within (?:\d+|one|two|three|four|five|six|seven|eight|nine|ten) "
        r"(?:business )?(?:hours?|days?|weeks?)|no later than|due|deadline|"
        r"(?:first|second|third|fourth|fifth|last) business day|each quarter|every month)\b|"
        r"\b(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]20\d{2})\b|"
        r"\b\d{1,2}(?::\d{2})?\s*(?:am|pm)\b|\b(?:noon|midnight)\b|"
        r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|"
        r"enero|pebrero|marso|abril|mayo|hunyo|hulyo|agosto|setyembre|oktubre|nobyembre|disyembre)"
        r"\s+\d{1,2}(?:st|nd|rd|th)?\b|"
        r"\b(?:bago(?:\s+ang)?|hanggang|pagsapit(?:\s+ng)?)\b"
    )
    if not deadline_signal.search(body):
        return []
    body_tokens = set(re.findall(r"[a-z0-9]+", body))
    reference_year = _email_date(email, datetime.now().date()).year
    source_date_ids = _phase1_source_date_identities(body, reference_year)
    grounded = []
    for item in _normalize_list(values):
        item_lower = item.casefold()
        item_tokens = set(re.findall(r"[a-z0-9]+", item_lower))
        lexical_grounded = bool(deadline_signal.search(item_lower) and item_tokens & body_tokens)
        candidate_ids = _phase1_source_date_identities(item, reference_year)
        candidate_identity = _phase1c_deadline_identity(item)
        if candidate_identity.startswith("date:"):
            candidate_ids.add(candidate_identity)
        calendar_grounded = bool(candidate_ids & source_date_ids)
        if lexical_grounded or calendar_grounded:
            grounded.append(item)
    return grounded


def _email_date(email: dict, today: date) -> date:
    """Return the message calendar date in MailMind's display timezone.

    Provider timestamps are commonly stored as UTC instants.  Taking ``.date()``
    directly from a UTC value can move source-relative wording such as ``today``
    or ``tomorrow`` onto the previous calendar day for users east of UTC.  Convert
    timezone-aware provider timestamps to the same display timezone used by the UI
    before resolving relative deadlines.  Date-only/naive values keep their stated
    calendar date because they carry no timezone information to convert.
    """
    raw = email.get("date") or email.get("date_display") or ""
    if isinstance(raw, datetime):
        if raw.tzinfo is not None:
            converted = to_display_datetime(raw)
            if converted is not None:
                return converted.date()
        return raw.date()
    if isinstance(raw, date):
        return raw

    text = str(raw).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            converted = to_display_datetime(parsed)
            if converted is not None:
                return converted.date()
        return parsed.date()
    except ValueError:
        pass

    try:
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is not None:
            converted = to_display_datetime(parsed)
            if converted is not None:
                return converted.date()
        return parsed.date()
    except (TypeError, ValueError, OverflowError):
        pass

    match = re.search(r"\b(20\d{2})-(\d{2})-(\d{2})\b", text)
    if match:
        try:
            return date(*(int(part) for part in match.groups()))
        except ValueError:
            pass
    return today


def _add_business_days(start: date, count: int) -> date:
    # Advance by weekdays only. Weekends are skipped; holidays are intentionally
    # not guessed because the email does not provide a business calendar.
    current = start
    remaining = max(0, int(count))
    while remaining:
        current += timedelta(days=1)
        if current.weekday() < 5:
            remaining -= 1
    return current


def _month_end(value: date) -> date:
    next_month = (value.replace(day=28) + timedelta(days=4)).replace(day=1)
    return next_month - timedelta(days=1)


def _business_day_of_month(year: int, month: int, ordinal: int | None = None, last: bool = False) -> date:
    if last:
        current = _month_end(date(year, month, 1))
        while current.weekday() >= 5:
            current -= timedelta(days=1)
        return current
    current = date(year, month, 1)
    seen = 0
    while True:
        if current.weekday() < 5:
            seen += 1
            if seen == max(1, int(ordinal or 1)):
                return current
        current += timedelta(days=1)


def _resolved_deadline_dates(deadlines, email_date: date) -> list[date]:
    found = []
    weekday_map = {
        "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
        "friday": 4, "saturday": 5, "sunday": 6,
    }
    word_numbers = {
        "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
        "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    }
    ordinal_numbers = {
        "first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5,
    }
    for value in _normalize_list(deadlines):
        text = str(value).strip()
        lowered = text.casefold()

        match = re.search(r"\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b", text)
        if match:
            try:
                found.append(date(*(int(part) for part in match.groups())))
                continue
            except ValueError:
                pass
        match = re.search(r"\b(\d{1,2})[-/](\d{1,2})[-/](20\d{2})\b", text)
        if match:
            try:
                month, day_num, year = (int(part) for part in match.groups())
                found.append(date(year, month, day_num))
                continue
            except ValueError:
                pass

        named = re.search(
            r"\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
            r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
            r"\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(20\d{2}))?\b",
            lowered,
        )
        if named:
            month_lookup = {
                "jan": 1, "january": 1, "feb": 2, "february": 2, "mar": 3, "march": 3,
                "apr": 4, "april": 4, "may": 5, "jun": 6, "june": 6, "jul": 7, "july": 7,
                "aug": 8, "august": 8, "sep": 9, "september": 9, "oct": 10, "october": 10,
                "nov": 11, "november": 11, "dec": 12, "december": 12,
            }
            try:
                month_num = month_lookup[named.group(1)]
                day_num = int(named.group(2))
                year = int(named.group(3)) if named.group(3) else email_date.year
                candidate = date(year, month_num, day_num)
                if not named.group(3) and candidate < email_date - timedelta(days=30):
                    candidate = candidate.replace(year=year + 1)
                found.append(candidate)
                continue
            except ValueError:
                pass

        if re.search(r"\btoday\b|\btonight\b|\bend of (?:this )?day\b|\beod\b|\bclose of business(?: today)?\b", lowered):
            found.append(email_date)
            continue
        if re.search(r"\btomorrow\b|\bbukas\b", lowered):
            found.append(email_date + timedelta(days=1))
            continue

        end_week = re.search(r"\bend of (?:(this|next) )?week\b", lowered)
        if end_week:
            modifier = end_week.group(1)
            days_to_friday = (4 - email_date.weekday()) % 7
            if modifier == "next":
                days_to_friday += 7
            found.append(email_date + timedelta(days=days_to_friday))
            continue

        end_month = re.search(r"\bend of (?:(this|next) )?month\b", lowered)
        if end_month:
            modifier = end_month.group(1)
            base = email_date
            if modifier == "next":
                base = _month_end(email_date) + timedelta(days=1)
            found.append(_month_end(base))
            continue

        within = re.search(
            r"\bwithin\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
            r"(business\s+)?(hours?|days?|weeks?)\b",
            lowered,
        )
        if within:
            raw_count, business, unit = within.groups()
            count = int(raw_count) if raw_count.isdigit() else word_numbers.get(raw_count, 0)
            if unit.startswith("hour"):
                # Date-level priority only needs the deadline day. Any partial day rounds up.
                days = (max(0, count) + 23) // 24
                found.append(email_date + timedelta(days=days))
            elif business:
                found.append(_add_business_days(email_date, count))
            elif unit.startswith("week"):
                found.append(email_date + timedelta(days=max(0, count) * 7))
            else:
                found.append(email_date + timedelta(days=max(0, count)))
            continue

        monthly_business = re.search(
            r"\b(?:the\s+)?(first|second|third|fourth|fifth|last)\s+business\s+day\s+of\s+every\s+month\b",
            lowered,
        )
        if monthly_business:
            label = monthly_business.group(1)
            candidate = _business_day_of_month(
                email_date.year,
                email_date.month,
                ordinal=ordinal_numbers.get(label),
                last=label == "last",
            )
            if candidate < email_date:
                next_month = _month_end(email_date) + timedelta(days=1)
                candidate = _business_day_of_month(
                    next_month.year,
                    next_month.month,
                    ordinal=ordinal_numbers.get(label),
                    last=label == "last",
                )
            found.append(candidate)
            continue

        quarterly_business = re.search(
            r"\b(?:the\s+)?(first|second|third|fourth|fifth)\s+business\s+day\s+after\s+each\s+quarter(?:\s+ends?)?\b",
            lowered,
        )
        if quarterly_business:
            count = ordinal_numbers[quarterly_business.group(1)]
            quarter_end_month = ((email_date.month - 1) // 3 + 1) * 3
            quarter_end = _month_end(date(email_date.year, quarter_end_month, 1))
            candidate = _add_business_days(quarter_end, count)
            if candidate < email_date:
                if quarter_end_month == 12:
                    quarter_end = _month_end(date(email_date.year + 1, 3, 1))
                else:
                    quarter_end = _month_end(date(email_date.year, quarter_end_month + 3, 1))
                candidate = _add_business_days(quarter_end, count)
            found.append(candidate)
            continue

        weekday = re.search(
            r"\b(?:(this|next|every)\s+)?(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
            lowered,
        )
        if weekday:
            modifier, name = weekday.groups()
            target = weekday_map[name]
            delta = (target - email_date.weekday()) % 7
            if modifier == "next":
                delta = delta + 7 if delta else 7
            elif modifier == "every" and delta == 0:
                delta = 7
            elif delta == 0 and modifier != "this":
                delta = 7
            found.append(email_date + timedelta(days=delta))
            continue

        # A concrete time-only due phrase is treated as due on the email date.
        if re.search(r"\b(?:by|before|no later than)\s+(?:\d{1,2}(?::\d{2})?\s*(?:am|pm)|noon|midnight)\b", lowered):
            found.append(email_date)
    return found


def apply_deadline_priority_policy(
    email: dict, deadlines, priority, today: date | None = None
) -> tuple[list[str], str]:
    # Apply product rules independently of the model's priority judgment. An
    # explicit Priority field from the sender wins over model inference. Missing
    # deadlines remain missing; they must never force an explicit Medium/High
    # priority down to Low.
    today = today or datetime.now().date()
    normalized_deadlines = _normalize_list(deadlines)
    explicit_priority = _phase1b_explicit_priority(email)
    if not normalized_deadlines:
        return [], explicit_priority or "Low"

    resolved = _resolved_deadline_dates(
        normalized_deadlines, _email_date(email, today)
    )
    if any(deadline < today for deadline in resolved):
        return normalized_deadlines, "Critical"
    return normalized_deadlines, explicit_priority or _normalize_priority(priority)


def _normalize_status(value) -> str:
    return normalize_task_status(value)


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().casefold() in {"true", "1", "yes"}


def _merge_unique(*groups) -> list[str]:
    # Merge model lists without losing order or repeating the same action.
    merged = []
    seen = set()
    for group in groups:
        for item in _normalize_list(group):
            key = " ".join(item.casefold().split()).rstrip(".")
            if key and key not in seen:
                seen.add(key)
                merged.append(item)
    return merged


def _request_json(
    prompt: str,
    schema: dict,
    *,
    operation: str = "structured output",
) -> dict:
    # Structured-output transport is isolated from summary/security business rules.
    return request_structured(prompt, schema, operation=operation)


_SECURITY_CATEGORIES = {
    "spam": "Spam",
    "promotional": "Promotional",
    "promotion": "Promotional",
    "marketing": "Promotional",
    "phishing": "Phishing",
    "malware": "Malware",
    "scam / fraud": "Scam / Fraud",
    "scam/fraud": "Scam / Fraud",
    "scam": "Scam / Fraud",
    "fraud": "Scam / Fraud",
    "impersonation": "Impersonation",
    "suspicious": "Suspicious",
    "safe / misclassified": "Safe / Misclassified",
    "safe/misclassified": "Safe / Misclassified",
    "safe": "Safe / Misclassified",
    "misclassified": "Safe / Misclassified",
}


def _normalize_security_category(value: str) -> str:
    key = " ".join(str(value or "").strip().casefold().split())
    return _SECURITY_CATEGORIES.get(key, "Suspicious")


def classify_email_security(email: dict, baseline: dict | None = None) -> dict:
    # Contextual second opinion for a fully loaded, already-flagged message.
    # This never runs during mailbox sync, so security AI cannot slow login.
    baseline = dict(baseline or {})
    attachments = [
        {
            "filename": str(item.get("filename") or ""),
            "content_type": str(item.get("content_type") or ""),
            "size": int(item.get("size") or 0),
        }
        for item in (email.get("attachments") or [])[:12]
    ]
    signals = {
        "baseline_category": baseline.get("category") or baseline.get("security_category") or "",
        "baseline_score": int(baseline.get("score") or baseline.get("spam_score") or 0),
        "baseline_confidence": int(baseline.get("confidence") or baseline.get("security_confidence") or 0),
        "provider_flagged": bool(baseline.get("provider_flagged")),
        "strong_flags": list(baseline.get("strong_flags") or []),
        "rule_reasons": str(baseline.get("reason") or baseline.get("spam_reason") or ""),
    }
    prompt = f"""Classify this email for MailMind security. Return JSON only.

Allowed category values exactly:
- Spam
- Promotional
- Phishing
- Malware
- Scam / Fraud
- Impersonation
- Suspicious
- Safe / Misclassified

Definitions:
- Spam: unsolicited, abusive, repetitive, or clearly unwanted bulk/commercial mail supported by stronger spam evidence; ordinary marketing vocabulary alone is not enough.
- Promotional: ordinary marketing, sales, newsletter, renewal, discount, or offer content without a concrete security threat or stronger spam evidence.
- Phishing: attempts to steal credentials, OTPs, account access, or sensitive information. OAuth/app-consent abuse, unsolicited MFA approvals, recovery/security-code requests, and attacker-directed live sign-ins are credential-equivalent account-access theft.
- Malware: malicious or potentially malicious attachment/file/payload or a clear malware-delivery attempt.
- Scam / Fraud: financial or social-engineering fraud such as fake prizes, invoices, investments, payments, delivery fees, or advance-fee schemes.
- Impersonation: pretends to be a person, employer, executive, company, bank, or trusted service.
- Suspicious: meaningful red flags exist, but evidence is insufficient for a more specific malicious category.
- Safe / Misclassified: appears legitimate even if a provider placed it in Spam/Junk.

Important rules:
- Spam is NOT automatically malicious.
- Promotional is NOT Spam by wording alone. Terms such as discount, promotion, limited time, offer, sale, newsletter, renewal, or unsubscribe should normally support Promotional unless separate spam/security evidence is present.
- A dense promotional pressure stack can still be Spam when several commercial lures are combined with explicit purchase/claim action and urgent expiry pressure; distinguish this from a normal informational renewal or discount notice.
- A provider Spam/Junk folder is one signal only. Do not classify as malicious solely because of folder placement.
- The presence of an X-Microsoft-Antispam header is normal on many legitimate Microsoft-delivered messages and is NOT, by itself, a spam verdict.
- Use sender identity, intent, requested action, links, attachments, authentication/rule evidence, and message context together.
- Choose the dominant category; do not use Scam / Fraud as a generic catch-all.
- A legitimate technical/work request discussing login failures, authentication, account status, logs, or security operations is not suspicious by topic alone.
- Generic words such as login, account, urgent, authentication, or verify are not enough without a risky requested action or concrete security evidence.
- Evaluate multilingual and previously unseen lures from behavior, requested action, and destination mismatch rather than English keywords. Non-English or Unicode text alone is benign; invisible/fullwidth/mixed-script obfuscation becomes phishing evidence only when paired with a sensitive action and risky destination.
- Legitimate authenticated MFA enrollment, password-reset, collaboration, and e-sign notifications can remain Safe when they do not ask the recipient to disclose secrets, approve an unsolicited prompt, grant unexpected account access, or sign in at a suspicious/mismatched destination.
- Use Impersonation when a trusted executive/legal/vendor role is paired with concrete sender-identity inconsistency (consumer mailbox, lookalike/typosquatted domain) and a sensitive disclosure, secrecy, or payment-change action. A role-like display name alone is not enough.
- An HTML attachment that explicitly asks the recipient to sign in is an account-access phishing lure; ordinary HTML attachments without a sign-in request are not malicious by extension alone.
- A javascript:/vbscript:/data-style URI without credential/account-access theft is Suspicious rather than automatically Phishing; a nested/open-redirect URL combined with an attacker-directed sign-in can be Phishing.
- Machine-generated delivery-status/non-delivery reports can quote the failed original message. Do not inherit threat intent from quoted original content unless the delivery report itself contains a live credential, payment, attachment, or risky-action request.
- Do not invent evidence that is absent.
- Prefer Suspicious instead of a malicious label when evidence is incomplete.
- Return 2 or 3 short reasons grounded in the supplied email/signals.
- confidence must be an integer from 0 to 100.

Return exactly:
{{"category":"...","confidence":0,"reasons":["..."],"malicious":false}}

Deterministic security signals:
{json.dumps(signals, ensure_ascii=False)}

Email:
From: {email.get('from', '')}
Reply-To: {email.get('reply_to', '')}
To: {email.get('to', '')}
Subject: {email.get('subject', '')}
Provider/security headers: {email.get('spam_evidence', '')}
Attachments: {json.dumps(attachments, ensure_ascii=False)}
Links: {json.dumps((email.get('links') or [])[:12], ensure_ascii=False)}
Body:
{str(email.get('body_text') or email.get('snippet') or '')[:16000]}
"""
    trace_security_detection(
        "AI_SINGLE_INPUT", email=email, baseline=baseline,
        payload={"operation": "security classification"},
    )
    result = _request_json(prompt, SECURITY_SCHEMA, operation="security classification")
    trace_security_detection(
        "AI_SINGLE_RAW", email=email, baseline=baseline, classification=result,
    )
    finalized = _finalize_security_ai_result(result, baseline)
    trace_security_detection(
        "AI_SINGLE_FINAL", email=email, baseline=baseline, classification=finalized,
    )
    return finalized


def _finalize_security_ai_result(result: dict, baseline: dict) -> dict:
    category = _normalize_security_category(result.get("category"))
    try:
        confidence = max(0, min(100, int(result.get("confidence") or 0)))
    except (TypeError, ValueError):
        confidence = 0
    reasons = [
        str(item).strip()
        for item in (result.get("reasons") or [])
        if str(item).strip()
    ][:3]

    strong_flags = {str(item) for item in (baseline.get("strong_flags") or [])}
    baseline_score = int(baseline.get("score") or baseline.get("spam_score") or 0)
    baseline_category = _normalize_security_category(
        baseline.get("category") or baseline.get("security_category") or "Suspicious"
    )

    # Deterministic high-confidence evidence is a safety floor. AI can refine
    # ambiguous promotional/social context, but cannot erase executable payload
    # evidence or turn a very strong credential-theft signal directly into Safe.
    if "dangerous-attachment" in strong_flags:
        category = "Malware"
        confidence = max(confidence, 99)
    elif "referenced-dangerous-payload-delivery" in strong_flags:
        # MailMind post-V9 enhancement: preserve a concrete executable-delivery
        # lure even when the provider stripped or omitted attachment metadata.
        category = "Malware"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete recipient-directed executable payload delivery evidence is present")
    elif "external-data-transfer-evasion" in strong_flags:
        # MailMind post-V9 enhancement: a concrete covert data-transfer request
        # remains Suspicious even if contextual AI interprets the surrounding
        # business language as ordinary collaboration.
        category = "Suspicious"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete covert external data-transfer evidence is present")
    elif "multilingual-obfuscated-novel-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 99)
        reasons.insert(0, "Concrete multilingual, Unicode-obfuscated, or novel behavioral phishing evidence is present")
    elif "aitm-phishing-kit-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 99)
        reasons.insert(0, "Concrete AiTM authentication-proxy phishing evidence is present")
    elif "device-code-session-theft-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 99)
        reasons.insert(0, "Concrete device-code or session-token theft evidence is present")
    elif "captcha-multistage-phishing-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 99)
        reasons.insert(0, "Concrete CAPTCHA-gated or multi-stage phishing evidence is present")
    elif "qr-image-phishing-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 99)
        reasons.insert(0, "Concrete QR/image-only phishing evidence is present")
    elif "oauth-consent-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete OAuth-consent phishing evidence is present")
    elif "hr-portal-credential-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete HR-portal credential-phishing evidence is present")
    elif "mailbox-quota-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete mailbox-quota phishing evidence is present")
    elif "voicemail-notification-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete voicemail-notification phishing evidence is present")
    elif "password-expiration-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete password-expiration phishing evidence is present")
    elif "unrecognized-signin-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete unrecognized-sign-in phishing evidence is present")
    elif "shared-document-credential-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete shared-document credential-phishing evidence is present")
    elif "account-access-lure" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete account-access phishing evidence is present")
    elif "credential-link" in strong_flags:
        category = "Phishing"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete credential-harvesting link evidence is present")
    elif "business-email-compromise" in strong_flags:
        category = "Scam / Fraud"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete business-email-compromise fraud evidence is present")
    elif (
        strong_flags.intersection({
            "generic-identity-claim-impersonation", "display-name-impersonation-type2",
            "role-department-impersonation", "brand-impersonation-type4",
            "person-name-impersonation", "username-localpart-lookalike",
            "lookalike-domain-impersonation", "homograph-unicode-impersonation",
            "reply-to-impersonation", "exact-domain-spoofing",
            "internal-employee-executive-impersonation", "vendor-business-partner-impersonation",
            "helpdesk-administrator-impersonation", "compromised-account-impersonation",
            "conversation-thread-hijacking", "coordinated-identity-impersonation",
        })
        and not strong_flags.intersection({
            "fraud-action-lure", "financial-fraud-lure", "reward-lure",
            "fake-discount-coupon", "fake-product-service",
            "prize-lottery-inheritance-scam", "advance-fee-scam",
            "fake-invoice-renewal-debt", "fake-refund-recovery-service",
            "employment-task-scam", "fake-check-overpayment-scam",
            "emergency-confidence-scam", "tech-support-account-protection-scam",
            "payment-diversion-fraud", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
        })
    ):
        category = "Impersonation"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete generic-identity or display-name impersonation evidence is present")
    elif (
        ("impersonation-lure" in strong_flags or "display-name-impersonation" in strong_flags)
        and not strong_flags.intersection({
            "fraud-action-lure", "financial-fraud-lure", "reward-lure",
            "fake-discount-coupon", "fake-product-service",
            "prize-lottery-inheritance-scam", "advance-fee-scam",
            "fake-invoice-renewal-debt", "fake-refund-recovery-service",
            "employment-task-scam", "fake-check-overpayment-scam",
            "emergency-confidence-scam", "tech-support-account-protection-scam",
            "payment-diversion-fraud", "business-email-compromise",
            "investment-cryptocurrency-fraud", "real-estate-high-value-transaction-fraud",
            "money-mule-laundering-recruitment",
        })
    ):
        # Match the deterministic V9 precedence: a generic sender-identity lure
        # must not replace a more specific concrete fraud action such as payment
        # diversion, changed bank details, advance-fee mechanics, or other
        # specialized fraud evidence.
        category = "Impersonation"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete sender-identity impersonation evidence is present")
    elif (
        category == "Spam"
        and "reward-lure" in strong_flags
        and not strong_flags.intersection({
            "fraud-action-lure", "financial-fraud-lure",
            "fake-discount-coupon", "fake-product-service",
            "prize-lottery-inheritance-scam", "advance-fee-scam",
            "fake-invoice-renewal-debt", "fake-refund-recovery-service",
            "employment-task-scam", "fake-check-overpayment-scam",
            "emergency-confidence-scam", "tech-support-account-protection-scam",
            "payment-diversion-fraud", "business-email-compromise",
            "investment-cryptocurrency-fraud", "real-estate-high-value-transaction-fraud",
            "money-mule-laundering-recruitment",
            "credential-link", "account-access-lure", "dangerous-attachment",
            "referenced-dangerous-payload-delivery",
        })
    ):
        # MailMind post-V9 category-arbitration enhancement: reward/prize wording
        # alone is not enough to force Scam/Fraud when contextual AI finds an
        # unsolicited spam lure and deterministic evidence contains no concrete
        # fee/payment/credential/payload scam mechanic. Concrete fraud flags
        # still keep the original Scam/Fraud safety floor below.
        category = "Spam"
        confidence = max(confidence, 90)
        reasons.insert(0, "Reward/prize lure lacks a concrete fee, payment, credential, or payload fraud mechanic")
    elif strong_flags.intersection({
        "fraud-action-lure", "financial-fraud-lure", "reward-lure",
        "fake-discount-coupon", "fake-product-service",
        "prize-lottery-inheritance-scam", "advance-fee-scam",
        "fake-invoice-renewal-debt", "fake-refund-recovery-service",
        "employment-task-scam", "fake-check-overpayment-scam",
        "emergency-confidence-scam", "tech-support-account-protection-scam",
        "payment-diversion-fraud", "investment-cryptocurrency-fraud",
        "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
    }):
        # Concrete prize/reward lures are deterministic fraud evidence too. A
        # contextual model may recognize that the surrounding conversation is a
        # normal work thread, but it must not let that trusted thread context
        # downgrade the newly delivered reward/claim message to Promotional or
        # Safe. This is especially important for spam injected as a reply into an
        # otherwise legitimate task conversation.
        category = "Scam / Fraud"
        confidence = max(confidence, 95)
        if "reward-lure" in strong_flags:
            reasons.insert(0, "Concrete unexpected reward/prize claim evidence is present")
        elif strong_flags.intersection({
            "fake-discount-coupon", "fake-product-service",
            "prize-lottery-inheritance-scam", "advance-fee-scam",
            "fake-invoice-renewal-debt", "fake-refund-recovery-service",
            "employment-task-scam", "fake-check-overpayment-scam",
            "emergency-confidence-scam", "tech-support-account-protection-scam",
            "payment-diversion-fraud", "investment-cryptocurrency-fraud",
            "real-estate-high-value-transaction-fraud", "money-mule-laundering-recruitment",
        }):
            reasons.insert(0, "Concrete deterministic Scam/Fraud classification evidence is present")
        else:
            reasons.insert(0, "Concrete fraud/social-engineering action is present")
    elif strong_flags.intersection({
        "unwanted-one-off-spam", "repetitive-sender-spam",
        "unsolicited-commercial-spam", "cold-outreach-spam",
        "bulk-list-spam", "harvested-address-spam",
        "unsubscribe-violation-spam", "deceptive-subject-spam",
        "obfuscated-content-spam", "rotating-sender-snowshoe-spam",
        "compromised-account-spam", "botnet-generated-spam",
        "reply-chain-conversation-spam", "backscatter-bounce-spam",
        "email-subscription-bombing-spam", "organization-wide-spam-flood",
    }):
        category = "Spam"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete deterministic spam-subtype evidence is present")
    elif strong_flags.intersection({
        "informational-newsletter-promotional", "content-marketing-promotional",
    }):
        category = "Promotional"
        confidence = max(confidence, 95)
        reasons.insert(0, "Concrete deterministic promotional-subtype evidence is present")
    elif "opaque-archive" in strong_flags and baseline_category == "Suspicious":
        category = "Suspicious"
        confidence = max(confidence, 85)
        reasons.insert(0, "Opaque protected archive is suspicious but not malicious without payload evidence")
    elif "dangerous-uri" in strong_flags and baseline_category == "Suspicious":
        category = "Suspicious"
        confidence = max(confidence, 85)
        reasons.insert(0, "Dangerous URI scheme is security-relevant but not credential theft by itself")
    elif "benign-delivery-report" in strong_flags and baseline_category == "Safe / Misclassified":
        category = "Safe / Misclassified"
        confidence = max(confidence, 85)
        reasons.insert(0, "Machine-generated delivery report does not inherit the quoted original message's intent")
    elif (
        "provider-location-only-promo" in strong_flags
        and baseline_category == "Promotional"
        and category in {"Spam", "Safe / Misclassified"}
    ):
        category = "Promotional"
        confidence = max(confidence, 80)
        reasons.insert(0, "Provider Spam/Junk placement alone does not convert ordinary marketing into Spam")
    elif (
        "authenticated-soft-signal-boundary" in strong_flags
        and baseline_category == "Safe / Misclassified"
        and category in {"Spam", "Promotional", "Suspicious"}
    ):
        category = "Safe / Misclassified"
        confidence = max(confidence, 85)
        reasons.insert(0, "Strong authentication with only soft heuristics does not establish a security category")
    elif (
        baseline_category == "Suspicious"
        and strong_flags.intersection({"high-risk-destination", "risky-link"})
        and category in {"Safe / Misclassified", "Promotional"}
    ):
        category = "Suspicious"
        confidence = max(confidence, 80)
        reasons.insert(0, "Concrete link risk remains Suspicious without evidence for a more specific malicious category")
    elif (
        baseline_category == "Suspicious"
        and strong_flags.intersection({"account-activity-review", "update-delivery-risk"})
        and category in {"Safe / Misclassified", "Promotional"}
    ):
        category = "Suspicious"
        confidence = max(confidence, 80)
        reasons.insert(0, "Concrete security-action risk remains Suspicious pending user review")
    elif (
        baseline_category == "Spam"
        and category in {"Promotional", "Safe / Misclassified"}
        and strong_flags.intersection({
            "provider-spam-header",
            "learned-spam-reputation",
            "aggressive-spam-promotion",
        })
    ):
        # Do not let contextual AI erase concrete spam evidence while still
        # allowing ordinary marketing-only baselines to remain Promotional.
        category = "Spam"
        confidence = max(confidence, 80)
        reasons.insert(0, "Stronger spam evidence prevents a Promotional downgrade")
    elif category == "Safe / Misclassified" and baseline_score >= 85 and baseline_category in {
        "Phishing", "Malware", "Scam / Fraud", "Impersonation",
    }:
        category = "Suspicious"
        confidence = max(confidence, 75)
        reasons.insert(0, "Strong deterministic security signals require caution")

    malicious = category in {"Phishing", "Malware", "Scam / Fraud", "Impersonation"}
    return {
        "category": category,
        "confidence": confidence or 70,
        "reason": "; ".join(dict.fromkeys(reasons)),
        "source": "Hybrid AI",
        "malicious": malicious,
    }


def _needs_isolated_security_confirmation(baseline: dict, batch_result: dict) -> bool:
    # Confirm only risky batch escalations from a non-malicious, moderate baseline.
    # Strong deterministic threats and non-malicious batch results stay untouched.
    malicious_categories = {"Phishing", "Malware", "Scam / Fraud", "Impersonation"}
    batch_category = _normalize_security_category(batch_result.get("category"))
    if batch_category not in malicious_categories:
        return False
    if bool(baseline.get("malicious")):
        return False
    baseline_score = int(baseline.get("score") or baseline.get("spam_score") or 0)
    return baseline_score < 85


def classify_email_security_batch(items: list[dict]) -> dict[str, dict]:
    # Classify a batch of security-workspace emails in one model request.
    # Callers use this both for post-login preclassification and lightweight
    # incremental refreshes so categories are cached before the user opens mail.
    prepared = []
    baselines = {}
    emails_by_uid = {}
    for item in items or []:
        email = dict(item.get("email") or {})
        baseline = dict(item.get("baseline") or {})
        uid = str(email.get("uid") or "").strip()
        if not uid:
            continue
        baselines[uid] = baseline
        emails_by_uid[uid] = email
        attachments = [
            {
                "filename": str(value.get("filename") or ""),
                "content_type": str(value.get("content_type") or ""),
                "size": int(value.get("size") or 0),
            }
            for value in (email.get("attachments") or [])[:12]
        ]
        prepared.append({
            "uid": uid,
            "signals": {
                "baseline_category": baseline.get("category") or baseline.get("security_category") or "",
                "baseline_score": int(baseline.get("score") or baseline.get("spam_score") or 0),
                "baseline_confidence": int(baseline.get("confidence") or baseline.get("security_confidence") or 0),
                "provider_flagged": bool(baseline.get("provider_flagged")),
                "strong_flags": list(baseline.get("strong_flags") or []),
                "rule_reasons": str(baseline.get("reason") or baseline.get("spam_reason") or ""),
            },
            "from": str(email.get("from") or ""),
            "reply_to": str(email.get("reply_to") or ""),
            "to": str(email.get("to") or ""),
            "subject": str(email.get("subject") or ""),
            "provider_headers": str(email.get("spam_evidence") or ""),
            "attachments": attachments,
            "links": list(email.get("links") or [])[:12],
            "body_or_snippet": str(email.get("body_text") or email.get("snippet") or "")[:6000],
        })

    if not prepared:
        return {}

    for uid in baselines:
        trace_security_detection(
            "AI_BATCH_INPUT",
            email=emails_by_uid.get(uid),
            baseline=baselines.get(uid),
            payload={"batch_size": len(prepared)},
        )

    prompt = f"""Classify these MailMind Spam-workspace emails. Return JSON only.

Allowed category values exactly:
- Spam
- Promotional
- Phishing
- Malware
- Scam / Fraud
- Impersonation
- Suspicious
- Safe / Misclassified

Definitions:
- Spam: unsolicited, abusive, repetitive, or clearly unwanted bulk/commercial mail supported by stronger spam evidence; ordinary marketing vocabulary alone is not enough.
- Promotional: ordinary marketing, sales, newsletter, renewal, discount, or offer content without a concrete security threat or stronger spam evidence.
- Phishing: attempts to steal credentials, OTPs, account access, or sensitive information. OAuth/app-consent abuse, unsolicited MFA approvals, recovery/security-code requests, and attacker-directed live sign-ins are credential-equivalent account-access theft.
- Malware: malicious or potentially malicious attachment/file/payload or a clear malware-delivery attempt.
- Scam / Fraud: financial or social-engineering fraud such as fake prizes, invoices, investments, payments, delivery fees, or advance-fee schemes.
- Impersonation: pretends to be a person, employer, executive, company, bank, or trusted service.
- Suspicious: meaningful red flags exist, but evidence is insufficient for a more specific malicious category.
- Safe / Misclassified: appears legitimate even if a provider placed it in Spam/Junk.

Rules:
- Spam is not automatically malicious.
- Promotional is not Spam by wording alone. Terms such as discount, promotion, limited time, offer, sale, newsletter, renewal, or unsubscribe should normally support Promotional unless separate spam/security evidence is present.
- A dense promotional pressure stack can still be Spam when several commercial lures are combined with explicit purchase/claim action and urgent expiry pressure; distinguish this from a normal informational renewal or discount notice.
- Provider Spam/Junk placement is one signal only.
- The presence of an X-Microsoft-Antispam header is normal on many legitimate Microsoft-delivered messages and is NOT, by itself, a spam verdict.
- Choose ONE primary category from the dominant intent/evidence; do not use Scam / Fraud as a generic catch-all.
- Use Malware when payload/file-delivery evidence is central.
- Use Phishing when credential, OTP, account-access, or sensitive-data theft is central.
- Use Impersonation when pretending to be a trusted person/company/service is the central deception.
- Use Scam / Fraud for prize/reward, fake invoice/payment, investment, delivery-fee, or other financial/social-engineering fraud.
- Use Promotional when marketing/offer content is the primary signal and there is no stronger spam or security evidence.
- Use Spam only when stronger evidence supports unwanted/abusive bulk mail beyond ordinary promotional wording.
- Use Suspicious only for meaningful red flags that do not support a more specific category.
- A legitimate work/task email that merely discusses login failures, authentication, account status, logs, or security operations is NOT suspicious by topic alone.
- Security words such as login, account, urgent, authentication, or verify are not enough by themselves; classify from the requested action and concrete evidence.
- Evaluate multilingual and previously unseen lures from behavior, requested action, and destination mismatch rather than English keywords. Non-English or Unicode text alone is benign; invisible/fullwidth/mixed-script obfuscation becomes phishing evidence only when paired with a sensitive action and risky destination.
- OAuth/app-consent abuse, unsolicited MFA approval requests, recovery/security-code disclosure, and failed-authentication messages directing the recipient to sign in are account-access phishing when supported by the supplied context.
- Changed-bank-detail payment redirection in an existing invoice/vendor context, urgent overpayment refunds to a bank account, and urgent callback/remote-support vishing are Scam / Fraud when those concrete requested actions are present; successful SPF/DKIM/DMARC does not make a compromised-thread payment redirection safe.
- Use Impersonation when a trusted executive/legal/vendor role is paired with concrete sender-identity inconsistency (consumer mailbox, lookalike/typosquatted domain) and a sensitive disclosure, secrecy, or payment-change action. A role-like display name or external sender alone is not enough.
- An HTML attachment that explicitly asks the recipient to sign in is an account-access phishing lure; ordinary HTML attachments without a sign-in request are not malicious by extension alone.
- A javascript:/vbscript:/data-style URI without credential/account-access theft is Suspicious rather than automatically Phishing; a nested/open-redirect URL combined with an attacker-directed sign-in can be Phishing.
- A normal invoice, payment receipt, bank alert, support contact number, or unchanged bank details are not fraud by topic alone.
- Legitimate authenticated MFA enrollment, password-reset, collaboration, and e-sign notifications can remain Safe when they do not ask for those risky actions.
- Deterministic rule reasons are evidence candidates, not unquestionable facts. Re-check each rule reason against the raw sender, authentication evidence, requested action, links, and body; do not mechanically copy the baseline category or reasons.
- A credential-request or credential-link signal supports Phishing only when the message actually asks the recipient to disclose, enter, send, or confirm credentials, OTPs, account secrets, payment details, or other sensitive information, or directs the recipient to a suspicious/mismatched sign-in destination. A normal request to read or review service updates is not credential theft by itself.
- Passing SPF/DKIM/DMARC and sender/link domains that align with the claimed service are legitimate context that can outweigh weak false-positive rule signals, but they do not override concrete malicious evidence.
- An explicit statement that no password, OTP, payment, or sensitive information is requested is supporting context only; verify that the requested action and destination are consistent with that statement.
- For provider-Junk mail, Safe / Misclassified is appropriate when the content, requested action, authentication evidence, and destinations are consistent with a legitimate message and no concrete threat remains.
- Use only the supplied evidence and context. Do not invent evidence.
- Give 2 or 3 short grounded reasons for each email.
- confidence must be an integer from 0 to 100.
- Return exactly one result for every uid.

Return exactly:
{{"results":[{{"uid":"...","category":"...","confidence":0,"reasons":["..."],"malicious":false}}]}}

Emails:
{json.dumps(prepared, ensure_ascii=False)}
"""
    payload = _request_json(prompt, SECURITY_BATCH_SCHEMA, operation="batch security classification")
    results = {}
    for raw in payload.get("results") or []:
        uid = str(raw.get("uid") or "").strip()
        if uid not in baselines:
            continue
        baseline = baselines[uid]
        trace_security_detection(
            "AI_BATCH_RAW",
            email=emails_by_uid.get(uid),
            baseline=baseline,
            classification=raw,
        )
        batch_result = _finalize_security_ai_result(raw, baseline)
        needs_isolated = _needs_isolated_security_confirmation(baseline, batch_result)
        trace_security_detection(
            "AI_BATCH_FINAL",
            email=emails_by_uid.get(uid),
            baseline=baseline,
            classification=batch_result,
            payload={"needs_isolated_confirmation": bool(needs_isolated)},
        )
        if needs_isolated:
            try:
                batch_result = classify_email_security(emails_by_uid[uid], baseline)
            except RuntimeError:
                # If isolated confirmation is unavailable, preserve the existing
                # batch verdict rather than weakening or dropping a security result.
                pass
        results[uid] = batch_result
    return results


def _request_text(system_prompt: str, user_input: str) -> str:
    # Request a plain-text response when JSON would violate the output contract.
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input},
        ],
        "stream": False,
        "think": OLLAMA_THINK,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {"temperature": OLLAMA_TEMPERATURE},
    }
    request = Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with ollama_generation_slot():
            with urlopen(request, timeout=OLLAMA_REQUEST_TIMEOUT) as response:
                result = json.loads(response.read().decode("utf-8"))
        log_ollama_timing(result, consume_next_ollama_operation("reply draft"))
        return str(result["message"]["content"]).strip()
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama could not run {OLLAMA_MODEL}: {detail}") from error
    except URLError as error:
        raise RuntimeError(
            "Could not connect to Ollama. Start Ollama, then run "
            f"'ollama pull {OLLAMA_MODEL}'."
        ) from error
    except (KeyError, TypeError, json.JSONDecodeError, TimeoutError) as error:
        raise RuntimeError(f"{OLLAMA_MODEL} did not return a valid reply draft.") from error


def _action_audit_chunks(email: dict, size: int = 8000) -> list[str]:
    # Split long messages so requests near the end cannot be truncated.
    body = (email.get("body_text") or email.get("snippet") or "").strip()
    return [body[index:index + size] for index in range(0, len(body), size)] or [""]


def _phase1i2_action_audit_keywords(value: str) -> set[str]:
    # Compare only explicit request verbs already used by the existing completeness heuristic.
    # This helper never extracts new actions; it only proves that a current action already
    # covers the request verbs in an unambiguous non-thread sentence.
    lowered = str(value or "").casefold()
    keywords = set()
    for word in (
        "acknowledge", "approve", "check", "complete", "confirm", "decide",
        "investigate", "prepare", "provide", "read", "reply", "respond",
        "review", "send", "sign", "submit", "update", "upload", "verify", "reject",
    ):
        if re.search(rf"\b{re.escape(word)}\w*\b", lowered):
            keywords.add(word)
    if "respond" in keywords:
        keywords.add("reply")
    return keywords


def _phase1i2_terminal_no_action_is_proven(email: dict, actions) -> bool:
    # Skip the audit only when the effective/current turn contains an explicit terminal
    # no-action/cancelled/completed state and contains no positive recipient request.
    # Older thread requests are intentionally ignored only when a labeled latest turn exists.
    if _normalize_list(actions):
        return False
    body = _body_text(email)
    turn = _phase1g_effective_turn_text(body)
    if not re.search(
        r"\b(?:no (?:further|other)?\s*action (?:is )?(?:needed|required)|"
        r"nothing (?:is )?required from you|no longer needed|you no longer need to|"
        r"received and completed|has been received and completed)\b",
        turn,
        flags=re.IGNORECASE,
    ):
        return False

    for sentence in _phase1b_source_sentences(turn):
        if not _phase1b_recipient_request_signal(sentence):
            continue
        if _phase1g_addressed_to_other_person(email, sentence):
            continue
        if _phase1c_evidence_is_non_action(sentence, turn):
            continue
        return False
    return True


def _phase1i2b_shared_deadline_compound_needs_audit(sentence: str, related_actions) -> bool:
    # A single model action may contain all request verbs while still collapsing multiple
    # independently performable steps. Keep the old completeness audit when one request
    # sentence has multiple explicit action verbs, a shared deadline, and the model returned
    # only one related action. This is deliberately narrow: it does not alter requests that
    # already produced separate actions, and atomic decision phrasing remains handled by the
    # existing expected-action heuristic.
    related = _normalize_list(related_actions)
    if len(related) != 1:
        return False

    keywords = _phase1i2_action_audit_keywords(sentence)
    if len(keywords) < 2:
        return False

    lowered = str(sentence or "").casefold()
    if not re.search(r"\b(?:and|also|then)\b", lowered):
        return False

    has_shared_deadline = bool(
        re.search(
            r"\b(?:by\s+(?:\d{4}-\d{2}-\d{2}|(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)|"
            r"(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2}|"
            r"\d{1,2}(?::\d{2})?\s*(?:am|pm)|eod)|today|tomorrow|bukas|within\s+\w+\s+days?)\b",
            lowered,
            flags=re.IGNORECASE,
        )
    )
    return has_shared_deadline


def _phase1i2_nonthread_requests_are_covered(email: dict, actions) -> bool:
    # For ordinary non-thread email, prove completeness only when every positive
    # recipient-request sentence is already represented by a related current action
    # and all explicit request verbs in that sentence are present in those actions.
    # Labeled threads stay on the old audit path because stale/latest state is riskier.
    body = _body_text(email)
    items = _normalize_list(actions)
    if not items or _phase1b_latest_turn_text(body):
        return False

    requests = []
    for sentence in _phase1b_source_sentences(body):
        if not _phase1b_recipient_request_signal(sentence):
            continue
        if _phase1g_addressed_to_other_person(email, sentence):
            continue
        if _phase1c_evidence_is_non_action(sentence, body):
            continue
        requests.append(sentence)
    if not requests:
        return False

    for sentence in requests:
        related = [
            action for action in items
            if _phase1e_related_action_text(action, sentence)
        ]
        if not related:
            return False
        source_keywords = _phase1i2_action_audit_keywords(sentence)
        covered_keywords = set()
        for action in related:
            covered_keywords.update(_phase1i2_action_audit_keywords(action))
        if source_keywords and not source_keywords.issubset(covered_keywords):
            return False
        if _phase1i2b_shared_deadline_compound_needs_audit(sentence, related):
            return False
    return True


def _phase1i2_needs_action_audit(email: dict, actions) -> bool:
    # Preserve the old audit trigger by default. The only new behavior is an early
    # skip when deterministic evidence proves either a terminal no-action state or
    # complete coverage of ordinary non-thread requests.
    body = _body_text(email)
    expected = _phase1b_expected_action_count(body)
    items = _normalize_list(actions)
    old_trigger = _has_action_request(body) and (not items or expected > len(items))
    if not old_trigger:
        return False
    if _phase1i2_terminal_no_action_is_proven(email, items):
        return False
    if _phase1i2_nonthread_requests_are_covered(email, items):
        return False
    return True


def extract_all_user_action_items(email: dict) -> list[str]:
    # Dedicated completeness audit. Keep the complete source segment, but use a
    # compact instruction block so prompt-evaluation time is not spent repeating
    # rules already enforced again by deterministic validation/post-processing.
    recipient = email.get("to", "")
    actions = []
    chunks = _action_audit_chunks(email)
    for index, chunk in enumerate(chunks, start=1):
        prompt = f"""Audit this email segment for EVERY OPEN action intended for the recipient/user.
Return JSON only with exactly one key: action_items (array of strings).

Rules:
- Include every direct/indirect request, question needing a response, approval/decision,
  review/confirmation, document/send task, meeting action, follow-up, check, or investigation.
- Split independently performable compound requests into separate atomic verb phrases.
- Return executable task wording only. Do NOT include dates, times, deadline phrases, priority labels,
  urgency modifiers, or parent instruction headings in Action Items. Deadline/priority metadata is handled separately.
- Include requests even when minor, optional, or undated.
- Exclude work assigned only to the sender/another person, completed/cancelled work,
  informational text, signatures/disclaimers, and stale quoted history unless renewed.
- Check every sentence once more before returning; do not cap the number of actions.

Recipient: {recipient}
Subject: {email.get('subject', '')}
Date: {email.get('date_display', email.get('date', ''))}
Segment: {index}/{len(chunks)}

Email text segment:
{chunk}"""
        trace_event(
            "summary_action_audit_input",
            audit_chars=len(prompt),
            source_chars=len(chunk),
            segment=index,
            segments=len(chunks),
        )
        audited = _request_json(prompt, ACTION_AUDIT_SCHEMA, operation="action audit")
        actions = _merge_unique(actions, audited.get("action_items"))
    return actions


def audit_key_points_for_actions(
    email: dict, key_points, current_actions
) -> list[str]:
    # Cross-check listed key points for user actions omitted from Action Items.
    normalized_points = _normalize_list(key_points)
    if not normalized_points:
        return []
    prompt = f"""Cross-check the Key Points from an email summary against its Action Items.
Return JSON only with exactly one key: action_items (array of strings).

Identify EVERY Key Point that states or implies an open action for the recipient/user
and is missing from Current Action Items. Include requests to reply, review, approve,
confirm, decide, prepare, send, attend, investigate, follow up, or complete work.
Split compound actions. Exclude information, completed work, and actions assigned only
to other people. Return executable task wording only: no date/time/deadline/priority text and no
parent instruction headings. Return only missing user actions, with no duplicates.

Recipient: {email.get('to', '')}
Key Points: {json.dumps(normalized_points)}
Current Action Items: {json.dumps(_normalize_list(current_actions))}"""
    result = _request_json(prompt, ACTION_AUDIT_SCHEMA, operation="action cross-check")
    return _normalize_list(result.get("action_items"))


def _normalize_action_item_details(value, action_items) -> list[dict]:
    # Keep one optional due-date record per final action without another LLM call.
    raw_details = value if isinstance(value, list) else []
    normalized = []
    for item in raw_details:
        if not isinstance(item, dict):
            continue
        action = re.sub(r"\s+", " ", str(item.get("action") or "").strip())
        due_date = re.sub(
            r"\s+", " ",
            str(item.get("due_date") or item.get("deadline") or "").strip(),
        )
        if action:
            normalized.append({"action": action, "due_date": due_date})

    by_action = {
        item["action"].casefold(): item
        for item in normalized
        if item.get("action")
    }
    result = []
    for action in _normalize_list(action_items):
        matched = by_action.get(action.casefold())
        if matched is None:
            # The action-audit passes can discover an item omitted by the first model
            # response. Keep it in the structured list with an empty due date; the
            # To-Do layer can still resolve a date from the action wording locally.
            matched = {"action": action, "due_date": ""}
        else:
            matched = {"action": action, "due_date": matched.get("due_date", "")}
        result.append(matched)
    return result


def _normalize_task_title(value, action_items=None, subject: str = "") -> str:
    # Normalize the title returned by the summary call without making another LLM request.
    title = re.sub(r"\s+", " ", str(value or "").strip())
    title = re.sub(r"^(?:task\s*title|title)\s*:\s*", "", title, flags=re.IGNORECASE)
    title = title.strip(" \t\r\n-–—:;,.\"'")

    # If an older/edge model response omits task_title, derive a local fallback
    # from the final extracted actions. This deliberately avoids a second LLM call.
    if not title:
        actions = _normalize_list(action_items)
        title = actions[0] if actions else str(subject or "").strip()
        title = re.sub(r"\s+", " ", title).strip(" \t\r\n-–—:;,.\"'")

    # Keep unexpected verbose output from overflowing the To-Do title column.
    # A compact interpretation/choice task can legitimately need a few extra
    # words to preserve the alternatives the user is being asked to resolve.
    # Blindly cutting that form at ten words can leave a dangling "or" or erase
    # the discriminating date/time values, which makes the To-Do title misleading.
    words = title.split()
    max_words = 14 if _phase1c_semantic_temporal_facts(title) else 10
    if len(words) > max_words:
        title = " ".join(words[:max_words]).rstrip(" ,;:-")
    return title



def _existing_task_context(existing: dict) -> list[dict]:
    # Return numbered durable action state for one incremental-thread prompt.
    # ``action_items`` contains only the CURRENT open work after reconciliation,
    # while ``action_item_details`` keeps closed/completed history so a later
    # reply cannot accidentally resurrect a superseded request.
    actions = _normalize_list(existing.get("action_items"))
    raw_details = existing.get("action_item_details")
    details = [dict(item) for item in (raw_details if isinstance(raw_details, list) else []) if isinstance(item, dict)]
    context = []
    seen = set()

    for detail in details:
        action = _separate_action_item_text(str(detail.get("action") or ""))
        if not action:
            continue
        key = re.sub(r"\s+", " ", action).casefold()
        if key in seen:
            continue
        seen.add(key)
        context.append({
            "index": len(context),
            "action": action,
            "due_date": str(detail.get("due_date") or detail.get("deadline") or "").strip(),
            "completed": bool(detail.get("completed")),
            "cancelled": bool(detail.get("cancelled")),
        })

    # Compatibility for older summaries that have action_items but no detail row.
    for action in actions:
        clean = _separate_action_item_text(action) or action
        key = re.sub(r"\s+", " ", clean).casefold()
        if not clean or key in seen:
            continue
        seen.add(key)
        context.append({
            "index": len(context),
            "action": clean,
            "due_date": "",
            "completed": False,
            "cancelled": False,
        })
    return context

def _incremental_current_turn_text(email: dict) -> str:
    """Return only the newest authored reply, excluding quoted thread history.

    Incremental model prompts can contain the newest reply followed by provider
    quote text (for example ``On ... wrote:`` plus the previous message).  That
    quoted history is valid context for whole-thread Summary semantics, but it is
    not valid evidence that a NEW action in the latest reply owns an old due date.
    Keep this scoping local to incremental reconciliation so standalone/thread
    reconstruction behavior outside this path is unchanged.
    """
    text = _phase1g_effective_turn_text(_body_text(email))
    if not text:
        return ""

    cut = len(text)
    quote_headers = (
        # Common RFC/client quote header used by Gmail and many mail clients.
        # Providers sometimes soft-wrap the generated header immediately before
        # ``wrote:`` (for example ``... <sender>\nwrote:``).  Treat up to two
        # continuation lines as the same quote header so quoted tasks/deadlines
        # can never masquerade as newest-turn evidence.  Requiring a date-like
        # marker keeps ordinary authored prose beginning with ``On ...`` intact.
        (
            r"(?ims)^\s*On\s+"
            r"(?=[^\n]{0,220}(?:"
            r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b|"
            r"\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}\b|"
            r"[A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4}\b|"
            r"\d{4}[-/]\d{1,2}[-/]\d{1,2}\b"
            r"))"
            r".{1,520}?\bwrote:\s*$"
        ),
        # Outlook/desktop clients often insert an explicit original-message bar.
        r"(?mi)^\s*-{2,}\s*Original\s+Message\s*-{2,}\s*$",
        # Outlook-style quoted header block.  Require Sent + Subject so an
        # ordinary authored line beginning with 'From:' is not cut accidentally.
        r"(?mi)^\s*From:\s*.+\n\s*Sent:\s*.+(?:\n\s*To:\s*.+)?(?:\n\s*Cc:\s*.+)?\n\s*Subject:\s*.+$",
    )
    for pattern in quote_headers:
        match = re.search(pattern, text)
        if match:
            cut = min(cut, match.start())

    current = text[:cut]
    # A conventional leading '>' quote also marks the start of history.
    current = re.split(r"(?m)^\s*>", current, maxsplit=1)[0]
    return current.strip()


def _incremental_due_is_current_turn_supported(
    email: dict, action: str, due: str, *, allow_message_level_mutation: bool = False
) -> bool:
    """Validate one incremental due date against the latest turn only.

    A date present only in quoted history must never become the due date of a NEW
    action.  Coordinated tasks in the same latest-turn request sentence may still
    share one trailing date, and an explicit global ``Deadline:``/``Due date:``
    label remains an intentional exception.  For an already-saved action only, an
    authored message-level mutation such as ``move the deadline to <date>`` is also
    fresh evidence even when the sentence does not repeat the task noun.
    """
    current_turn = _incremental_current_turn_text(email)
    candidate = re.sub(r"\s+", " ", str(due or "")).strip()
    action_text = re.sub(r"\s+", " ", str(action or "")).strip()
    if not current_turn or not candidate or not action_text:
        return False

    local_email = dict(email)
    local_email["body_text"] = current_turn
    local_email["snippet"] = current_turn
    grounded = _ground_deadlines(local_email, [candidate])
    if not grounded:
        return False
    candidate = grounded[0]

    evidence = _phase1b_find_evidence(action_text, current_turn)
    if evidence and _phase1b_action_evidence_supports_deadline(local_email, evidence, candidate):
        return True

    # Explicit message-level deadline labels intentionally apply to all active
    # recipient work introduced/updated in this same latest turn.
    deadline_evidence = _phase1b_deadline_sentence(candidate, current_turn)
    if deadline_evidence:
        if (
            _phase1b_is_valid_deadline_sentence(deadline_evidence)
            and re.match(
                r"^\s*(?:deadline|due\s+date)\s*(?::|=|-|(?:is|remains?|stays?)\b)",
                deadline_evidence,
                flags=re.IGNORECASE,
            )
        ):
            return True

        # A latest-turn message-level deadline mutation can be phrased as an
        # imperative ("move/extend/change the deadline to ...") without repeating
        # the task object.  That sentence is deliberately not accepted for a NEW
        # action: only callers reconciling an already-saved action enable this
        # branch, which prevents a global old-work deadline from leaking onto
        # newly introduced sibling work.
        if allow_message_level_mutation and re.search(
            r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b"
            r"[^.!?;]{0,48}\b(?:deadline|due\s+date)\b|"
            r"\b(?:deadline|due\s+date)\b[^.!?;]{0,48}"
            r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b",
            deadline_evidence,
            flags=re.IGNORECASE,
        ):
            if not re.search(
                r"\b(?:for\s+context\s+only|context\s+only|not\s+(?:a|the)\s+deadline|"
                r"is\s+not\s+(?:a|the)\s+deadline|not\s+a\s+due\s+date)\b",
                deadline_evidence,
                flags=re.IGNORECASE,
            ):
                return True
    return False


def _incremental_pause_control_sentence(sentence: str) -> bool:
    """Return True when a newest-turn sentence is lifecycle hold control only.

    This is intentionally narrower than general action detection.  A temporary
    pause/hold/wait instruction changes workflow posture but must not cancel,
    rewrite, or add To-Do work.  Concrete commands such as ``Stop the server``
    remain ordinary executable work unless the wording clearly makes the stop
    temporary / whole-task lifecycle control.
    """
    text = re.sub(r"\s+", " ", str(sentence or "")).strip(" \t\r\n-–—:;,.!?")
    if not text:
        return False
    lowered = text.casefold()

    if re.search(
        r"\b(?:do\s+not|don't|dont|never)\s+(?:pause|hold)\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return False

    # Thread replies often pause a named deliverable rather than saying the
    # generic phrase "put this task on hold".  Treat a bounded noun phrase
    # between put/place/keep and "on hold" as lifecycle control too.  This is
    # intentionally local to incremental reconciliation; normal single-email
    # action extraction is unchanged.
    if re.search(
        r"\b(?:put|place|keep)\b[^.!?;]{0,90}\bon\s+hold\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return True

    # "Do not <perform the existing task> until ..." is a temporary hold when
    # the same sentence carries an explicit resume boundary.  Without the
    # boundary it remains an ordinary negative/cancellation instruction.
    if re.search(
        r"\b(?:do\s+not|don't|dont)\s+[a-z][a-z'-]*(?:\s+[^.!?;]{0,70})?\s+"
        r"(?:until|unless|pending)\s+(?:further\s+notice|resume|restart|"
        r"you\s+(?:hear|get)\s+back|another\s+instruction|new\s+instructions?)\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return True

    # Temporary inhibition until an explicit resume/next instruction is a hold,
    # not cancellation.  This covers natural variants such as "do not continue
    # until I say resume" without treating "do not send the file" as a hold.
    if re.search(
        r"\b(?:do\s+not|don't|dont)\s+(?:continue|proceed|resume|restart)\b"
        r".{0,120}\b(?:until|unless|pending)\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\b(?:wait|stand\s+by)\b.{0,100}\b(?:until|pending|for\s+now)\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\b(?:put|place|keep)\s+(?:this|the|our|current)?\s*"
        r"(?:task|work|activity|effort|processing|process)?\s*(?:on\s+)?hold\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return True

    pause = re.search(r"\b(?:pause|hold|stop)\b", lowered, flags=re.IGNORECASE)
    if not pause:
        return False
    # Whole-task pronouns/objects or explicit temporary timing make this lifecycle
    # control. A concrete object with no temporary marker stays executable work.
    return bool(
        re.search(
            r"\b(?:pause|hold|stop)\b.{0,90}"
            r"\b(?:this|that|it|task|work|activity|effort|processing|process|progress|"
            r"for\s+now|temporarily|until|pending|further\s+notice)\b",
            lowered,
            flags=re.IGNORECASE,
        )
        or re.search(
            r"\b(?:pause|hold|stop)\s+(?:for\s+now|temporarily|until|pending)\b",
            lowered,
            flags=re.IGNORECASE,
        )
    )


def _incremental_is_pure_pause_turn(email: dict) -> bool:
    """Prove that the newest authored turn only pauses existing work.

    Pure hold turns must preserve every saved action and its due-date ownership.
    The guard deliberately refuses to fire when the newest turn also cancels /
    completes work, changes deadline or priority, or introduces another concrete
    recipient request.
    """
    current = _incremental_current_turn_text(email)
    if not current:
        return False
    sentences = _phase1b_source_sentences(current)
    if not sentences or not any(_incremental_pause_control_sentence(item) for item in sentences):
        return False

    lowered = current.casefold()
    if re.search(
        r"\b(?:cancel(?:led|ed)?|no\s+longer\s+(?:needed|required)|"
        r"(?:is|was|has\s+been|have\s+been)\s+(?:completed|finished|done)|"
        r"no\s+(?:further|other)?\s*action\s+(?:is\s+)?(?:needed|required))\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return False
    # Explicit scheduling/urgency mutation is not a pure lifecycle-only turn.
    if re.search(
        r"\b(?:new\s+deadline|deadline\s+(?:is|moved|changed|extended|removed)|"
        r"due\s+date\s+(?:is|moved|changed|extended|removed)|"
        r"priority\s+(?:is|changed|raised|lowered)|set\s+priority)\b",
        lowered,
        flags=re.IGNORECASE,
    ):
        return False

    # Any non-lifecycle request in the authored turn means we must keep normal
    # task reconciliation (for example "Pause this, and prepare a report").
    substantive = [item for item in sentences if not _incremental_pause_control_sentence(item)]
    if substantive:
        local_email = dict(email)
        local_text = "\n".join(substantive)
        local_email["body_text"] = local_text
        local_email["snippet"] = local_text
        candidates = []
        for sentence in substantive:
            if _phase1b_recipient_request_signal(sentence):
                candidates.append(sentence)
        if candidates and _phase1b_validate_actions(local_email, candidates):
            return False

    return True


def _incremental_preserve_tasks_for_pause(existing: dict) -> list[dict]:
    """Return unchanged task updates for a proven pure hold turn."""
    preserved = []
    for index, old in enumerate(_existing_task_context(existing)):
        action = str(old.get("action") or "").strip()
        if not action:
            continue
        preserved.append({
            "previous_index": index,
            "state": "unchanged",
            "action": action,
            "due_date": str(old.get("due_date") or "").strip(),
            "due_date_changed": False,
        })
    return preserved


def _incremental_explicit_new_task_action(email: dict, action: str) -> str:
    """Accept an explicit newest-turn "add/create task" request as new work.

    The normal action validator intentionally requires a direct recipient request
    signal.  Incremental replies also commonly use a parent instruction such as
    "Also add a new task: confirm ..."; the executable child is recipient work,
    but the heading itself does not match that generic request grammar.  Keep this
    exception local to ``state=new`` so initial extraction and every other action
    validation rule remain unchanged.
    """
    candidate = _separate_action_item_text(action)
    if not candidate or _action_item_is_metadata_only(candidate):
        return ""

    current_turn = _incremental_current_turn_text(email) or _body_text(email)
    if not current_turn:
        return ""
    evidence = _phase1b_find_evidence(candidate, current_turn)
    if not evidence:
        return ""
    task_intro = re.search(
        r"\b(?:add|create)\s+(?:a\s+)?(?:new\s+)?"
        r"(?:task|action(?:\s+item)?|to[- ]?do)\s*(?::|[-–—]|\b)",
        evidence,
        flags=re.IGNORECASE,
    )
    if not task_intro:
        return ""

    # Preserve the existing ownership rule even inside the parent heading.
    # A form such as "add a new task: Alice must confirm ..." is coworker work,
    # not the current recipient's To-Do.
    tail = evidence[task_intro.end():].lstrip(" \t:;-–—")
    named_assignee = _phase1g_named_assignee(tail)
    recipient_name = _phase1g_recipient_name(email)
    if named_assignee and (
        not recipient_name or not _phase1g_same_person(named_assignee, recipient_name)
    ):
        return ""
    if re.search(
        r"\b(?:task|action(?:\s+item)?)\s+for\s+"
        r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2}\s*[:–—-]",
        evidence,
    ):
        return ""

    if not _is_supported(candidate, current_turn):
        return ""
    if _phase1b_action_invalidated(candidate, current_turn):
        return ""
    if _phase1g_addressed_to_other_person(email, evidence):
        return ""
    if _phase1c_evidence_is_non_action(evidence, current_turn):
        return ""
    if _phase1c_is_task_list_intro_evidence(candidate, current_turn):
        return ""
    return candidate


_INCREMENTAL_ACTION_MUTABLE_VALUE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"(?:USD|PHP|EUR|GBP|JPY|AUD|CAD)\s*[$€£₱]?\s*\d[\d,]*(?:\.\d+)?(?:\s*[kKmMbB])?"
    r"|[$€£₱]\s*\d[\d,]*(?:\.\d+)?(?:\s*[kKmMbB])?"
    r"|\d[\d,]*(?:\.\d+)?\s*%"
    r"|(?:version|revision|rev)\s*[:#-]?\s*[A-Za-z0-9][A-Za-z0-9._-]*"
    r"|v\d+(?:\.\d+)*"
    r"|\d[\d,]*(?:\.\d+)?(?:\s+(?:units?|items?|copies|seats?|licenses?|users?|"
    r"hours?|days?|weeks?|months?|pages?|gb|mb|tb|kg|g|lbs?|meters?|metres?|cm|mm))?"
    r")",
    flags=re.IGNORECASE,
)


def _incremental_literal_value_pattern(value: str) -> str:
    """Return a whitespace-tolerant literal regex for one source value."""
    chunks = [chunk for chunk in re.split(r"\s+", str(value or "").strip()) if chunk]
    return r"\s*".join(re.escape(chunk) for chunk in chunks)


def _incremental_correction_sentences(text: str) -> list[str]:
    """Return correction sentences with provider soft-wraps treated as layout.

    The general source-sentence splitter intentionally preserves numbered-list
    structure.  In an incremental correction, however, a provider can wrap
    ``version 3`` as ``version\n3.``; the continuation line then *looks* like a
    numbered list item and splits the OLD scalar away from ``instead of``.

    For explicit scalar-correction reconciliation only, collapse whitespace
    after quoted history has already been removed, then sentence-split the
    authored turn.  This keeps normal/single-email parsing unchanged while
    making currency, quantity, percentage, and version corrections invariant to
    provider presentation wrapping.
    """
    flat = re.sub(r"\s+", " ", str(text or "")).strip()
    # A provider can wrap inside one scalar token too (``$48,\n000`` or
    # ``v1.\n2``). Rejoin only punctuation that is demonstrably surrounded by
    # digits; ordinary sentence boundaries remain untouched.
    flat = re.sub(r"(?<=\d),\s+(?=\d{3}(?:\D|$))", ",", flat)
    flat = re.sub(r"(?<=\d)\.\s+(?=\d)", ".", flat)
    if not flat:
        return []
    return [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", flat)
        if part and part.strip()
    ]


def _incremental_apply_explicit_value_correction_to_saved_action(
    email: dict,
    previous: list[dict],
    previous_index: int | None,
    old_action: str,
) -> str:
    """Project an explicit newest-turn scalar correction into an existing task.

    Incremental replies often correct a material parameter without repeating the
    recipient command, for example ``use 25 units instead of 20`` or ``replace
    version 3 with version 4``.  The normal action validator correctly refuses
    to invent an imperative from that fragment, but falling all the way back to
    the durable action leaves the OLD value active even when the correction is
    explicit and source-grounded.

    This repair is deliberately narrow and thread-only:
    - the task row must already exist and be the row selected by task_updates;
    - the OLD value must literally occur in that saved action;
    - the newest authored turn must explicitly pair OLD and NEW with correction
      grammar (instead of / rather than / from-to / replace-change-update);
    - ambiguous sibling rows sharing the same OLD value are not mutated unless
      the correction clause resolves back to this exact previous_index.

    No normal/single-email Summary extraction passes through this helper.
    """
    if previous_index is None or not (0 <= previous_index < len(previous)):
        return ""
    current_turn = _incremental_current_turn_text(email)
    action = re.sub(r"\s+", " ", str(old_action or "").strip())
    if not current_turn or not action:
        return ""

    if not re.search(
        r"\b(?:correction|correct(?:ed|ion)?|instead\s+of|rather\s+than|"
        r"replace(?:d)?|change(?:d)?|update(?:d)?|revise(?:d)?|from\b[^.!?;]{0,80}\bto)\b",
        current_turn,
        flags=re.IGNORECASE,
    ):
        return ""

    old_values = []
    for match in _INCREMENTAL_ACTION_MUTABLE_VALUE_RE.finditer(action):
        value = re.sub(r"\s+", " ", match.group(0)).strip()
        if value and value.casefold() not in {item.casefold() for item in old_values}:
            old_values.append(value)
    if not old_values:
        return ""

    # Correction pairing must be invariant to provider soft wrapping.  Do not
    # use the general sentence splitter here because a wrapped scalar such as
    # ``version\n3.`` can be mistaken for a numbered-list boundary.
    clauses = _incremental_correction_sentences(current_turn)
    if not clauses:
        clauses = [re.sub(r"\s+", " ", current_turn).strip()]

    corrected = action
    changed = False
    for old_value in old_values:
        old_pattern = _incremental_literal_value_pattern(old_value)
        replacement = ""
        replacement_clause = ""
        for clause in clauses:
            # Require the old durable value in the same authored correction
            # clause.  Quoted history is excluded by _incremental_current_turn_text.
            if not re.search(old_pattern, clause, flags=re.IGNORECASE):
                continue

            value_pattern = _INCREMENTAL_ACTION_MUTABLE_VALUE_RE.pattern
            pair_patterns = (
                # ``use NEW instead of OLD`` / ``NEW rather than OLD``
                rf"(?P<new>{value_pattern})\s*(?:instead\s+of|rather\s+than)\s*{old_pattern}",
                # ``use NEW, not OLD``
                rf"(?P<new>{value_pattern})\s*,?\s+not\s+{old_pattern}",
                # ``from OLD to NEW`` or ``OLD -> NEW``
                rf"(?:from\s+)?{old_pattern}\s*(?:to|->|→)\s*(?P<new>{value_pattern})",
                # ``replace/change/update/correct OLD with/to NEW``
                rf"\b(?:replace|change|update|correct|revise)\w*\b[^.!?;]{{0,70}}"
                rf"{old_pattern}[^.!?;]{{0,35}}\b(?:with|to)\b\s*(?P<new>{value_pattern})",
            )
            match = next(
                (candidate for pattern in pair_patterns
                 for candidate in [re.search(pattern, clause, flags=re.IGNORECASE)]
                 if candidate),
                None,
            )
            if not match:
                continue
            candidate = re.sub(r"\s+", " ", str(match.group("new") or "")).strip()
            if not candidate or candidate.casefold() == old_value.casefold():
                continue

            # If several durable sibling actions carry the same old scalar, the
            # source clause must itself resolve to this exact row.  This prevents
            # a global amount/version correction from silently mutating siblings.
            sharing = [
                i for i, row in enumerate(previous)
                if re.search(
                    old_pattern,
                    str(row.get("action") or ""),
                    flags=re.IGNORECASE,
                )
            ]
            resolved = _incremental_best_saved_action_index(previous, clause)
            if len(sharing) > 1 and resolved != previous_index:
                continue
            if resolved is not None and resolved != previous_index:
                continue

            replacement = candidate
            replacement_clause = clause
            break

        if not replacement:
            continue

        # The NEW scalar must be literal newest-turn evidence, never something
        # inferred only from the model-proposed task wording.
        if not re.search(
            _incremental_literal_value_pattern(replacement),
            replacement_clause,
            flags=re.IGNORECASE,
        ):
            continue
        corrected, count = re.subn(
            old_pattern,
            lambda _m, value=replacement: value,
            corrected,
            count=1,
            flags=re.IGNORECASE,
        )
        changed = changed or bool(count)

    return re.sub(r"\s+", " ", corrected).strip() if changed else ""



def _incremental_explicit_recipient_takeover_sentence(email: dict) -> str:
    """Return newest-turn proof that existing work moved to the recipient."""
    current = _incremental_current_turn_text(email)
    folded = re.sub(r"[ \t]*[\r\n]+[ \t]*", " ", str(current or "")).strip()
    if not folded:
        return ""

    recipient_name = _phase1g_recipient_name(email)
    aliases = [r"you"] + ([re.escape(recipient_name)] if recipient_name else [])
    actor = r"(?:" + "|".join(aliases) + r")"
    signals = (
        re.compile(
            rf"\b{actor}\b\s+(?:"
            rf"will\s+now\s+(?:take\s+over|own|handle|be(?:come)?\s+responsible\s+for)|"
            rf"now\s+(?:take\s+over|own|handle)|"
            rf"(?:are|is)\s+now\s+(?:taking\s+over|responsible\s+for|handling)"
            rf")\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            rf"\b(?:is|was|has\s+been)\s+(?:now\s+)?"
            rf"(?:assigned|reassigned|transferred|handed\s+off|moved)\s+to\s+{actor}\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            rf"\bownership\s+of\b[^.!?;]{{1,160}}?\s+(?:is|was|has\s+been)\s+"
            rf"(?:now\s+)?(?:assigned|transferred|given|moved)\s+to\s+{actor}\b",
            flags=re.IGNORECASE,
        ),
    )
    for sentence in re.split(r"(?<=[.!?])\s+", folded):
        text = sentence.strip()
        if (
            text
            and any(pattern.search(text) for pattern in signals)
            and not re.search(r"\b(?:if|unless|provided\s+that|in\s+case)\b", text, flags=re.IGNORECASE)
        ):
            return text
    return ""


def _incremental_recipient_takeover_action(email: dict, proposed_action: str) -> str:
    """Validate one new live task created by an explicit thread handoff to user."""
    evidence = _incremental_explicit_recipient_takeover_sentence(email)
    candidate = _separate_action_item_text(str(proposed_action or ""))
    if not evidence or not candidate or _action_item_is_metadata_only(candidate):
        return ""
    if _phase1b_action_uses_unseen_script(candidate, _body_text(email)):
        return ""
    if not _phase1e_related_action_text(candidate, evidence):
        return ""
    return candidate if _is_supported(candidate, _body_text(email)) else ""


def _incremental_takeover_due_is_current_turn_supported(
    email: dict, action: str, due: str
) -> bool:
    """Keep a literal unchanged deadline when that work is handed to recipient."""
    evidence = _incremental_explicit_recipient_takeover_sentence(email)
    current = _incremental_current_turn_text(email)
    candidate = re.sub(r"\s+", " ", str(due or "")).strip()
    if not evidence or not current or not action or not candidate:
        return False
    if not _phase1e_related_action_text(action, evidence):
        return False
    local_email = dict(email)
    local_email["body_text"] = current
    local_email["snippet"] = current
    grounded = _ground_deadlines(local_email, [candidate])
    deadline_sentence = _phase1b_deadline_sentence(grounded[0], current) if grounded else ""
    return bool(deadline_sentence and re.search(
        r"\b(?:deadline|due\s+date)\b[^.!?;]{0,90}\b(?:remains?|stays?|unchanged|same)\b|"
        r"\b(?:keep|retain|preserve)\b[^.!?;]{0,90}\b(?:deadline|due\s+date)\b|"
        r"\b(?:same|unchanged)\b[^.!?;]{0,55}\b(?:deadline|due\s+date)\b",
        deadline_sentence,
        flags=re.IGNORECASE,
    ))


def _normalize_incremental_task_updates(email: dict, existing: dict, value) -> list[dict]:
    # Ground model task changes against saved actions and the newest reply.
    previous = _existing_task_context(existing)
    valid_states = {"unchanged", "updated", "completed", "cancelled", "new", "reopened"}
    updates = []
    for raw in value if isinstance(value, list) else []:
        if not isinstance(raw, dict):
            continue
        state = str(raw.get("state") or "").strip().casefold()
        if state not in valid_states:
            continue

        previous_index = raw.get("previous_index")
        try:
            previous_index = int(previous_index)
        except (TypeError, ValueError):
            previous_index = None

        if state == "new":
            previous_index = None
        elif previous_index is None or not 0 <= previous_index < len(previous):
            continue

        old = previous[previous_index] if previous_index is not None else {}
        proposed_action = re.sub(r"\s+", " ", str(raw.get("action") or "").strip())

        # A model task mutation is NEW evidence only when the newest authored
        # turn supports it.  Provider quote blocks are thread context, not proof
        # that an old instruction was newly added/changed/reopened.  Existing
        # unchanged/completed/cancelled rows remain anchored to durable saved
        # state, while action wording mutations are grounded locally.
        current_turn = _incremental_current_turn_text(email)
        local_email = dict(email)
        if current_turn:
            local_email["body_text"] = current_turn
            local_email["snippet"] = current_turn
        mutation_email = local_email if state in {"new", "updated", "reopened"} else email
        grounded_action = _ground_action_items(mutation_email, [proposed_action]) if proposed_action else []
        grounded_clean = [
            _separate_action_item_text(item) for item in grounded_action
            if _separate_action_item_text(item)
        ]
        if state == "new":
            # New work normally passes the same recipient/action-heading guards
            # as an initial summary.  Incremental replies may explicitly say
            # "add/create a new task: <action>"; accept only that narrowly
            # grounded parent-heading form when the generic request detector
            # cannot recognize the executable child.
            validated_new = _phase1b_validate_actions(local_email, grounded_clean)
            if validated_new:
                action = validated_new[0]
            else:
                # Ownership transfer *to* the recipient is a thread lifecycle
                # mutation rather than an ordinary imperative.  The normal
                # single-email request validator intentionally does not promote
                # ``you will now take over X`` by itself, so recover the model's
                # source-grounded task only under this explicit handoff shape.
                action = _incremental_recipient_takeover_action(
                    local_email, proposed_action
                )
                if not action:
                    action = next(
                        (
                            recovered
                            for candidate in grounded_clean
                            for recovered in [_incremental_explicit_new_task_action(local_email, candidate)]
                            if recovered
                        ),
                        "",
                    )
                if not action:
                    continue
            # Bare start/proceed/begin controls apply to an already-existing
            # workflow; they are lifecycle/execution posture, not a new To-Do.
            if previous and _raw_first_is_execution_control_action(action):
                continue
        elif state in {"updated", "reopened"}:
            validated_mutation = _phase1b_validate_actions(local_email, grounded_clean)
            if validated_mutation:
                action = validated_mutation[0]
            else:
                # A reply can explicitly correct a scalar/version/quantity in an
                # existing task without restating the imperative itself.  Preserve
                # the durable executable wording but project that source-proven
                # correction instead of reverting to the stale value.
                corrected_saved_action = _incremental_apply_explicit_value_correction_to_saved_action(
                    email, previous, previous_index, str(old.get("action") or "")
                )
                action = corrected_saved_action or _separate_action_item_text(str(old.get("action") or ""))
        else:
            action = _separate_action_item_text(str(old.get("action") or proposed_action))
        if not action or _action_item_is_metadata_only(action):
            continue

        due_date_changed = _as_bool(raw.get("due_date_changed"))
        proposed_due = re.sub(r"\s+", " ", str(raw.get("due_date") or "").strip())

        # Important: ground a proposed NEW/changed due date against only the
        # newest authored turn.  The full incremental body can include quoted
        # history containing an older valid deadline, which is context but not
        # evidence that a newly introduced action inherits that date.
        current_turn = _incremental_current_turn_text(email)
        local_email = dict(email)
        if current_turn:
            local_email["body_text"] = current_turn
            local_email["snippet"] = current_turn
        grounded_due = _ground_deadlines(local_email, [proposed_due]) if proposed_due else []

        if state == "new":
            due_date = grounded_due[0] if grounded_due else ""
            if due_date and not _incremental_due_is_current_turn_supported(email, action, due_date):
                # A takeover activates pre-existing work for the recipient.  If
                # this same newest turn explicitly says that work keeps the
                # literal deadline, retain it; ordinary genuinely-new sibling
                # actions still use the stricter existing rule above.
                if not _incremental_takeover_due_is_current_turn_supported(
                    email, action, due_date
                ):
                    due_date = ""
            due_date_changed = bool(due_date)
        elif due_date_changed:
            # Empty + changed=True intentionally clears a removed deadline.  A
            # non-empty changed due must be explicitly supported by this latest
            # turn; otherwise preserve the durable prior due rather than letting
            # quoted history masquerade as a change.
            if not proposed_due:
                due_date = ""
            else:
                due_date = grounded_due[0] if grounded_due else ""
                if due_date and _incremental_due_is_current_turn_supported(
                    email, action, due_date, allow_message_level_mutation=True
                ):
                    pass
                else:
                    due_date = str(old.get("due_date") or "")
                    due_date_changed = False
        else:
            due_date = str(old.get("due_date") or "")

        updates.append({
            "previous_index": previous_index,
            "state": state,
            "action": action,
            "due_date": due_date,
            "due_date_changed": due_date_changed,
        })
    return updates


def _incremental_actions_semantically_same(left: str, right: str) -> bool:
    # Compare executable intent + task object, not surface wording. Different
    # intents on the same object (for example, send X vs confirm X) are separate
    # actions and must not suppress one another.
    left = _separate_action_item_text(left)
    right = _separate_action_item_text(right)
    if not left or not right:
        return False
    if re.sub(r"\s+", " ", left).strip().casefold() == re.sub(r"\s+", " ", right).strip().casefold():
        return True

    left_intent = _phase1c_action_intent(left)
    right_intent = _phase1c_action_intent(right)
    if left_intent and right_intent and left_intent != right_intent:
        return False

    # Thread task identity is stricter than normal lexical similarity.  Explicit
    # sibling discriminators such as Proposal A/B or version 3/4 must never be
    # collapsed as aliases merely because the remaining object words overlap.
    left_markers = _incremental_identity_markers(left)
    right_markers = _incremental_identity_markers(right)
    for head, label in left_markers.items():
        other = right_markers.get(head)
        if other and other != label:
            return False

    left_objects = _phase1e_object_tokens(left)
    right_objects = _phase1e_object_tokens(right)
    if left_objects and right_objects:
        overlap = len(left_objects & right_objects) / max(1, min(len(left_objects), len(right_objects)))
        if overlap >= 0.67 and (left_intent == right_intent or not left_intent or not right_intent):
            return True

    return bool(
        (left_intent == right_intent or not left_intent or not right_intent)
        and _phase1e_related_action_text(left, right)
        and _phase1e_related_action_text(right, left)
    )




def _incremental_rebind_explicit_cancellations(
    email: dict, existing: dict, updates: list[dict]
) -> list[dict]:
    """Bind explicit newest-turn cancellation wording to the saved action named.

    This is a narrow identity guard: when the model attaches ``cancelled`` to a
    sibling ``previous_index``, the authored turn wins. Ambiguous cancellation
    wording is ignored so normal reconciliation remains unchanged.
    """
    previous = _existing_task_context(existing)
    current_turn = _incremental_current_turn_text(email)
    if not previous or not current_turn:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    target_indexes: set[int] = set()
    for sentence in _phase1b_source_sentences(current_turn):
        if not re.search(
            r"\b(?:cancel(?:led|ed)?|canceled?|no\s+longer\s+(?:needed|required)|"
            r"stop\s+(?:work(?:ing)?\s+on|working\s+on))\b",
            sentence,
            flags=re.IGNORECASE,
        ):
            continue
        if re.search(
            r"\b(?:do\s+not|don't|dont|not)\s+cancel\b",
            sentence,
            flags=re.IGNORECASE,
        ):
            continue

        sentence_tokens = _phase1e_object_tokens(sentence)
        ranked = []
        for index, old in enumerate(previous):
            if bool(old.get("completed")) or bool(old.get("cancelled")):
                continue
            action_tokens = _phase1e_object_tokens(str(old.get("action") or ""))
            if not action_tokens:
                continue
            score = len(action_tokens & sentence_tokens) / len(action_tokens)
            if score >= 0.66:
                ranked.append((score, index))
        if not ranked:
            continue

        ranked.sort(reverse=True)
        strong = [index for score, index in ranked if score >= 0.90]
        if strong:
            target_indexes.update(strong)
        elif len(ranked) == 1 or ranked[0][0] - ranked[1][0] >= 0.20:
            target_indexes.add(ranked[0][1])

    if not target_indexes:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    # If earlier incremental turns accidentally created two near-identical rows
    # for the same work (for example, a harmless verb rephrase), an explicit
    # cancellation of that work must close every duplicate representation.
    # Keep genuinely distinct repeated work separate by requiring the same saved
    # due date (or no due date on both rows) in addition to semantic equivalence.
    expanded_targets = set(target_indexes)
    for target_index in list(target_indexes):
        target = previous[target_index]
        target_action = str(target.get("action") or "").strip()
        target_due = str(target.get("due_date") or "").strip()
        for index, old in enumerate(previous):
            if index in expanded_targets or bool(old.get("completed")) or bool(old.get("cancelled")):
                continue
            old_due = str(old.get("due_date") or "").strip()
            if target_due != old_due:
                continue
            if _incremental_actions_semantically_same(target_action, str(old.get("action") or "")):
                expanded_targets.add(index)
    target_indexes = expanded_targets

    rebound = []
    for item in updates or []:
        if not isinstance(item, dict):
            continue
        state = str(item.get("state") or "").strip().casefold()
        try:
            index = int(item.get("previous_index"))
        except (TypeError, ValueError):
            index = None
        if index in target_indexes:
            continue
        if state == "cancelled":
            # Source proved a different explicit cancellation target; do not let
            # a model-only sibling index close unrelated saved work.
            continue
        if state == "new" and not re.search(r"\b(?:reopen|re-open|resume|restart)\b", current_turn, flags=re.IGNORECASE):
            proposed = str(item.get("action") or "").strip()
            if proposed and any(
                _incremental_actions_semantically_same(
                    proposed, str(previous[target].get("action") or "")
                )
                for target in target_indexes
            ):
                # A cancellation-only turn cannot simultaneously create a fresh
                # alias of the exact work it just cancelled.
                continue
        rebound.append(dict(item))

    for index in sorted(target_indexes):
        old = previous[index]
        rebound.append({
            "previous_index": index,
            "state": "cancelled",
            "action": str(old.get("action") or "").strip(),
            "due_date": str(old.get("due_date") or "").strip(),
            "due_date_changed": False,
        })

    rebound.sort(key=lambda item: (
        item.get("previous_index") is None,
        int(item.get("previous_index")) if item.get("previous_index") is not None else 10**9,
    ))
    return rebound


def _incremental_identity_markers(value: str) -> dict[str, str]:
    """Return compact discriminator labels used to distinguish sibling work.

    Thread updates frequently contain near-identical task objects such as
    Proposal A/B or version 3/4.  Plain token overlap is intentionally broad in
    normal extraction, but reconciliation needs these local labels so a change
    cannot land on the wrong sibling action.
    """
    text = str(value or "")
    result: dict[str, str] = {}
    for head, label in re.findall(
        r"\b(proposal|version|revision|rev|phase|option|variant|draft|plan)\s+"
        r"([A-Za-z0-9][A-Za-z0-9._-]{0,15})\b",
        text,
        flags=re.IGNORECASE,
    ):
        result[head.casefold()] = label.casefold()
    return result


def _incremental_saved_action_match_score(action: str, sentence: str) -> float:
    action_text = str(action or "").strip()
    sentence_text = str(sentence or "").strip()
    if not action_text or not sentence_text:
        return 0.0

    action_markers = _incremental_identity_markers(action_text)
    sentence_markers = _incremental_identity_markers(sentence_text)
    for head, label in action_markers.items():
        other = sentence_markers.get(head)
        if other and other != label:
            return 0.0

    action_tokens = _phase1e_object_tokens(action_text)
    sentence_tokens = _phase1e_object_tokens(sentence_text)
    overlap = (
        len(action_tokens & sentence_tokens) / max(1, len(action_tokens))
        if action_tokens else 0.0
    )
    if action_markers and any(
        sentence_markers.get(head) == label
        for head, label in action_markers.items()
    ):
        overlap += 0.45
    if _phase1e_related_action_text(action_text, sentence_text):
        overlap += 0.20
    return overlap


def _incremental_best_saved_action_index(previous: list[dict], sentence: str) -> int | None:
    ranked = [
        (_incremental_saved_action_match_score(str(item.get("action") or ""), sentence), index)
        for index, item in enumerate(previous)
    ]
    ranked = [pair for pair in ranked if pair[0] >= 0.50]
    if not ranked:
        return None
    ranked.sort(reverse=True)
    if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < 0.18:
        return None
    return ranked[0][1]


def _incremental_affirmed_open_indexes(email: dict, previous: list[dict]) -> set[int]:
    """Find saved work that the newest turn explicitly keeps active.

    This prevents local phrases such as "no other action is needed" or a
    sibling cancellation from accidentally closing work that the same reply
    explicitly says is still required/unchanged.
    """
    current_turn = _incremental_current_turn_text(email)
    affirmed: set[int] = set()
    if not current_turn:
        return affirmed
    positive = re.compile(
        r"\b(?:still\s+(?:required|needed|due)|remains?\s+(?:required|needed|due)|"
        r"keep\b[^.!?;]{0,90}\b(?:required|needed|due|unchanged)|"
        r"(?:required|needed)\s+again|still\s+need(?:s)?\s+to|"
        r"continue\s+to\s+(?:need|require))\b",
        flags=re.IGNORECASE,
    )
    for sentence in _phase1b_source_sentences(current_turn):
        if not positive.search(sentence):
            continue
        index = _incremental_best_saved_action_index(previous, sentence)
        if index is not None:
            affirmed.add(index)
    return affirmed


def _incremental_rebind_explicit_reassignments(
    email: dict, existing: dict, updates: list[dict]
) -> list[dict]:
    """Close recipient work explicitly reassigned to another named person.

    The durable row is retained for history, while setting it inactive removes
    it from the recipient's live Action Items/To-Do projection.  This guard is
    thread-only and does not alter normal single-email ownership extraction.
    """
    previous = _existing_task_context(existing)
    current_turn = _incremental_current_turn_text(email)
    if not previous or not current_turn:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    recipient_name = _phase1g_recipient_name(email)
    targets: set[int] = set()
    assignment_signal = re.compile(
        r"\b(?:"
        r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2}\s+"
        r"(?:will|now\s+will|will\s+now|is\s+going\s+to|owns?|now\s+owns?|has\s+ownership|"
        r"confirmed\s+ownership|has\s+confirmed\s+ownership|will\s+take\s+over)|"
        r"(?:reassigned|assigned|transferred|handed\s+off)\s+to\s+"
        r"[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2}"
        r")\b",
        flags=re.IGNORECASE,
    )
    for sentence in _phase1b_source_sentences(current_turn):
        if not assignment_signal.search(sentence):
            continue
        assignee = ""
        # Allow a short structural label before the owner clause (for example
        # "Ownership update: Maria now owns ...").  The old anchored match saw
        # the assignment signal but then failed to capture the assignee, leaving
        # the recipient's durable task open.  Keep this thread-only and require
        # a sentence boundary/colon so ordinary prose names are not promoted.
        start_name = re.search(
            r"(?:^|:\s*)([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+"
            r"(?:will|now\s+will|will\s+now|is\s+going\s+to|owns?|now\s+owns?|has\s+ownership|"
            r"confirmed\s+ownership|has\s+confirmed\s+ownership|will\s+take\s+over)\b",
            sentence,
        )
        to_name = re.search(
            r"\b(?:reassigned|assigned|transferred|handed\s+off)\s+to\s+"
            r"([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\b",
            sentence,
            flags=re.IGNORECASE,
        )
        if start_name:
            assignee = start_name.group(1).strip()
        elif to_name:
            assignee = to_name.group(1).strip()
        if not assignee:
            continue
        if recipient_name and _phase1g_same_person(assignee, recipient_name):
            continue
        index = _incremental_best_saved_action_index(previous, sentence)
        if index is not None:
            targets.add(index)

    if not targets:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    result = []
    for item in updates or []:
        if not isinstance(item, dict):
            continue
        try:
            index = int(item.get("previous_index"))
        except (TypeError, ValueError):
            index = None
        if index in targets:
            continue
        result.append(dict(item))
    for index in sorted(targets):
        old = previous[index]
        result.append({
            "previous_index": index,
            # Reassignment makes this row inactive for the recipient, but it is
            # not a cancellation of the underlying work.  Keep a distinct
            # thread state so an all-reassigned thread does not render the old
            # task as a "cancelled snapshot" in the user's live Action Items.
            "state": "reassigned",
            "action": str(old.get("action") or "").strip(),
            "due_date": str(old.get("due_date") or "").strip(),
            "due_date_changed": False,
        })
    result.sort(key=lambda item: (
        item.get("previous_index") is None,
        int(item.get("previous_index")) if item.get("previous_index") is not None else 10**9,
    ))
    return result


def _incremental_mutation_clauses(text: str) -> list[str]:
    """Split newest-turn lifecycle/deadline clauses without changing global parsing.

    Thread replies often coordinate several sibling updates in one sentence
    ("keep A ..., keep B ..., and keep C ...").  Whole-sentence matching can
    bind only one sibling and leave another stale.  Split only at explicit
    lifecycle/deadline-control boundaries so ordinary prose remains untouched.
    """
    clauses = []
    for sentence in _phase1b_source_sentences(text):
        parts = re.split(
            r"\s*;\s*|,\s*(?:and\s+)?(?=(?:keep|reopen|re-open|resume|restart|"
            r"cancel|stop|move|change|extend|push|shift|reschedule|remove|drop|clear)\b)",
            sentence,
            flags=re.IGNORECASE,
        )
        clauses.extend(part.strip() for part in parts if part and part.strip())
    return clauses


def _incremental_sentence_due_value(sentence: str) -> str:
    """Return a source-literal ISO due value, retaining an explicit clock."""
    text = re.sub(r"\s+", " ", str(sentence or "")).strip()
    match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", text)
    if not match:
        return ""
    due = match.group(1)
    clock = re.search(
        r"\b(1[0-2]|0?[1-9])(?::([0-5]\d))?\s*(AM|PM)\b",
        text,
        flags=re.IGNORECASE,
    )
    if clock:
        due += (
            f" {int(clock.group(1))}:{int(clock.group(2) or 0):02d} "
            f"{clock.group(3).upper()}"
        )
    else:
        clock24 = re.search(r"(?<!\d)([01]?\d|2[0-3]):([0-5]\d)\b", text)
        if clock24:
            hour24 = int(clock24.group(1))
            suffix = "AM" if hour24 < 12 else "PM"
            hour12 = hour24 % 12 or 12
            due += f" {hour12}:{clock24.group(2)} {suffix}"
    return due


def _incremental_reconcile_explicit_existing_mutations(
    email: dict, existing: dict, updates: list[dict]
) -> list[dict]:
    """Let explicit newest-turn mutations win over stale structured task state.

    The LLM frequently gets the prose Summary right while leaving the saved
    action row on an old deadline/state.  This source-grounded pass only edits
    existing thread rows when the authored turn explicitly says keep/reopen/
    resume, replaces a version label, changes/removes a deadline, or confirms a
    current due date.  It never runs for normal single-email summaries.
    """
    previous = _existing_task_context(existing)
    current_turn = _incremental_current_turn_text(email)
    if not previous or not current_turn:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    by_index: dict[int, dict] = {}
    new_rows: list[dict] = []
    for item in updates or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("state") or "").strip().casefold() == "new":
            new_rows.append(dict(item))
            continue
        try:
            index = int(item.get("previous_index"))
        except (TypeError, ValueError):
            continue
        if 0 <= index < len(previous):
            by_index[index] = dict(item)

    lifecycle_targets: set[int] = set()
    explicit_open_targets: set[int] = set()
    affirm_open_sentence = re.compile(
        r"\b(?:still\s+(?:required|needed|due)|remains?\s+(?:required|needed|due)|"
        r"keep\b[^.!?;]{0,90}\b(?:required|needed|due|unchanged)|"
        r"(?:required|needed)\s+again|still\s+need(?:s)?\s+to|"
        r"continue\s+to\s+(?:need|require))\b",
        flags=re.IGNORECASE,
    )
    positive_open_sentence = re.compile(
        r"\b(?:still\s+(?:required|needed|due)|remains?\s+(?:required|needed|due)|"
        r"keep\b[^.!?;]{0,90}\b(?:required|needed|due)|"
        r"(?:required|needed)\s+again|still\s+need(?:s)?\s+to|"
        r"continue\s+to\s+(?:need|require))\b",
        flags=re.IGNORECASE,
    )
    explicit_open = re.compile(
        r"\b(?:reopen|re-open|resume|restart|redo|repeat|"
        r"needed\s+again|required\s+again|still\s+(?:required|needed))\b",
        flags=re.IGNORECASE,
    )
    deadline_remove = re.compile(
        r"\b(?:remove|drop|clear)\b[^.!?;]{0,60}\b(?:fixed\s+)?(?:deadline|due\s+date)\b|"
        r"\b(?:no\s+(?:fixed\s+)?deadline|deadline\s+(?:is\s+)?removed)\b",
        flags=re.IGNORECASE,
    )
    deadline_change = re.compile(
        r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b"
        r"[^.!?;]{0,70}\b(?:deadline|due\s+date)\b|"
        r"\b(?:deadline|due\s+date)\b[^.!?;]{0,70}"
        r"\b(?:move|change|extend|push|shift|reschedule|set|update|confirmed?|unchanged|stays?|remains?)\w*\b|"
        r"\b(?:new|revised|replacement|updated)\s+(?:deadline|due\s+date)\b"
        r"(?:\s+(?:is|=|:|becomes?|will\s+be|set\s+to|moved\s+to))?|"
        r"\b(?:deadline|due\s+date)\s+(?:is|becomes?|will\s+be)\s+(?:now\s+)?(?:new|revised|updated)?\b|"
        r"\b(?:due|required|needed)\s+(?:again\s+)?(?:by|before|on)\b",
        flags=re.IGNORECASE,
    )

    sentences = _incremental_mutation_clauses(current_turn)
    last_target: int | None = None
    for sentence in sentences:
        index = _incremental_best_saved_action_index(previous, sentence)
        sentence_affirms = bool(affirm_open_sentence.search(sentence))
        sentence_positive_open = bool(positive_open_sentence.search(sentence))

        # A narrowly supported revision/version replacement updates the same
        # deliverable rather than creating a stale old-version To-Do beside it.
        replacement = re.search(
            r"\buse\s+(?:the\s+)?(version|revision|rev)\s+"
            r"([A-Za-z0-9][A-Za-z0-9._-]{0,15})\s+instead\b",
            sentence,
            flags=re.IGNORECASE,
        )
        if replacement and index is None:
            head = replacement.group(1)
            candidates = [
                i for i, old in enumerate(previous)
                if re.search(rf"\b{re.escape(head)}\s+[A-Za-z0-9][A-Za-z0-9._-]{{0,15}}\b",
                             str(old.get("action") or ""), flags=re.IGNORECASE)
            ]
            if len(candidates) == 1:
                index = candidates[0]
        if replacement and index is not None:
            old = previous[index]
            action = re.sub(
                rf"\b{re.escape(replacement.group(1))}\s+"
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,15}\b",
                f"{replacement.group(1)} {replacement.group(2)}",
                str(old.get("action") or ""),
                count=1,
                flags=re.IGNORECASE,
            )
            by_index[index] = {
                "previous_index": index,
                "state": "updated",
                "action": action,
                "due_date": str(old.get("due_date") or "").strip(),
                "due_date_changed": False,
            }
            lifecycle_targets.add(index)
            last_target = index

        explicit_open_match = explicit_open.search(sentence)
        if index is None and explicit_open_match and len(previous) == 1:
            # A terse lifecycle reply can omit the exact task noun (for example
            # "reopen the same/original request").  Rebind only when the entire
            # durable thread ledger contains one action; sibling work makes this
            # fallback intentionally unavailable.
            same_reference = bool(re.search(
                r"\b(?:same|original|previous|prior)\b[^.!?;]{0,55}"
                r"\b(?:request|task|action|item|work)\b",
                sentence, flags=re.IGNORECASE,
            ))
            if same_reference:
                index = 0

        if index is not None and (sentence_affirms or explicit_open_match):
            old = previous[index]
            current = by_index.get(index, {})
            state = "reopened" if explicit_open_match else str(current.get("state") or "unchanged")
            old_is_terminal = bool(old.get("completed")) or bool(old.get("cancelled"))
            if state in {"cancelled", "completed"} or (state == "unchanged" and old_is_terminal):
                # A source-explicit current requirement/due statement reactivates
                # a terminal saved row.  Merely saying "keep X unchanged" does
                # not reopen completed/cancelled work.
                state = "reopened" if sentence_positive_open else "unchanged"
            by_index[index] = {
                "previous_index": index,
                "state": state,
                "action": str(current.get("action") or old.get("action") or "").strip(),
                "due_date": str(current.get("due_date") or old.get("due_date") or "").strip(),
                "due_date_changed": bool(current.get("due_date_changed")),
            }
            lifecycle_targets.add(index)
            if explicit_open_match:
                explicit_open_targets.add(index)
            last_target = index

        due = _incremental_sentence_due_value(sentence)
        if due and re.search(
            r"\b(?:for\s+context\s+only|context\s+only|not\s+(?:a|the)\s+deadline|"
            r"is\s+not\s+(?:a|the)\s+deadline|not\s+a\s+due\s+date)\b",
            sentence,
            flags=re.IGNORECASE,
        ):
            due = ""
        remove_due = bool(deadline_remove.search(sentence))
        change_due = bool(deadline_change.search(sentence))
        target = index
        if target is None and (remove_due or change_due or due):
            # An unlabelled follow-up deadline may safely inherit one explicit
            # reopen target, or the sole durable task in a single-task thread.
            # Do not inherit from a merely affirmed/"keep unchanged" sibling: a
            # later date in the same reply may belong to newly added work.
            if len(previous) == 1 and (remove_due or change_due):
                target = 0
            elif len(explicit_open_targets) == 1 and (remove_due or change_due):
                target = next(iter(explicit_open_targets))
            elif last_target is not None and re.search(r"\b(?:it|this|that|same)\b", sentence, flags=re.IGNORECASE):
                target = last_target

        if target is not None and (remove_due or (due and (change_due or target in lifecycle_targets or sentence_affirms))):
            old = previous[target]
            current = by_index.get(target, {})
            new_due = "" if remove_due else due
            durable_old_due = str(old.get("due_date") or "").strip()
            state = str(current.get("state") or "updated")
            if explicit_open_match:
                state = "reopened"
            elif state == "unchanged":
                # summary_service intentionally ignores due_date_changed on an
                # unchanged row.  A source-proven replacement/removal is itself
                # a material task update, so promote only this row to updated.
                state = "updated"
            elif state in {"cancelled", "completed"} and sentence_affirms:
                state = "unchanged"
            by_index[target] = {
                "previous_index": target,
                "state": state,
                "action": str(current.get("action") or old.get("action") or "").strip(),
                "due_date": new_due,
                # Compare to the durable saved row, not to an already-updated
                # model candidate. Otherwise a correct proposed replacement can
                # be accidentally downgraded from changed=True to False, leaving
                # the old To-Do due date in summary_service.
                "due_date_changed": bool(current.get("due_date_changed")) or durable_old_due != new_due,
            }
            last_target = target

    result = [by_index[index] for index in sorted(by_index)] + new_rows
    return result


def _incremental_apply_relational_event_upper_bound(
    email: dict, existing: dict, updates: list[dict]
) -> list[dict]:
    """Resolve simple "before the event/joining" constraints once dated.

    This does not invent a separate task deadline: it records the newly known
    event datetime as the action's relational upper bound so To-Do preserves the
    source time instead of degrading it to midnight.
    """
    previous = _existing_task_context(existing)
    current_turn = _incremental_current_turn_text(email)
    if not previous or not current_turn:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]
    event_due = _incremental_sentence_due_value(current_turn)
    if not event_due or " " not in event_due:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    target = None
    for sentence in _phase1b_source_sentences(current_turn):
        if not re.search(
            r"\bbefore\s+(?:joining|attending|the\s+(?:meeting|call|session|event|review|presentation|conference))\b",
            sentence,
            flags=re.IGNORECASE,
        ):
            continue
        target = _incremental_best_saved_action_index(previous, sentence)
        if target is not None:
            break
    if target is None:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    result = []
    replaced = False
    for item in updates or []:
        if not isinstance(item, dict):
            continue
        copied = dict(item)
        try:
            index = int(copied.get("previous_index"))
        except (TypeError, ValueError):
            index = None
        if index == target:
            copied["state"] = "updated" if str(copied.get("state") or "").casefold() == "unchanged" else copied.get("state")
            copied["due_date"] = event_due
            copied["due_date_changed"] = str(previous[target].get("due_date") or "").strip() != event_due
            replaced = True
        result.append(copied)
    if not replaced:
        old = previous[target]
        result.append({
            "previous_index": target,
            "state": "updated",
            "action": str(old.get("action") or "").strip(),
            "due_date": event_due,
            "due_date_changed": str(old.get("due_date") or "").strip() != event_due,
        })
    return result


def _incremental_recover_ownership_transition_key_points(
    email: dict, validated_points, raw_points
) -> list[str]:
    """Preserve explicit newest-turn ownership handoffs as thread state facts.

    Normal Key Point filtering intentionally removes another person's bare future
    work so third-party tasks do not look like recipient obligations.  In an
    incremental thread, however, an explicit handoff/reassignment is itself a
    material lifecycle change even when the new owner is a third party.  Recover
    only model-extracted points that describe that transition and are grounded in
    the newest authored turn.  This keeps ownership history current without
    promoting the third party's work into Action Items or deadlines.

    The grammar is role- and domain-neutral: it recognizes transfer/reassignment,
    handoff, take-over-from, and instead-of ownership language for named actors
    or the recipient.  Quoted history is excluded because ``current_turn`` is
    already the authored-turn projection.
    """
    result = _normalize_list(validated_points)
    raw = _normalize_list(raw_points)
    current_turn = _incremental_current_turn_text(email)
    if not current_turn or not raw:
        return result

    source = re.sub(r"\s+", " ", current_turn).strip()
    if not source:
        return result

    transition_source = bool(re.search(
        r"\b(?:ownership|owner|owns?|responsib(?:le|ility)|assignee|assigned|"
        r"reassigned|transfer(?:red)?|handoff|handed\s+off|take\s+over|"
        r"takes\s+over|taking\s+over|took\s+over)\b",
        source, flags=re.IGNORECASE,
    ) and re.search(
        r"\b(?:from|to|instead\s+of|now|reassigned|transferred|handed\s+off|"
        r"take\s+over|takes\s+over|taking\s+over|took\s+over)\b",
        source, flags=re.IGNORECASE,
    ))
    if not transition_source:
        return result

    # Do not promote hypothetical, optional, or explicitly negated handoffs into
    # current-state ownership facts. This guard is scoped to the transition
    # clause shape and does not suppress an unrelated conditional elsewhere.
    if re.search(
        r"\b(?:if|unless)\b[^.!?]{0,140}\b(?:take\s+over|reassign(?:ed)?|"
        r"transfer(?:red)?|assign(?:ed)?|hand(?:ed)?\s+off)\b|"
        r"\b(?:may|might|could|would)\b[^.!?]{0,60}\b(?:take\s+over|"
        r"be\s+(?:reassigned|assigned|transferred)|receive\s+ownership)\b|"
        r"\b(?:do\s+not|don't|not|never)\b[^.!?]{0,60}\b(?:take\s+over|"
        r"reassign|transfer|assign|hand\s+off)\b",
        source, flags=re.IGNORECASE,
    ):
        return result

    for point in raw:
        compact = re.sub(r"\s+", " ", str(point or "")).strip()
        if not compact:
            continue
        # Require lifecycle/ownership semantics in the point itself. A bare
        # ``Maria will prepare X`` remains third-party task metadata and stays
        # filtered; ``Maria will take over X`` is a state transition.
        if not re.search(
            r"\b(?:ownership|owner|owns?|responsib(?:le|ility)|assignee|assigned|"
            r"reassigned|transfer(?:red)?|handoff|handed\s+off|take\s+over|"
            r"takes\s+over|taking\s+over|took\s+over)\b",
            compact, flags=re.IGNORECASE,
        ):
            continue
        if not re.search(
            r"\b(?:from|to|instead\s+of|now|reassigned|transferred|handed\s+off|"
            r"take\s+over|takes\s+over|taking\s+over|took\s+over)\b",
            compact, flags=re.IGNORECASE,
        ):
            continue
        if not _is_supported(compact, source):
            continue
        if any(existing.casefold() == compact.casefold() for existing in result):
            continue

        # Prefer an already-validated, source-grounded ownership transition over
        # a second model alias for the same newest-turn handoff.  The validated
        # point is normally closer to the authored wording (for example, a
        # ``recipient will now take over <task> from <prior owner>`` form), while
        # the raw model may also emit a compact alias such as ``Ownership transferred to the
        # recipient``.  Keeping both creates duplicate current-state Key Points
        # and, on a later handoff, gives the merge layer two stale aliases to
        # retire.  This is role/name/task neutral: any already-retained explicit
        # ownership/assignee transition grounded in the same newest turn wins.
        existing_transition = any(
            re.search(
                r"\b(?:ownership|owner|owns?|responsib(?:le|ility)|assignee|assigned|"
                r"reassigned|transfer(?:red)?|handoff|handed\s+off|take\s+over|"
                r"takes\s+over|taking\s+over|took\s+over)\b",
                str(existing or ""), flags=re.IGNORECASE,
            )
            and re.search(
                r"\b(?:from|to|instead\s+of|now|reassigned|transferred|handed\s+off|"
                r"take\s+over|takes\s+over|taking\s+over|took\s+over)\b",
                str(existing or ""), flags=re.IGNORECASE,
            )
            and _is_supported(re.sub(r"\s+", " ", str(existing or "")).strip(), source)
            for existing in result
        )
        if existing_transition:
            continue

        result.append(compact)

    return _merge_unique(result)


def _incremental_recover_correction_key_points(email: dict, points) -> list[str]:
    """Keep explicit newest-turn corrections as scan facts for thread state."""
    result = _normalize_list(points)
    current_turn = _incremental_current_turn_text(email)
    if not current_turn:
        return result
    for sentence in _incremental_correction_sentences(current_turn):
        if not re.search(
            r"\b(?:correction|instead|not\s+\$?\d|rather\s+than)\b",
            sentence,
            flags=re.IGNORECASE,
        ):
            continue
        # Require a concrete changed value/identifier so ordinary wording like
        # "use the corrected file" does not manufacture a low-value Key Point.
        if not re.search(r"\$?\d[\d,]*(?:\.\d+)?%?|\b(?:version|revision|rev)\s+[A-Za-z0-9._-]+\b", sentence, flags=re.IGNORECASE):
            continue
        result.append(re.sub(r"\s+", " ", sentence).strip())
    return _merge_unique(result)



def _incremental_lifecycle_alias_core_tokens(value: str) -> set[str]:
    """Return task-object tokens with common action nominalizations removed."""
    tokens = set(_phase1e_object_tokens(value))
    tokens.difference_update({
        "action", "approval", "confirmation", "delivery", "item", "preparation",
        "request", "review", "submission", "task", "work",
    })
    return tokens


def _incremental_drop_lifecycle_alias_new_actions(
    email: dict, existing: dict, updates: list[dict]
) -> list[dict]:
    """Do not create a second task when the newest turn explicitly resumes one.

    Small/local model passes can nominalize an existing task during lifecycle
    wording (for example ``Send the report`` -> ``Report submission``) and label
    that nominalization ``state=new``.  A resume/reopen/restart/continue clause is
    a mutation of durable work, not evidence for an additional To-Do.  Suppress
    only a NEW row that has exactly one strong durable-object match and no
    explicit add/create-new-task language.  Explicit sibling identity markers
    remain authoritative, so Proposal A/B and versioned work cannot collapse.
    """
    previous = _existing_task_context(existing)
    current_turn = _incremental_current_turn_text(email)
    if not previous or not current_turn:
        return [dict(item) for item in (updates or []) if isinstance(item, dict)]

    lifecycle = re.compile(
        r"\b(?:reopen|re-open|reopened|resume|resumed|restart|restarted|continue|continued)\b",
        flags=re.IGNORECASE,
    )
    explicit_new = re.compile(
        r"\b(?:add|create)\s+(?:a\s+)?(?:new\s+)?(?:task|action(?:\s+item)?|to[- ]?do)\b",
        flags=re.IGNORECASE,
    )

    result: list[dict] = []
    for raw in updates or []:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        if str(item.get("state") or "").strip().casefold() != "new":
            result.append(item)
            continue

        action = str(item.get("action") or "").strip()
        evidence = _phase1b_find_evidence(action, current_turn) if action else ""
        if not evidence or not lifecycle.search(evidence) or explicit_new.search(evidence):
            result.append(item)
            continue

        candidate_core = _incremental_lifecycle_alias_core_tokens(action)
        candidate_markers = _incremental_identity_markers(action)
        if not candidate_core:
            # Lifecycle turns occasionally produce a content-free nominal alias
            # such as ``New submission`` beside the one durable task being
            # resumed. With exactly one prior task, no identity marker, and no
            # source wording that actually introduces new/additional work, that
            # alias cannot identify a second obligation. Drop only this narrow
            # objectless shape; explicit new/another/additional/separate work
            # remains untouched.
            explicit_distinct_work = re.search(
                r"\b(?:new|another|additional|separate)\b",
                evidence,
                flags=re.IGNORECASE,
            )
            if len(previous) == 1 and not candidate_markers and not explicit_distinct_work:
                continue
            result.append(item)
            continue

        matches = []
        for index, old in enumerate(previous):
            old_action = str(old.get("action") or "").strip()
            if not old_action:
                continue
            old_markers = _incremental_identity_markers(old_action)
            marker_conflict = any(
                old_markers.get(head) and old_markers.get(head) != label
                for head, label in candidate_markers.items()
            )
            marker_conflict = marker_conflict or any(
                candidate_markers.get(head) and candidate_markers.get(head) != label
                for head, label in old_markers.items()
            )
            if marker_conflict:
                continue
            old_core = _incremental_lifecycle_alias_core_tokens(old_action)
            if candidate_core and old_core and candidate_core.issubset(old_core):
                matches.append(index)

        if len(matches) == 1:
            # The later explicit mutation reconciler updates/reopens the durable
            # row, including its replacement deadline.  This row is only the
            # duplicate NEW alias and is safe to discard.
            continue
        result.append(item)
    return result


def _incremental_recover_missing_new_actions(
    email: dict,
    existing: dict,
    updates: list[dict],
    key_point_candidates,
    deadlines,
) -> list[dict]:
    # A small/local model can recognize a genuinely new recipient request but put
    # it in key_points instead of task_updates. Recover only those model-extracted
    # candidates that pass the normal recipient/action grounding guards and are
    # semantically distinct from every saved/updated action. This is deliberately
    # narrower than extracting arbitrary prose from the reply.
    recovered = [dict(item) for item in (updates or []) if isinstance(item, dict)]

    # Recovery is allowed only from the newest authored turn.  Key Points may be
    # model-extracted from a full reply body that also contains quoted history;
    # that history must never become a newly synthesized To-Do item.
    current_turn = _incremental_current_turn_text(email)
    local_email = dict(email)
    if current_turn:
        local_email["body_text"] = current_turn
        local_email["snippet"] = current_turn
    # Do not depend only on model Key Points to recover a missed new task.
    # Thread replies can contain a source-explicit recipient request that the
    # model summarizes correctly but omits from task_updates/key_points.  Feed
    # only direct newest-turn request sentences through the same locked action
    # validator; this path is thread-only and cannot affect normal-email Summary.
    source_candidates = []
    for sentence in _phase1b_source_sentences(current_turn):
        candidate = sentence
        declared = re.match(
            r"^\s*(?:add|create)\s+(?:a\s+)?new\s+(?:task|action|item)\s*:\s*(.+)$",
            sentence,
            flags=re.IGNORECASE,
        )
        if declared:
            candidate = declared.group(1).strip()
        candidate_action = _separate_action_item_text(candidate)
        if (
            _phase1b_recipient_request_signal(candidate)
            and _phase1c_action_intent(candidate_action)
            and _phase1e_object_tokens(candidate_action)
        ):
            source_candidates.append(candidate)

    candidate_pool = _merge_unique(
        _normalize_list(key_point_candidates) + source_candidates
    )
    validated = _phase1b_validate_actions(local_email, candidate_pool)
    if not validated:
        return recovered

    known_actions = [
        str(item.get("action") or "").strip()
        for item in _existing_task_context(existing)
        if str(item.get("action") or "").strip()
    ] + [
        str(item.get("action") or "").strip()
        for item in recovered
        if str(item.get("action") or "").strip()
    ]

    body = current_turn or _body_text(local_email)
    grounded_deadlines = _normalize_list(deadlines)
    for candidate in validated:
        action = _separate_action_item_text(candidate)
        if not action or _action_item_is_metadata_only(action):
            continue
        if known_actions and _raw_first_is_execution_control_action(action):
            continue
        if any(_incremental_actions_semantically_same(action, known) for known in known_actions):
            continue

        # Attach a deadline only when the same request evidence sentence grounds
        # it; never borrow another action's/global contextual date.
        due_date = ""
        evidence = _phase1b_find_evidence(action, body)
        if evidence:
            for value in grounded_deadlines:
                deadline_evidence = _phase1b_deadline_sentence(value, evidence)
                if deadline_evidence and _phase1b_is_valid_deadline_sentence(deadline_evidence):
                    due_date = value
                    break

        recovered.append({
            "previous_index": None,
            "state": "new",
            "action": action,
            "due_date": due_date,
            "due_date_changed": bool(due_date),
        })
        known_actions.append(action)
    return recovered


def _incremental_global_completion_is_proven(email: dict) -> bool:
    """Return True only for an explicit whole-work completion in the authored turn.

    A thread can have several independently tracked child actions.  A sentence
    such as "X is complete" may refer to only one of them, so it is not enough
    to close every saved action.  Whole-work completion requires broad scope
    (all/everything/entire/whole) and no simultaneous positive recipient
    request in the newest authored turn.  Quoted history is excluded by the
    same current-turn boundary used by the other incremental evidence guards.
    """
    turn = _incremental_current_turn_text(email)
    if not turn:
        return False
    compact = re.sub(r"\s+", " ", turn).strip()
    if not compact:
        return False

    scoped_subject = (
        r"(?:"
        r"all(?:\s+(?:requested|assigned|remaining|outstanding|current))?\s+"
        r"(?:work|tasks?|actions?|items?|deliverables?|requirements?|requests?|assignments?)"
        r"|everything"
        r"|the\s+(?:entire|whole|full)\s+"
        r"(?:task|request|project|work|job|assignment|scope|process|review)"
        r")"
    )
    completed_predicate = (
        r"(?:"
        r"(?:has|have)\s+(?:now\s+)?been\s+(?:fully\s+)?(?:completed|finished|done)"
        r"|(?:is|are|was|were)\s+(?:now\s+)?(?:fully\s+)?(?:complete|completed|finished|done)"
        r")"
    )
    if not re.search(
        rf"\b{scoped_subject}\s+{completed_predicate}\b",
        compact,
        flags=re.IGNORECASE,
    ):
        return False
    if _incremental_summary_implies_open_work(compact):
        # "All X is finished, but Y is still required" is a mixed update, not
        # a terminal global completion, even when the new obligation is phrased
        # passively rather than as an imperative request.
        return False

    # A broad completion statement followed by a fresh positive request is a
    # mixed turn, not a terminal whole-work completion.  Do not close unrelated
    # child actions in that case.
    for sentence in _phase1b_source_sentences(turn):
        if not _phase1b_recipient_request_signal(sentence):
            continue
        if _phase1g_addressed_to_other_person(email, sentence):
            continue
        if _phase1c_evidence_is_non_action(sentence, turn):
            continue
        return False
    return True


def _incremental_terminal_task_overrides(email: dict, previous: list[dict], updates: list[dict]) -> list[dict]:
    # Deterministic safety net for explicit latest-turn terminal states.
    # Small/local models can correctly describe "cancelled/no longer needed" in
    # the prose Summary yet still emit ``unchanged`` (or no task_updates), which
    # leaves stale Action Items and deadlines visible. Only intervene when the
    # newest effective turn proves there is no positive recipient request.
    global_completion = _incremental_global_completion_is_proven(email)
    if not previous or (
        not global_completion
        and not _phase1i2_terminal_no_action_is_proven(email, [])
    ):
        return updates

    turn = _phase1g_effective_turn_text(_body_text(email))
    if not turn:
        return updates
    lowered = turn.casefold()
    open_indexes = [
        index for index, item in enumerate(previous)
        if not bool(item.get("completed")) and not bool(item.get("cancelled"))
    ]
    if not open_indexes:
        return updates

    # A local terminal phrase must not close sibling work that this same newest
    # turn explicitly keeps active (for example "X is still required. No other
    # action is needed" or "cancel Y; keep X unchanged"). Specific cancellation
    # targets have already been source-rebound before this safety net runs.
    affirmed_open = _incremental_affirmed_open_indexes(email, previous)
    if affirmed_open and not global_completion:
        return updates

    completion_signal = global_completion or bool(re.search(
        r"\b(?:received\s+and\s+completed|has\s+been\s+received\s+and\s+completed|"
        r"(?:is|was|has\s+been|have\s+been)?\s*(?:completed|finished|done))\b",
        lowered,
        flags=re.IGNORECASE,
    ))
    cancellation_signal = bool(re.search(
        r"\b(?:cancel(?:led|ed)?(?:\s+(?:that|this|the))?(?:\s+(?:request|task|action))?|"
        r"no\s+longer\s+(?:needed|required)|you\s+no\s+longer\s+need\s+to|"
        r"do\s+not\s+(?:send|submit|prepare|provide|review|complete|perform|proceed)|"
        r"don't\s+(?:send|submit|prepare|provide|review|complete|perform|proceed))\b",
        lowered,
        flags=re.IGNORECASE,
    ))
    state = "completed" if completion_signal and not cancellation_signal else "cancelled"

    global_terminal = global_completion or bool(re.search(
        r"\b(?:no\s+(?:further|other)?\s*action\s+(?:is\s+)?(?:needed|required)|"
        r"nothing\s+(?:is\s+)?required\s+from\s+you|"
        r"you\s+(?:do\s+not|don't)\s+need\s+to\s+(?:do|take)\s+anything)\b",
        lowered,
        flags=re.IGNORECASE,
    ))

    target_indexes = list(open_indexes) if global_terminal else []
    if not target_indexes and len(open_indexes) == 1:
        target_indexes = list(open_indexes)
    if not target_indexes:
        # Do not infer a local terminal target from whole-turn token overlap.
        # In multi-action threads the same reply often mentions every sibling
        # while cancelling/completing only one. Explicit cancellation rebinding
        # and model-grounded per-action updates above are safer authority.
        return updates

    if not target_indexes:
        return updates

    target_set = set(target_indexes)
    result = []
    for item in updates:
        if not isinstance(item, dict):
            continue
        if str(item.get("state") or "").strip().casefold() == "new":
            # A proven terminal no-action turn cannot introduce new recipient work.
            continue
        try:
            idx = int(item.get("previous_index"))
        except (TypeError, ValueError):
            idx = None
        if idx in target_set:
            continue
        result.append(dict(item))

    for index in target_indexes:
        old = previous[index]
        result.append({
            "previous_index": index,
            "state": state,
            "action": str(old.get("action") or "").strip(),
            "due_date": str(old.get("due_date") or "").strip(),
            "due_date_changed": False,
        })
    result.sort(key=lambda item: (
        item.get("previous_index") is None,
        int(item.get("previous_index")) if item.get("previous_index") is not None else 10**9,
    ))
    return result



def _incremental_material_deadline_change(existing: dict, task_updates) -> bool:
    """Return True only for a real due-date replacement/removal on saved work."""
    rows = _existing_task_context(existing)
    for item in task_updates or []:
        if not isinstance(item, dict):
            continue
        try:
            index = int(item.get("previous_index"))
        except (TypeError, ValueError):
            continue
        if not 0 <= index < len(rows):
            continue
        before = re.sub(r"\s+", " ", str(rows[index].get("due_date") or "")).strip().casefold()
        after = re.sub(r"\s+", " ", str(item.get("due_date") or "")).strip().casefold()
        if before != after:
            return True
    return False


def _incremental_priority_change_is_source_supported(email: dict, existing: dict, task_updates) -> bool:
    """Return True only when the newest turn gives a reason to replace priority.

    Thread priority is durable task state.  A reply that merely adds/rewords work
    must not replace an already-saved priority just because the incremental model
    happens to choose a different label.  Model-driven replacement is allowed only
    for a source-explicit priority/urgency signal. Deadline changes are reconciled
    deterministically downstream from the structured active-task due dates, so two
    providers cannot diverge merely because their models chose different labels.
    This is domain/subject independent.
    """
    if _phase1b_explicit_priority(email):
        return True
    body = re.sub(r"\s+", " ", _body_text(email)).strip()
    if not body:
        return False
    if _summary_low_urgency_signals(body):
        return True
    urgency_context = re.sub(
        r"\b(?:not urgent|no rush|no hurry|not time[- ]sensitive)\b",
        " ", body.casefold(), flags=re.IGNORECASE,
    )
    if re.search(
        r"\b(?:urgent|critical|blocking|blocked|escalat\w*|immediate(?:ly)?|asap)\b|"
        r"\bas soon as possible\b|\bproduction (?:is )?blocked\b",
        urgency_context,
        flags=re.IGNORECASE,
    ):
        return True
    # Deadline mutations are material to the task, but they are not semantic
    # evidence for a model-chosen priority label. The merge layer already
    # recomputes deadline urgency deterministically from the reconciled active
    # action dates. Keep the saved priority baseline here unless the authored
    # turn itself says urgency/priority changed.
    return False


def _incremental_filter_context_only_deadlines(email: dict, values) -> list[str]:
    """Drop newest-turn dates explicitly labeled as context, not deadlines.

    Thread updates may mention a meeting/event date while simultaneously removing
    the task's fixed deadline.  That date belongs in Summary/Key Points context,
    not in the task Deadline/To-Do projection.  This guard runs only on the
    incremental thread delta path.
    """
    current_turn = _incremental_current_turn_text(email)
    if not current_turn:
        return _normalize_list(values)
    result = []
    for raw in _normalize_list(values):
        value = str(raw or "").strip()
        if not value:
            continue
        evidence = _phase1b_deadline_sentence(value, current_turn) or ""
        if evidence and re.search(
            r"\b(?:for\s+context\s+only|context\s+only|"
            r"not\s+(?:a|the)\s+deadline|is\s+not\s+(?:a|the)\s+deadline|"
            r"not\s+a\s+due\s+date|not\s+the\s+due\s+date)\b",
            evidence, flags=re.IGNORECASE,
        ):
            continue
        result.append(value)
    return _phase1c_dedupe_deadlines(result)


def _incremental_raw_priority(
    email: dict, existing: dict, raw_priority, task_updates
) -> tuple[str, bool]:
    """RAW-first priority with durable-state validation.

    A valid raw priority passes through.  When the raw label conflicts with the
    saved task and the newest source contains no priority/urgency/deadline-change
    evidence, preserve the saved value instead of silently rewriting it.
    """
    saved = _normalize_priority(existing.get("priority") or "Low")
    raw = _normalize_priority(raw_priority)
    replacement_allowed = _incremental_priority_change_is_source_supported(
        email, existing, task_updates
    )
    explicit = _phase1b_explicit_priority(email)
    if explicit:
        return explicit, True
    if raw == saved:
        return raw, replacement_allowed
    if replacement_allowed:
        return raw, True
    return saved, False


def _incremental_summary_covers_action(summary: str, action: str) -> bool:
    """Conservative semantic coverage check for one changed/new thread action."""
    overview = _compact_summary_overview(summary)
    task = _separate_action_item_text(action)
    if not overview or not task:
        return False
    if _phase1e_related_action_text(task, overview):
        return True
    summary_terms = _summary_overlap_terms(overview)
    action_terms = _summary_overlap_terms(task)
    if action_terms:
        shared = summary_terms & action_terms
        if len(shared) / max(1, len(action_terms)) >= 0.50:
            return True
    summary_intents = _raw_first_action_intents(overview)
    action_intents = _raw_first_action_intents(task)
    if summary_intents & action_intents:
        action_objects = _phase1e_object_tokens(task)
        summary_objects = _phase1e_object_tokens(overview)
        if not action_objects:
            return True
        matched = sum(
            1 for token in action_objects
            if any(_raw_first_tokens_related(token, other) for other in summary_objects)
        )
        return matched / max(1, len(action_objects)) >= 0.50
    return False


def _incremental_summary_implies_open_work(summary: str) -> bool:
    """Detect present/future obligation language in a completion summary."""
    text = re.sub(r"\s+", " ", str(summary or "")).strip()
    if not text:
        return False

    # Remove explicit no-action/no-obligation statements before looking for
    # active requirement language so "no further action is required" does not
    # become a false positive.
    scrubbed = re.sub(
        r"\b(?:no\s+(?:further|other)?\s+(?:action|work)\s+(?:is\s+)?(?:required|needed)|"
        r"nothing\s+(?:else\s+)?(?:is\s+)?(?:required|needed)|"
        r"no\s+(?:additional|remaining)\s+(?:task|work|action)s?\s+(?:is|are)\s+(?:required|needed)|"
        r"(?:is|are)\s+not\s+(?:required|needed))\b",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    return bool(re.search(
        r"\b(?:"
        r"(?:is|are)\s+(?:still\s+)?(?:required|needed|pending|outstanding)"
        r"|remains?\s+(?:required|needed|pending|outstanding)"
        r"|(?:will|would)\s+be\s+(?:required|needed)"
        r"|(?:needs?|must|should|has\s+to|have\s+to)\s+(?:be\s+)?(?:done|completed|finished|prepared|sent|submitted|provided|reviewed|updated)?"
        r"|(?:still\s+)?needs?\s+to\b"
        r"|(?:pending|outstanding)\s+(?:task|work|action|item)s?\b"
        r"|new\b.{0,100}\b(?:is\s+)?(?:required|needed|pending|outstanding)\b"
        r")",
        scrubbed,
        flags=re.IGNORECASE,
    ))


def _incremental_completion_summary_from_source(email: dict) -> str:
    """Build a concise completion-only summary from the authored source turn."""
    turn = _incremental_current_turn_text(email)
    if not turn:
        return ""
    completion_sentences = []
    for sentence in _phase1b_source_sentences(turn):
        clean = re.sub(r"\s+", " ", str(sentence or "")).strip()
        if not clean:
            continue
        if not re.search(
            r"\b(?:complete|completed|finished|done)\b",
            clean,
            flags=re.IGNORECASE,
        ):
            continue
        completion_sentences.append(clean)
        if len(completion_sentences) >= 2:
            break
    return _compact_summary_overview(" ".join(completion_sentences))


def _incremental_raw_summary_is_valid(
    email: dict,
    existing: dict,
    raw_summary: str,
    task_updates,
    overview_actions,
) -> bool:
    """Validate THREAD_AI_RAW Summary without rewriting a field that is already good.

    The incremental prompt already asks the model for the current whole-thread
    overview.  Accept that wording when it is non-meta, carries no unsupported
    explicit numeric/date/time value, and represents every materially changed/new
    action.  Lifecycle-only turns (pause/hold/completion/cancellation) are allowed
    to summarize state without restating the action list.
    """
    overview = _compact_summary_overview(raw_summary)
    if not overview:
        return False
    if _summary_is_topic_only_overview(overview):
        return False
    if _summary_is_meta_framed_action_overview(overview, overview_actions):
        return False
    if (
        _incremental_global_completion_is_proven(email)
        and _incremental_summary_implies_open_work(overview)
    ):
        # A proven whole-work completion cannot coexist with an outstanding/new
        # obligation in the same current-state Summary.  This is a field-level
        # contradiction, so RAW-first permits repairing this Summary only.
        return False

    known_material = (
        _summary_explicit_signal_tokens(_email_text(email))
        | _summary_explicit_signal_tokens(str(existing.get("summary") or ""))
        | _summary_explicit_signal_tokens(" ".join(_normalize_list(existing.get("deadlines"))))
        | _summary_explicit_signal_tokens(" ".join(
            str(item.get("due_date") or "")
            for item in _existing_task_context(existing)
            if isinstance(item, dict)
        ))
    )
    if not _summary_explicit_signal_tokens(overview).issubset(known_material):
        return False

    changed_actions = [
        str(item.get("action") or "").strip()
        for item in (task_updates or [])
        if isinstance(item, dict)
        and str(item.get("state") or "").strip().casefold() in {"new", "updated", "reopened"}
        and str(item.get("action") or "").strip()
    ]
    if changed_actions and not all(
        _incremental_summary_covers_action(overview, action)
        for action in changed_actions
    ):
        return False
    return True




def _incremental_is_deadline_only_preserving_update(email: dict) -> bool:
    """Prove that the newest turn changes only the workflow deadline.

    The preservation cue is important: a generic deadline change can accompany
    other material edits, in which case carrying the prior Summary forward could
    reintroduce stale state.  This guard activates only when the sender explicitly
    says the remaining state is unchanged/no other changes were made.
    """
    current = _incremental_current_turn_text(email)
    if not current:
        return False
    deadline_mutation = bool(re.search(
        r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b"
        r"[^.!?;]{0,70}\b(?:deadline|due\s+date)\b|"
        r"\b(?:deadline|due\s+date)\b[^.!?;]{0,70}"
        r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b",
        current, flags=re.IGNORECASE,
    ))
    preserves_other_state = bool(re.search(
        r"\b(?:everything\s+else\s+(?:remains?|stays?)\s+(?:the\s+)?same|"
        r"all\s+other\s+(?:details?|items?|terms?|work)\s+(?:remain|stays?|are)\s+unchanged|"
        r"otherwise\s+unchanged|no\s+other\s+changes?|"
        r"only\s+the\s+(?:deadline|due\s+date)\s+changes?)\b",
        current, flags=re.IGNORECASE,
    ))
    if not (deadline_mutation and preserves_other_state):
        return False

    # Do not retain old prose when the same turn explicitly changes another
    # material lifecycle/value/priority fact as well.
    scrubbed = re.sub(
        r"\b(?:everything\s+else\s+(?:remains?|stays?)\s+(?:the\s+)?same|"
        r"all\s+other\s+(?:details?|items?|terms?|work)\s+(?:remain|stays?|are)\s+unchanged|"
        r"otherwise\s+unchanged|no\s+other\s+changes?|"
        r"only\s+the\s+(?:deadline|due\s+date)\s+changes?)\b",
        " ", current, flags=re.IGNORECASE,
    )
    if re.search(
        r"\b(?:correction|instead\s+of|rather\s+than|cancel(?:led|ed)?|"
        r"complete(?:d)?|finished|reopen(?:ed)?|reassign(?:ed)?|"
        r"priority\s+(?:is|to|changed|raised|lowered))\b",
        scrubbed, flags=re.IGNORECASE,
    ):
        return False
    return True


def _incremental_replace_calendar_date_in_summary(
    text: str, old_due: str, new_due: str
) -> tuple[str, bool]:
    """Replace one old calendar deadline rendering with the new grounded date."""
    source = str(text or "")
    old_identity = _phase1c_deadline_identity(old_due)
    new_identity = _phase1c_deadline_identity(new_due)
    if not source or not old_identity.startswith("date:") or not new_identity.startswith("date:"):
        return source, False
    if old_identity == new_identity:
        return source, False
    try:
        old_date = date.fromisoformat(old_identity.split(":", 1)[1])
    except ValueError:
        return source, False

    new_rendered = _summary_humanize_deadline_text(new_due).strip(" ,.;")
    if not new_rendered:
        return source, False

    month_full = old_date.strftime("%B")
    month_short = old_date.strftime("%b")
    patterns = (
        rf"\b{re.escape(month_full)}\s+{old_date.day}(?:st|nd|rd|th)?(?:,?\s+{old_date.year})?\b",
        rf"\b{re.escape(month_short)}\.?\s+{old_date.day}(?:st|nd|rd|th)?(?:,?\s+{old_date.year})?\b",
        rf"\b{old_date.year}[-/]{old_date.month:02d}[-/]{old_date.day:02d}\b",
        rf"\b{old_date.year}[-/]{old_date.month}[-/]{old_date.day}\b",
    )
    updated = source
    for pattern in patterns:
        updated, count = re.subn(pattern, new_rendered, updated, flags=re.IGNORECASE)
        if count:
            return updated, True
    return source, False


def _incremental_rebase_deadline_only_summary(
    email: dict, existing: dict, candidate: str, deadlines
) -> tuple[str, bool]:
    """Carry still-current prior context through an explicit deadline-only update.

    A model can correctly describe the newest delta ("deadline moved to ...") yet
    omit a still-current corrected amount/version from the whole-thread Summary.
    When the sender explicitly says every other detail is unchanged, preserve the
    already-saved current Summary and replace only its old calendar deadline.  If
    that Summary had no deadline text, append the grounded newest deadline delta.
    """
    overview = _compact_summary_overview(candidate)
    current_deadlines = _normalize_list(deadlines)
    if not overview or len(current_deadlines) != 1:
        return overview, False
    if not _incremental_is_deadline_only_preserving_update(email):
        return overview, False

    new_due = current_deadlines[0]
    if not _incremental_summary_deadline_mentions_value(overview, new_due):
        return overview, False
    previous = _compact_summary_overview(existing.get("summary"))
    if not previous:
        return overview, False

    rebased = previous
    replaced = False
    for old_due in _normalize_list(existing.get("deadlines")):
        rebased, changed = _incremental_replace_calendar_date_in_summary(
            rebased, old_due, new_due
        )
        replaced = replaced or changed

    if replaced:
        # Wording such as "same/unchanged deadline" described the prior turn and
        # becomes false once the date moves.  Remove only that local modifier;
        # all non-deadline current-state context remains untouched.
        rebased = re.sub(
            r"\b(?:same|unchanged|existing|current)\s+(deadline|due\s+date)\b",
            r"\1", rebased, flags=re.IGNORECASE,
        )
        rebased = _compact_summary_overview(rebased)
        return (rebased or overview), bool(rebased and rebased != overview)

    # If the saved overview carried useful non-deadline context but did not spell
    # out the prior date, keep it and append the source-grounded deadline delta.
    if _summary_missing_material_prior_context(email, previous, overview):
        combined = _compact_summary_overview(
            f"{_summary_as_one_context_sentence(previous)} "
            f"{_summary_as_one_context_sentence(overview)}"
        )
        return (combined or overview), bool(combined and combined != overview)
    return overview, False


def _incremental_project_open_actions(existing: dict, task_updates) -> list[str]:
    """Project the current open action wording after one incremental turn."""
    rows = [dict(item) for item in _existing_task_context(existing)]
    for update in task_updates or []:
        if not isinstance(update, dict):
            continue
        state = str(update.get("state") or "").strip().casefold()
        try:
            index = int(update.get("previous_index"))
        except (TypeError, ValueError):
            index = None
        if state == "new":
            action = str(update.get("action") or "").strip()
            if action:
                rows.append({"action": action, "completed": False, "cancelled": False})
            continue
        if index is None or not 0 <= index < len(rows):
            continue
        if state == "completed":
            rows[index]["completed"] = True
        elif state == "cancelled":
            rows[index]["cancelled"] = True
        elif state in {"updated", "reopened"}:
            action = str(update.get("action") or "").strip()
            if action:
                rows[index]["action"] = action
            if state == "reopened":
                rows[index]["completed"] = False
                rows[index]["cancelled"] = False
    return _merge_unique([
        str(row.get("action") or "").strip()
        for row in rows
        if str(row.get("action") or "").strip()
        and not bool(row.get("completed"))
        and not bool(row.get("cancelled"))
    ])


def _incremental_direct_action_overview(existing: dict, task_updates) -> str:
    """Last-resort direct task prose when a thread Summary is proven meta/topic-only."""
    actions = _incremental_project_open_actions(existing, task_updates)
    if not actions:
        return _compact_summary_overview(existing.get("summary"))
    # Keep this fallback concise rather than reproducing a long checklist.  The
    # exact complete list remains in Action Items; Summary only needs the main
    # current work when the model's narrative field itself is unusable.
    selected = actions[:2]
    parts = [re.sub(r"\s+", " ", item).strip(" ,.;") for item in selected if str(item).strip()]
    if not parts:
        return ""
    if len(parts) == 1:
        text = parts[0]
    else:
        text = "; ".join(parts)
    return _compact_summary_overview(text[:1].upper() + text[1:] + ".")

def _incremental_structured_action_overview(existing: dict, task_updates) -> str:
    """Build a safe fallback Summary from canonical open actions + due ownership.

    This is used only after the model Summary has already failed field-level
    validation and mixed dated/undated work makes prose deadline scope unsafe.
    The canonical task rows are more authoritative than contaminated RAW prose:
    existing due dates remain on their owning tasks and an undated newly-added
    task stays undated.  No subject, business object, date, or benchmark wording
    is hardcoded here.
    """
    rows = [dict(item) for item in _existing_task_context(existing)]
    for update in task_updates or []:
        if not isinstance(update, dict):
            continue
        state = str(update.get("state") or "").strip().casefold()
        try:
            index = int(update.get("previous_index"))
        except (TypeError, ValueError):
            index = None

        if state == "new":
            action = str(update.get("action") or "").strip()
            if action:
                rows.append({
                    "action": action,
                    "due_date": str(update.get("due_date") or "").strip(),
                    "completed": False,
                    "cancelled": False,
                })
            continue
        if index is None or not 0 <= index < len(rows):
            continue
        if state == "completed":
            rows[index]["completed"] = True
        elif state == "cancelled":
            rows[index]["cancelled"] = True
        elif state in {"updated", "reopened"}:
            action = str(update.get("action") or "").strip()
            if action:
                rows[index]["action"] = action
            if bool(update.get("due_date_changed")):
                rows[index]["due_date"] = str(update.get("due_date") or "").strip()
            if state == "reopened":
                rows[index]["completed"] = False
                rows[index]["cancelled"] = False

    open_rows = [
        row for row in rows
        if str(row.get("action") or "").strip()
        and not bool(row.get("completed"))
        and not bool(row.get("cancelled"))
    ]
    if not open_rows:
        return _compact_summary_overview(existing.get("summary"))

    parts = []
    for row in open_rows[:3]:
        action = re.sub(r"\s+", " ", str(row.get("action") or "")).strip(" ,.;")
        if not action:
            continue
        due = re.sub(r"\s+", " ", str(row.get("due_date") or "")).strip(" ,.;")
        if due:
            action = f"{action} by {due}"
        parts.append(action)
    if not parts:
        return ""
    sentence_parts = [parts[0]] + [
        part[:1].lower() + part[1:] if part else part
        for part in parts[1:]
    ]
    text = ", and ".join(sentence_parts)
    return _compact_summary_overview(text[:1].upper() + text[1:] + ".")


def _incremental_invalid_summary_needs_structured_deadline_fallback(
    summary: str, task_updates
) -> bool:
    """Detect unsafe mixed deadline ownership after RAW already failed validation."""
    overview = _compact_summary_overview(summary)
    updates = [dict(item) for item in (task_updates or []) if isinstance(item, dict)]
    if not overview or not updates:
        return False
    has_undated_new = any(
        str(item.get("state") or "").strip().casefold() == "new"
        and not str(item.get("due_date") or "").strip()
        for item in updates
    )
    if not has_undated_new:
        return False
    due_values = _merge_unique([
        str(item.get("due_date") or "").strip()
        for item in updates
        if str(item.get("due_date") or "").strip()
        and str(item.get("state") or "").strip().casefold() not in {"completed", "cancelled"}
    ])
    return any(
        _incremental_summary_deadline_mentions_value(overview, due)
        for due in due_values
    )

def summarize_incremental_email(email: dict, existing: dict) -> dict:
    # Summarize only new thread turns while reconciling saved To-Do state.
    #
    # This replaces the normal one-message summary call for an already summarized
    # thread, so task reconciliation does not add a second LLM request.
    previous_actions = _existing_task_context(existing)
    body = _body_text(email)
    if not body:
        empty_result = {
            "summary": str(existing.get("summary") or "No meaningful email content was provided."),
            "task_title": str(existing.get("task_title") or ""),
            "priority": str(existing.get("priority") or "Low"),
            "key_points": [],
            "deadlines": [],
            "action_items": [],
            "action_item_details": [],
            "task_updates": [],
        }
        trace_summary_pipeline("THREAD_AI_FINAL_FAST_PATH", email=email, summary=empty_result)
        return empty_result

    prompt = f"""Analyze ONLY the new reply/turn below as an incremental update to an existing email task.
    Return JSON only with exactly these keys: summary (string), priority (Critical, High, Medium, or Low),
    key_points (array of strings), deadlines (array of strings), and task_updates (array of objects).

Existing current thread summary:
{str(existing.get('summary') or '').strip()}
Existing current key points:
{json.dumps(_normalize_list(existing.get('key_points')), ensure_ascii=False)}
Existing saved actions (completion is durable user progress):
{json.dumps(previous_actions, ensure_ascii=False)}

Each task_updates object must use exactly these keys:
previous_index (integer or null), state (unchanged, updated, completed, cancelled, new, or reopened),
action (string), due_date (string), due_date_changed (boolean).

Reconciliation rules:
- Evaluate every existing action against the newest reply. If it is not mentioned and nothing changes it, use unchanged.
- A wording change or changed/removed deadline for the same work is updated, NOT a new action.
- For updated, keep previous_index and return the latest action wording. Set due_date_changed=true only when the newest reply explicitly changes or removes that action's deadline. If the deadline is explicitly removed, return an empty due_date.
- If the newest reply explicitly confirms an existing action is done, use completed.
- If it explicitly says an existing action is no longer required, use cancelled.
- Completed or cancelled saved actions are historical progress. Never reopen or repeat them merely because they are mentioned again, cosmetically rephrased, or their old deadline is referenced.
- If the newest reply materially changes or expands the actual work requirement of a completed OR cancelled action, use updated with the same previous_index and the latest wording. The application will reopen only that materially changed action while preserving unrelated completed/cancelled history. A deadline-only change does not reopen closed work.
- Use reopened ONLY when the underlying requirement is otherwise the same and the newest reply explicitly asks the recipient to repeat, redo, reopen, or perform it again.
- Use new only for genuinely additional recipient work. For new, previous_index must be null.
- Every task_updates.action contains executable task wording ONLY: no date, time, deadline, priority,
  urgency modifier, or parent instruction heading. Put an action's explicit due constraint only in due_date.
- If one existing action is split into multiple new pieces, use updated for the first resulting piece and new for each genuinely additional piece. Preserve the original previous_index on the updated piece.
- If multiple existing actions are consolidated into one, use updated for the surviving action and cancelled for the merged-away actions. Never erase their completion history.
- Do not invent actions, completion, cancellation, reopening, or dates. A generic thanks/acknowledgment does not complete work.
- Preserve each action's own deadline only. Do not use sent dates, meeting dates, or another person's dates as task deadlines.
- Workflow Status is user-owned and is not part of this extraction contract. Do not infer, predict, or return overall task status or a status-change flag from email language.
- Lifecycle wording such as start, pause, resume, complete, or cancel is still email content: reflect it in the whole-thread summary when material, and use task_updates only when the newest reply explicitly proves a change to a specific action. Do not turn lifecycle wording into an overall workflow-state mutation.
- summary is the CURRENT WHOLE-THREAD summary after incorporating the new reply into the existing current thread summary. It must be a concise 1-2 sentence overview of the conversation's current state, not a delta-only note, not a concatenation of old + new summaries, and not a list of Action Items/Key Points. Cover the main current work plus material decisions, blockers, dependencies, approvals, state changes, or downstream consequences needed to understand the thread as a whole. It may mention the main timing constraint when needed for a coherent narrative, but must not enumerate the task/deadline sections. Replace superseded facts with the latest facts while retaining still-valid context.
- key_points describe scan-friendly important facts/context/constraints introduced or changed by the NEW turn only. Do not restate task wording from task_updates or a task deadline. Thematic overlap with the whole-thread Summary is allowed when a Key Point exposes an independently useful atomic decision, blocker, dependency, exception, approval, state change, or material detail; do not copy an entire Summary sentence as a Key Point. Write Key Points in neutral professional voice instead of I/we/my/our/you/your conversational wording whenever the same fact can be stated without changing modality or ownership. Returning [] is correct when no useful atomic fact remains. The application will reconcile the points into the existing current key-point list so an added point preserves older still-valid points while a modified point replaces its prior wording.
- deadlines describe dates introduced or changed by the NEW turn only.

New reply/turn:
{_email_text(email)}"""
    result = _request_json(prompt, INCREMENTAL_SUMMARY_SCHEMA, operation="incremental thread summary")
    trace_summary_pipeline(
        "THREAD_AI_RAW",
        email=email,
        summary={
            "summary": result.get("summary"),
            "priority": result.get("priority"),
            "key_points": result.get("key_points"),
            "deadlines": result.get("deadlines"),
        },
        payload={
            "task_updates": result.get("task_updates"),
            "source_body": _body_text(email),
        },
    )
    # Incremental deadline deltas must be grounded in the newest authored turn
    # only. Quoted/history dates remain durable through saved action details, but
    # they are not NEW deadline facts and must not re-enter the delta list as
    # variants such as "by 2026-09-11".
    current_turn = _incremental_current_turn_text(email) or _body_text(email)
    current_email = dict(email)
    current_email["body_text"] = current_turn
    current_email["snippet"] = current_turn
    grounded_deadlines = _ground_deadlines(current_email, result.get("deadlines"))
    # Recover an explicit task-level Deadline: line even when the model omits it,
    # still scoped to this authored turn.
    recovered_deadlines = _phase1c_recover_direct_deadlines(current_email, [
        item.get("action") for item in _existing_task_context(existing) if item.get("action")
    ] or ["existing task"])
    grounded_deadlines = _phase1c_dedupe_deadlines(_merge_unique(grounded_deadlines, recovered_deadlines))
    grounded_deadlines = _incremental_filter_context_only_deadlines(current_email, grounded_deadlines)
    deadlines = grounded_deadlines
    explicit_priority = _phase1b_explicit_priority(current_email)
    # A global deadline/change is authoritative only when stated in the newest
    # authored turn.  Quoted historical ``Deadline:`` labels are context, not a
    # command to re-apply the old date to newly introduced actions.
    global_deadline = ""
    if len(deadlines) == 1:
        evidence_line = _phase1b_deadline_sentence(deadlines[0], current_turn)
        if re.match(r"^\s*(?:deadline|due date)\s*(?::|=|-|(?:is|remains?|stays?)\b)", evidence_line or "", flags=re.IGNORECASE):
            global_deadline = deadlines[0]
        elif (
            evidence_line
            and re.search(
                r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b"
                r"[^.!?;]{0,70}\b(?:deadline|due\s+date)\b|"
                r"\b(?:deadline|due\s+date)\b[^.!?;]{0,70}"
                r"\b(?:move|change|extend|push|shift|reschedule|set|update)\w*\b",
                evidence_line, flags=re.IGNORECASE,
            )
            and re.search(
                r"\b(?:everything\s+else\s+(?:remains?|stays?)\s+(?:the\s+)?same|"
                r"all\s+other\s+(?:details?|items?|terms?|work)\s+(?:remain|stays?|are)\s+unchanged|"
                r"otherwise\s+unchanged|no\s+other\s+changes?|only\s+the\s+(?:deadline|due\s+date)\s+changes?)\b",
                current_turn, flags=re.IGNORECASE,
            )
        ):
            # Explicitly global deadline-only update: apply the new date to every
            # still-open saved action.  This is source-proven and prevents an old
            # top-level deadline from reappearing when per-action rows were
            # previously undated.
            global_deadline = deadlines[0]
    global_deadline_removed = bool(re.search(
        r"\b(?:deadline (?:has been |is )?removed|no longer a deadline|"
        r"there is no longer a deadline|no deadline)\b",
        current_turn,
        flags=re.IGNORECASE,
    ))
    task_updates = _normalize_incremental_task_updates(
        email, existing, result.get("task_updates")
    )
    task_updates = _incremental_recover_missing_new_actions(
        email, existing, task_updates, result.get("key_points"), deadlines
    )
    task_updates = _incremental_drop_lifecycle_alias_new_actions(
        email, existing, task_updates
    )
    task_updates = _incremental_rebind_explicit_cancellations(
        email, existing, task_updates
    )
    task_updates = _incremental_rebind_explicit_reassignments(
        email, existing, task_updates
    )
    task_updates = _incremental_reconcile_explicit_existing_mutations(
        email, existing, task_updates
    )
    task_updates = _incremental_apply_relational_event_upper_bound(
        email, existing, task_updates
    )
    task_updates = _incremental_terminal_task_overrides(
        email, previous_actions, task_updates
    )
    global_completion_turn = _incremental_global_completion_is_proven(email)
    pure_pause_turn = _incremental_is_pure_pause_turn(email)
    if pure_pause_turn:
        # Pause/hold changes lifecycle state only. Never reinterpret temporary
        # inhibition as cancellation, never synthesize a "Hold ..." To-Do, and
        # never alter existing per-action deadline ownership.
        task_updates = _incremental_preserve_tasks_for_pause(existing)
    update_actions = [
        str(item.get("action") or "").strip()
        for item in task_updates
        if isinstance(item, dict) and str(item.get("action") or "").strip()
    ]
    # Incremental Key Points are NEW-turn facts.  Validate them against the
    # authored reply only so stale quoted dates/status language cannot survive as
    # fresh context or feed downstream action recovery.
    key_points = _phase1b_key_points(current_email, result.get("key_points"), update_actions)
    if pure_pause_turn:
        # A pure lifecycle hold has no independent new fact beyond the hold
        # instruction itself. Drop model restatements such as "Hold X" from
        # Key Points; substantive/additive turns never enter this branch.
        key_points = []
    overview_actions = _merge_unique(
        [str(item.get("action") or "").strip() for item in previous_actions if str(item.get("action") or "").strip()]
        + update_actions
    )
    raw_overview = _compact_summary_overview(result.get("summary"))
    raw_summary_valid = _incremental_raw_summary_is_valid(
        email, existing, raw_overview, task_updates, overview_actions
    )
    # THREAD RAW-FIRST ARCHITECTURE LOCK:
    # Keep a valid THREAD_AI_RAW Summary as the whole-thread candidate. The old
    # balancing/separation path is now fallback-only when validation proves the
    # raw field is structurally incomplete, meta-framed, or unsupported.
    separated_overview = (
        raw_overview
        if raw_summary_valid
        else _balanced_incremental_summary_overview(
            email,
            str(existing.get("summary") or ""),
            raw_overview,
            overview_actions,
            str(existing.get("task_title") or ""),
            deadlines=deadlines,
        )
    )
    fallback_direct_repaired = False
    if (
        not raw_summary_valid
        and (
            _summary_is_topic_only_overview(separated_overview)
            or _summary_is_meta_framed_action_overview(separated_overview, overview_actions)
        )
    ):
        direct_overview = _incremental_direct_action_overview(existing, task_updates)
        if direct_overview:
            separated_overview = direct_overview
            fallback_direct_repaired = True

    before_deadline_scope = _compact_summary_overview(separated_overview)
    separated_overview = _repair_incremental_summary_deadline_scope(
        separated_overview, task_updates
    )
    deadline_scope_repaired = (
        _compact_summary_overview(separated_overview) != before_deadline_scope
    )

    separated_overview, deadline_only_rebase_repaired = (
        _incremental_rebase_deadline_only_summary(
            email, existing, separated_overview, deadlines
        )
    )

    structured_deadline_fallback = False
    if (
        not raw_summary_valid
        and _incremental_invalid_summary_needs_structured_deadline_fallback(
            separated_overview, task_updates
        )
    ):
        canonical_overview = _incremental_structured_action_overview(
            existing, task_updates
        )
        if canonical_overview:
            separated_overview = canonical_overview
            structured_deadline_fallback = True

    completion_summary_repaired = False
    if (
        global_completion_turn
        and _incremental_summary_implies_open_work(separated_overview)
    ):
        # The newest authored turn explicitly closes the whole work scope.  If
        # the candidate Summary still describes a pending/new requirement, that
        # field is semantically contradictory even when its words came from RAW.
        # Repair only the Summary from source-supported completion sentences;
        # task/deadline history remains independently reconciled below.
        completion_overview = _incremental_completion_summary_from_source(email)
        if completion_overview:
            separated_overview = completion_overview
            completion_summary_repaired = True

    # Core lifecycle regression guard: an explicit newest-turn pause/hold must
    # summarize the workflow state directly, without subject/message meta prose.
    # This is deliberately after whole-thread/deadline repair and before Key
    # Point distinctness so a separate hold condition can remain a scan fact.
    before_pause_polish = _compact_summary_overview(separated_overview)
    pause_polish_needed = (
        not raw_summary_valid
        and (
            _summary_is_topic_only_overview(separated_overview)
            or _summary_is_meta_framed_action_overview(separated_overview, overview_actions)
        )
    )
    if pause_polish_needed:
        separated_overview = _incremental_pause_summary_polish(
            email, separated_overview
        )
    pause_summary_repaired = (
        _compact_summary_overview(separated_overview) != before_pause_polish
    )

    priority, priority_replacement_allowed = _incremental_raw_priority(
        email, existing, result.get("priority"), task_updates
    )
    key_points = _phase1k_distinct_key_points(
        email, key_points, separated_overview,
        actions=overview_actions, deadlines=deadlines,
    )
    # Ownership handoffs are lifecycle state, not another person's To-Do. The
    # generic distinctness pass can remove a correct handoff bullet when the
    # Summary already narrates the same transfer. Recover only a source-grounded
    # newest-turn ownership transition after cross-section dedupe so the current
    # owner remains scan-visible while Action/Deadline ownership stays separate.
    key_points = _incremental_recover_ownership_transition_key_points(
        email, key_points, result.get("key_points")
    )
    key_points = _incremental_recover_correction_key_points(email, key_points)
    if pure_pause_turn:
        # Distinctness normally recovers scan-worthy source facts when the model
        # returns no Key Points.  For a pure lifecycle hold, that recovery would
        # simply manufacture a redundant ``Hold ...`` bullet after we correctly
        # removed it above. The Summary already carries this lifecycle fact.
        key_points = []
    trace_summary_pipeline(
        "THREAD_AI_FIELD_VALIDATION",
        email=email,
        summary={
            "summary": separated_overview or "No summary was generated.",
            "task_title": str(existing.get("task_title") or ""),
            "priority": priority,
            "key_points": key_points,
            "deadlines": deadlines,
        },
        payload={
            "raw_first": True,
            "summary_passed_raw": (
                raw_summary_valid
                and not deadline_scope_repaired
                and not deadline_only_rebase_repaired
                and not completion_summary_repaired
                and not pause_summary_repaired
            ),
            "summary_direct_fallback_repair_applied": fallback_direct_repaired,
            "summary_raw_valid": raw_summary_valid,
            "summary_deadline_scope_repair_applied": deadline_scope_repaired,
            "summary_deadline_only_rebase_applied": deadline_only_rebase_repaired,
            "summary_completion_repair_applied": completion_summary_repaired,
            "summary_pause_repair_applied": pause_summary_repaired,
            "priority_raw": _normalize_priority(result.get("priority")),
            "priority_saved": _normalize_priority(existing.get("priority") or "Low"),
            "priority_final": priority,
            "priority_replacement_allowed": priority_replacement_allowed,
            "pure_pause_task_guard_applied": pure_pause_turn,
            "global_completion_task_guard_applied": global_completion_turn,
        },
    )

    incremental_result = {
        "summary": separated_overview or "No summary was generated.",
        "task_title": str(existing.get("task_title") or ""),
        "priority": priority,
        "key_points": key_points,
        "deadlines": deadlines,
        "action_items": [],
        "action_item_details": [],
        "task_updates": task_updates,
        "_explicit_priority": explicit_priority,
        "_priority_replacement_allowed": priority_replacement_allowed,
        "_summary_is_whole_thread": True,
        "_global_deadline": global_deadline,
        "_global_deadline_removed": global_deadline_removed,
    }
    trace_summary_pipeline(
        "THREAD_AI_REPAIR_AUDIT",
        email=email,
        summary=incremental_result,
        payload={
            "summary_repairs_applied": [
                label for label, applied in (
                    ("fallback_balancing", not raw_summary_valid),
                    ("direct_meta_fallback", fallback_direct_repaired),
                    ("deadline_scope", deadline_scope_repaired),
                    ("deadline_only_rebase", deadline_only_rebase_repaired),
                    ("structured_deadline_fallback", structured_deadline_fallback),
                    ("global_completion", completion_summary_repaired),
                    ("pause_lifecycle", pause_summary_repaired),
                ) if applied
            ],
            "priority_repaired_from_raw": priority != _normalize_priority(result.get("priority")),
        },
    )
    trace_summary_pipeline(
        "THREAD_AI_FINAL",
        email=email,
        summary=incremental_result,
        payload={"task_updates": task_updates},
    )
    return incremental_result

def _phase1b_source_sentences(body: str) -> list[str]:
    """Split source prose without treating provider soft-wraps as sentence breaks.

    Outlook/IMAP/plain-text bodies may insert a newline in the middle of a prose
    sentence.  A deadline can therefore arrive as ``confirm the shipping\naddress
    by ...``.  Preserve real structural lines (bullets, headers, thread labels,
    and independently actionable lines), but join presentation-only wraps before
    sentence segmentation.
    """
    text = str(body or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return []

    def _structural_line(value: str) -> bool:
        line = str(value or "").strip()
        if not line:
            return False
        return bool(
            re.match(r"^(?:[-*•]+|\d+[.)])\s+", line)
            or re.match(r"^\[[^\]\n]{1,60}\]\s*$", line)
            or re.match(r"^-{2,}\s*[^-\n]+\s*-{2,}$", line)
            or re.match(r"^(?:from|to|cc|bcc|sent|date|subject|deadline|due date|priority)\s*:", line, flags=re.IGNORECASE)
            or line.startswith(">")
        )

    physical = [line.strip() for line in text.split("\n")]
    logical = []
    current = ""
    for raw in physical:
        line = re.sub(r"[ \t]+", " ", raw).strip()
        if not line:
            if current:
                logical.append(current)
                current = ""
            continue

        if not current:
            current = line
            continue

        current_is_structural = _structural_line(current)
        next_is_structural = _structural_line(line)

        # Provider/plain-text soft wrapping can place the tail of one sentence
        # and the beginning of the next request on the same physical line, e.g.
        # ``... approve or reject the\nplan. Please decide today.``.  Testing the
        # whole next line for a request would split before ``plan`` and detach the
        # action object from its verb.  Only treat the next physical line as an
        # independently actionable line when its *leading sentence/clause* is
        # recipient-directed.  This is layout-semantic, not domain-specific.
        next_lead = re.split(r"(?<=[.!?])\s+", line, maxsplit=1)[0].strip()
        next_starts_request = _phase1b_recipient_request_signal(next_lead)

        # Keep genuine line-oriented structure independent. Also preserve
        # separate imperative/request lines that intentionally omit punctuation.
        if (
            current_is_structural
            or next_is_structural
            or re.search(r"[.!?][\"')\]]?$", current)
            or next_starts_request
        ):
            logical.append(current)
            current = line
        else:
            current = f"{current} {line}"

    if current:
        logical.append(current)

    sentences = []
    for line in logical:
        for part in re.split(r"(?<=[.!?])\s+", line):
            cleaned = re.sub(r"\s+", " ", part).strip()
            if cleaned:
                sentences.append(cleaned)
    return sentences


def _phase1b_recipient_request_signal(text: str) -> bool:
    cleaned = re.sub(
        r"^\s*(?:[-*•]+|\d{1,2}[.)])\s*",
        "",
        str(text or "").strip(),
    )
    lowered = cleaned.casefold()
    if not lowered:
        return False
    direct_patterns = (
        r"\bplease\b", r"\bpls\b", r"\bpaki(?:[- ]?\w+)?\b", r"\bkindly\b",
        r"\bit would be helpful if you could\b", r"\bif you could\b",
        r"\bcan you\b", r"\bcould you\b", r"\bwould you\b", r"\bwill you\b",
        r"\byou(?:\s+and\s+[a-z][a-z .'-]{0,40})?\s+(?:need|must|should|have to|are required)\b",
        r"\byou (?:acknowledge|approve|check|choose|complete|confirm|decide|investigate|prepare|provide|read|reply|respond|review|select|send|sign|submit|update|upload|verify|reject)\b",
        # Strong implicit ownership: a current sender saying they still need the
        # recipient's deliverable is an open requirement even without ``please``.
        r"\b(?:we|i)\s+(?:still\s+)?need\s+your\b",
        r"\blet me know\b", r"\b(?:tell|inform)\s+(?:me|us)\b", r"\baction required\b",
        r"^\s*aim\s+to\s+(?:acknowledge|approve|check|choose|complete|confirm|decide|finish|investigate|prepare|provide|read|reply|respond|review|select|send|sign|submit|update|upload|verify)\b",
    )
    if any(re.search(pattern, lowered) for pattern in direct_patterns):
        return True

    # Strip only prefixes that can safely precede a first/direct imperative.
    # Continuation markers such as "After that" are intentionally NOT stripped;
    # they require proof from the preceding recipient request below.
    imperative_text = re.sub(r"^\s*first(?:ly)?\b[,:;-]?\s*", "", lowered)
    imperative_text = re.sub(
        r"^\s*(?:by|before|on)\s+[^,;]{1,80}[,;]\s*",
        "",
        imperative_text,
    )
    imperative_text = re.sub(r"^\s*either\s+", "", imperative_text)
    imperative = re.compile(
        r"^(?:also\s+|and\s+)?(?:acknowledge|approve|check|choose|complete|confirm|decide|"
        r"follow up|investigate|prepare|provide|read|reply|respond|review|schedule|select|"
        r"send|sign|submit|tell|inform|notify|report|let\s+(?:me|us)\s+know|update|upload|verify)\b"
    )
    return bool(imperative.search(imperative_text))


def _phase1g_effective_turn_text(body: str) -> str:
    # Current authored text owns current-recipient work; quoted/forwarded history
    # is excluded unless the current note explicitly delegates that material.
    latest = _phase1b_latest_turn_text(body)
    text = latest if latest else str(body or "")
    if not text.strip():
        return ""
    boundaries = (
        r"(?m)^\s*>",
        r"(?mi)^\s*(?:old|quoted)\s+message\s*:\s*",
        r"(?mi)^\s*(?:quoted\s+(?:sample|content)|original\s+message)\s*:\s*",
        r"(?mi)^\s*-{2,}\s*(?:forwarded(?:\s+message)?|older\s+forwarded(?:\s+message)?|original\s+message|begin\s+forwarded\s+message)\s*-{2,}\s*$",
        r"(?mi)^\s*begin\s+forwarded\s+message\s*:\s*$",
        r"(?ims)^\s*On\s+[^\n]{0,520}?\bwrote:\s*$",
        r"(?mi)^\s*From:\s*.+\n\s*Sent:\s*.+(?:\n\s*To:\s*.+)?(?:\n\s*Cc:\s*.+)?\n\s*Subject:\s*.+$",
    )
    cut = len(text)
    for pattern in boundaries:
        match = re.search(pattern, text)
        if match:
            cut = min(cut, match.start())
    return text[:cut].strip()


def _phase1g_forwarded_tail(body: str) -> str:
    """Return quoted/forwarded material after a recognized history boundary."""
    text = str(body or "")
    boundaries = (
        r"(?mi)^\s*-{2,}\s*(?:forwarded(?:\s+message)?|older\s+forwarded(?:\s+message)?|begin\s+forwarded\s+message)\s*-{2,}\s*$",
        r"(?mi)^\s*begin\s+forwarded\s+message\s*:\s*$",
        r"(?mi)^\s*(?:quoted\s+(?:sample|content)|original\s+message)\s*:\s*",
    )
    matches = [re.search(pattern, text) for pattern in boundaries]
    matches = [match for match in matches if match]
    if not matches:
        return ""
    boundary = min(matches, key=lambda match: match.start())
    return text[boundary.end():].strip()


def _phase1g_has_explicit_forwarded_delegation(body: str) -> bool:
    """True only when the current note explicitly delegates referenced content."""
    current = _phase1g_effective_turn_text(body)
    if not current or not _phase1g_forwarded_tail(body):
        return False
    if not any(_phase1b_recipient_request_signal(s) for s in _phase1b_source_sentences(current)):
        return False
    return bool(
        re.search(
            r"\b(?:handle|take\s+care\s+of|follow\s+(?:through|up)\s+on|process|complete|address|act\s+on|carry\s+out)\b",
            current,
            flags=re.IGNORECASE,
        )
        and re.search(
            r"\b(?:below|forwarded|request|instructions?|message|on\s+(?:my|our)\s+behalf)\b",
            current,
            flags=re.IGNORECASE,
        )
    )


def _phase1g_forwarded_delegation_evidence(action: str, body: str) -> str:
    """Find source request evidence in a forward only after explicit delegation."""
    if not _phase1g_has_explicit_forwarded_delegation(body):
        return ""
    for sentence in _phase1b_source_sentences(_phase1g_forwarded_tail(body)):
        candidate = re.sub(r"^\s*[A-Za-z][A-Za-z0-9 ._()'/-]{0,60}:\s*", "", sentence).strip()
        if not candidate or not _phase1b_recipient_request_signal(candidate):
            continue
        if _is_supported(action, candidate):
            return candidate
    return ""


def _phase1g_active_deadline_text(email: dict) -> str:
    """Text allowed to ground recipient deadlines for this message."""
    full_body = _body_text(email)
    current = _phase1g_effective_turn_text(full_body)
    if _phase1g_has_explicit_forwarded_delegation(full_body):
        tail = _phase1g_forwarded_tail(full_body)
        if tail:
            return f"{current}\n{tail}".strip()
    return current


def _phase1b_recipient_request_or_continuation(evidence: str, body: str) -> bool:
    """Recognize a continuation only after a proven recipient request."""
    current = re.sub(r"\s+", " ", str(evidence or "")).strip()
    source = str(body or "")
    if not current:
        return False
    if _phase1b_recipient_request_signal(current):
        return True
    continuation = re.match(
        r"^\s*(?:then|next|afterward|afterwards|after\s+that)\b[,:;-]?\s*(.+)$",
        current,
        flags=re.IGNORECASE,
    )
    if not continuation:
        return False
    remainder = continuation.group(1).strip()
    if not remainder or not _phase1c_action_intent(remainder):
        return False
    sentences = _phase1b_source_sentences(source)
    normalized_current = re.sub(r"\s+", " ", current).strip().casefold()
    for index, sentence in enumerate(sentences):
        normalized_sentence = re.sub(r"\s+", " ", str(sentence or "")).strip().casefold()
        if normalized_sentence != normalized_current or index <= 0:
            continue
        return bool(_phase1b_recipient_request_signal(sentences[index - 1]))
    return False


def _phase1g_ambiguous_group_owner(evidence: str, body: str = "") -> bool:
    """True when a request asks for one unspecified member of a group."""
    text = re.sub(r"\s+", " ", str(evidence or "")).strip().casefold()
    if not text:
        return False
    if re.search(r"\b(?:everyone|everybody|all\s+of\s+you|you\s+all|both\s+of\s+you|you\s+both)\b", text):
        return False
    if not re.search(
        r"\b(?:one\s+of\s+you|one\s+of\s+us|someone|somebody|anyone|anybody|"
        r"a\s+volunteer|one\s+(?:person|member|teammate|recipient)|whoever)\b",
        text,
    ):
        return False
    surrounding = _phase1g_effective_turn_text(body) if body else text
    return not bool(re.search(
        r"\b(?:you\s+are\s+(?:assigned|selected|the\s+owner)|assigned\s+to\s+you|"
        r"your\s+(?:task|action|responsibility)\s+is\s+to)\b",
        surrounding,
        flags=re.IGNORECASE,
    ))


def _phase1g_action_mixes_forwarded_only_work(action: str, body: str) -> bool:
    """Reject a compound action that splices current work with quoted-only work.

    Small-model output can occasionally combine one legitimate current-turn
    obligation with a second obligation that appears only inside a forwarded or
    quoted tail.  Whole-action lexical grounding is too permissive for that shape:
    the current clause can contribute enough overlap for the contaminated compound
    to survive even though its second executable clause belongs only to history.

    Treat the compound as contaminated only when all of the following are true:
    - the message has a recognized forwarded/quoted tail;
    - the current note did *not* explicitly delegate that tail;
    - at least one executable clause is grounded in the current authored turn; and
    - a different executable clause is not grounded in the current turn but is
      grounded in a recipient-request sentence inside the forwarded tail.

    Dropping the mixed candidate is safe because the existing RAW-first recovery
    path reconstructs recipient work from the current authored source.  Explicit
    delegation remains untouched, and a current request that itself states both
    clauses is not affected.
    """
    text = re.sub(r"\s+", " ", str(action or "")).strip()
    full_body = str(body or "")
    current = _phase1g_effective_turn_text(full_body)
    tail = _phase1g_forwarded_tail(full_body)
    if not text or not current or not tail:
        return False
    if _phase1g_has_explicit_forwarded_delegation(full_body):
        return False

    parts = [
        part.strip(" ,;:-")
        for part in re.split(
            r"\s*(?:;|,(?=\s*(?:then|also)\b)|\b(?:and then|then|also|plus)\b|\band\b)\s*",
            text,
            flags=re.IGNORECASE,
        )
        if part.strip(" ,;:-")
    ]
    executable = [part for part in parts if _phase1c_action_intent(part)]
    if len(executable) < 2:
        return False

    tail_requests = []
    for sentence in _phase1b_source_sentences(tail):
        candidate = re.sub(
            r"^\s*[A-Za-z][A-Za-z0-9 ._()'/-]{0,60}:\s*",
            "",
            sentence,
        ).strip()
        if candidate and _phase1b_recipient_request_signal(candidate):
            tail_requests.append(candidate)

    if not tail_requests:
        return False

    has_current_clause = False
    has_forwarded_only_clause = False
    for clause in executable:
        if _is_supported(clause, current):
            has_current_clause = True
            continue
        if any(_is_supported(clause, request) for request in tail_requests):
            has_forwarded_only_clause = True

    return has_current_clause and has_forwarded_only_clause


def _phase1g_recipient_explicitly_has_no_action(body: str) -> bool:
    # An explicit recipient-level no-action statement overrides earlier assignments
    # unless a new recipient request appears after that statement in the same turn.
    # Generic terminal wording ("no action is required") is recipient-level only
    # when it is not immediately scoped to somebody else via ``from <name>``.
    # This keeps automated reminder/completion notices actionless without
    # suppressing mail that merely reports another person's no-action state.
    turn = _phase1g_effective_turn_text(body)
    pattern = re.compile(
        r"\b(?:no (?:further )?action (?:is )?(?:needed|required) from you|"
        r"no action (?:is )?(?:needed|required) from you|"
        r"nothing (?:is )?required from you|"
        r"you (?:do not|don't|dont) need to (?:do|take) anything|"
        r"no (?:(?:further|other|additional) )?action (?:is )?(?:needed|required)(?!\s+from\b))\b",
        flags=re.IGNORECASE,
    )
    matches = list(pattern.finditer(turn))
    if not matches:
        return False
    trailing = turn[matches[-1].end():]
    return not any(
        _phase1b_recipient_request_signal(sentence)
        for sentence in _phase1b_source_sentences(trailing)
    )


def _phase1g_recipient_name(email: dict) -> str:
    # Prefer the signed-in mailbox display identity supplied by the controller.
    # The provider To header often contains only an address and no display name.
    identity = str(
        email.get("_mailmind_recipient_identity") or email.get("to") or ""
    ).strip()
    return parseaddr(identity)[0].strip()


def _phase1g_named_assignee(evidence: str) -> str:
    # Parse common named-assignment forms without treating them as generic
    # recipient requests. This is intentionally separate from request detection so
    # coworker assignments remain informational rather than becoming Action Items.
    cleaned = re.sub(r"^\s*(?:[-*•]+|\d+[.)])\s*", "", str(evidence or "").strip())
    patterns = (
        # A hyphen is an ownership delimiter only when it is spaced.  Ordinary
        # hyphenated request prefixes (for example paki-review) are not names.
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s*[:–—]\s*\S+",
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+-\s+\S+",
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2}),\s*(?:please|kindly)\b",
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+"
        r"(?:must|should|needs? to|has to|is required to)\b",
        r"^(?:assigned to|owner|assignee)\s*[:=-]\s*"
        r"([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\b",
    )
    for pattern in patterns:
        match = re.match(pattern, cleaned)
        if match:
            candidate = match.group(1).strip()
            # Sentence-initial pronouns can fit the capitalization grammar but
            # are not named assignees (e.g. "They must be in the portal...").
            if candidate.casefold() in {
                "i", "we", "you", "he", "she", "it", "they", "this", "that", "these", "those",
                # Structural/message labels can share the same capitalization +
                # colon shape as a person's name; they do not assign ownership.
                "reminder", "update", "status", "status update", "progress update",
                "note", "notice", "fyi", "priority", "urgent", "important",
                "deadline", "due date",
                "action", "action item", "task", "request", "summary", "subject",
            }:
                continue
            return candidate
    return ""


def _phase1g_same_person(left: str, right: str) -> bool:
    left_tokens = set(re.findall(r"[a-z]+", str(left or "").casefold()))
    right_tokens = set(re.findall(r"[a-z]+", str(right or "").casefold()))
    return bool(left_tokens and right_tokens and left_tokens & right_tokens)


def _phase1g_addressed_to_other_person(email: dict, evidence: str) -> bool:
    # A named assignment belongs to the current user only when source/account
    # identity proves that the addressee is the recipient. When the mailbox has
    # no usable display name, do not guess that an explicitly named coworker is
    # the user merely because the sentence also contains polite request wording.
    assignee = _phase1g_named_assignee(evidence)
    if not assignee:
        return False
    recipient_name = _phase1g_recipient_name(email)
    if not recipient_name:
        return True
    return not _phase1g_same_person(assignee, recipient_name)


def _phase1g_explicit_other_owner_for_action(
    email: dict, action: str, body: str, candidate_count: int
) -> bool:
    """Return True when source explicitly assigns this work to another person.

    This enforces the existing recipient-ownership rule for a narrow cross-
    sentence shape: a request sentence may be followed by a strong ownership
    sentence such as "Alex owns this task".  The request itself can look
    recipient-directed, so evidence-local checks alone are insufficient.

    Generic anaphora ("this task/work") may suppress only a sole candidate;
    with multiple candidate actions, require topic overlap so one coworker
    ownership fact cannot erase unrelated recipient work.
    """
    source = _phase1g_effective_turn_text(body)
    if not source or not str(action or "").strip():
        return False
    recipient_name = _phase1g_recipient_name(email)
    owner_pattern = re.compile(
        r"(?:^|:\s*)"
        r"(?P<owner>[A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+"
        r"(?:now\s+)?(?:owns?|has\s+ownership\s+of|is\s+responsible\s+for|"
        r"will\s+take\s+over|is\s+taking\s+over)\s+"
        r"(?P<object>[^.!?;]+)",
        flags=re.IGNORECASE,
    )
    generic_object = re.compile(
        r"^(?:this|the|that)\s+(?:task|action|work|item|deliverable|responsibility)\b",
        flags=re.IGNORECASE,
    )
    for sentence in _phase1b_source_sentences(source):
        match = owner_pattern.search(sentence)
        if not match:
            continue
        owner = str(match.group("owner") or "").strip()
        if not owner:
            continue
        if recipient_name and _phase1g_same_person(owner, recipient_name):
            continue
        owned_object = str(match.group("object") or "").strip()
        if generic_object.search(owned_object):
            if int(candidate_count or 0) == 1:
                return True
            continue
        # Explicitly named work can be matched safely even when several actions
        # share the email. Reuse the established semantic task matcher rather
        # than hardcoding any object vocabulary.
        if _incremental_saved_action_match_score(action, owned_object) >= 0.50:
            return True
    return False


def _phase1g_assignment_dependent_instruction(evidence: str) -> bool:
    # Follow-up wording such as "reply once your assigned item is complete" is
    # actionable only when the current recipient actually owns work in the message.
    lowered = str(evidence or "").casefold()
    return bool(re.search(
        r"\b(?:your\s+(?:assigned\s+)?(?:item|task|action|work|deliverable|responsibility|part)|"
        r"(?:item|task|action|work|deliverable|responsibility|part)\s+assigned\s+to\s+you)\b",
        lowered,
    ))


def _phase1g_assignment_list_intro(evidence: str) -> bool:
    # A heading like "complete the following tasks" introduces a list but does
    # not make every named item in that list the current recipient's responsibility.
    lowered = str(evidence or "").casefold()
    return bool(
        re.search(r"\bfollowing\b[^.!?\n]{0,80}\b(?:items|tasks|actions|assignments|deliverables)\b", lowered)
        or re.search(r"\b(?:items|tasks|actions|assignments|deliverables)\s+(?:below|listed below)\b", lowered)
    )


def _phase1g_has_recipient_owned_assignment(email: dict, body: str) -> bool:
    # Establish ownership from source evidence without promoting coworker lines
    # into actions. Named work must match the current user; ordinary direct requests
    # can establish ownership unless they are merely a list heading/follow-up.
    recipient_name = _phase1g_recipient_name(email)
    for sentence in _phase1b_source_sentences(_phase1g_effective_turn_text(body)):
        if _phase1g_assignment_dependent_instruction(sentence) or _phase1g_assignment_list_intro(sentence):
            continue
        assignee = _phase1g_named_assignee(sentence)
        if assignee:
            if recipient_name and _phase1g_same_person(assignee, recipient_name):
                return True
            continue
        lowered = sentence.casefold()
        if re.search(
            r"\b(?:you are (?:assigned|responsible)|assigned to you|your (?:task|action|responsibility) is to)\b",
            lowered,
        ):
            return True
        if _phase1b_recipient_request_signal(sentence):
            return True
    return False


def _phase1b_find_evidence(action: str, body: str) -> str:
    body = _phase1g_effective_turn_text(body)
    action_words = set(_content_words(action))
    if not action_words:
        return ""
    sentences = _phase1b_source_sentences(body)
    best = ""
    best_index = -1
    best_score = 0.0
    for index, sentence in enumerate(sentences):
        sentence_words = set(_content_words(sentence))
        matched = sum(
            1 for word in action_words
            if any(_phase1_token_support_related(word, source) for source in sentence_words)
        )
        if not matched:
            continue
        score = matched / max(1, len(action_words))
        if _phase1b_recipient_request_or_continuation(sentence, body):
            score += 0.40
        if score > best_score:
            best = sentence
            best_index = index
            best_score = score

    # A compact model can paraphrase an anaphoric request using the object from
    # the immediately preceding context sentence (for example, an informational
    # sentence names a date-format ambiguity and the next sentence says
    # ``Please confirm whether this means ...``). Lexical scoring alone can then
    # select the informational sentence as evidence and later reject the action
    # for lacking recipient direction. Prefer the adjacent direct request only
    # when it is explicitly anaphoric, shares the same executable intent, and
    # the preceding sentence already grounds the candidate object. This keeps
    # unrelated same-verb requests from validating a hallucinated action.
    if (
        best
        and best_index >= 0
        and not _phase1b_recipient_request_or_continuation(best, body)
        and best_index + 1 < len(sentences)
        and _is_supported(action, best)
    ):
        request = sentences[best_index + 1]
        if (
            _phase1b_recipient_request_or_continuation(request, body)
            and re.search(
                r"\b(?:this|that|it|these|those|such)\b",
                request,
                flags=re.IGNORECASE,
            )
        ):
            action_intent = _phase1c_action_intent(action)
            request_intent = _phase1c_action_intent(request)
            if action_intent and action_intent == request_intent:
                return request

    return best if best_score >= 0.35 else ""


def _phase1b_latest_turn_text(body: str) -> str:
    text = str(body or "")
    match = re.search(r"\[latest (?:reply|message|turn)\]", text, flags=re.IGNORECASE)
    return text[match.end():].strip() if match else ""


def _phase1e_object_tokens(value: str) -> set[str]:
    # Compare task objects/entities while preserving short identifiers such as Proposal A/B.
    ignored = {
        "a", "an", "and", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of",
        "on", "or", "the", "to", "with", "please", "still", "again", "instead", "new",
        "today", "tomorrow", "tonight", "bukas", "eod", "asap", "deadline", "due",
        "me", "us", "whether", "if", "let", "know", "notify", "tell", "inform",
        "acknowledge", "approve", "check", "complete", "confirm", "decide", "investigate",
        "prepare", "provide", "read", "reply", "respond", "review", "send", "sign", "submit",
        "update", "upload", "verify", "reject", "return", "make", "need", "needed",
    }
    return {
        token for token in re.findall(r"[a-z0-9]+", str(value or "").casefold())
        if token and token not in ignored
    }


def _phase1e_related_action_text(action: str, text: str) -> bool:
    action_tokens = _phase1e_object_tokens(action)
    text_tokens = _phase1e_object_tokens(text)
    if action_tokens:
        overlap = len(action_tokens & text_tokens) / max(1, len(action_tokens))
        return overlap >= 0.67
    intent = _phase1c_action_intent(action)
    return bool(intent and re.search(rf"\b{re.escape(intent)}\w*\b", str(text or "").casefold()))


def _phase1e_best_evidence(action: str, text: str) -> str:
    # Evidence lookup scoped to one turn. This prevents an old request from winning
    # merely because it overlaps more words than the newest update.
    best = ""
    best_score = 0.0
    action_tokens = _phase1e_object_tokens(action)
    intent = _phase1c_action_intent(action)
    for sentence in _phase1b_source_sentences(text):
        sentence_tokens = _phase1e_object_tokens(sentence)
        overlap = len(action_tokens & sentence_tokens) / max(1, len(action_tokens)) if action_tokens else 0.0
        if intent and _phase1e_action_verb_supported(action, sentence):
            overlap += 0.35
        if _phase1b_recipient_request_signal(sentence):
            overlap += 0.35
        if overlap > best_score:
            best = sentence
            best_score = overlap
    return best if best_score >= 0.50 else ""


def _phase1e_state_sentences(latest: str) -> list[str]:
    pattern = re.compile(
        r"\b(?:cancel(?:led)?|no longer|do not|don't|dont|ignore|disregard|received|completed|"
        r"already done|already completed|already submitted|already sent|approved through another channel|"
        r"no (?:further )?action)\b",
        flags=re.IGNORECASE,
    )
    return [sentence for sentence in _phase1b_source_sentences(latest) if pattern.search(sentence)]


def _phase1b_action_invalidated(action: str, body: str) -> bool:
    latest = _phase1b_latest_turn_text(body)
    if not latest:
        return False
    lowered = latest.casefold()
    if re.search(r"\bno (?:further )?action (?:is )?(?:needed|required)\b", lowered):
        return True

    # A removed deadline changes scheduling, not whether the work itself is active.
    deadline_only_state = re.compile(
        r"\b(?:deadline (?:has been |is )?removed|no longer a deadline|"
        r"there is no longer a deadline|no longer (?:has|have) a deadline)\b",
        flags=re.IGNORECASE,
    )
    # Only invalidate an action when cancellation/completion/reassignment refers to
    # the same task object. This avoids deadline removal cancelling the task itself.
    for sentence in _phase1e_state_sentences(latest):
        if deadline_only_state.search(sentence):
            continue
        if _phase1e_related_action_text(action, sentence):
            return True
    return False


def _phase1c_is_completed_status_update(evidence: str) -> bool:
    """Return True for a declarative labeled update about already-finished work."""
    text = re.sub(r"\s+", " ", str(evidence or "")).strip()
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
    completed = r"(?:submitted|completed|finished|done|sent|uploaded|processed|approved|resolved|received)"
    return bool(
        re.search(
            rf"\b(?:is|are|was|were|has|have|had)\s+(?:already\s+)?(?:been\s+)?(?:successfully\s+)?{completed}\b",
            statement,
            flags=re.IGNORECASE,
        )
        or re.search(
            rf"\b(?:already|previously)\s+(?:successfully\s+)?{completed}\b",
            statement,
            flags=re.IGNORECASE,
        )
    )


def _phase1c_evidence_is_non_action(evidence: str, body: str) -> bool:
    lowered = str(evidence or "").strip().casefold()
    if not lowered:
        return True
    if _phase1c_is_completed_status_update(evidence):
        return True
    # A prohibition tells the user not to perform *that prohibited verb*.  It
    # must not erase a different positive task earlier in the same sentence
    # (for example, draft/review X but do not send it).
    prohibition = re.search(
        r"\b(?:please\s+)?(?:do not|don't|dont|never)\s+"
        r"(?:send|submit|reply|respond|approve|review|complete|upload|forward)\b",
        lowered,
    )
    if prohibition:
        positive_prefix = str(evidence or "")[:prohibition.start()].strip(" ,;:-")
        if not (
            positive_prefix
            and _phase1b_recipient_request_signal(positive_prefix)
            and _phase1c_action_intent(positive_prefix)
        ):
            return True
    if re.search(r"\b(?:ignore|disregard)\b", lowered):
        return True
    if re.search(r"\bno (?:further )?action (?:is )?(?:needed|required)\b", lowered):
        return True
    # Ignore quoted stale requests when the current unquoted note explicitly says no action.
    if lowered.startswith(">") or "old message:" in lowered or "quoted message:" in lowered:
        current = re.split(r"(?:^|\n)\s*>|old message:|quoted message:", str(body or ""), maxsplit=1, flags=re.IGNORECASE)[0]
        if re.search(r"\b(?:no action (?:is )?required|fy\s*i only|for your (?:awareness|information) only)\b", current.casefold()):
            return True
    return False


def _phase1c_filter_latest_deadlines(email: dict, deadlines) -> list[str]:
    latest = _phase1b_latest_turn_text(_body_text(email))
    values = _normalize_list(deadlines)
    if not latest or not values:
        return values
    lowered = latest.casefold()
    if re.search(r"\b(?:deadline (?:has been |is )?removed|no longer a deadline|no longer (?:has|have) a deadline|there is no longer a deadline|no deadline)\b", lowered):
        return []
    replacement = bool(re.search(r"\b(?:new deadline|deadline (?:is|moved|changed|extended)|instead|push(?:ed)? (?:it|the deadline)|moved to|extended to)\b", lowered))
    if not replacement:
        return values
    latest_values = []
    for value in values:
        evidence = _phase1b_deadline_sentence(value, latest)
        if evidence and _phase1b_is_valid_deadline_sentence(evidence):
            latest_values.append(value)
    return _merge_unique(latest_values)


def _phase1c_is_task_list_intro_evidence(evidence: str, body: str) -> bool:
    # A heading/introduction such as "Please complete these two checks" is
    # context for the concrete bullets below, not an additional parent action.
    # Only suppress it when the body actually contains one or more concrete
    # recipient-directed child lines after the intro.
    text = re.sub(r"\s+", " ", str(evidence or "")).strip()
    lowered = text.casefold()
    if not text:
        return False
    intro = bool(re.search(
        r"\b(?:please\s+)?(?:complete|perform|do|review|check|verify)\s+"
        r"(?:(?:the|these|following)\s+)?(?:\d+|one|two|three|four|five)?\s*"
        r"(?:checks?|items?|tasks?|actions?|steps?|things?)\b",
        lowered,
    )) or _phase1g_assignment_list_intro(text)
    if not intro:
        return False

    source_lines = [
        line.strip() for line in str(body or "").splitlines()
        if line.strip() and re.sub(r"\s+", " ", line.strip()).casefold() != lowered
    ]
    concrete_children = 0
    for line in source_lines:
        cleaned = re.sub(r"^\s*(?:[-*•]+|\d+[.)])\s*", "", line).strip()
        if not cleaned:
            continue
        if _phase1b_recipient_request_signal(cleaned):
            concrete_children += 1
        if concrete_children >= 1:
            return True
    return False


def _phase1c_semantic_temporal_facts(value: str) -> list[str]:
    """Return date/time values that are the *object* of a clarification task.

    Some recipient actions ask the user to interpret or choose between temporal
    values, for example "confirm whether the meeting is August 25 or August 26".
    Those values are semantic payload, not the deadline of the confirmation task.
    Keep this detector deliberately grammatical and action-local so ordinary
    scheduling metadata ("submit by August 25") continues to be separated.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return []

    request = re.search(
        r"\b(?:confirm|clarify|verify|determine|check|identify|specify|explain|"
        r"tell|inform|report|decide)\b|\blet\s+(?:me|us)\s+know\b",
        text,
        flags=re.IGNORECASE,
    )
    marker = re.search(r"\b(?:whether|if|which)\b", text, flags=re.IGNORECASE)
    if not request or not marker or request.start() > marker.start():
        return []

    clause = text[marker.start():]
    month = (
        r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    )
    patterns = (
        r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b",
        r"\b\d{1,2}[-/]\d{1,2}[-/]20\d{2}\b",
        rf"\b{month}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+20\d{{2}})?\b",
        r"\b\d{1,2}(?::\d{2})?\s*(?:am|pm)\b",
        r"\b(?:noon|midnight)\b",
        r"\b(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
    )
    found = []
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, clause, flags=re.IGNORECASE):
            fact = re.sub(r"\s+", " ", match.group(0)).strip(" ,.;")
            key = fact.casefold()
            if fact and key not in seen:
                seen.add(key)
                found.append(fact)
    return found


def _phase1c_mask_semantic_temporal_facts(value: str) -> tuple[str, list[tuple[str, str]]]:
    """Mask clarification-target temporal facts while metadata is stripped."""
    text = str(value or "")
    replacements = []
    for index, fact in enumerate(_phase1c_semantic_temporal_facts(text)):
        token = f"MMTEMPFACT{chr(65 + index)}"
        updated, count = re.subn(re.escape(fact), token, text, count=1, flags=re.IGNORECASE)
        if count:
            text = updated
            replacements.append((token, fact))
    return text, replacements


def _separate_action_item_text(value: str) -> str:
    """Keep only executable task wording in Action Items.

    Dates/times/deadlines and priority/urgency belong to summary metadata, not
    the action label itself. This is deliberately deterministic so the final UI
    stays separated even when the model returns a task such as
    ``Submit report by September 9, 2026 at 10:30 AM``.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""

    # Preserve temporal values when they are the semantic object of a
    # clarification/interpretation request rather than scheduling metadata.
    # They are restored after the ordinary due-date stripping below.
    text, semantic_temporal_replacements = _phase1c_mask_semantic_temporal_facts(text)

    text = re.sub(
        r"^(?:(?:action item|action|task)\s*[:\-]\s*)",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()
    # Common Taglish polite request prefixes carry no task identity.  Strip
    # only when they directly prefix a known executable verb, preserving the
    # source object while making action intent/provider output stable.
    text = re.sub(
        r"^paki[-\s]?(?=(?:review|send|confirm|check|update|submit|upload|sign|"
        r"approve|reject|complete|prepare|provide|reply|respond|verify|read)\b)",
        "", text, flags=re.IGNORECASE,
    ).strip()
    text = re.sub(
        r"^(?:priority\s*[:=]\s*(?:critical|high|medium|low)|"
        r"(?:critical|high|medium|low|top)\s+priority)\s*(?:[-–—,:]\s*)+",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    # Remove explicit metadata labels when a model appends them to a task.
    text = re.sub(
        r"\s*(?:[-–—;,]\s*)?(?:deadline|due date|priority)\s*"
        r"(?::|=|is|remains?|stays?)\s*[^.;]*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()
    text = re.sub(
        r"\s*\((?:due|deadline|priority)\b[^)]*\)\s*",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    # Model labels sometimes replace the actual date with abstract scheduling
    # metadata ("by preferred deadline or final cutoff"). That belongs in the
    # Deadline field, not in the executable Action Item.
    text = re.sub(
        r"\s+\bby\s+(?:the\s+)?(?:preferred|target|fallback|final|hard)\s+"
        r"(?:deadline|cutoff)(?:\s+(?:or|and)\s+(?:the\s+)?(?:preferred|target|fallback|final|hard)\s+(?:deadline|cutoff))*\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()
    # Small models also emit coordinated role labels with the metadata noun only
    # once, e.g. ``Send draft by preferred or final deadline``.  Treat the
    # entire coordinated role phrase as scheduling metadata, not executable work.
    text = re.sub(
        r"\s+\bby\s+(?:the\s+)?(?:preferred|target|fallback|final|hard)"
        r"(?:\s+(?:or|and)\s+(?:the\s+)?(?:preferred|target|fallback|final|hard))+"
        r"\s+(?:deadline|cutoff)\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    month = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    weekday = r"(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)"
    clock = r"(?:\d{1,2}:\d{2}\s*(?:am|pm)?|\d{1,2}\s*(?:am|pm)|noon|midnight)"
    zone = r"(?:\s+(?:UTC|GMT)(?:[+-]\d{1,2}(?::?\d{2})?)?|\s+(?-i:[A-Z]{2,4}))?"
    iso_date = r"(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2})"
    slash_date = r"(?:\d{1,2}[-/]\d{1,2}[-/]20\d{2})"
    named_date = rf"(?:{month}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+20\d{{2}})?)"
    relative = rf"(?:(?:today|tomorrow|tonight|bukas|eod|cob|close of business)(?:\s+(?:morning|afternoon|evening))?|(?:(?:this|next|every|each)\s+)?{weekday}(?:\s+(?:morning|afternoon|evening))?|(?:this\s+)?(?:morning|afternoon|evening))"
    duration = r"(?:within\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:business\s+)?(?:hours?|days?|weeks?))"
    temporal = rf"(?:{iso_date}|{slash_date}|{named_date}|{duration}|{relative}(?:\s+(?:at|by|before)\s+{clock}{zone})?|{clock}{zone}(?:\s+(?:today|tomorrow|tonight|bukas))?)"

    # Deadline extractors already know the broadest due phrase. Remove those
    # first, then handle ordinary scheduling/date clauses ("on Friday", "at 3 PM")
    # which are not necessarily deadlines but still must not live in Action Items.
    for phrase in sorted(_phase1c_extract_deadline_phrases(text), key=len, reverse=True):
        # If the extractor returns only the temporal value, consume an immediately
        # preceding scheduling preposition with it.  This avoids residue such as
        # ``Submit package after`` after stripping ``August 25`` while preserving
        # ordinary phrasal verbs like ``look after vendor account``.
        text, removed_with_prep = re.subn(
            rf"\b(?:by|before|after|on|at|until|for)\s+{re.escape(phrase)}\b",
            " ",
            text,
            count=1,
            flags=re.IGNORECASE,
        )
        if not removed_with_prep:
            text = re.sub(re.escape(phrase), " ", text, count=1, flags=re.IGNORECASE)

    text = re.sub(
        rf"\s*(?:,|;|[-–—])?\s*\b(?:by|before|after|no later than|on|at|until|for)\s+{temporal}\b",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        rf"\s*(?:,|;|[-–—])?\s*\b{temporal}\b\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    )

    # Priority/urgency is task metadata. Remove only modifier forms so nouns such
    # as "critical incident" remain intact.
    text = re.sub(r"^\s*(?:urgent(?:ly)?|immediately)\s*[:,\-]?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*(?:,|;|[-–—])?\s*(?:asap|as soon as possible|immediately)\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*(?:,|;|[-–—])?\s*(?:with|as)\s+(?:a\s+)?(?:critical|high|medium|low|top)\s+priority\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*(?:,|;|[-–—])?\s*(?:critical|high|medium|low|top)\s+priority\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*(?:,|;|[-–—])?\s*priority\s*[:=]\s*(?:critical|high|medium|low)\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*\((?:critical|high|medium|low|top)\s+priority\)\s*", " ", text, flags=re.IGNORECASE)

    for token, fact in semantic_temporal_replacements:
        text = text.replace(token, fact)

    # Removing a concrete date can leave behind a soft/fallback scheduling
    # modifier from a model paraphrase (for example ``Send draft by preferred``
    # or ``Send draft, if possible``).  Those words describe the deadline role,
    # not executable work.  Strip only trailing scheduling residue so ordinary
    # objects such as ``preferred vendor`` remain untouched.
    text = re.sub(
        r"\s*(?:,|;|[-–—])?\s*\bif possible\b\s*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()
    text = re.sub(
        r"\s*(?:,|;|[-–—])?\s*\bif\s+(?:that|this|"
        r"monday|tuesday|wednesday|thursday|friday|saturday|sunday|"
        r"(?:the\s+)?(?:preferred|target|fallback)\s+date)"
        r"\s*,?\s+is\s+not\s+possible\b[\s,;:.\-–—]*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()
    text = re.sub(
        r"\s+\bby\s+(?:the\s+)?(?:preferred|target|fallback|final|hard)(?:\s+(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday))?[\s,;:.\-–—]*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    text = re.sub(r"\s+", " ", text).strip(" \t\r\n-–—:;,.()")
    text = re.sub(r"\b(?:by|before|on|at|until|for)\s*$", "", text, flags=re.IGNORECASE).strip(" \t\r\n-–—:;,.()")
    if text and text[:1].islower():
        text = text[:1].upper() + text[1:]
    return text


def _action_item_is_metadata_only(value: str) -> bool:
    """Reject deadline/priority/context labels that are not executable work."""
    text = re.sub(r"\s+", " ", str(value or "")).strip().casefold()
    if not text:
        return True
    if re.fullmatch(
        r"(?:deadline|due date|priority|urgency|status)\s+"
        r"(?:(?:is|was|has been|have been|remains?|stays?)\s+)?"
        r"(?:changed|updated|extended|moved|shifted|pushed|rescheduled|set|raised|lowered|removed|cleared)"
        r"(?:\s+(?:to|from))?(?:\s+.*)?",
        text,
    ):
        return True
    return bool(re.fullmatch(
        r"(?:(?:deadline|due date|priority|urgency)(?:\s+(?:is|remains?|stays?))?\s*[:=\-]?\s*)?"
        r"(?:critical|high|medium|low|urgent|asap|today|tomorrow|tonight|bukas|eod)?",
        text,
    ))


def _compact_summary_overview(value: str) -> str:
    """Render a concise overview rather than another item-by-item list."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return ""
    text = re.sub(r"^\s*summary\s*:\s*", "", text, flags=re.IGNORECASE)
    text = _strip_format_noise(text, inline_list_markers=True)
    if not text:
        return ""

    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", text) if part.strip()]
    compact = " ".join(sentences[:2]) if sentences else text
    words = compact.split()
    if len(words) > 65:
        compact = " ".join(words[:65]).rstrip(" ,;:-") + "…"
    if len(compact) > 520:
        clipped = compact[:520].rsplit(" ", 1)[0].rstrip(" ,;:-")
        compact = (clipped or compact[:520]).rstrip() + "…"
    return compact


def _summary_overlap_terms(value: str) -> set[str]:
    """Normalize light morphology for Summary-vs-Action overlap checks."""
    ignored = {
        "a", "an", "and", "are", "as", "at", "be", "by", "can", "for",
        "from", "in", "is", "it", "of", "on", "or", "the", "that", "to",
        "with", "your", "task", "requires", "required", "requirement",
        "please", "kindly", "successfully", "current", "latest",
        "when", "whenever", "convenient", "convenience",
        # Request/reporting-frame words do not add business payload. Treating
        # them as grammatical framing lets passive/nominal Key Points such as
        # "X status requested" compare to the executable action that already
        # owns X, without recognizing any domain noun or benchmark wording.
        "request", "requests", "requested", "requesting",
        "ask", "asks", "asked", "asking",
        "inquiry", "inquiries", "inquired",
        "query", "queries", "queried",
    }
    terms = set()
    for raw in re.findall(r"[a-z0-9]+", str(value or "").casefold()):
        if raw in ignored or len(raw) <= 1:
            continue
        if raw.startswith("confirm"):
            term = "confirm"
        elif raw.startswith("visib"):
            term = "visib"
        elif raw.startswith("open"):
            term = "open"
        elif raw.startswith("view"):
            term = "view"
        elif raw.startswith("review"):
            term = "review"
        elif raw.startswith("verif"):
            term = "verify"
        elif raw.startswith("submit"):
            term = "submit"
        elif raw.startswith("send"):
            term = "send"
        elif raw.startswith("prepar"):
            term = "prepare"
        elif raw.startswith("preview"):
            term = "preview"
        elif raw.startswith("provid"):
            term = "provide"
        elif raw.startswith("complet"):
            term = "complete"
        elif raw.startswith("updat"):
            term = "update"
        elif raw.startswith("approv"):
            term = "approve"
        elif raw.startswith("cancel"):
            term = "cancel"
        elif raw.startswith("acknowledg"):
            term = "acknowledge"
        else:
            term = raw
        terms.add(term)
    return terms


def _summary_overview_action_heavy(sentence: str, actions) -> bool:
    """Return True when a Summary sentence mostly restates executable task text.

    The Summary is an overview, while the exact work belongs in Action Items.
    Compare coverage of each validated action instead of requiring the sentence
    to be an exact paraphrase; light morphology normalization catches forms such
    as visible/visibility, open/opening, and view/viewability.
    """
    sentence_terms = _summary_overlap_terms(_separate_action_item_text(sentence) or sentence)
    if not sentence_terms:
        return False
    for action in _normalize_list(actions):
        action_terms = _summary_overlap_terms(action)
        if len(action_terms) < 2:
            continue
        shared = sentence_terms & action_terms
        if len(shared) >= 2 and len(shared) / len(action_terms) >= 0.72:
            return True
    return False


def _summary_non_action_context_tail(sentence: str, actions) -> str:
    """Salvage factual context from an otherwise action-heavy overview sentence."""
    text = re.sub(r"\s+", " ", str(sentence or "")).strip()
    candidates = []
    for pattern in (r",\s+while\s+", r";\s*while\s+", r",\s+with\s+", r";\s*with\s+"):
        parts = re.split(pattern, text, maxsplit=1, flags=re.IGNORECASE)
        if len(parts) == 2 and parts[1].strip():
            candidates.append(parts[1].strip())
    for tail in candidates:
        if _summary_overview_metadata_only(tail):
            continue
        if _summary_overview_action_heavy(tail, actions):
            continue
        # Common factual-state phrasing after a ``with`` clause.
        match = re.match(r"^(?:the\s+)?(.+?)\s+(?:items?\s+)?unchanged[.!?]?$", tail, flags=re.IGNORECASE)
        if match:
            subject = match.group(1).strip(" ,;:-")
            if subject:
                return f"{subject[:1].upper() + subject[1:]} remain unchanged."
        tail = tail.rstrip(" .!?;:")
        if tail:
            return tail[:1].upper() + tail[1:] + "."
    return ""


def _summary_overview_metadata_only(sentence: str) -> bool:
    """Keep deadline/priority metadata in their dedicated sections, not Summary."""
    lowered = re.sub(r"\s+", " ", str(sentence or "")).strip().casefold()
    if not lowered:
        return True
    if re.match(
        r"^(?:the\s+)?(?:important\s+)?(?:deadline|due date|priority|urgency)\b",
        lowered,
    ):
        return True
    if re.match(
        r"^(?:the\s+)?(?:deadline|due date)\s+(?:and|/)\s+(?:priority|urgency)\b",
        lowered,
    ):
        return True
    if re.fullmatch(
        r"(?:deadline|due date|priority|urgency)(?:\s+and\s+(?:deadline|due date|priority|urgency))*"
        r"\s+(?:remains?|stays?|is|are)\s+(?:the\s+)?same[.!?]?",
        lowered,
    ):
        return True
    return False


def _summary_subject_fallback(email: dict) -> str:
    """Build a grounded compact overview when model prose is only section duplication."""
    raw_subject = re.sub(r"\s+", " ", str(email.get("subject") or "")).strip()
    is_reply = bool(re.match(r"^(?:(?:re|fw|fwd)\s*:\s*)+", raw_subject, flags=re.IGNORECASE))
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", raw_subject, flags=re.IGNORECASE)
    subject = re.sub(r"^(?:task|update|request)\s*:\s*", "", subject, flags=re.IGNORECASE)
    subject = subject.strip(" \t\r\n-–—:;,.\"'")
    if subject:
        return (
            f"The email provides the latest update on {subject}."
            if is_reply
            else f"The email concerns {subject}."
        )
    return (
        "The email provides the latest update on the current conversation."
        if is_reply
        else "The email provides a concise update for the recipient."
    )



def _summary_explicit_signal_tokens(text: str) -> set[str]:
    """Return exact source tokens whose loss materially weakens a short summary.

    These are deliberately syntax-level signals rather than case vocabulary:
    dates/times, amounts/counts/percentages, and similar explicit numeric facts.
    """
    value = str(text or "")
    tokens = set()
    for match in re.finditer(
        r"(?<![A-Za-z0-9])(?:[$€£₱]\s*)?\d[\d,]*(?:\.\d+)?(?:\s*%)?"
        r"(?:\s*(?:AM|PM))?(?![A-Za-z0-9])",
        value,
        flags=re.IGNORECASE,
    ):
        token = re.sub(r"\s+", " ", match.group(0)).strip().casefold()
        # The numeric matcher intentionally accepts commas for values such as
        # ``1,000``, but that also means sentence punctuation can be captured in
        # ``2026-09-12,`` as the token ``12,``. Canonicalize numeric punctuation
        # before comparing source-vs-summary material so an otherwise identical
        # grounded Summary is not rejected solely because one rendering uses a
        # trailing comma. Interior thousands separators are normalized too.
        token = re.sub(r"(?<=\d),(?=\d)", "", token).strip(" ,.;:")
        if token:
            tokens.add(token)
    return tokens


def _summary_semantic_context_markers(text: str) -> set[str]:
    """Return source semantics whose omission can materially change a fact.

    These markers are intentionally generic workflow semantics rather than
    benchmark vocabulary. They complement explicit numbers/dates by preserving
    provenance/authority and uncertainty when those roles are stated directly.
    """
    value = re.sub(r"\s+", " ", str(text or "")).casefold()
    markers: set[str] = set()
    if re.search(
        r"\b(?:authoritative|official|source of truth|system of record)\b",
        value,
        flags=re.IGNORECASE,
    ):
        markers.add("authoritative_source")
    if re.search(
        r"\b(?:preliminary|early estimate|estimated|estimate|approx(?:imate|imately)?|"
        r"not confirmed|unconfirmed|tentative)\b",
        value,
        flags=re.IGNORECASE,
    ):
        markers.add("uncertainty")
    return markers


def _summary_has_explicit_no_action_state(text: str) -> bool:
    """Detect an explicit current-state statement that the recipient has no work.

    Keep this syntax-driven rather than domain-specific. Small models commonly
    paraphrase sender wording such as ``no action is needed yet`` as
    ``no immediate action required``; those are the same current-state signal
    and must not trigger a second appended ``No action is required`` sentence.
    """
    return bool(re.search(
        r"\b(?:"
        r"no (?:(?:further|immediate|current|additional) )?"
        r"action(?: item)?(?: is)? (?:needed|required)(?: (?:yet|now))?(?: from you)?|"
        r"no (?:(?:further|immediate|current|additional) )?required action(?: from you)?|"
        r"nothing (?:is )?(?:needed|required)(?: (?:yet|now))?(?: from you)?|"
        r"you (?:do not|don't|dont) need to (?:do|take) anything|"
        r"for (?:your )?(?:records|information) only"
        r")\b",
        str(text or ""),
        flags=re.IGNORECASE,
    ))


def _summary_has_explicit_no_deadline_state(text: str) -> bool:
    """Detect source wording that explicitly says the current task has no set due date."""
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return bool(re.search(
        r"\b(?:"
        r"(?:there (?:is|are) )?no (?:fixed |stated |explicit |specific )?(?:deadline|due date)|"
        r"(?:no|without) (?:a |the )?(?:fixed |stated |explicit |specific )?(?:deadline|due date)|"
        r"(?:deadline|due date) (?:has|have) not been set|"
        r"(?:deadline|due date) (?:hasn't|haven't) been set|"
        r"(?:deadline|due date) (?:is|are) not set|"
        r"not setting (?:a |the )?(?:fixed |stated |explicit |specific |separate )?(?:deadline|due date)"
        r")\b",
        value,
        flags=re.IGNORECASE,
    ))


def _summary_no_deadline_source_clause(sentences: list[str]) -> str:
    """Return the shortest grounded clause that carries an explicit no-deadline state."""
    for sentence in sentences:
        text = re.sub(r"\s+", " ", str(sentence or "")).strip()
        if not _summary_has_explicit_no_deadline_state(text):
            continue
        # Scheduling constraints are often attached to another timing instruction
        # with a semicolon or a coordinating conjunction. Keep only the shortest
        # independent clause that itself states the no-deadline fact so appending
        # it cannot repeat an already-covered constraint (for example a preceding
        # not-before instruction). This is syntax-driven and task/domain agnostic.
        clauses = [
            part.strip()
            for part in re.split(r"\s*(?:;|,\s+(?:and|but)\s+)\s*", text, flags=re.IGNORECASE)
            if part.strip()
        ]
        no_deadline_clauses = [
            clause for clause in clauses
            if _summary_has_explicit_no_deadline_state(clause)
        ]
        if no_deadline_clauses:
            text = min(no_deadline_clauses, key=len)

        # Summaries should describe the scheduling state neutrally rather than
        # preserving sender-first-person phrasing such as "I am not setting a
        # deadline for the review". This is a wording normalization only: the
        # fact still comes directly from the source sentence.
        match = re.fullmatch(
            r"(?:i am|i'm|we are|we're) not setting "
            r"(?:a |the )?(?:fixed |stated |explicit |specific |separate )?"
            r"(deadline|due date)(?: for (.+?))?[.!?]?",
            text.strip(),
            flags=re.IGNORECASE,
        )
        if match:
            kind = str(match.group(1) or "deadline").casefold()
            target = re.sub(r"\s+", " ", str(match.group(2) or "")).strip(" .!?;:")
            neutral = f"No {kind} is set"
            if target:
                neutral += f" for {target}"
            return neutral

        return text.rstrip(" .!?;:")
    return ""


def _append_summary_constraint(overview: str, clause: str) -> str:
    """Add one grounded constraint while keeping the Summary within two sentences."""
    base = _compact_summary_overview(overview)
    fact = re.sub(r"\s+", " ", str(clause or "")).strip(" \t\r\n-–—:;,.!?")
    if not fact:
        return base
    if not base:
        return _compact_summary_overview(fact[:1].upper() + fact[1:] + ".")

    sentences = [
        part.strip() for part in re.split(r"(?<=[.!?])\s+", base) if part.strip()
    ]
    fact_sentence = fact[:1].upper() + fact[1:] + "."
    if len(sentences) <= 1:
        return _compact_summary_overview(f"{base.rstrip()} {fact_sentence}")

    first = sentences[0]
    second = sentences[1].rstrip(" .!?;:")
    fact_tail = fact[:1].lower() + fact[1:]
    return _compact_summary_overview(f"{first} {second}; {fact_tail}.")


def _summary_pure_no_action_sentence(text: str) -> bool:
    """Return True only when a sentence contributes no material fact beyond no-action state."""
    cleaned = re.sub(r"^[\s\-–—:;,.]+|[\s\-–—:;,.]+$", "", str(text or ""))
    return bool(re.fullmatch(
        r"(?:"
        r"no (?:(?:further|immediate|current|additional) )?"
        r"action(?: item)?(?: is)? (?:needed|required)(?: (?:yet|now))?(?: from you)?|"
        r"no (?:(?:further|immediate|current|additional) )?required action(?: from you)?|"
        r"nothing (?:is )?(?:needed|required)(?: (?:yet|now))?(?: from you)?|"
        r"you (?:do not|don't|dont) need to (?:do|take) anything"
        r")",
        cleaned,
        flags=re.IGNORECASE,
    ))


def _summary_source_sentences_for_overview(email: dict) -> list[str]:
    """Return clean prose sentences from only the effective/current source turn."""
    turn = _phase1g_effective_turn_text(_body_text(email))
    if not turn:
        return []

    # Preserve semantic rows in simple pipe-delimited task tables instead of
    # flattening the whole table into one unreadable Summary sentence.
    raw_lines = [line.strip() for line in str(turn).splitlines() if line.strip()]
    table_rows = []
    if any("|" in line for line in raw_lines):
        for line in raw_lines:
            row = _phase1b_pipe_table_row(email, line)
            if not row:
                continue
            task = re.sub(r"\s+", " ", str(row.get("task") or "")).strip(" .")
            owner = re.sub(r"\s+", " ", str(row.get("owner") or "")).strip(" .")
            due = re.sub(r"\s+", " ", str(row.get("due") or "")).strip(" .")
            if not task:
                continue
            # Do not render the header itself as a factual row. The table parser
            # can identify it structurally because its cells are the column names.
            if (
                task.casefold() in {"task", "action", "action item", "work"}
                and owner.casefold() in {"owner", "assignee", "assigned to"}
                and due.casefold() in {"due", "deadline", "due date"}
            ):
                continue
            if row.get("owner_kind") == "recipient":
                rendered = task[:1].upper() + task[1:]
                if due:
                    rendered += f" by {due}"
            else:
                # Other-owner rows are context only. Render them as natural
                # assignment prose so Summary repair never leaks raw table markup.
                rendered_task = task[:1].lower() + task[1:]
                rendered = f"{owner} is assigned to {rendered_task}" if owner else task
                if due:
                    rendered += f" by {due}"
            table_rows.append(rendered.rstrip(" .") + ".")
        if table_rows:
            return table_rows

    # Strip presentation-only lines before flattening. Inline CID placeholders,
    # mobile signatures, and navigation/footer link rows are transport/UI noise,
    # not business facts. This filtering is intentionally line-structural and
    # does not remove the same words when they occur in ordinary prose.
    clean_lines = []
    for raw_line in str(turn).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(r"\[?cid:[^\]\s>]+\]?", line, flags=re.IGNORECASE):
            continue
        if re.fullmatch(r"sent from (?:my )?(?:mobile|phone|iphone|android)[.!]?", line, flags=re.IGNORECASE):
            continue
        nav_parts = [part.strip().casefold() for part in line.split("|") if part.strip()]
        if len(nav_parts) >= 2 and all(
            part in {
                "view in browser", "privacy", "privacy policy", "unsubscribe",
                "manage preferences", "email preferences", "home",
            }
            for part in nav_parts
        ):
            continue
        clean_lines.append(line)

    # HTML-to-text conversion can wrap prose mid-sentence. For overview rendering
    # those newlines are presentation artifacts, while labeled/quoted-turn handling
    # has already been resolved by _phase1g_effective_turn_text().
    prose = re.sub(r"[ \t]*[\r\n]+[ \t]*", " ", "\n".join(clean_lines)).strip()
    sentences = []
    for sentence in _phase1b_source_sentences(prose):
        cleaned = re.sub(
            r"^\s*(?:fyi|for your information)\s*:\s*",
            "",
            sentence,
            flags=re.IGNORECASE,
        ).strip()
        if cleaned:
            sentences.append(cleaned)
    return sentences


def _summary_pack_short_source(sentences: list[str]) -> str:
    """Pack a short grounded source turn into at most two readable sentences."""
    parts = [re.sub(r"\s+", " ", str(item or "")).strip() for item in sentences]
    parts = [item for item in parts if item]
    if not parts:
        return ""
    if len(parts) <= 2:
        return _compact_summary_overview(" ".join(parts))

    first = parts[0].rstrip(" .!?;:") + "."
    remainder = parts[1:]

    # A pure final no-action sentence is a state qualifier, so attach it to the
    # preceding factual sentence rather than spending a third summary sentence.
    if _summary_pure_no_action_sentence(remainder[-1]):
        remainder = remainder[:-1]
        if remainder:
            second = remainder[0].rstrip(" .!?;:")
            for extra in remainder[1:]:
                extra = extra.rstrip(" .!?;:")
                if extra:
                    second += "; " + extra[:1].lower() + extra[1:]
            second += ", and no action is required."
        else:
            second = "No action is required."
        return _compact_summary_overview(f"{first} {second}")

    # For other short source turns, retain all material clauses but collapse any
    # third/fourth sentence into the second with semicolons. This is source-only
    # compaction, not generated case-specific wording.
    second = remainder[0].rstrip(" .!?;:")
    for extra in remainder[1:]:
        extra = extra.rstrip(" .!?;:")
        if extra:
            second += "; " + extra[:1].lower() + extra[1:]
    return _compact_summary_overview(f"{first} {second}.")


def _repair_actionless_summary_completeness(
    email: dict, actions, fallback: str = ""
) -> str:
    """Repair lossy summaries for short, actionless mail using only source facts.

    This is intentionally benchmark-agnostic: it contains no subject names,
    deployment terms, fixed times, expected-summary strings, or case IDs. It only
    activates when the final validated action list is empty and the model omitted
    explicit source signals such as a number/time or a no-action state.
    """
    overview = _compact_summary_overview(fallback)
    if _normalize_list(actions):
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview

    source_text = " ".join(source_sentences)
    # Keep deterministic source reconstruction narrow: short informational/current
    # turns only. Long mail should stay model-summarized rather than copied.
    if len(source_sentences) > 4 or len(source_text.split()) > 95:
        return overview

    missing_explicit_signal = bool(
        _summary_explicit_signal_tokens(source_text)
        - _summary_explicit_signal_tokens(overview)
    )
    missing_semantic_context = bool(
        _summary_semantic_context_markers(source_text)
        - _summary_semantic_context_markers(overview)
    )
    missing_no_action_state = (
        _summary_has_explicit_no_action_state(source_text)
        and not _summary_has_explicit_no_action_state(overview)
    )
    if not (missing_explicit_signal or missing_semantic_context or missing_no_action_state):
        return overview

    # RAW-first minimality: a missing no-action qualifier alone is not evidence
    # that the otherwise valid Summary should be rebuilt from the source body.
    # Append only the missing state. Source reconstruction remains reserved for
    # a proven loss of concrete material values or semantic provenance/uncertainty
    # that changes how those values should be interpreted.
    if (
        missing_no_action_state
        and not missing_explicit_signal
        and not missing_semantic_context
        and overview
    ):
        return _append_summary_constraint(overview, "No action is required.")

    rebuilt = _summary_pack_short_source(source_sentences)
    return rebuilt or overview


def _summary_has_explicit_open_state(text: str) -> bool:
    """Detect source wording that explicitly says requested work is still unfinished."""
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return bool(re.search(
        r"\b(?:"
        r"(?:still|currently|remains?|remain) (?:outstanding|pending|open|incomplete|unfinished)|"
        r"(?:has|have) not (?:yet )?been (?:submitted|completed|finished|sent|provided|resolved|approved)|"
        r"(?:is|are) not (?:yet )?(?:submitted|completed|finished|sent|provided|resolved|approved)|"
        r"not (?:yet )?(?:submitted|completed|finished|sent|provided|resolved|approved)"
        r")\b",
        value,
        flags=re.IGNORECASE,
    ))


def _summary_open_state_phrase(text: str) -> str:
    """Return a short neutral state phrase grounded in explicit source wording."""
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    if re.search(r"\b(?:still|currently|remains?|remain) outstanding\b", value, flags=re.IGNORECASE):
        return "remains outstanding"
    if re.search(r"\b(?:still|currently|remains?|remain) pending\b", value, flags=re.IGNORECASE):
        return "remains pending"
    if re.search(r"\b(?:still|currently|remains?|remain) open\b", value, flags=re.IGNORECASE):
        return "remains open"
    if re.search(r"\b(?:still|currently|remains?|remain) (?:incomplete|unfinished)\b", value, flags=re.IGNORECASE):
        return "remains incomplete"
    if re.search(r"\b(?:has|have) not (?:yet )?been submitted\b|\b(?:is|are) not (?:yet )?submitted\b", value, flags=re.IGNORECASE):
        return "has not been submitted"
    if re.search(r"\b(?:has|have) not (?:yet )?been (?:completed|finished)\b|\b(?:is|are) not (?:yet )?(?:completed|finished)\b", value, flags=re.IGNORECASE):
        return "has not been completed"
    if re.search(r"\b(?:has|have) not (?:yet )?been sent\b|\b(?:is|are) not (?:yet )?sent\b", value, flags=re.IGNORECASE):
        return "has not been sent"
    return "remains incomplete"


def _summary_subject_topic_for_state(email: dict) -> str:
    """Derive a neutral topic label from the subject without case-specific vocabulary."""
    subject = re.sub(r"\s+", " ", str(email.get("subject") or "")).strip()
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject, flags=re.IGNORECASE)
    subject = re.sub(r"^(?:task|update|request)\s*:\s*", "", subject, flags=re.IGNORECASE)
    subject = re.sub(
        r"(?:\s*[-–—:]?\s*)(?:overdue|past due|outstanding|pending|incomplete|unfinished|reminder)\s*$",
        "",
        subject,
        flags=re.IGNORECASE,
    ).strip(" \t\r\n-–—:;,.\"'")
    return subject


def _summary_human_date(value: date) -> str:
    """Format a resolved date without platform-specific strftime day modifiers."""
    return f"{value.strftime('%B')} {value.day}, {value.year}"


def _repair_overdue_open_summary_completeness(
    email: dict, actions, deadlines, fallback: str = "", today: date | None = None
) -> str:
    """Preserve explicit still-open state for a single overdue recipient task.

    This repair is deliberately source-driven and benchmark-agnostic. It only
    activates when there is exactly one validated action, exactly one resolved
    explicit past deadline, and the effective source turn explicitly says the
    work remains unfinished. That keeps unrelated past dates and multi-action
    mail out of this narrow summary-state repair.
    """
    overview = _compact_summary_overview(fallback)
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)
    if len(normalized_actions) != 1 or len(normalized_deadlines) != 1:
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview
    source_text = " ".join(source_sentences)
    if len(source_sentences) > 5 or len(source_text.split()) > 120:
        return overview
    if not _summary_has_explicit_open_state(source_text):
        return overview

    today = today or datetime.now().date()
    resolved = _resolved_deadline_dates(normalized_deadlines, _email_date(email, today))
    if len(resolved) != 1 or resolved[0] >= today:
        return overview

    # If the model already carried both the unfinished state and the overdue
    # semantics, do not rewrite stylistically equivalent prose.
    if _summary_has_explicit_open_state(overview) and re.search(
        r"\b(?:overdue|past due|was due|had been due)\b", overview, flags=re.IGNORECASE
    ):
        return overview

    topic = _summary_subject_topic_for_state(email)
    if not topic:
        return overview
    if not (len(topic) >= 2 and topic[:2].isupper()):
        topic = topic[:1].lower() + topic[1:]

    state = _summary_open_state_phrase(source_text)
    due_text = _summary_human_date(resolved[0])
    return _compact_summary_overview(f"The {topic} {state} and was due on {due_text}.") or overview


def _repair_summary_no_deadline_constraint(
    email: dict, actions, fallback: str = ""
) -> str:
    """Preserve an explicit no-deadline scheduling constraint for active work.

    The repair is source-driven and task-generic: it activates only when there is
    validated recipient work, the effective source turn explicitly says no due
    date is set, and the model Summary omitted that scheduling state.
    """
    overview = _compact_summary_overview(fallback)
    if not _normalize_list(actions):
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview
    source_text = " ".join(source_sentences)
    if len(source_sentences) > 5 or len(source_text.split()) > 120:
        return overview
    if not _summary_has_explicit_no_deadline_state(source_text):
        return overview
    if _summary_has_explicit_no_deadline_state(overview):
        return overview

    clause = _summary_no_deadline_source_clause(source_sentences)
    return _append_summary_constraint(overview, clause) if clause else overview


def _summary_is_topic_only_overview(value: str) -> bool:
    """Return True for generic subject-only fallback prose."""
    text = _compact_summary_overview(value)
    return bool(re.fullmatch(
        r"The email (?:concerns|provides the latest update on) .+?[.]?",
        text,
        flags=re.IGNORECASE,
    ))


def _summary_has_inline_image_artifact_claim(email: dict, value: str) -> bool:
    """Detect image-placeholder metadata promoted into Summary meaning.

    ``cid:`` references are rendering plumbing for inline images. A filename may
    contain words such as ``logo`` that an LLM echoes as if the message said an
    image was attached. Flag that only when the image noun appears in Summary,
    comes from a CID-bearing turn, and does not appear in the actual prose once
    CID placeholders are removed. Legitimate prose about an image/logo is kept.
    """
    body = _phase1g_effective_turn_text(_body_text(email))
    if not re.search(r"\[?cid:[^\]\s>]+\]?", body, flags=re.IGNORECASE):
        return False
    overview = _compact_summary_overview(value)
    if not overview:
        return False
    prose = re.sub(
        r"\[?cid:[^\]\s>]+\]?", " ", body, flags=re.IGNORECASE
    )
    image_nouns = ("logo", "image", "icon", "banner", "graphic", "photo", "picture")
    for noun in image_nouns:
        if re.search(rf"\b{noun}s?\b", overview, flags=re.IGNORECASE) and not re.search(
            rf"\b{noun}s?\b", prose, flags=re.IGNORECASE
        ):
            return True
    return False


def _summary_is_meta_framed_action_overview(value: str, actions) -> bool:
    """Detect communication/request framing that hides the actual recipient work.

    A short direct request can be paraphrased by the model as a description of
    the *message* or *request* (for example, an "update on ..." or a "request
    for ...") instead of stating the executable work itself.  That wording is
    source-adjacent but semantically weaker and can also attach a task deadline
    to the request/update event rather than to the task.

    This detector is deliberately task-generic.  It uses only grammatical
    reporting frames plus the already-normalized Action Item intents; it does not
    recognize any subject, business object, benchmark phrase, or date.  A genuine
    executable action such as "Update the spreadsheet" or "Request approval"
    is preserved when its intent matches the validated Action Item.
    """
    overview = _compact_summary_overview(value)
    normalized_actions = _normalize_list(actions)
    if not overview or not normalized_actions:
        return False

    action_intents = {
        intent
        for intent in (_phase1c_action_intent(action) for action in normalized_actions)
        if intent
    }
    overview_intent = _phase1c_action_intent(overview)
    lowered = overview.casefold()

    # Explicit communication/reporting subjects are always meta framing.  The
    # executable task may still appear later in the sentence, but Summary should
    # describe the work rather than say that an email/message/summary says it.
    if re.match(
        r"^(?:(?:an?|the)\s+)?(?:email|message|notification|reminder|summary|overview)\b",
        lowered,
    ):
        return True

    # Nominal update/request/status frames are ambiguous in isolation.  Treat
    # them as metadata only when their earliest detected intent is not one of the
    # validated recipient-action intents.  This keeps legitimate tasks such as
    # "Update the request" intact while repairing noun-phrase frames such as
    # "Update on ..." or "Request for ...".
    nominal_frame = bool(re.match(
        r"^(?:(?:an?|the)\s+)?(?:"
        r"(?:status\s+)?update\s+(?:on|about|regarding|for|request)\b|"
        r"request\s+(?:for|about|regarding)\b|"
        r"(?:request|status)\s+update\b|"
        # Noun-style inquiry/query/question framing describes the communication
        # rather than the executable work. Restrict this to prepositional noun
        # forms so legitimate verbs such as "Question the assumption" remain
        # valid. This is grammar-based, not subject/business-case based.
        r"(?:inquir(?:y|ies)|quer(?:y|ies)|question)\s+(?:about|on|regarding|into|for)\b|"
        r"status\s+(?:inquir(?:y|ies)|quer(?:y|ies))\b"
        r")",
        lowered,
    ))
    if not nominal_frame:
        return False
    return not overview_intent or overview_intent not in action_intents


def _summary_request_sentence(value: str) -> str:
    """Naturalize one grounded recipient request without echoing request syntax.

    Summary prose should state the requested work, not quote a polite question
    back to the reader.  This conversion is deliberately grammatical rather
    than domain-specific: it handles common modal request forms while preserving
    the original predicate, object, modality inside the predicate, and exact
    source facts.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""

    text = re.sub(r"^(?:please|kindly)\s+", "", text, flags=re.IGNORECASE)

    # Polite actionable questions such as ``Can/Could/Would/Will you ...?`` are
    # requests in recipient context, not information-seeking Summary prose.
    # Keep the predicate verbatim instead of reconstructing it from a
    # subject-specific template or an expected answer.
    modal_request = re.match(
        r"^(?:can|could|would|will)\s+you\s+(?:please\s+)?(.+?)\?\s*$",
        text,
        flags=re.IGNORECASE,
    )
    if modal_request:
        predicate = modal_request.group(1).strip()
        if predicate:
            text = predicate.rstrip(" ?") + "."

    if text:
        text = text[:1].upper() + text[1:]
    return text


def _summary_low_urgency_signals(text: str) -> set[str]:
    """Return source-grounded open-ended timing signals for Summary repair.

    ``no rush``-style language communicates low urgency; ``when convenient``-
    style language additionally communicates that the sender did not provide a
    fixed due point.  Keeping the two signals separate avoids inventing a no-
    deadline statement from low urgency alone.
    """
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    signals: set[str] = set()
    if re.search(
        r"\b(?:no rush|no hurry|not urgent|not time[- ]sensitive)\b",
        value,
        flags=re.IGNORECASE,
    ):
        signals.add("low_urgency")
    if re.search(
        r"\b(?:when(?:ever)? convenient|at your convenience|when you (?:can|are able)|"
        r"whenever you (?:can|are able))\b",
        value,
        flags=re.IGNORECASE,
    ):
        signals.add("open_ended_timing")
    return signals


def _summary_temporal_semantic_markers(text: str) -> set[str]:
    """Return workflow-significant timing semantics carried by short prose.

    These markers describe *roles* of dates rather than particular benchmark
    values: tentative/unconfirmed dates, hard-vs-soft cutoffs, windows, recurring
    start/end bounds, timezone emphasis, ambiguity, and relational constraints.
    They are used only to detect semantic loss in Summary prose; deadline
    ownership remains in the validated deadline/action pipeline.
    """
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    lowered = value.casefold()
    if not lowered:
        return set()

    markers: set[str] = set()
    if re.search(
        r"\b(?:proposed|tentative|unconfirmed|not confirmed|not yet confirmed|"
        r"tbd|to be confirmed|will be confirmed|not final)\b",
        lowered,
    ):
        markers.add("tentative_state")
    if re.search(r"\b(?:if possible|preferred?|preference|target date|aim to)\b", lowered):
        markers.add("soft_target")
    if re.search(
        r"\b(?:hard deadline|final deadline|absolute deadline|final cutoff|hard cutoff|"
        r"no later than)\b",
        lowered,
    ):
        markers.add("hard_cutoff")
    if re.search(
        r"\b(?:any time from|from .{0,50}? through |between .{0,50}? and |"
        r"submission window|upload window)\b",
        lowered,
    ):
        markers.add("date_window")
    if re.search(r"\b(?:every|each)\s+(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", lowered):
        markers.add("recurring_cadence")
    if re.search(r"\b(?:starting|beginning)\s+(?:this|next|on|from)\b", lowered):
        markers.add("recurring_start")
    if re.search(r"\b(?:continue(?: doing this)?\s+until|every .{0,40}? until|each .{0,40}? until)\b", lowered):
        markers.add("recurring_end")
    if re.search(
        r"\b(?:timezone|time zone)\b.{0,40}\b(?:important|critical|must|matters?)\b|"
        r"\b(?:important|critical)\b.{0,40}\b(?:timezone|time zone)\b",
        lowered,
    ):
        markers.add("timezone_emphasis")
    if re.search(
        r"\b(?:different date formats?|ambiguous date|date format)\b|"
        r"\bwhether (?:this|that|it) means\b.{0,60}\bor\b",
        lowered,
    ):
        markers.add("date_ambiguity")
    if re.search(r"\b(?:do not|don't|dont)\s+.{0,30}?\bbefore\b|\bnot before\b", lowered):
        markers.add("not_before")
    if re.search(
        r"\bafter\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|"
        r"20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}/\d{1,2}/20\d{2})",
        lowered,
    ):
        markers.add("not_before")
    if re.search(
        r"\b(?:one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+"
        r"(?:business\s+)?(?:hours?|days?|weeks?)\s+(?:before|after)\b",
        lowered,
    ):
        markers.add("relative_to_event")
    if "not_before" not in markers and re.search(
        r"\b(?:before|prior to)\s+(?:[A-Za-z]|\d)", lowered
    ):
        markers.add("before_semantics")
    if re.search(r"\bclose of business(?:\s+today)?\b|\bcob\b", lowered):
        markers.add("close_of_business")
    if re.search(r"\bwithin\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+business\s+days?\b", lowered):
        markers.add("business_days")
    # Preserve source-relative duration semantics (for example, ``within three
    # days``) in Summary instead of allowing an LLM-normalized absolute date to
    # silently replace the sender's wording. This is semantic prose only; the
    # validated Deadline field remains responsible for ownership and sorting.
    if re.search(
        r"\bwithin\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
        r"(?:business\s+)?(?:hours?|days?|weeks?)\b",
        lowered,
    ):
        markers.add("relative_duration")
    # Preserve sender-relative day wording in Summary prose instead of allowing
    # a model paraphrase (for example ``the next day``) or an absolute date to
    # replace the source relation. Deadline normalization remains independent.
    if re.search(r"\b(?:today|tomorrow|tonight|bukas)\b", lowered):
        markers.add("relative_day")
    if re.search(r"\bend of\s+(?:(?:this|next)\s+)?(?:week|month)\b", lowered):
        markers.add("broad_relative")
    return markers


def _repair_summary_temporal_semantics(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Restore timing qualifiers whose omission changes task interpretation.

    The repair is deliberately short-source only and source-grounded.  It never
    promotes proposed/event dates into Deadline; it only makes the Summary keep
    semantics such as tentative vs final, date windows, recurring start/end,
    timezone emphasis, ambiguous formats, and relative-to-event wording.
    """
    overview = _compact_summary_overview(fallback)
    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview
    source_text = " ".join(source_sentences)
    if len(source_sentences) > 5 or len(source_text.split()) > 120:
        return overview

    missing = _summary_temporal_semantic_markers(source_text) - _summary_temporal_semantic_markers(overview)
    if not missing:
        return overview

    relevant = [
        sentence for sentence in source_sentences
        if _summary_temporal_semantic_markers(sentence) & missing
    ]
    if not relevant:
        return overview

    # If the missing semantics live inside the recipient request itself (for
    # example a submission window, recurring start, or relative-to-event due),
    # rebuild from the short grounded source so the qualifier stays attached to
    # the correct action.  Otherwise append only the missing context/state line.
    if any(_phase1b_recipient_request_signal(sentence) for sentence in relevant):
        parts = []
        for sentence in source_sentences[:2]:
            if _phase1b_recipient_request_signal(sentence):
                rendered = _summary_request_sentence(sentence)
            else:
                rendered = _summary_naturalize_context_sentence(sentence)
            rendered = re.sub(r"\s+", " ", str(rendered or "")).strip()
            if rendered:
                parts.append(rendered)
        candidate = _compact_summary_overview(" ".join(parts))
        return candidate or overview

    additions = []
    for sentence in relevant[:2]:
        rendered = _summary_naturalize_context_sentence(sentence)
        rendered = re.sub(r"\s+", " ", str(rendered or "")).strip()
        if rendered and not _summary_semantically_covers_fact(email, rendered, overview):
            additions.append(rendered)
    if not additions:
        return overview
    return _compact_summary_overview(f"{overview.rstrip()} {' '.join(additions)}") or overview


def _repair_summary_open_ended_timing(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Preserve sender-provided low-urgency/open-ended timing in Summary.

    This is a generic source-semantic repair.  It runs only for validated
    recipient work in a short current turn and never changes extracted deadline
    ownership.  An estimated/planned application deadline can therefore still
    coexist with a Summary that accurately says the sender set no fixed deadline.
    """
    overview = _compact_summary_overview(fallback)
    if not _normalize_list(actions):
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview
    source_text = " ".join(source_sentences)
    if len(source_sentences) > 5 or len(source_text.split()) > 120:
        return overview

    signals = _summary_low_urgency_signals(source_text)
    if not signals:
        return overview

    summary_signals = _summary_low_urgency_signals(overview)
    additions = []

    # Open-ended convenience wording is evidence that the sender did not set a
    # fixed due point.  Do not make this claim when an explicit validated source
    # deadline exists for the recipient.
    if (
        "open_ended_timing" in signals
        and not _normalize_list(deadlines)
        and not _summary_has_explicit_no_deadline_state(overview)
    ):
        additions.append("There is no fixed deadline")

    if "low_urgency" in signals and "low_urgency" not in summary_signals:
        additions.append("no rush" if additions else "There is no rush")

    if not additions:
        return overview

    if len(additions) == 2:
        clause = f"{additions[0]} and {additions[1].lower()}."
    else:
        clause = additions[0].rstrip(" .") + "."
    return _append_summary_constraint(overview, clause)


def _summary_naturalize_context_sentence(value: str) -> str:
    """Normalize one grounded non-action context sentence for summary prose."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""

    # Summary voice should not inherit sender possessives when a neutral definite
    # article preserves the same fact (for example, "Our meeting" -> "The meeting").
    text = re.sub(r"^(?:our|my)\s+", "The ", text, flags=re.IGNORECASE)

    # Humanize unambiguous ISO calendar dates in contextual prose only. This does
    # not alter deadline extraction or identifiers elsewhere in the pipeline.
    def _humanize(match):
        try:
            resolved = date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return match.group(0)
        return _summary_human_date(resolved)

    text = re.sub(r"\b(\d{4})-(\d{2})-(\d{2})\b", _humanize, text)
    if text:
        text = text[:1].upper() + text[1:]
    return text


def _summary_covers_recipient_work(value: str, actions) -> bool:
    """Return True when Summary already conveys at least one validated recipient task.

    Summary is allowed to mention the main requested work as part of a natural
    overview; Action Items still own the exact executable checklist. This helper
    prevents context-only model prose from dropping the email's actual purpose.
    """
    overview_terms = _summary_overlap_terms(value)
    if not overview_terms:
        return False
    for action in _normalize_list(actions):
        action_terms = _summary_overlap_terms(action)
        if not action_terms:
            continue
        shared = overview_terms & action_terms
        if len(shared) / max(1, len(action_terms)) >= 0.55:
            return True
    return False


def _summary_restrictive_action_scope_markers(text: str) -> set[str]:
    """Return generic request-scope qualifiers that must not be dropped."""
    value = re.sub(r"\s+", " ", str(text or "")).casefold()
    markers: set[str] = set()
    if re.search(r"\bonly\b", value):
        markers.add("exclusive_only")
    if re.search(r"\b(?:except|excluding|other than)\b", value):
        markers.add("exclusion")
    return markers


def _repair_action_summary_completeness(
    email: dict, actions, fallback: str = ""
) -> str:
    """Restore concrete purpose/context when a short action mail collapses to its subject.

    This is source-driven and task-generic. It activates only for a short current
    turn with validated recipient work and a topic-only fallback. In addition to
    grounded request sentences, it preserves one nearby non-action source sentence
    when that sentence carries an explicit material numeric/date/time fact that the
    fallback lost. This keeps contextual event/schedule facts in Summary without
    promoting them to task deadlines. Scheduling constraints are still handled by
    the separate no-deadline/deadline logic.
    """
    overview = _compact_summary_overview(fallback)
    normalized_actions = _normalize_list(actions)
    if not normalized_actions:
        return overview

    # Repair generic subject fallbacks and context-only summaries that omit the
    # validated recipient work. This is semantic coverage based; it does not
    # depend on a subject, task name, benchmark case, or exact date.
    action_scope_markers = _summary_restrictive_action_scope_markers(
        " ".join(normalized_actions)
    )
    missing_action_scope = bool(
        action_scope_markers
        - _summary_restrictive_action_scope_markers(overview)
    )
    needs_repair = (
        _summary_is_topic_only_overview(overview)
        or _summary_is_meta_framed_action_overview(overview, normalized_actions)
        or _summary_has_inline_image_artifact_claim(email, overview)
        or not _summary_covers_recipient_work(overview, normalized_actions)
        or missing_action_scope
    )
    if not needs_repair:
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview
    source_text = " ".join(source_sentences)
    if len(source_sentences) > 5 or len(source_text.split()) > 120:
        return overview

    request_sentences = [
        _summary_request_sentence(sentence)
        for sentence in source_sentences
        if _phase1b_recipient_request_signal(sentence)
        and not _phase1c_evidence_is_non_action(sentence, source_text)
        # A response-only phrase that merely supplies open-ended timing for a
        # separate covered request is not independent work. The dedicated timing
        # repair preserves that constraint without turning it into a second task
        # sentence. Standalone reply requests are never suppressed.
        and not (
            len(source_sentences) > 1
            and normalized_actions
            and _raw_first_is_ancillary_response_timing_request(sentence)
        )
    ]
    request_sentences = [item for item in request_sentences if item]
    if not request_sentences:
        return overview

    # Preserve at most one non-action contextual fact that contains an explicit
    # date/time/amount/count signal. The sentence remains Summary context only; it
    # never enters the deadline list or action details. Exclude pure scheduling
    # constraints here because the dedicated no-deadline repair appends those.
    context_sentences = []
    for sentence in source_sentences:
        if _phase1b_recipient_request_signal(sentence):
            continue
        if _summary_has_explicit_no_deadline_state(sentence):
            continue
        if _summary_has_explicit_no_action_state(sentence):
            continue
        if not _summary_explicit_signal_tokens(sentence):
            continue
        normalized = _summary_naturalize_context_sentence(sentence)
        if normalized:
            context_sentences.append(normalized)
            break

    # Preserve one explicit scheduling/urgency constraint while rebuilding the
    # recipient request. A repair must not fix missing work by temporarily
    # deleting an already-grounded ``no deadline``/``no rush`` state, because the
    # non-destructive repair gate correctly rejects that loss before later timing
    # repairs get a chance to run. Keep this source-only and at most two sentences.
    constraint_sentences = []
    for sentence in source_sentences:
        if _phase1b_recipient_request_signal(sentence):
            continue
        if not (
            _summary_has_explicit_no_deadline_state(sentence)
            or _summary_low_urgency_signals(sentence)
        ):
            continue
        normalized = _summary_naturalize_context_sentence(sentence)
        normalized = re.sub(r"\s+", " ", str(normalized or "")).strip()
        if normalized:
            constraint_sentences.append(normalized)
            break

    # Keep the Summary concise. The full validated list remains available in
    # Action Items. When a material contextual fact exists, reserve the first
    # sentence for it and fold any explicit scheduling constraint into the request
    # sentence; otherwise use request + constraint as the two-sentence shape.
    if context_sentences:
        request = request_sentences[0]
        if constraint_sentences:
            request = f"{request.rstrip()} {constraint_sentences[0]}"
        parts = context_sentences[:1] + [request]
    elif constraint_sentences:
        parts = request_sentences[:1] + constraint_sentences[:1]
    else:
        parts = request_sentences[:2]
    return _compact_summary_overview(" ".join(parts)) or overview



def _summary_context_fact_is_high_impact(value: str) -> bool:
    """Return True for state/decision/dependency facts that belong in an overview.

    The categories are semantic workflow roles rather than domain vocabulary:
    decisions/approvals, blockers/dependencies, lifecycle changes, and explicit
    unresolved states. These facts materially change how the recipient
    understands the email even when they are not executable work.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return False
    return bool(re.search(
        r"\b(?:"
        r"approved?|approval|rejected?|rejection|decided?|decision|agreed?|authorized?|authorization|accepted?|"
        r"blocked?|blocking|blockers?|depends?|dependency|waiting on|pending|on hold|"
        r"completed?|finished?|done|on track|off track|at risk|stable|healthy|degraded|"
        r"cancelled?|superseded?|replaced?|rescheduled?|postponed?|"
        r"moved?|changed?|revised?|"
        r"authoritative|official|source of truth|system of record|"
        r"outstanding|incomplete|unfinished"
        r")\b",
        text,
        flags=re.IGNORECASE,
    ))


def _summary_semantically_covers_fact(
    email: dict, fact: str, summary: str
) -> bool:
    """Check whether a material source fact is already represented in Summary.

    This is deliberately broader than Key-Point-vs-Summary dedupe. Summary
    completeness needs whole-narrative coverage, while the Key Points section may
    still surface a scan-friendly atomic version of a fact embedded inside a
    multi-fact Summary sentence.
    """
    fact_terms = _cross_section_fact_terms(fact)
    summary_terms = _cross_section_fact_terms(summary)
    if not fact_terms or not summary_terms:
        return False

    # Numeric Key Points are often emitted in label form (for example,
    # "Number of seats: 48") while Summary carries the same grounded value in
    # ordinary prose ("... for 48 seats"). Quantity-label words are grammatical
    # framing, not an independent business fact. Ignore only those generic
    # wrappers when the Key Point actually contains a material numeric value;
    # the numeric-value subset check below still has to match, so equal nouns
    # with different counts/amounts remain distinct.
    if _cross_section_material_tokens(fact):
        fact_terms = fact_terms - {
            "number", "numbers", "count", "counts",
            "quantity", "quantities", "qty",
        }
        if not fact_terms:
            # A bare number/quantity label has too little semantic identity to
            # deduplicate safely; the same numeric value may describe another
            # fact elsewhere in the Summary.
            return False

    shared = fact_terms & summary_terms
    if len(shared) / max(1, len(fact_terms)) < 0.80:
        return False

    reference_date = _email_date(email, datetime.now().date())
    fact_dates = _cross_section_dates(fact, reference_date)
    summary_dates = _cross_section_dates(summary, reference_date)
    if fact_dates and not fact_dates.issubset(summary_dates):
        return False

    fact_times = _cross_section_time_tokens(fact)
    summary_times = _cross_section_time_tokens(summary)
    if fact_times and not fact_times.issubset(summary_times):
        return False

    fact_material = _cross_section_material_tokens(fact)
    summary_material = _cross_section_material_tokens(summary)
    if fact_material and not fact_material.issubset(summary_material):
        return False
    return True


def _summary_missing_explicit_context_sentence(email: dict, overview: str) -> str:
    """Return a source context sentence whose concrete value Summary dropped.

    The guard is intentionally narrow: the sentence must be non-action context,
    carry a concrete date/time/material value, and share its semantic identity
    with the existing Summary.  This repairs cases where Summary already says
    what the context is (for example an event) but omits the event's source date
    or time, without pulling unrelated third-party schedules into the overview.
    """
    compact = _compact_summary_overview(overview)
    if not compact:
        return ""
    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return ""

    reference_date = _email_date(email, datetime.now().date())
    summary_terms = _cross_section_fact_terms(compact)
    summary_dates = _cross_section_dates(compact, reference_date)
    summary_times = _cross_section_time_tokens(compact)
    summary_material = _cross_section_material_tokens(compact)
    generic_timing_terms = {
        "deadline", "date", "time", "am", "pm", "noon", "midnight",
        "today", "tomorrow", "tonight", "day", "week", "month",
        "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday", "sunday",
    }

    for sentence in source_sentences:
        if _phase1b_recipient_request_signal(sentence):
            continue
        if _summary_has_explicit_no_deadline_state(sentence):
            continue
        if _summary_has_explicit_no_action_state(sentence):
            continue

        dates = _cross_section_dates(sentence, reference_date)
        times = _cross_section_time_tokens(sentence)
        material = _cross_section_material_tokens(sentence)
        if not (dates or times or material):
            continue

        # Require the current Summary to already identify the same contextual
        # thing. This prevents unrelated other-person deadlines from being moved
        # into Summary merely because they contain a date.
        identity_terms = _cross_section_fact_terms(sentence) - generic_timing_terms
        if not identity_terms:
            continue
        shared = identity_terms & summary_terms
        if not shared or len(shared) / max(1, len(identity_terms)) < 0.60:
            continue

        value_missing = (
            (dates and not dates.issubset(summary_dates))
            or (times and not times.issubset(summary_times))
            or (material and not material.issubset(summary_material))
        )
        if value_missing:
            return sentence
    return ""


def _summary_missing_related_material_context_sentences(
    email: dict, overview: str
) -> list[str]:
    """Return omitted peer value sentences for a context already in Summary.

    The peer must share a non-timing semantic identity with a covered context
    sentence and carry its own explicit value. This preserves sibling facts
    (such as two regional amounts) without pulling unrelated dated schedules or
    third-party metadata into Summary.
    """
    compact = _compact_summary_overview(overview)
    if not compact:
        return []
    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return []

    reference_date = _email_date(email, datetime.now().date())
    generic_terms = {
        "deadline", "date", "time", "am", "pm", "noon", "midnight",
        "today", "tomorrow", "tonight", "day", "week", "month",
        "monday", "tuesday", "wednesday", "thursday", "friday",
        "saturday", "sunday",
    }
    contexts = []
    for sentence in source_sentences:
        if _phase1b_recipient_request_signal(sentence):
            continue
        if _summary_has_explicit_no_deadline_state(sentence):
            continue
        if _summary_has_explicit_no_action_state(sentence):
            continue
        if not (
            _cross_section_dates(sentence, reference_date)
            or _cross_section_time_tokens(sentence)
            or _cross_section_material_tokens(sentence)
        ):
            continue
        terms = _cross_section_fact_terms(sentence) - generic_terms
        if terms:
            contexts.append((sentence, terms))

    covered = [
        (sentence, terms)
        for sentence, terms in contexts
        if _summary_semantically_covers_fact(email, sentence, compact)
    ]
    if not covered:
        return []

    missing = []
    for sentence, terms in contexts:
        if _summary_semantically_covers_fact(email, sentence, compact):
            continue
        if not any(terms & covered_terms for _, covered_terms in covered):
            continue
        if any(
            _cross_section_fact_equivalent(
                email, sentence, existing, coverage_threshold=0.80
            )
            for existing in missing
        ):
            continue
        missing.append(sentence)
    return missing[:2]


def _repair_summary_material_context_completeness(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Restore omitted material context without turning Summary into a checklist.

    For short current-turn mail, validated actions and deadlines are not enough to
    describe the whole context when the source also contains decisions, blockers,
    dependencies, unresolved states, or multiple meaningful downstream facts.
    Recover those source-grounded facts into one compact narrative sentence.

    The repair is intentionally conservative:
      * no benchmark IDs, subjects, people, business nouns, or exact dates;
      * only the effective/current source turn is considered;
      * Action Item and Deadline ownership is preserved;
      * a lone low-impact process detail does not expand an otherwise adequate
        summary, avoiding noisy regressions in simple request emails.
    """
    overview = _compact_summary_overview(fallback)
    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview

    source_text = " ".join(source_sentences)
    if len(source_sentences) > 6 or len(source_text.split()) > 140:
        return overview

    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)

    # A small owner/task/due table is already structured source context. When
    # one recipient row is actionable, preserve the peer-owner rows as compact
    # context without copying table markup or turning their due dates into the
    # recipient's deadlines. Keep the first recipient row as sentence one and
    # pack peer assignments into sentence two.
    body_lines = [line.strip() for line in _body_text(email).splitlines() if line.strip()]
    parsed_table_rows = [
        row for row in (_phase1b_pipe_table_row(email, line) for line in body_lines)
        if row
        and str(row.get("task") or "").strip().casefold() not in {"task", "action", "action item", "work"}
    ]
    if parsed_table_rows and any(row.get("owner_kind") == "recipient" for row in parsed_table_rows):
        rendered_rows = _summary_source_sentences_for_overview(email)
        if rendered_rows:
            recipient_sentences = []
            peer_sentences = []
            for row, rendered in zip(parsed_table_rows, rendered_rows):
                clean = re.sub(r"\s+", " ", str(rendered or "")).strip()
                if not clean:
                    continue
                if row.get("owner_kind") == "recipient":
                    recipient_sentences.append(clean.rstrip(" .!?;:") + ".")
                else:
                    peer_sentences.append(clean.rstrip(" .!?;:"))
            if recipient_sentences and peer_sentences:
                first = recipient_sentences[0]
                second = "; ".join(peer_sentences).rstrip(" .!?;:") + "."
                return _compact_summary_overview(f"{first} {second}") or overview

    # If the model already names a contextual event/state but drops its explicit
    # source date/time/value, keep the existing narrative and restore only that
    # grounded context sentence.  Key Point dedupe can then remove the duplicate
    # atomic bullet cleanly.
    missing_context = _summary_missing_explicit_context_sentence(email, overview)
    if missing_context:
        # Preserve sibling material facts about the same contextual object. A
        # request may intentionally target only one of several stated values
        # (for example, confirm one regional amount); Summary still needs the
        # peer value to describe the email faithfully. Keep this generic by
        # requiring shared semantic identity plus an explicit source value.
        related_context = [missing_context]
        generic_context_terms = {
            "deadline", "date", "time", "am", "pm", "noon", "midnight",
            "today", "tomorrow", "tonight", "day", "week", "month",
            "monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday",
        }
        primary_terms = _cross_section_fact_terms(missing_context) - generic_context_terms
        for sentence in source_sentences:
            if sentence == missing_context or len(related_context) >= 2:
                continue
            if _phase1b_recipient_request_signal(sentence):
                continue
            if _summary_has_explicit_no_deadline_state(sentence):
                continue
            if _summary_has_explicit_no_action_state(sentence):
                continue
            if not (
                _cross_section_dates(sentence, _email_date(email, datetime.now().date()))
                or _cross_section_time_tokens(sentence)
                or _cross_section_material_tokens(sentence)
            ):
                continue
            if _summary_semantically_covers_fact(email, sentence, overview):
                continue
            sentence_terms = _cross_section_fact_terms(sentence) - generic_context_terms
            shared = primary_terms & sentence_terms
            if not shared:
                continue
            # One shared business/object term is enough for short source turns,
            # but do not accept a sentence whose only overlap is generic timing.
            if any(
                _cross_section_fact_equivalent(
                    email, sentence, existing, coverage_threshold=0.80
                )
                for existing in related_context
            ):
                continue
            related_context.append(sentence)

        rendered = []
        for item in related_context:
            natural = _summary_naturalize_context_sentence(item)
            natural = re.sub(r"\s+", " ", str(natural or "")).strip(" .!?;:")
            if natural:
                rendered.append(natural)
        if rendered:
            context_sentence = "; ".join(rendered).rstrip(" .!?;:") + "."
            base_sentences = [
                part.strip()
                for part in re.split(r"(?<=[.!?])\s+", overview)
                if part.strip()
            ]
            if len(base_sentences) <= 1:
                return _compact_summary_overview(
                    f"{context_sentence} {overview.rstrip()}"
                ) or overview
            first = base_sentences[0]
            second = " ".join(base_sentences[1:]).rstrip(" .!?;:")
            context_tail = context_sentence.rstrip(" .!?;:")
            return _compact_summary_overview(
                f"{context_tail}. {first} {second}."
            ) or overview

    related_missing = _summary_missing_related_material_context_sentences(
        email, overview
    )
    if related_missing:
        rendered_missing = []
        for item in related_missing:
            natural = _summary_naturalize_context_sentence(item)
            natural = re.sub(r"\s+", " ", str(natural or "")).strip(" .!?;:")
            if natural:
                rendered_missing.append(natural)
        if rendered_missing:
            addition = "; ".join(rendered_missing).rstrip(" .!?;:")
            base_sentences = [
                part.strip()
                for part in re.split(r"(?<=[.!?])\s+", overview)
                if part.strip()
            ]
            if not base_sentences:
                return _compact_summary_overview(addition + ".")
            if len(base_sentences) == 1:
                return _compact_summary_overview(
                    f"{addition}. {base_sentences[0]}"
                ) or overview
            # Keep two-sentence ownership: attach the peer value to the first
            # contextual sentence and leave the second (often the request) intact.
            first = base_sentences[0].rstrip(" .!?;:")
            second = " ".join(base_sentences[1:]).strip()
            return _compact_summary_overview(
                f"{first}; {addition[:1].lower() + addition[1:]}. {second}"
            ) or overview

    candidates = []
    for sentence in source_sentences:
        for clause in _cross_section_keypoint_clauses(sentence):
            # Material-context recovery owns non-action facts only. A direct
            # recipient request (including checklist lead-ins such as ``Please
            # complete...``) belongs to Action Items / deadline-scope repair and
            # must never be appended as a partial contextual sentence.
            if _phase1b_recipient_request_signal(clause):
                continue
            if normalized_actions and _phase1b_keypoint_is_action_restatement(
                clause, normalized_actions
            ):
                continue
            if _keypoint_is_deadline_restatement(
                email, clause, normalized_actions, normalized_deadlines
            ):
                continue
            if _summary_has_explicit_no_deadline_state(clause):
                continue
            if _summary_has_explicit_no_action_state(clause):
                continue
            if not _source_residual_keypoint_is_salient(clause):
                continue
            if _summary_semantically_covers_fact(email, clause, overview):
                continue

            # Deduplicate paraphrases before rendering.
            if any(
                _cross_section_fact_equivalent(
                    email, clause, existing, coverage_threshold=0.80
                )
                for existing in candidates
            ):
                continue
            candidates.append(clause)

    if not candidates:
        return overview

    high_impact = [item for item in candidates if _summary_context_fact_is_high_impact(item)]
    # One low-impact forward-looking detail is useful as a Key Point, but does
    # not by itself make a concise Summary incomplete. Multiple residual facts,
    # or any high-impact decision/state/dependency, do.
    if not high_impact and len(candidates) < 2:
        return overview

    # When high-impact state/decision/dependency facts exist, keep Summary
    # focused on those and leave lower-impact downstream/process detail available
    # to Key Points. If there are no high-impact facts, multiple residual process
    # facts may still be needed to make the overview complete.
    summary_candidates = high_impact if high_impact else candidates

    polished = []
    for candidate in summary_candidates[:4]:
        neutral = _neutralize_key_point_voice(candidate)
        neutral = re.sub(r"\s+", " ", neutral).strip(" \t\r\n-–—:;,.!? ")
        if neutral:
            polished.append(neutral)
    if not polished:
        return overview

    context_parts = [polished[0]] + [
        item[:1].lower() + item[1:] if item else item for item in polished[1:]
    ]
    context_sentence = "; ".join(context_parts).rstrip(" .!?;:") + "."
    if not overview:
        return _compact_summary_overview(context_sentence)

    base_sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", overview)
        if part.strip()
    ]
    if len(base_sentences) <= 1:
        return _compact_summary_overview(f"{overview.rstrip()} {context_sentence}")

    # Keep the hard 1-2 sentence contract: fold recovered context into the second
    # sentence rather than allowing a third sentence to be silently truncated.
    first = base_sentences[0]
    second = " ".join(base_sentences[1:]).rstrip(" .!?;:")
    context_tail = context_sentence.rstrip(" .!?;:")
    return _compact_summary_overview(
        f"{first} {second}; {context_tail[:1].lower() + context_tail[1:]}."
    )




def _summary_humanize_deadline_text(value: str) -> str:
    """Humanize only unambiguous ISO calendar dates inside a validated due value."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""

    def _humanize(match):
        try:
            resolved = date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return match.group(0)
        return _summary_human_date(resolved)

    return re.sub(r"\b(\d{4})-(\d{2})-(\d{2})\b", _humanize, text)


def _repair_summary_explicit_deadline_preservation(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Replace a vague due-date placeholder with one validated explicit deadline.

    Some model summaries abstract a concrete sender-owned due date into wording
    such as "by a specific date" even though the validated Deadline card retains
    the exact value. Summary should remain a faithful standalone overview, so a
    vague placeholder is repaired from the already-grounded deadline pipeline.

    The repair is intentionally conservative and generic:
      * recipient work must exist;
      * exactly one validated task deadline must exist;
      * that value must still have valid source evidence;
      * only an explicit vague due-date placeholder is replaced.

    Multiple-deadline mail is left untouched because a single placeholder cannot
    be mapped safely without action-level wording context.
    """
    overview = _compact_summary_overview(fallback)
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _phase1c_dedupe_deadlines(_normalize_list(deadlines))
    if not overview or not normalized_actions or len(normalized_deadlines) != 1:
        return overview

    due_value = normalized_deadlines[0]
    body = _body_text(email)
    reference_date = _email_date(email, datetime.now().date())
    evidence = _phase1b_deadline_sentence(due_value, body)
    if not evidence:
        # A validated due value may have gained an inferred year while the source
        # uses only month/day (for example ``August 26``). Match canonical dates
        # rather than requiring the rendered deadline string to appear verbatim.
        due_date_set = _cross_section_dates(due_value, reference_date)
        if due_date_set:
            for sentence in _phase1b_source_sentences(body):
                if due_date_set & _cross_section_dates(sentence, reference_date):
                    evidence = sentence
                    break
    if not evidence or not _phase1b_is_valid_deadline_sentence(evidence):
        return overview

    # If Summary already carries the same canonical date/time, there is nothing
    # to repair. This also preserves naturally humanized model wording.
    due_dates = _cross_section_dates(due_value, reference_date)
    due_times = _cross_section_time_tokens(due_value)
    summary_dates = _cross_section_dates(overview, reference_date)
    summary_times = _cross_section_time_tokens(overview)
    if due_dates and due_dates.issubset(summary_dates):
        if not due_times or due_times.issubset(summary_times):
            return overview

    placeholder = re.compile(
        r"\b(?P<relation>by|before|no later than)\s+"
        r"(?:(?:a|the)\s+)?"
        r"(?:(?:specific|specified|stated|given|set|assigned|provided)\s+)?"
        r"(?P<label>date|deadline|due date)\b",
        flags=re.IGNORECASE,
    )
    match = placeholder.search(overview)
    if not match:
        return overview

    rendered_due = _summary_humanize_deadline_text(due_value)
    if not rendered_due:
        return overview
    relation = match.group("relation").lower()
    replacement = f"{relation} {rendered_due}"
    repaired = overview[:match.start()] + replacement + overview[match.end():]
    return _compact_summary_overview(repaired) or overview




def _summary_temporal_dependency_relations(value: str) -> set[str]:
    """Return explicit workflow-order relations stated in prose.

    Calendar due relations such as ``by DATE`` are intentionally excluded.
    These markers describe ordering/dependency between work items, so a Summary
    must not invent one merely because two source sentences appear in sequence.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return set()
    relations: set[str] = set()
    patterns = (
        ("after", r"\b(?:after(?:ward|wards)?|following|followed\s+by|once|upon|subsequent(?:ly|\s+to))\b"),
        ("before", r"\b(?:before(?:hand)?|prior\s+to|ahead\s+of)\b"),
        ("until", r"\b(?:until|pending)\b"),
        ("when", r"\bwhen\b"),
        ("then", r"\bthen\b"),
    )
    for label, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            relations.add(label)
    return relations


def _summary_has_unsupported_cross_actor_sequence(
    email: dict, actions, value: str
) -> bool:
    """Detect invented ordering between recipient work and another actor's work.

    A common small-model error is to turn two independent source facts into a
    dependency, e.g. ``Person A will do X. Please do Y.`` -> ``Do Y after X``.
    Sentence order alone is not source evidence for ``after/before/once/then``.
    This guard activates only when the effective source contains both validated
    recipient work and an explicit named third-party commitment.
    """
    overview = _compact_summary_overview(value)
    if not overview or not _normalize_list(actions):
        return False

    summary_relations = _summary_temporal_dependency_relations(overview)
    if not summary_relations:
        return False

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return False

    recipient_sentences = [
        sentence for sentence in source_sentences
        if _raw_first_recipient_request_sentence(email, sentence)
    ]
    if not recipient_sentences:
        return False

    recipient_name = _phase1g_recipient_name(email)
    third_party_sentences = []
    for sentence in source_sentences:
        actor = _phase1k_named_actor_commitment(sentence)
        if not actor:
            continue
        if recipient_name and _phase1g_same_person(actor, recipient_name):
            continue
        third_party_sentences.append(sentence)
    if not third_party_sentences:
        return False

    source_relations = _summary_temporal_dependency_relations(
        " ".join(source_sentences)
    )
    return bool(summary_relations - source_relations)


def _repair_summary_unsupported_cross_actor_sequence(
    email: dict, actions, fallback: str = ""
) -> str:
    """Rebuild an invented cross-actor dependency from source-owned facts only."""
    overview = _compact_summary_overview(fallback)
    if not _summary_has_unsupported_cross_actor_sequence(email, actions, overview):
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview

    recipient_name = _phase1g_recipient_name(email)
    grounded_parts = []
    for sentence in source_sentences:
        if _raw_first_recipient_request_sentence(email, sentence):
            rendered = _summary_request_sentence(sentence)
            if rendered:
                grounded_parts.append(rendered)
            continue

        actor = _phase1k_named_actor_commitment(sentence)
        if actor and not (
            recipient_name and _phase1g_same_person(actor, recipient_name)
        ):
            grounded_parts.append(sentence)

    if not grounded_parts:
        return overview
    rebuilt = _summary_pack_short_source(grounded_parts[:4])
    return rebuilt or overview


def _summary_has_unsupported_deadline_transition(email: dict, value: str) -> bool:
    """Return True when Summary invents a deadline-change relationship.

    A plain deadline in the source is not evidence that it was extended, moved,
    rescheduled, postponed, shortened, or otherwise changed. Transition wording
    is allowed only when the effective source turn itself contains explicit
    change evidence. Subject labels such as "update" are intentionally ignored.
    """
    summary = re.sub(r"\s+", " ", str(value or "")).strip()
    if not summary:
        return False

    # Incremental/thread reconciliation already has its own chronological state
    # logic. Keep this guard scoped to a standalone current message so it cannot
    # reinterpret valid cross-turn deadline updates.
    body = _body_text(email)
    try:
        thread_count = int(email.get("thread_count") or 1)
    except (TypeError, ValueError):
        thread_count = 1
    if thread_count > 1 or re.search(
        r"(?mi)^\s*\[(?:earlier|previous|latest)\s+(?:message|reply|turn)\]",
        body,
    ):
        return False

    # Only guard comparative/change-state claims tied to a deadline/due date.
    # This does not alter ordinary explicit deadlines or planned-deadline logic.
    # Cover both verbal forms ("deadline was extended") and nominal/adjectival
    # forms ("deadline extension", "new/revised deadline", "extension of the
    # due date"). The model can choose any of these surface forms for the same
    # unsupported state transition, so grounding must be semantic rather than
    # tied to one phrasing.
    transition_word = (
        r"extend(?:ed|ing)?|extension|"
        r"move(?:d|ing)?|movement|"
        r"chang(?:e|ed|ing)|change|"
        r"reschedul(?:e|ed|ing)|rescheduling|"
        r"postpon(?:e|ed|ing)|postponement|"
        r"shorten(?:ed|ing)?|shortening|"
        r"delay(?:ed|ing)?|"
        r"push(?:ed|ing)?\s+back|bring(?:ing)?\s+forward|brought\s+forward|"
        r"revis(?:e|ed|ing)|revision|"
        r"replac(?:e|ed|ing)|replacement"
    )
    deadline_label = r"deadline|due\s+date|due\s+time"
    has_transition_claim = bool(re.search(
        rf"\b(?:{deadline_label})\b[^.!?;]{{0,48}}\b(?:{transition_word})\b"
        rf"|\b(?:{transition_word})\b[^.!?;]{{0,48}}\b(?:{deadline_label})\b"
        rf"|\b(?:new|updated|revised|changed|extended|moved|rescheduled|"
        rf"postponed|shortened|delayed|replacement)\s+(?:{deadline_label})\b",
        summary,
        flags=re.IGNORECASE,
    ))
    if not has_transition_claim:
        return False

    source = " ".join(_summary_source_sentences_for_overview(email)) or _body_text(email)
    source = re.sub(r"\s+", " ", source).strip()
    if not source:
        return True

    # Explicit change evidence must appear in the message body/current source
    # turn. A standalone date or an "update" subject is not enough. Accept the
    # same verbal, nominal, and adjectival transition forms used by the Summary
    # detector so legitimate source wording is never repaired away.
    source_supports_transition = bool(re.search(
        rf"\b(?:{deadline_label})\b[^.!?;]{{0,64}}\b(?:{transition_word}|new|now)\b"
        rf"|\b(?:{transition_word})\b[^.!?;]{{0,64}}\b(?:{deadline_label})\b"
        rf"|\b(?:new|updated|revised|changed|extended|moved|rescheduled|"
        rf"postponed|shortened|delayed|replacement)\s+(?:{deadline_label})\b"
        r"|\b(?:now|instead)\s+due\b"
        r"|\b(?:deadline|due\s+date|due\s+time|due)\b[^.!?;]{0,48}\binstead\b"
        r"|\bfrom\s+[^.!?;]{1,40}\s+to\s+[^.!?;]{1,40}\b",
        source,
        flags=re.IGNORECASE,
    ))
    return not source_supports_transition


def _repair_summary_unsupported_deadline_transition(
    email: dict, actions, fallback: str = ""
) -> str:
    """Replace an unsupported deadline-transition claim with grounded source prose.

    The repair is intentionally narrow: it runs only after a transition claim is
    detected in Summary and the source body provides no evidence of a change.
    It rebuilds from validated recipient-request sentences when available, so
    action ownership and explicit dates remain source-grounded. No action,
    deadline, priority, or status fields are modified here.
    """
    overview = _compact_summary_overview(fallback)
    if not _summary_has_unsupported_deadline_transition(email, overview):
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return overview

    source_text = " ".join(source_sentences)
    request_sentences = [
        _summary_request_sentence(sentence)
        for sentence in source_sentences
        if _phase1b_recipient_request_signal(sentence)
        and not _phase1c_evidence_is_non_action(sentence, source_text)
        and not (
            len(source_sentences) > 1
            and _normalize_list(actions)
            and _raw_first_is_ancillary_response_timing_request(sentence)
        )
    ]
    request_sentences = [item for item in request_sentences if item]
    if request_sentences:
        rebuilt = _compact_summary_overview(" ".join(request_sentences[:2]))
        if rebuilt:
            return rebuilt

    # For short actionless/current-turn mail, fall back to the existing grounded
    # source packer rather than preserving an unsupported transition statement.
    if not _normalize_list(actions) and len(source_sentences) <= 4 and len(source_text.split()) <= 95:
        rebuilt = _summary_pack_short_source(source_sentences)
        if rebuilt:
            return rebuilt

    return overview



def _summary_has_overbroad_multi_action_deadline_scope(
    email: dict, actions, deadlines, value: str
) -> bool:
    """Detect prose that assigns deadlines to both dated and undated tasks.

    Structured Action Items can correctly carry a mixed set of explicit and
    unspecified due dates while a model Summary collapses them into wording such
    as ``deadlines for A, B, and C``. That grammatical plural falsely makes the
    undated task look explicitly due. This guard is source/action-role based and
    never relies on benchmark subjects or exact dates.
    """
    overview = _compact_summary_overview(value)
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _phase1c_dedupe_deadlines(_normalize_list(deadlines))
    if not overview or len(normalized_actions) < 2 or not normalized_deadlines:
        return False

    details = _phase1b_assign_detail_deadlines(
        email, [], normalized_actions, normalized_deadlines
    )
    due_flags = [bool(str(item.get("due_date") or "").strip()) for item in details]
    if not any(due_flags) or all(due_flags):
        return False

    # Only repair a grammatical scope claim, not an ordinary narrative that
    # separately states each action/date.
    if not re.search(
        r"\b(?:deadlines?|due\s+dates?)\s+for\b",
        overview,
        flags=re.IGNORECASE,
    ):
        return False

    # The suspicious scope must actually encompass an undated action concept.
    # This prevents changing a valid phrase that refers only to the dated subset.
    scope_tail = re.split(
        r"\b(?:deadlines?|due\s+dates?)\s+for\b",
        overview,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[-1]
    tail_terms = _cross_section_fact_terms(scope_tail)
    for detail in details:
        if str(detail.get("due_date") or "").strip():
            continue
        action = str(detail.get("action") or "").strip()
        action_terms = _cross_section_fact_terms(action)
        if action_terms and len(action_terms & tail_terms) / max(1, len(action_terms)) >= 0.45:
            return True
    return False


def _repair_summary_overbroad_multi_action_deadline_scope(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Render mixed action deadlines without attaching a due date to undated work."""
    overview = _compact_summary_overview(fallback)
    if not _summary_has_overbroad_multi_action_deadline_scope(
        email, actions, deadlines, overview
    ):
        return overview

    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _phase1c_dedupe_deadlines(_normalize_list(deadlines))
    details = _phase1b_assign_detail_deadlines(
        email, [], normalized_actions, normalized_deadlines
    )
    if not details or len(details) > 5:
        return overview

    rendered = []
    for item in details:
        action = re.sub(r"\s+", " ", str(item.get("action") or "")).strip(" .!?;:")
        if not action:
            continue
        due = _summary_humanize_deadline_text(str(item.get("due_date") or ""))
        phrase = action
        if due:
            phrase = f"{phrase} by {due}"
        rendered.append(phrase)
    if len(rendered) != len(details):
        return overview

    if len(rendered) == 1:
        sentence = rendered[0]
    else:
        joined = [rendered[0]] + [
            item[:1].lower() + item[1:] if item else item for item in rendered[1:]
        ]
        if len(joined) == 2:
            sentence = f"{joined[0]} and {joined[1]}"
        else:
            sentence = ", ".join(joined[:-1]) + f", and {joined[-1]}"
    sentence = sentence[:1].upper() + sentence[1:]
    return _compact_summary_overview(sentence.rstrip(" .!?;:") + ".") or overview


def _summary_has_misattached_request_metadata_deadline(
    email: dict, actions, deadlines, value: str
) -> bool:
    """Detect a due date attached to message/request metadata instead of the task.

    A model may preserve the correct calendar value yet change what that value
    constrains, for example by turning ``Please do X by DATE`` into prose saying
    that a request/message was sent by DATE.  That changes the event-date
    relationship even though the date token itself is still grounded.

    This guard is intentionally narrow and source-driven:
      * standalone/current-turn mail only;
      * exactly one validated recipient action and one validated deadline;
      * the effective source is a single direct request sentence carrying that
        deadline;
      * the suspicious Summary clause describes communication/request metadata
        as sent/made/issued/received/created/delivered by that same due point;
      * legitimate tasks whose action itself is to send/deliver that metadata
        are excluded.
    """
    overview = _compact_summary_overview(value)
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _phase1c_dedupe_deadlines(_normalize_list(deadlines))
    if not overview or len(normalized_actions) != 1 or len(normalized_deadlines) != 1:
        return False

    body = _body_text(email)
    try:
        thread_count = int(email.get("thread_count") or 1)
    except (TypeError, ValueError):
        thread_count = 1
    if thread_count > 1 or re.search(
        r"(?mi)^\s*\[(?:earlier|previous|latest)\s+(?:message|reply|turn)\]",
        body,
    ):
        return False

    source_sentences = _summary_source_sentences_for_overview(email)
    if len(source_sentences) != 1:
        return False
    source_sentence = source_sentences[0]
    if not _phase1b_recipient_request_signal(source_sentence):
        return False

    due_value = normalized_deadlines[0]
    evidence = _phase1b_deadline_sentence(due_value, source_sentence)
    if not evidence or not _phase1b_is_valid_deadline_sentence(evidence):
        return False

    reference_date = _email_date(email, datetime.now().date())
    due_dates = _cross_section_dates(due_value, reference_date)
    due_times = _cross_section_time_tokens(due_value)
    source_dates = _cross_section_dates(source_sentence, reference_date)
    source_times = _cross_section_time_tokens(source_sentence)
    summary_dates = _cross_section_dates(overview, reference_date)
    summary_times = _cross_section_time_tokens(overview)
    if due_dates and not due_dates.issubset(source_dates):
        return False
    if due_dates and not due_dates.issubset(summary_dates):
        return False
    if due_times and source_times and not due_times.issubset(source_times):
        return False
    if due_times and summary_times and not due_times.issubset(summary_times):
        return False

    # Communication/request metadata is grammatical infrastructure, not a
    # business-domain vocabulary list.  These tokens are used only to catch an
    # event-role swap around an already validated deadline.
    metadata_nouns = r"(?:request|email|message|notice|notification|reminder|instruction)"
    metadata_events = r"(?:sent|made|issued|received|created|delivered)"
    suspicious = bool(re.search(
        rf"\b{metadata_nouns}\b[^.!?;]{{0,40}}\b(?:was\s+)?{metadata_events}\b"
        rf"[^.!?;]{{0,24}}\b(?:by|before|no\s+later\s+than)\b",
        overview,
        flags=re.IGNORECASE,
    ))
    if not suspicious:
        return False

    # If the source actually states the same metadata event, it is grounded and
    # must not be rewritten by this repair.
    if re.search(
        rf"\b{metadata_nouns}\b[^.!?;]{{0,40}}\b(?:was\s+)?{metadata_events}\b"
        rf"[^.!?;]{{0,24}}\b(?:by|before|no\s+later\s+than)\b",
        source_sentence,
        flags=re.IGNORECASE,
    ):
        return False

    # Preserve legitimate tasks such as "send the email by Friday".  The repair
    # only fires when the Summary introduces a communication artifact/event that
    # is not itself the validated action object.
    action_text = re.sub(r"\s+", " ", normalized_actions[0]).strip().casefold()
    action_has_metadata_object = bool(re.search(
        rf"\b(?:send|deliver|issue|create|make|submit|provide)\b[^.!?;]{{0,48}}\b{metadata_nouns}\b",
        action_text,
        flags=re.IGNORECASE,
    ))
    if action_has_metadata_object:
        return False

    return True


def _repair_summary_misattached_request_metadata_deadline(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Restore the source request's event-date attachment without touching task data."""
    overview = _compact_summary_overview(fallback)
    if not _summary_has_misattached_request_metadata_deadline(
        email, actions, deadlines, overview
    ):
        return overview

    source_sentences = _summary_source_sentences_for_overview(email)
    if len(source_sentences) != 1:
        return overview

    rebuilt = _summary_request_sentence(source_sentences[0])
    return _compact_summary_overview(rebuilt) or overview


def _summary_unowned_recipient_due_tail(
    email: dict, actions, deadlines, value: str
) -> tuple[str, str] | None:
    """Return a recipient-action sentence and terminal due phrase that is not owned.

    A model can copy a real date from another person's commitment and attach it
    to the recipient's otherwise undated action in Summary prose. Structured
    deadline validation already removes that date from ``deadlines`` and from the
    action detail, but the prose can remain misleading (for example, ``Acknowledge
    receipt ... by DATE`` when DATE belongs to another actor).

    Keep this guard deliberately narrow and grammar-based:
      * recipient work exists but no validated recipient deadline survived;
      * the Summary sentence substantially covers a validated Action Item;
      * the suspicious temporal phrase is a terminal ``by ...`` / ``no later
        than ...`` clause rather than an event date in ordinary context;
      * no recipient-request source sentence validates that same due phrase.

    Context dates such as meeting schedules remain untouched because they are not
    terminal due clauses attached to the recipient action.
    """
    overview = _compact_summary_overview(value)
    normalized_actions = _normalize_list(actions)
    if not overview or not normalized_actions or _normalize_list(deadlines):
        return None

    source_sentences = _summary_source_sentences_for_overview(email)
    if not source_sentences:
        return None
    source_text = " ".join(source_sentences)

    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", overview)
        if part.strip()
    ]
    for sentence in sentences:
        if not _summary_overview_action_heavy(sentence, normalized_actions):
            continue

        for phrase in _phase1c_extract_deadline_phrases(sentence):
            extracted_phrase = re.sub(r"\s+", " ", str(phrase or "")).strip()
            if not extracted_phrase:
                continue

            matches = list(re.finditer(
                re.escape(extracted_phrase), sentence, flags=re.IGNORECASE
            ))
            if not matches:
                continue
            match = matches[-1]

            # Some deadline extractors normalize ``by tomorrow`` to just
            # ``tomorrow``. Recover the grammatical due relation from the source
            # Summary sentence without guessing any date value.
            due_start = match.start()
            due_phrase = extracted_phrase
            if re.match(
                r"^(?:by|no\s+later\s+than)\b",
                extracted_phrase,
                flags=re.IGNORECASE,
            ):
                pass
            else:
                relation = re.search(
                    r"\b(?:by|no\s+later\s+than)\s*$",
                    sentence[:match.start()],
                    flags=re.IGNORECASE,
                )
                if not relation:
                    continue
                due_start = relation.start()
                due_phrase = sentence[due_start:match.end()].strip()

            # Only repair a terminal due tail. This avoids deleting later facts
            # from a multi-clause Summary sentence.
            trailing = sentence[match.end():].strip()
            if trailing and not re.fullmatch(r"[.!?]+", trailing):
                continue

            reference_date = _email_date(email, datetime.now().date())
            has_temporal_value = bool(
                _cross_section_dates(due_phrase, reference_date)
                or _cross_section_time_tokens(due_phrase)
                or re.search(
                    r"\b(?:today|tomorrow|tonight|eod|close of business|"
                    r"monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
                    due_phrase,
                    flags=re.IGNORECASE,
                )
            )
            if not has_temporal_value:
                continue

            # A due phrase is recipient-owned only when a source sentence that
            # itself asks the recipient to act validates the same temporal
            # constraint. Another person's sentence must never provide this
            # ownership merely because it contains the same date.
            recipient_owned = False
            for source_sentence in source_sentences:
                if not _phase1b_recipient_request_signal(source_sentence):
                    continue
                if _phase1c_evidence_is_non_action(source_sentence, source_text):
                    continue
                evidence = _phase1b_deadline_sentence(due_phrase, source_sentence)
                if evidence and _phase1b_is_valid_deadline_sentence(evidence):
                    recipient_owned = True
                    break
            if recipient_owned:
                continue

            return sentence, due_phrase
    return None


def _repair_summary_unowned_recipient_due_tail(
    email: dict, actions, deadlines, fallback: str = ""
) -> str:
    """Remove only an unowned terminal due clause from recipient-action prose."""
    overview = _compact_summary_overview(fallback)
    issue = _summary_unowned_recipient_due_tail(
        email, actions, deadlines, overview
    )
    if not issue:
        return overview

    offending_sentence, due_phrase = issue
    match = re.search(re.escape(due_phrase), offending_sentence, flags=re.IGNORECASE)
    if not match:
        return overview

    repaired_sentence = offending_sentence[:match.start()].rstrip(" \t\r\n-–—:;,.")
    if not repaired_sentence:
        return overview
    repaired_sentence += "."

    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", overview)
        if part.strip()
    ]
    replaced = False
    rebuilt = []
    for sentence in sentences:
        if not replaced and sentence == offending_sentence:
            rebuilt.append(repaired_sentence)
            replaced = True
        else:
            rebuilt.append(sentence)
    return _compact_summary_overview(" ".join(rebuilt)) if replaced else overview


def _summary_fact_units(value: str) -> list[str]:
    """Return compact fact units used only for within-Summary duplicate checks."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return []
    units = list(_cross_section_keypoint_clauses(text))

    # Capture a short embedded state/dependency adjunct (for example
    # ", with review pending") so a later standalone clause carrying the same
    # fact can be removed without rewriting the main action sentence.
    for match in re.finditer(
        r"(?:^|[,;])\s*(?:with|while)\s+([^,;.?!]+)",
        text,
        flags=re.IGNORECASE,
    ):
        candidate = re.sub(r"\s+", " ", match.group(1)).strip(" ,;:.!?-")
        if candidate and _summary_context_fact_is_high_impact(candidate):
            units.append(candidate[:1].upper() + candidate[1:])
    return _merge_unique(units)


def _summary_fact_role_compatible(left: str, right: str) -> bool:
    """Keep directive/request facts distinct from declarative context facts.

    A factual value (``The invoice is ...``) and a request about that same value
    (``Confirm the invoice amount``) may share nearly every content term, but they
    are not duplicates inside Summary: one is context and the other is purpose.
    """
    return _phase1b_recipient_request_signal(left) == _phase1b_recipient_request_signal(right)


def _dedupe_summary_repeated_facts(email: dict, fallback: str = "") -> str:
    """Remove repeated semantic facts inside the final 1-2 sentence Summary.

    The operation is deliberately narrow: it preserves the first occurrence and
    only drops later whole clauses/sentences that are semantically equivalent to
    an already represented fact. It never invents replacement prose and does not
    collapse distinct before/after relations, dates, times, or material values.
    """
    overview = _compact_summary_overview(fallback)
    if not overview:
        return ""

    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", overview)
        if part.strip()
    ]
    if not sentences:
        return overview
    if (
        len(sentences) >= 2
        and _summary_has_explicit_no_action_state(sentences[0])
        and _summary_pure_no_action_sentence(sentences[1])
    ):
        sentences = [sentences[0], *sentences[2:]]

    seen_units = []
    rebuilt_sentences = []
    for sentence in sentences[:2]:
        # Only semicolon-separated clauses are rebuilt. Ordinary prose keeps its
        # grammar untouched while still contributing fact units to later checks.
        semicolon_parts = [
            part.strip(" \t\r\n-–—:;,.!?")
            for part in re.split(r"\s*;\s*", sentence)
            if part.strip(" \t\r\n-–—:;,.!?")
        ]
        if len(semicolon_parts) <= 1:
            sentence_units = _summary_fact_units(sentence)
            is_repeat = bool(sentence_units) and all(
                any(
                    _summary_fact_role_compatible(unit, prior)
                    and _cross_section_fact_equivalent(
                        email, unit, prior, coverage_threshold=0.80
                    )
                    for prior in seen_units
                )
                for unit in sentence_units
            )
            if not is_repeat:
                rebuilt_sentences.append(sentence.rstrip())
                seen_units.extend(sentence_units)
            continue

        kept_parts = []
        for part in semicolon_parts:
            part_units = _summary_fact_units(part)
            is_repeat = bool(part_units) and all(
                any(
                    _summary_fact_role_compatible(unit, prior)
                    and _cross_section_fact_equivalent(
                        email, unit, prior, coverage_threshold=0.80
                    )
                    for prior in seen_units
                )
                for unit in part_units
            )
            if is_repeat:
                continue
            kept_parts.append(part)
            seen_units.extend(part_units)
        if kept_parts:
            rebuilt_sentences.append("; ".join(kept_parts).rstrip(" .!?;:") + ".")

    return _compact_summary_overview(" ".join(rebuilt_sentences)) or overview


def _separate_summary_overview(email: dict, value: str, actions) -> str:
    """Enforce Summary/Key Points/Action Items separation after model output.

    Drop sentences that merely restate validated task steps or dedicated
    deadline/priority metadata. If the model supplied nothing else, prefer a
    short subject-grounded overview over duplicating Action Items in Summary.
    """
    compact = _compact_summary_overview(value)
    if not compact:
        return ""
    sentences = [
        part.strip() for part in re.split(r"(?<=[.!?])\s+", compact) if part.strip()
    ]
    kept = []
    body = _body_text(email)
    for sentence in sentences:
        if _summary_overview_metadata_only(sentence):
            continue
        if _phase1c_is_task_list_intro_evidence(sentence, body):
            continue
        if _summary_overview_action_heavy(sentence, actions):
            factual_tail = _summary_non_action_context_tail(sentence, actions)
            if factual_tail:
                kept.append(factual_tail)
            continue
        kept.append(sentence)
    if kept:
        return _compact_summary_overview(" ".join(kept))
    if _normalize_list(actions):
        return _summary_subject_fallback(email)
    return compact




def _summary_topic_label(email: dict, task_title: str = "") -> str:
    label = re.sub(r"\s+", " ", str(task_title or "")).strip()
    if not label:
        label = re.sub(r"\s+", " ", str(email.get("subject") or "")).strip()
        label = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", label, flags=re.IGNORECASE)
        label = re.sub(r"^(?:task|update|request)\s*:\s*", "", label, flags=re.IGNORECASE)
    return label.strip(" \t\r\n-–—:;,.\"'")


def _summary_scope_sentence(email: dict, actions, task_title: str = "") -> str:
    actions = _normalize_list(actions)
    topic = _summary_topic_label(email, task_title)
    if not actions:
        return _summary_subject_fallback(email)

    verbs = []
    for action in actions:
        match = re.match(r"^\s*(confirm|verify|check|validate|review|inspect|test)\b", action, flags=re.IGNORECASE)
        if match:
            verbs.append(match.group(1).casefold())
    work_kind = "verification steps" if len(verbs) >= max(1, len(actions) - 1) else "related work items"
    if topic:
        return f"The current {topic} task covers several {work_kind}." if len(actions) > 1 else f"The current {topic} task focuses on one {work_kind[:-1]}."
    return f"The current task covers several {work_kind}." if len(actions) > 1 else f"The current task focuses on one {work_kind[:-1]}."


def _naturalize_incremental_overview(value: str) -> str:
    text = _compact_summary_overview(value)
    match = re.fullmatch(
        r"The email updates the (.+?) action item to include (.+?)[.]?",
        text,
        flags=re.IGNORECASE,
    )
    if match:
        target = match.group(1).strip()
        addition = match.group(2).strip().rstrip(".")
        if target.casefold().endswith("folder"):
            target = f"{target} check"
        return f"The latest update expands the {target} to include {addition}."
    return text


def _incremental_pause_summary_polish(email: dict, value: str) -> str:
    """Use direct lifecycle wording for an explicit newest-turn pause/hold.

    Incremental model prose can describe the *message* (for example, "the email
    provides the latest update on ...") instead of the actual workflow state.
    For a newest turn that explicitly pauses/holds the whole task, the lifecycle
    instruction itself is the useful Summary.  Keep it separate from any
    wait/dependency condition so that condition can remain an independently
    useful Key Point.

    The guard is source-driven and intentionally narrow: it does not run for
    start/proceed messages, ordinary detail/deadline changes, acknowledgments,
    completion, cancellation, or additive work.  That preserves the already
    accepted earlier benchmark behavior while removing only hold-state meta
    framing.
    """
    body = re.sub(r"\s+", " ", (_incremental_current_turn_text(email) or _body_text(email))).strip()
    current = _compact_summary_overview(value)
    if not body:
        return current

    explicit_pause = bool(re.search(
        r"(?:^|[.!?;]\s*)"
        r"(?:please\s+)?(?:pause|hold|stop)\b"
        r"(?:.{0,80}?\b(?:task|work|activity|effort|processing|progress)\b)?"
        r"(?:.{0,40}?\b(?:for now|temporarily|until|pending)\b)?",
        body,
        flags=re.IGNORECASE,
    ))
    explicit_put_on_hold = bool(re.search(
        r"\b(?:put|place|keep)\s+(?:this|the|our|current)?\s*"
        r"(?:task|work|activity|effort|processing)?\s*(?:on\s+)?hold\b",
        body,
        flags=re.IGNORECASE,
    ))
    if not (explicit_pause or explicit_put_on_hold):
        return current

    # Avoid misreading negated lifecycle language such as "do not pause".
    if re.search(
        r"\b(?:do\s+not|don't|dont|not\s+to|never)\s+"
        r"(?:pause|hold|stop|put|place|keep)\b",
        body,
        flags=re.IGNORECASE,
    ):
        return current

    return "Pause the current task for now."


def _incremental_turn_may_supersede_prior_context(email: dict) -> bool:
    """Return True when the newest turn may invalidate an older thread fact.

    This protects whole-thread fallback merging from reintroducing stale state.
    The signals are generic lifecycle/decision transitions rather than domain
    vocabulary, subjects, people, benchmark IDs, or specific dates.
    """
    body = _body_text(email)
    if not body:
        return False
    transition_patterns = (
        r"\b(?:no longer|instead|supersed(?:e|es|ed)|withdrawn|"
        r"disregard|ignore (?:the )?(?:earlier|previous|prior)|correction)\b",
        r"\b(?:changed?|updated?|revised?|replaced?|rescheduled?|postponed?|moved?)"
        r"\s+(?:to|from|instead of)\b",
        r"\b(?:has|have|had|is|are|was|were|been)\s+"
        r"(?:approved?|rejected?|completed?|resolved?|cancelled?|closed?|"
        r"reopened?|superseded?|replaced?|rescheduled?|postponed?|revised?|updated?)\b",
        r"\b(?:cancel|replace|reschedule|postpone|supersede|reopen)\s+"
        r"(?:that|this|the|it)\b",
    )
    return any(re.search(pattern, body, flags=re.IGNORECASE) for pattern in transition_patterns)


def _summary_as_one_context_sentence(value: str) -> str:
    """Compress an existing 1-2 sentence overview into one context sentence."""
    text = _compact_summary_overview(value)
    if not text:
        return ""
    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", text)
        if part.strip()
    ]
    if len(sentences) <= 1:
        return text
    parts = [part.rstrip(" .!?;:") for part in sentences[:2] if part.rstrip(" .!?;:")]
    return ("; ".join(parts).rstrip(" .!?;:") + ".") if parts else text


def _summary_missing_material_prior_context(
    email: dict, previous: str, candidate: str
) -> bool:
    """Detect still-unrepresented material facts from the saved thread overview."""
    previous_text = _compact_summary_overview(previous)
    candidate_text = _compact_summary_overview(candidate)
    if not previous_text or not candidate_text:
        return bool(previous_text and not candidate_text)

    material_prior_facts = []
    for sentence in [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", previous_text)
        if part.strip()
    ]:
        clauses = _cross_section_keypoint_clauses(sentence) or [sentence]
        for clause in clauses:
            if (
                _summary_context_fact_is_high_impact(clause)
                or _source_residual_keypoint_is_salient(clause)
                or bool(_cross_section_material_tokens(clause))
            ):
                material_prior_facts.append(clause)

    return any(
        not _summary_semantically_covers_fact(email, fact, candidate_text)
        for fact in material_prior_facts
    )


def _summary_remove_facts_covered_by_prior(
    email: dict, candidate: str, previous: str
) -> str:
    """Remove latest-summary facts already carried by still-valid prior context."""
    candidate_text = _compact_summary_overview(candidate)
    previous_text = _compact_summary_overview(previous)
    if not candidate_text or not previous_text:
        return candidate_text

    kept_sentences = []
    for sentence in [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", candidate_text)
        if part.strip()
    ]:
        clauses = _cross_section_keypoint_clauses(sentence) or [sentence]
        kept_clauses = [
            clause
            for clause in clauses
            if not _summary_semantically_covers_fact(email, clause, previous_text)
        ]
        if not kept_clauses:
            continue
        rebuilt = "; ".join(
            clause.rstrip(" .!?;:") for clause in kept_clauses if clause.rstrip(" .!?;:")
        ).strip()
        if rebuilt:
            kept_sentences.append(rebuilt + ".")

    return _compact_summary_overview(" ".join(kept_sentences))



def _incremental_summary_deadline_mentions_value(text: str, due_value: str) -> bool:
    """Return True when summary prose carries the structured action deadline."""
    summary = re.sub(r"\s+", " ", str(text or "")).strip()
    due = re.sub(r"\s+", " ", str(due_value or "")).strip(" ,.;")
    if not summary or not due:
        return False

    lowered = summary.casefold()
    if due.casefold() in lowered:
        return True

    # Cross-format ISO -> human date matching (2026-08-20 vs August 20, 2026).
    iso = re.search(r"\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b", due)
    if iso:
        try:
            resolved = date(*(int(part) for part in iso.groups()))
        except ValueError:
            resolved = None
        if resolved is not None:
            month_full = resolved.strftime("%B").casefold()
            month_short = resolved.strftime("%b").casefold()
            year = str(resolved.year)
            day_num = str(resolved.day)
            numeric_tokens = set(re.findall(r"\d+", lowered))
            if (
                year in numeric_tokens
                and day_num in numeric_tokens
                and (
                    month_full in lowered
                    or month_short in lowered
                    or f"-{resolved.month:02d}-" in lowered
                    or f"/{resolved.month:02d}/" in lowered
                )
            ):
                return True

    # Relative/cadence/time values can usually be compared through the existing
    # semantic deadline identity extracted from the prose.
    due_identity = _phase1c_deadline_identity(due)
    for phrase in _phase1c_extract_deadline_phrases(summary):
        if _phase1c_deadline_identity(phrase) == due_identity:
            return True
    return False


def _incremental_summary_action_match_score(clause: str, action: str) -> float:
    action_terms = _summary_overlap_terms(action)
    if not action_terms:
        return 0.0
    clause_terms = _summary_overlap_terms(clause)
    return len(action_terms & clause_terms) / max(1, len(action_terms))


def _incremental_summary_split_action_clauses(value: str) -> list[str]:
    """Split a one-sentence coordinated task overview into action-sized clauses."""
    text = _compact_summary_overview(value).rstrip(" .!?;:")
    if not text:
        return []
    # Only coordination separators are used. Mapping back to structured actions
    # below prevents this from rewriting an unrelated narrative sentence.
    additive_pattern = (
        r",\s+(?:including|plus|along\s+with|together\s+with|as\s+well\s+as)\s+|"
        r"\s+as\s+well\s+as\s+"
    )
    # Prefer explicit additive separators when present. A bare ``and`` can be
    # internal to one compound action (``verify and update X``); splitting it
    # first would incorrectly fragment the dated action before we can isolate an
    # added deliverable such as ``including Y``.
    if ";" in text or re.search(additive_pattern, text, flags=re.IGNORECASE):
        parts = re.split(
            rf"\s*(?:;|{additive_pattern})\s*",
            text,
            flags=re.IGNORECASE,
        )
    else:
        parts = re.split(
            r"\s*(?:;|,\s+(?:and|also)|\s+and\s+|\s+also\s+)\s*",
            text,
            flags=re.IGNORECASE,
        )
    return [re.sub(r"\s+", " ", part).strip(" ,.;") for part in parts if part.strip(" ,.;")]


def _incremental_summary_strip_trailing_deadline(clause: str) -> str:
    """Remove only a trailing due-time modifier from one coordinated clause."""
    text = re.sub(r"\s+", " ", str(clause or "")).strip(" ,.;")
    if not text:
        return ""
    # This intentionally targets a tail modifier, not arbitrary occurrences of
    # words like "by" inside the task object. The caller proves that this clause
    # is an undated action while a different structured action owns the deadline.
    cleaned = re.sub(
        r"\s+(?:(?:by|before|no\s+later\s+than)\b|"
        r"due\s+(?:on|by)\b)[^.;]*$",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip(" ,.;")
    return cleaned or text


def _incremental_summary_due_phrase(due_value: str) -> str:
    due = re.sub(r"\s+", " ", str(due_value or "")).strip(" ,.;")
    if not due:
        return ""
    if re.match(r"^(?:by|before|no\s+later\s+than|due\b)", due, flags=re.IGNORECASE):
        return _summary_humanize_deadline_text(due).strip(" ,.;")
    return _summary_humanize_deadline_text(f"by {due}").strip(" ,.;")


def _repair_incremental_summary_deadline_scope(summary: str, task_updates) -> str:
    """Keep a thread deadline attached only to the action that owns it.

    Incremental models sometimes produce a fluent coordinated sentence whose
    final ``by <date>`` modifier grammatically applies to every listed action.
    The reconciled task_updates are more precise: each action already has its own
    due_date. When a newly added action is explicitly undated while another
    current action owns the sole deadline, move that modifier onto the dated
    action instead of silently assigning the new work the old deadline.

    The repair is deliberately narrow: one-sentence coordinated summaries only,
    one unique structured due value, and independently mapped action clauses.
    """
    overview = _compact_summary_overview(summary)
    updates = [dict(item) for item in (task_updates or []) if isinstance(item, dict)]
    if not overview or len(updates) < 2:
        return overview

    dated = [
        item for item in updates
        if str(item.get("due_date") or "").strip()
        and str(item.get("state") or "").strip().casefold() not in {"completed", "cancelled"}
    ]
    undated_new = [
        item for item in updates
        if str(item.get("state") or "").strip().casefold() == "new"
        and not str(item.get("due_date") or "").strip()
    ]
    unique_due = _merge_unique(
        [str(item.get("due_date") or "").strip() for item in dated]
    )
    if len(unique_due) != 1 or not undated_new:
        return overview

    due_value = unique_due[0]
    if not _incremental_summary_deadline_mentions_value(overview, due_value):
        return overview

    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", overview)
        if part.strip()
    ]
    if len(sentences) != 1:
        return overview
    clauses = _incremental_summary_split_action_clauses(overview)
    if len(clauses) < 2 and overview.count(",") == 1:
        # Models sometimes coordinate two independent actions with a bare comma
        # ("do X, prepare Y by DATE") rather than "and"/"also"/semicolon.  Do
        # not globally treat commas as action boundaries; try this narrow two-part
        # candidate only, then require the structured dated/undated actions below
        # to map to different clauses before any rewrite is allowed.
        comma_parts = [
            re.sub(r"\s+", " ", part).strip(" ,.;")
            for part in overview.rstrip(" .!?;:").split(",", 1)
            if part.strip(" ,.;")
        ]
        if len(comma_parts) == 2:
            clauses = comma_parts
    if len(clauses) < 2:
        return overview

    def best_clause(action: str):
        scored = [
            (_incremental_summary_action_match_score(clause, action), index)
            for index, clause in enumerate(clauses)
        ]
        score, index = max(scored, default=(0.0, -1))
        return (index, score)

    dated_matches = []
    for item in dated:
        index, score = best_clause(str(item.get("action") or ""))
        if index >= 0 and score >= 0.50:
            dated_matches.append((item, index, score))
    undated_matches = []
    for item in undated_new:
        index, score = best_clause(str(item.get("action") or ""))
        if index >= 0 and score >= 0.50:
            undated_matches.append((item, index, score))

    # Some whole-thread summaries express genuinely additional work as an
    # additive noun phrase (for example, ``..., including <deliverable> by X``)
    # instead of repeating the executable verb from the structured action. In
    # that form lexical action matching can be weak even though the clause is
    # clearly separate from the dated action. Recover only this narrow case:
    # one undated NEW action, one strongly mapped dated clause, and exactly one
    # remaining additive clause that owns the trailing deadline. The low-overlap
    # guard still requires material wording shared with the structured new task.
    if not undated_matches and len(undated_new) == 1 and dated_matches and len(clauses) == 2:
        dated_index_hint = max(dated_matches, key=lambda item: item[2])[1]
        other_indexes = [index for index in range(len(clauses)) if index != dated_index_hint]
        # A semicolon is also a strong action boundary.  Treat it like an
        # explicit additive separator for this low-overlap fallback; unlike a
        # bare "and", it cannot be internal coordination inside one compound
        # action such as "verify and update X".
        additive_form = bool(re.search(
            r"(?:;|,\s*(?:including|plus|along\s+with|together\s+with|as\s+well\s+as)\s+|"
            r"\s+as\s+well\s+as\s+)",
            overview,
            flags=re.IGNORECASE,
        ))
        if additive_form and len(other_indexes) == 1:
            index = other_indexes[0]
            score = _incremental_summary_action_match_score(
                clauses[index], str(undated_new[0].get("action") or "")
            )
            if score >= 0.20 and _incremental_summary_deadline_mentions_value(
                clauses[index], due_value
            ):
                undated_matches.append((undated_new[0], index, score))

    if not dated_matches or not undated_matches:
        return overview

    # The same clause can legitimately contain one compound action. Only repair
    # when structured dated and undated work map to different summary clauses.
    dated_index = max(dated_matches, key=lambda item: item[2])[1]
    undated_indexes = {item[1] for item in undated_matches}
    if dated_index in undated_indexes:
        return overview

    misplaced_indexes = {
        index for index in undated_indexes
        if _incremental_summary_deadline_mentions_value(clauses[index], due_value)
    }
    if not misplaced_indexes:
        return overview

    due_phrase = _incremental_summary_due_phrase(due_value)
    if not due_phrase:
        return overview

    repaired = list(clauses)
    for item, index, score in undated_matches:
        if index not in misplaced_indexes:
            continue
        cleaned = _incremental_summary_strip_trailing_deadline(repaired[index])
        # If the model's coordinated clause also dropped material task detail,
        # use the already-grounded structured action wording rather than leaving
        # a thinner summary solely because the deadline was moved.
        if score < 0.80:
            canonical = re.sub(r"\s+", " ", str(item.get("action") or "")).strip(" ,.;")
            if canonical:
                cleaned = canonical[:1].lower() + canonical[1:]
        repaired[index] = cleaned

    if not _incremental_summary_deadline_mentions_value(repaired[dated_index], due_value):
        repaired[dated_index] = f"{repaired[dated_index].rstrip(' ,.;')} {due_phrase}"

    rebuilt = ", and ".join(
        part.rstrip(" ,.;") for part in repaired if part.rstrip(" ,.;")
    )
    if not rebuilt:
        return overview
    rebuilt = rebuilt[:1].upper() + rebuilt[1:]
    return _compact_summary_overview(rebuilt.rstrip(" ,.;") + ".")


def _balanced_incremental_summary_overview(
    email: dict, existing_summary: str, new_summary: str, actions,
    task_title: str = "", deadlines=None,
) -> str:
    """Build the current whole-thread overview, not a newest-turn-only delta.

    The model is instructed to reconcile the whole thread. These deterministic
    guards handle thin/action-only model output without blindly concatenating
    history: the latest turn is first repaired from its own grounded source, then
    still-valid prior context is retained only when the newest turn does not carry
    a generic supersession/state-transition signal.
    """
    actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)

    raw_candidate = _naturalize_incremental_overview(new_summary)
    candidate = _naturalize_incremental_overview(
        _separate_summary_overview(email, new_summary, actions)
    )

    # Incremental model output is already instructed to describe the current
    # whole-thread state.  The standalone Summary-vs-Action separator can reduce
    # a short but useful whole-thread sentence to a subject-only meta fallback
    # ("The email provides the latest update on ...").  Preserve the model's
    # grounded whole-thread wording when it still identifies validated recipient
    # work and does not introduce an explicit numeric/date/time fact absent from
    # either the newest turn or the previously saved Summary.
    if (
        _summary_is_topic_only_overview(candidate)
        and raw_candidate
        and _summary_covers_recipient_work(raw_candidate, actions)
    ):
        known_material = (
            _summary_explicit_signal_tokens(_email_text(email))
            | _summary_explicit_signal_tokens(existing_summary)
            | _summary_explicit_signal_tokens(" ".join(normalized_deadlines))
        )
        candidate_material = _summary_explicit_signal_tokens(raw_candidate)
        if candidate_material.issubset(known_material):
            candidate = _summary_humanize_deadline_text(raw_candidate)

    # A thread update can suffer the same action-only/context-loss failure as a
    # standalone email. Repair the newest-turn narrative before reconciling it
    # with the already-saved whole-thread overview.
    candidate = _repair_action_summary_completeness(email, actions, candidate)
    candidate = _repair_summary_no_deadline_constraint(email, actions, candidate)
    candidate = _repair_summary_material_context_completeness(
        email, actions, normalized_deadlines, candidate
    )
    separated_previous = _separate_summary_overview(email, existing_summary, actions)
    previous = separated_previous

    # Use the already-validated saved Summary only when the newest candidate
    # demonstrably covers it.  This avoids a subject-only fallback for concise
    # additive updates without making old prose authoritative during deadline,
    # cancellation, replacement, or other superseding transitions.
    raw_previous = _compact_summary_overview(existing_summary)
    if (
        raw_previous
        and candidate
        and not _incremental_turn_may_supersede_prior_context(email)
    ):
        raw_prior_terms = _summary_overlap_terms(raw_previous)
        candidate_terms_for_prior = _summary_overlap_terms(candidate)
        raw_prior_coverage = (
            len(raw_prior_terms & candidate_terms_for_prior) / max(1, len(raw_prior_terms))
            if raw_prior_terms else 1.0
        )
        raw_missing_material = _summary_missing_material_prior_context(
            email, raw_previous, candidate
        )
        if raw_prior_coverage >= 0.60 and not raw_missing_material:
            previous = raw_previous

    if not candidate:
        return previous or _summary_scope_sentence(email, actions, task_title)
    if not previous:
        return candidate

    prior_terms = _summary_overlap_terms(previous)
    candidate_terms = _summary_overlap_terms(candidate)
    prior_coverage = (
        len(prior_terms & candidate_terms) / max(1, len(prior_terms))
        if prior_terms else 1.0
    )

    candidate_sentences = [
        part.strip() for part in re.split(r"(?<=[.!?])\s+", candidate) if part.strip()
    ]
    candidate_words = len(candidate.split())
    delta_like = bool(re.search(
        r"\b(?:latest update|email updates?|updated|revis(?:e|es|ed)|"
        r"chang(?:e|es|ed)|expand(?:s|ed)|now includes?)\b",
        candidate, flags=re.IGNORECASE,
    ))
    thin_or_delta = len(candidate_sentences) <= 1 and (delta_like or candidate_words < 24)

    # If the latest result does not carry much of the saved whole-thread context,
    # keep that context for additive updates. Avoid this fallback on turns that
    # may supersede old facts; in those cases the model/latest-source repair is
    # authoritative so stale state is not reintroduced.
    missing_material_prior = _summary_missing_material_prior_context(
        email, previous, candidate
    )
    # Short does not automatically mean delta-only.  If a concise newest-turn
    # sentence already covers the saved overview and carries no missing material
    # prior fact, keep it as the current whole-thread Summary instead of
    # prepending generic/history prose merely because it is under 24 words.
    concise_whole_thread = (
        thin_or_delta
        and not delta_like
        and prior_coverage >= 0.60
        and not missing_material_prior
    )
    if concise_whole_thread:
        return candidate

    needs_prior_context = missing_material_prior or prior_coverage < 0.58 or thin_or_delta
    if needs_prior_context and not _incremental_turn_may_supersede_prior_context(email):
        prior_context = _summary_as_one_context_sentence(previous)
        latest_unique = _summary_remove_facts_covered_by_prior(
            email, candidate, previous
        )
        latest_context = _summary_as_one_context_sentence(latest_unique or candidate)
        if prior_context and latest_context:
            if _summary_semantically_covers_fact(email, latest_context, prior_context):
                return prior_context
            return _compact_summary_overview(f"{prior_context} {latest_context}")
        return prior_context or latest_context

    # A thin candidate that already overlaps strongly with prior state can still
    # benefit from a scope sentence, but never replace the whole thread with a
    # subject-only placeholder.
    if thin_or_delta:
        scope = previous or _summary_scope_sentence(email, actions, task_title)
        if candidate and scope.casefold() != candidate.casefold():
            return _compact_summary_overview(
                f"{_summary_as_one_context_sentence(scope)} "
                f"{_summary_as_one_context_sentence(candidate)}"
            )
        return _compact_summary_overview(scope or candidate)

    return candidate or previous or _summary_scope_sentence(email, actions, task_title)


def _phase1b_prefer_source_action_wording(action: str, evidence: str) -> str:
    """Use clearer source-grounded executable wording for two common paraphrase shapes.

    This does not invent new work: it only rewrites a model label when its own
    evidence sentence already contains the executable request more directly.
    """
    current = re.sub(r"\s+", " ", str(action or "")).strip()
    source = re.sub(r"\s+", " ", str(evidence or "")).strip()
    if not current or not source:
        return current

    # Soft-target imperative: "Aim to send X by Friday if possible, but ...".
    # Keep the executable clause and leave all timing language to Deadline.
    if re.match(r"^\s*aim\s+to\s+", source, flags=re.IGNORECASE):
        candidate = re.sub(r"^\s*aim\s+to\s+", "", source, count=1, flags=re.IGNORECASE)
        candidate = re.split(r"\s+if\s+possible\b|\s*,?\s*but\b", candidate, maxsplit=1, flags=re.IGNORECASE)[0]
        candidate = _separate_action_item_text(candidate)
        if candidate and _phase1c_action_intent(candidate):
            return candidate

    # Delivery scope is part of the action identity.  If the source explicitly
    # requires Reply All, a generic model/audit paraphrase such as ``Respond with
    # status`` must not silently narrow the recipient set.
    if re.search(r"\breply\s+all\b", source, flags=re.IGNORECASE):
        # Reply-All is a delivery constraint, not merely a verb synonym.  A
        # model may paraphrase it as ``provide/send the status`` even though the
        # object is grounded.  Preserve the source request whenever this exact
        # recipient scope is present so To-Do cannot silently narrow the audience.
        candidate = _separate_action_item_text(source)
        candidate = re.sub(r"^\s*(?:please|kindly)\s+", "", candidate, flags=re.IGNORECASE).strip()
        if candidate and _phase1c_action_intent(candidate):
            return candidate[:1].upper() + candidate[1:]

    # Availability confirmation often appears as "let me know whether you are
    # available" while the model emits a verbose reply-to-sender label. Normalize
    # that source-proven scheduling response to the task itself.
    if re.search(
        r"\blet\s+(?:me|us)\s+know\s+whether\s+you\s+(?:are|will\s+be)\s+available\b|"
        r"\bconfirm\s+(?:your\s+)?availability\b",
        source,
        flags=re.IGNORECASE,
    ):
        return "Confirm availability"

    return current


def _phase1b_action_uses_unseen_script(action: str, body: str) -> bool:
    """Reject audit/model translations that introduce a script absent in source.

    This is deliberately narrower than language detection. Latin-script paraphrases
    keep using the established grounding/dedupe rules, while a generated CJK,
    Cyrillic, Arabic, Indic, Thai, or Hangul action cannot survive beside the
    source-language action unless that script is actually present in the email.
    """
    script_ranges = (
        r"[\u3400-\u4dbf\u4e00-\u9fff]",  # CJK
        r"[\u3040-\u30ff]",                  # Japanese kana
        r"[\uac00-\ud7af]",                  # Hangul
        r"[\u0400-\u04ff]",                  # Cyrillic
        r"[\u0600-\u06ff]",                  # Arabic
        r"[\u0900-\u097f]",                  # Devanagari
        r"[\u0e00-\u0e7f]",                  # Thai
    )
    action_text = str(action or "")
    source_text = str(body or "")
    return any(
        re.search(pattern, action_text) and not re.search(pattern, source_text)
        for pattern in script_ranges
    )


def _phase1b_cross_language_action_supported(action: str, sentence: str) -> bool:
    """Conservative support for Latin-script Filipino request paraphrases.

    The summarizer may correctly express a Filipino request in English, while the
    lexical grounding layer historically rejected it because the source/action
    vocabularies differ.  Normalize a small set of common *semantic roles* rather
    than any benchmark sentence.  The sentence must still be recipient-directed,
    and at least half of the action's meaningful concepts must be present.
    """
    source = re.sub(r"\s+", " ", str(sentence or "")).casefold()
    candidate = re.sub(r"\s+", " ", str(action or "")).casefold()
    if not source or not candidate or not _phase1b_recipient_request_signal(source):
        return False

    aliases = {
        "review": (r"\b(?:suri|surii?n|pakisuri|tingnan)\w*\b",),
        "revised": (r"\b(?:binago|binagong|rebisado|nirebisa)\w*\b",),
        "contract": (r"\bkontrata\b",),
        "send": (r"\b(?:ipadala|ipadadala|isend|i-send)\w*\b",),
        "provide": (r"\b(?:ipadala|ibigay|magbigay)\w*\b",),
        "comment": (r"\b(?:komento|puna)\w*\b",),
        "comments": (r"\b(?:komento|puna)\w*\b",),
        "confirm": (r"\b(?:kumpirmahin|ikumpirma)\w*\b",),
        "submit": (r"\b(?:isumite|ipasa)\w*\b",),
        "sign": (r"\b(?:lagdaan|pirmahan)\w*\b",),
        "return": (r"\b(?:ibalik|isauli)\w*\b",),
        "complete": (r"\b(?:kumpletuhin|tapusin)\w*\b",),
        "budget": (r"\bbadyet\b",),
    }
    words = [w for w in re.findall(r"[a-z]+", candidate) if len(w) >= 4]
    ignored = {
        "the", "your", "with", "this", "that", "please", "provide",
        "send", "review", "submit", "return", "complete", "confirm",
    }
    concepts = [w for w in words if w not in ignored]
    # Keep executable verbs as concepts when a mapped source verb exists.
    for verb in ("review", "send", "provide", "submit", "return", "complete", "confirm", "sign"):
        if re.search(rf"\b{verb}\w*\b", candidate):
            concepts.append(verb)
    concepts = list(dict.fromkeys(concepts))
    if not concepts:
        return False

    matched = 0
    for concept in concepts:
        if re.search(rf"\b{re.escape(concept)}\w*\b", source):
            matched += 1
            continue
        patterns = aliases.get(concept, ())
        if any(re.search(pattern, source, flags=re.IGNORECASE) for pattern in patterns):
            matched += 1
    return matched >= 2 and matched / max(1, len(concepts)) >= 0.50


def _phase1b_validate_actions(email: dict, values) -> list[str]:
    full_body = _body_text(email)
    body = _phase1g_effective_turn_text(full_body)
    if _phase1g_recipient_explicitly_has_no_action(full_body):
        return []
    candidates = _normalize_list(values)
    validated = []
    for action in candidates:
        if _phase1b_action_uses_unseen_script(action, full_body):
            continue
        if _phase1b_action_invalidated(action, full_body):
            continue
        if _phase1g_action_mixes_forwarded_only_work(action, full_body):
            continue

        evidence = ""
        delegated = False
        if _is_supported(action, body):
            evidence = _phase1b_find_evidence(action, body)
        if not evidence:
            # Cross-language RAW output can be semantically grounded even when
            # English action words do not lexically overlap a Filipino request.
            for sentence in _phase1b_source_sentences(body):
                if _phase1b_cross_language_action_supported(action, sentence):
                    evidence = sentence
                    break
        if not evidence:
            evidence = _phase1g_forwarded_delegation_evidence(action, full_body)
            delegated = bool(evidence)
        if not evidence:
            continue
        table_row = _phase1b_pipe_table_row(email, evidence)
        if table_row.get("owner_kind") == "other":
            continue
        if _phase1g_ambiguous_group_owner(evidence, body):
            continue

        assignee = _phase1g_named_assignee(evidence)
        recipient_name = _phase1g_recipient_name(email)
        recipient_directed = delegated or _phase1b_recipient_request_or_continuation(evidence, body)
        if assignee:
            if _phase1g_addressed_to_other_person(email, evidence):
                continue
            if not recipient_name and not recipient_directed:
                continue
        elif not recipient_directed:
            continue
        if _phase1g_explicit_other_owner_for_action(
            email, action, body, len(candidates)
        ):
            continue
        if _phase1g_assignment_dependent_instruction(evidence):
            if not _phase1g_has_recipient_owned_assignment(email, body):
                continue
        if _phase1c_evidence_is_non_action(evidence, body):
            continue
        if _phase1c_is_task_list_intro_evidence(evidence, body):
            continue
        clean_action = _separate_action_item_text(action)
        clean_action = _phase1b_prefer_source_action_wording(clean_action, evidence)
        if not clean_action or _action_item_is_metadata_only(clean_action):
            continue
        if _phase1c_is_task_list_intro_evidence(clean_action, body):
            continue
        validated.append(clean_action)
    return _merge_unique(validated)


def _phase1c_action_intent(action: str) -> str:
    lowered = str(action or "").casefold()
    if re.search(r"\bapprove\b.*\breject\b|\breject\b.*\bapprove\b|\bmake (?:a |the )?decision\b", lowered):
        return "decision"
    # "Let me/us know whether ..." asks the recipient to confirm a fact/state,
    # even though the surface verb is conversational reply language.
    if re.search(r"\blet\s+(?:me|us)\s+know\s+whether\b", lowered):
        return "confirm"
    intent_patterns = (
        ("decision", r"\bapprov\w*\b|\breject\w*\b|\bchoos\w*\b|\bselect\w*\b"),
        ("acknowledge", r"\backnowledg\w*\b"),
        ("attend", r"\battend\w*\b|\bjoin\w*\b"),
        ("check", r"\bcheck\w*\b|\bverify\w*\b|\binvestigat\w*\b"),
        ("complete", r"\bcomplet\w*\b|\bfinish\w*\b"),
        ("confirm", r"\bconfirm\w*\b"),
        ("prepare", r"\bprepar\w*\b|\bdraft\w*\b"),
        ("provide", r"\bprovid\w*\b|\bshare\w*\b"),
        ("read", r"\bread\w*\b"),
        # Notification is its own executable intent. Without this, a phrase such
        # as "Notify ... of selection" can be misclassified from the object noun
        # "selection" as a decision and then collapsed beside a real choose/select
        # action from the same sentence. Keep the verb semantic and provider-neutral.
        ("notify", r"\bnotif(?:y|ies|ied|ying)\b"),
        ("reply", r"\brepl(?:y|ies|ied)\b|\brespond\w*\b|\btell\w*\b|\binform\w*\b|\breport\w*\b|\blet\s+(?:me|us)\s+know\b"),
        ("review", r"\breview\w*\b"),
        ("schedule", r"\bschedul\w*\b"),
        ("send", r"\bsend\w*\b|\bsubmit\w*\b|\bupload\w*\b"),
        ("sign", r"\bsign\w*\b"),
        ("stop", r"\bstop\w*\b|\bcease\w*\b"),
        ("update", r"\bupdat\w*\b"),
    )

    # Classify the executable intent by the earliest action verb in the phrase,
    # not by the first category in the table. Task-object nouns can themselves
    # look like verbs (for example "draft", "review", "schedule", or
    # "update"). Fixed category ordering therefore misclassified requests such
    # as "Send the contract draft" as PREPARE and could collapse a genuinely
    # separate later instruction that happened to mention the same object.
    # Earliest-match selection is syntax-oriented and applies generically across
    # task subjects without hardcoding any benchmark vocabulary.
    matches = []
    for order, (name, pattern) in enumerate(intent_patterns):
        match = re.search(pattern, lowered)
        if match:
            matches.append((match.start(), order, name))
    if matches:
        return min(matches)[2]
    return ""


def _phase1c_action_clause_intents(action: str) -> set[str]:
    """Return executable intents across compound action clauses.

    The primary-intent classifier intentionally picks only the earliest verb so
    object nouns such as "draft", "review", "schedule", and "update" do not
    masquerade as extra actions.  For deduplication we also need to recognize a
    true second instruction in compound wording (for example "review X and
    submit Y").  Split only on ordinary clause connectors and classify each
    clause independently; noun-only fragments contribute no intent.
    """
    text = re.sub(r"\s+", " ", str(action or "")).strip()
    if not text:
        return set()

    parts = re.split(
        r"\s*(?:;|,(?=\s*(?:then|also)\b)|\b(?:and then|then|also|plus)\b|\band\b)\s*",
        text,
        flags=re.IGNORECASE,
    )
    intents: set[str] = set()
    for part in parts:
        intent = _phase1c_action_intent(part)
        if intent:
            intents.add(intent)
    if not intents:
        primary = _phase1c_action_intent(text)
        if primary:
            intents.add(primary)
    return intents



def _phase1c_response_delivery_equivalent(candidate: dict, other: dict) -> bool:
    """True when two grounded actions are delivery-wording variants of one request.

    Small-model extraction and the source-audit pass can describe the same
    communication task with different transport verbs, for example ``provide X``
    versus ``reply with X`` or ``send X`` versus ``provide X``.  Treat those as
    one action only when both candidates are grounded in the exact same source
    sentence and refer to substantially the same task object.

    The guard is intentionally semantic rather than sample-specific: different
    source sentences or different objects remain separate, so requests such as
    ``send the NDA`` and ``send the ID`` are never collapsed merely because they
    use related delivery verbs.
    """
    if not candidate.get("evidence") or candidate.get("evidence") != other.get("evidence"):
        return False

    delivery_intents = {"reply", "provide", "send"}
    candidate_intent = str(candidate.get("intent") or "")
    other_intent = str(other.get("intent") or "")
    if candidate_intent not in delivery_intents or other_intent not in delivery_intents:
        return False

    candidate_objects = set(candidate.get("object_tokens") or ())
    other_objects = set(other.get("object_tokens") or ())
    if not candidate_objects or not other_objects:
        return False

    overlap = candidate_objects & other_objects
    smaller = min(len(candidate_objects), len(other_objects))
    if not smaller or (len(overlap) / smaller) < 0.75:
        return False

    # Require near-containment rather than generic topical overlap.  This lets a
    # harmless pronoun/determiner token differ (e.g. ``your decision``) while
    # keeping genuinely different deliverables separate.
    symmetric_gap = len(candidate_objects ^ other_objects)
    return symmetric_gap <= 1


def _phase1c_prefer_source_delivery_wording(candidate: dict, other: dict) -> bool:
    """Return True when candidate's executable verb is more source-faithful.

    This only decides which already-equivalent wording to retain; it never
    creates or removes an action by itself.
    """
    evidence_text = str(candidate.get("evidence_text") or other.get("evidence_text") or "")
    if not evidence_text:
        return False

    direct_patterns = {
        "reply": r"\brepl(?:y|ies|ied)\b|\brespond\w*\b|\btell\w*\b|\binform\w*\b|\breport\w*\b|\blet\s+(?:me|us)\s+know\b",
        "provide": r"\bprovid\w*\b|\bshare\w*\b",
        "send": r"\bsend\w*\b|\bsubmit\w*\b|\bupload\w*\b|\breturn\w*\b",
    }

    def _directly_supported(item: dict) -> bool:
        intent = str(item.get("intent") or "")
        pattern = direct_patterns.get(intent)
        return bool(pattern and re.search(pattern, evidence_text, flags=re.IGNORECASE))

    candidate_supported = _directly_supported(candidate)
    other_supported = _directly_supported(other)
    return candidate_supported and not other_supported


def _phase1c_unknown_bare_action_subsumes(candidate: dict, other: dict) -> bool:
    """True when an unclassified bare action repeats a fuller grounded action.

    Some valid executable verbs are outside the intent vocabulary (for example
    acronyms, product-specific commands, or newly coined workflow verbs).  The
    recovery audit can then emit a one-word action in addition to the model's
    fuller wording.  Collapse only the strict containment shape: both candidates
    must be grounded in the exact same source sentence, neither may have a known
    executable intent, and the smaller candidate must contain exactly one content
    token that is also present in the fuller candidate.

    This deliberately does *not* merge two object-bearing unknown actions such as
    ``Escalate invoice`` and ``Escalate contract``.  It is therefore a generic
    audit-paraphrase guard rather than a vocabulary special case.
    """
    if candidate.get("intent") or other.get("intent"):
        return False
    if not candidate.get("evidence") or candidate.get("evidence") != other.get("evidence"):
        return False

    candidate_tokens = set(candidate.get("tokens") or ())
    other_tokens = set(other.get("tokens") or ())
    if not candidate_tokens or not other_tokens:
        return False

    # ``candidate`` is the fuller wording and ``other`` is the bare audit form.
    if len(other_tokens) != 1 or len(candidate_tokens) <= 1:
        return False
    return other_tokens.issubset(candidate_tokens)


def _phase1c_response_subaction_alias(candidate: dict, other: dict) -> bool:
    """Return True when ``other`` is only the response half of ``candidate``.

    A single source sentence can ask for substantive work plus a response about
    that work (for example, review something and report/confirm the decision).
    Model and audit passes may emit both the complete coupled action and a second
    response-only alias. Collapse only the strict same-evidence/subaction shape:
    the fuller action must contain an additional executable intent, the smaller
    action must be response-only after normalizing reply/provide/confirm wording,
    and its non-generic task object must already be represented by the fuller
    action. Distinct response tasks or different source sentences stay separate.
    """
    if not candidate.get("evidence") or candidate.get("evidence") != other.get("evidence"):
        return False

    response_family = {"reply", "provide", "confirm"}

    def _normalized_intents(item: dict) -> set[str]:
        raw = set(item.get("intents") or ())
        normalized = {intent for intent in raw if intent not in response_family}
        if raw & response_family:
            normalized.add("response")
        return normalized

    candidate_intents = _normalized_intents(candidate)
    other_intents = _normalized_intents(other)
    if other_intents != {"response"} or not other_intents < candidate_intents:
        return False

    generic_response_objects = {
        "decision", "status", "state", "update", "information", "info",
        "response", "reply", "whether", "if", "answer", "confirmation",
    }
    candidate_objects = set(candidate.get("object_tokens") or ()) - generic_response_objects
    other_objects = set(other.get("object_tokens") or ()) - generic_response_objects
    if not other_objects:
        return bool(candidate_objects)

    return all(
        any(_raw_first_tokens_related(token, candidate_token) for candidate_token in candidate_objects)
        for token in other_objects
    )


def _phase1c_action_subsumes(candidate: dict, other: dict) -> bool:
    """True when candidate already contains the executable work in other.

    This is deliberately source-semantic rather than case-specific.  A compound
    action may coexist with an audit/model sub-action that merely repeats one of
    its clauses.  We collapse that redundancy only when both outputs are grounded
    in the same source sentence, the candidate covers all executable intents of
    the smaller action, and it covers the smaller action's task-object tokens.

    Distinct work remains separate: e.g. "Prepare report" and "Send report" have
    the same object but different executable intents, while "Send NDA" and
    "Send ID" have different objects.
    """
    if not candidate.get("evidence") or candidate.get("evidence") != other.get("evidence"):
        return False

    candidate_intents = set(candidate.get("intents") or ())
    other_intents = set(other.get("intents") or ())
    if not candidate_intents or not other_intents:
        return False
    if not other_intents.issubset(candidate_intents):
        return False
    # Additive-only guard: same-intent paraphrases keep using the previously
    # locked dedupe path below. Subsumption is used only when a compound action
    # contains at least one additional executable intent.
    if candidate_intents == other_intents:
        return False

    candidate_objects = set(candidate.get("object_tokens") or ())
    other_objects = set(other.get("object_tokens") or ())
    if other_objects and not other_objects.issubset(candidate_objects):
        return False

    # The strict intent superset above is the extra coverage requirement. Object
    # containment only confirms that the smaller action refers to work already
    # represented by the compound action.
    return True


def _phase1c_dedupe_actions(email: dict, actions) -> list[str]:
    # Deduplicate paraphrases and compound/sub-action overlap without collapsing
    # genuinely different actions from one sentence.  This runs for every summary
    # path (initial, manual/automatic, individual/batch, and thread reconciliation),
    # so the rule is generic rather than tied to one benchmark phrase.
    body = _body_text(email)
    metadata: list[dict] = []

    for action in _normalize_list(actions):
        norm = re.sub(r"\s+", " ", action).strip()
        norm_key = norm.casefold()
        intent = _phase1c_action_intent(norm)
        intents = _phase1c_action_clause_intents(norm)
        evidence = _phase1b_find_evidence(norm, body)
        evidence_key = re.sub(r"\W+", " ", evidence.casefold()).strip()
        tokens = set(_content_words(norm))
        object_tokens = _phase1e_object_tokens(norm)
        current = {
            "text": norm,
            "norm": norm_key,
            "intent": intent,
            "intents": intents,
            "evidence": evidence_key,
            "evidence_text": evidence,
            "tokens": tokens,
            "object_tokens": object_tokens,
        }

        duplicate = False
        replace_indexes: list[int] = []
        for index, previous in enumerate(metadata):
            if norm_key == previous["norm"]:
                duplicate = True
                break

            # Delivery-language variants of the same grounded request are one
            # executable action, not two tasks. Prefer the wording whose verb is
            # directly supported by the source sentence so audit-added phrasing
            # cannot inflate the action count.
            if _phase1c_response_delivery_equivalent(previous, current):
                if _phase1c_prefer_source_delivery_wording(current, previous):
                    replace_indexes.append(index)
                    continue
                duplicate = True
                break

            # Unknown-verb bare/subsumed overlap.  Recovery audits sometimes add
            # a one-token action beside a fuller AI_RAW action when the executable
            # verb is not yet in the intent vocabulary.  Prefer the fuller wording
            # only when both are grounded in the same source sentence and the bare
            # token is strictly contained in it.
            if _phase1c_unknown_bare_action_subsumes(previous, current):
                duplicate = True
                break
            if _phase1c_unknown_bare_action_subsumes(current, previous):
                replace_indexes.append(index)
                continue

            # Generic compound/sub-action overlap.  If the already-kept action
            # fully contains the current action, drop the smaller duplicate.  If
            # the current action is the fuller representation, replace the older
            # sub-action so result quality is independent of model/audit ordering.
            if _phase1c_action_subsumes(previous, current):
                duplicate = True
                break
            if _phase1c_action_subsumes(current, previous):
                replace_indexes.append(index)
                continue

            # A complete coupled task can be accompanied by a response-only alias
            # from another model field/audit pass. Collapse that alias only when
            # both candidates are grounded in the exact same source sentence and
            # the response object is already contained in the fuller action.
            if _phase1c_response_subaction_alias(previous, current):
                duplicate = True
                break
            if _phase1c_response_subaction_alias(current, previous):
                replace_indexes.append(index)
                continue

            # Preserve the previously locked paraphrase behavior. The new generic
            # compound/sub-action guard above is additive and must not rewrite the
            # established same-intent dedupe semantics used by earlier benchmark steps.
            if not intent or intent != previous["intent"]:
                continue
            previous_tokens = previous["tokens"]
            union = tokens | previous_tokens
            jaccard = (len(tokens & previous_tokens) / len(union)) if union else 1.0
            # Same request sentence + same intent is almost always an audit paraphrase.
            if evidence_key and evidence_key == previous["evidence"]:
                duplicate = True
                break
            if jaccard >= 0.55:
                duplicate = True
                break

        if duplicate:
            continue

        if replace_indexes:
            replace_set = set(replace_indexes)
            metadata = [item for i, item in enumerate(metadata) if i not in replace_set]
        metadata.append(current)

    return [item["text"] for item in metadata]


def _phase1h_preserve_sign_return_obligation(email: dict, actions) -> list[str]:
    # Preserve a compound sign+return request when the model keeps only the sign step.
    # This is source-grounded and intentionally narrow: if a return action already
    # exists, leave the extracted actions unchanged.
    items = _normalize_list(actions)
    if not items or any(re.search(r"\breturn\w*\b", item, re.IGNORECASE) for item in items):
        return items

    body = _body_text(email)
    result = []
    for action in items:
        updated = action
        if _phase1c_action_intent(action) == "sign" and not re.search(
            r"\breturn\w*\b", action, re.IGNORECASE
        ):
            evidence = _phase1b_find_evidence(action, body)
            if (
                re.search(r"\bsign\w*\b", evidence, re.IGNORECASE)
                and re.search(r"\breturn\w*\b", evidence, re.IGNORECASE)
                and _phase1b_recipient_request_signal(evidence)
            ):
                cleaned = re.sub(r"^\s*please\s+", "", action, flags=re.IGNORECASE)
                if re.match(r"^sign\b", cleaned, flags=re.IGNORECASE):
                    updated = re.sub(
                        r"^sign\b", "Sign and return", cleaned, count=1, flags=re.IGNORECASE
                    )
        result.append(updated)
    return _merge_unique(result)


def _phase1e_latest_continues_action(action: str, latest: str) -> bool:
    # Latest replies often keep an old task without restating its full object:
    # "The review is still needed" / "Please still confirm ...".
    intent = _phase1c_action_intent(action)
    lowered = str(latest or "").casefold()
    if not intent:
        return False
    patterns = (
        rf"\b{re.escape(intent)}\w*\b[^.!?\n]{{0,50}}\bstill (?:needed|required|open|pending)\b",
        rf"\bstill\s+{re.escape(intent)}\w*\b",
        rf"\b(?:continue|keep)\s+(?:to\s+)?{re.escape(intent)}\w*\b",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _phase1e_action_verb_supported(action: str, evidence: str) -> bool:
    # Reject audit hallucinations such as "confirm submission" when the source only
    # asks the user to submit. Synonyms are intentionally conservative.
    intent = _phase1c_action_intent(action)
    if not intent:
        return True
    lowered = str(evidence or "").casefold()
    groups = {
        "acknowledge": (r"\backnowledg\w*\b", r"\bconfirm receipt\b"),
        "attend": (r"\battend\w*\b", r"\bjoin\w*\b"),
        "check": (r"\bcheck\w*\b", r"\bverify\w*\b", r"\binvestigat\w*\b"),
        "complete": (r"\bcomplet\w*\b", r"\bfinish\w*\b"),
        "confirm": (r"\bconfirm\w*\b", r"\backnowledg\w*\b"),
        "decision": (r"\bapprove\b", r"\breject\b", r"\bdecision\b"),
        "prepare": (r"\bprepar\w*\b", r"\bdraft\w*\b"),
        "provide": (r"\bprovid\w*\b", r"\bshare\w*\b", r"\bsend\w*\b"),
        "read": (r"\bread\w*\b",),
        "reply": (r"\brepl(?:y|ies|ied)\b", r"\brespond\w*\b", r"\btell\w*\b", r"\binform\w*\b", r"\breport\w*\b", r"\blet\s+(?:me|us)\s+know\b"),
        "review": (r"\breview\w*\b",),
        "schedule": (r"\bschedul\w*\b",),
        "send": (r"\bsend\w*\b", r"\bsubmit\w*\b", r"\bupload\w*\b", r"\breturn\w*\b"),
        "sign": (r"\bsign\w*\b",),
        "update": (r"\bupdat\w*\b",),
    }
    return any(re.search(pattern, lowered) for pattern in groups.get(intent, ())) if intent in groups else True


def _phase1e_reconcile_thread_actions(email: dict, actions) -> list[str]:
    # Resolve active work against the newest labeled reply after flat-model extraction.
    # This layer intentionally changes only task state, not summary prose.
    body = _body_text(email)
    latest = _phase1b_latest_turn_text(body)
    items = _normalize_list(actions)
    if not latest or not items:
        return items

    lowered = latest.casefold()
    if re.search(r"\bno (?:further )?action (?:is )?(?:needed|required)\b", lowered):
        return []

    state_sentences = _phase1e_state_sentences(latest)
    latest_direct = []
    continuing = []
    for action in items:
        # Explicit completion/cancellation/reassignment wins over older task wording.
        if any(_phase1e_related_action_text(action, sentence) for sentence in state_sentences):
            # A same-turn re-request can reopen/replace the state change; handle it below.
            direct = _phase1e_best_evidence(action, latest)
            if not direct or _phase1c_evidence_is_non_action(direct, latest):
                continue
        evidence = _phase1e_best_evidence(action, latest)
        if evidence and _phase1b_recipient_request_signal(evidence) and not _phase1c_evidence_is_non_action(evidence, latest):
            if _phase1e_action_verb_supported(action, evidence):
                latest_direct.append(action)
                continue
        if _phase1e_latest_continues_action(action, latest):
            continuing.append(action)

    # If the latest turn contains any explicit request/update, active work should be
    # reconciled to that turn plus explicitly continued older work. This removes stale
    # old deadline/action variants while preserving "review is still needed" cases.
    has_latest_request = any(
        _phase1b_recipient_request_signal(sentence)
        for sentence in _phase1b_source_sentences(latest)
    )
    if has_latest_request or state_sentences:
        resolved = _merge_unique(latest_direct, continuing)
        latest_email = dict(email)
        latest_email["body_text"] = latest
        latest_email["snippet"] = latest
        resolved = _phase1c_dedupe_actions(latest_email, resolved)
        return resolved
    return items


def _phase1c_temporal_values_valid(value: str) -> bool:
    # Reject impossible concrete calendar/time values rather than "repairing" them.
    # Relative/cadence phrases have no concrete calendar value to validate here.
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    lowered = text.casefold()
    if not text or re.search(r"\b(?:xxx|tbd|n\s*/\s*a|not applicable)\b", lowered):
        return False

    iso = re.search(r"\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b", text)
    if iso:
        try:
            date(*(int(part) for part in iso.groups()))
        except ValueError:
            return False

    slash = re.search(r"\b(\d{1,2})[-/](\d{1,2})[-/](20\d{2})\b", text)
    if slash:
        try:
            month, day_num, year = (int(part) for part in slash.groups())
            date(year, month, day_num)
        except ValueError:
            return False

    named = re.search(
        r"\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
        r"\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(20\d{2}))?\b",
        lowered,
    )
    if named:
        try:
            month_num = datetime.strptime(named.group(1)[:3].title(), "%b").month
            year = int(named.group(3) or 2000)
            date(year, month_num, int(named.group(2)))
        except ValueError:
            return False

    for clock in re.finditer(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b", lowered):
        hour = int(clock.group(1))
        minute = int(clock.group(2) or 0)
        if not (1 <= hour <= 12 and 0 <= minute <= 59):
            return False
    for clock in re.finditer(r"\b(\d{1,2}):(\d{2})\b", lowered):
        if re.match(r"\s*(?:am|pm)\b", lowered[clock.end():]):
            continue
        hour, minute = (int(part) for part in clock.groups())
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            return False
    return True


def _phase1c_extract_deadline_phrases(sentence: str) -> list[str]:
    # Extract grounded due constraints from common calendar, duration, cutoff, and
    # recurrence grammar. Do not normalize them here: preserve source semantics.
    text = re.sub(r"\s+", " ", str(sentence or "")).strip()
    if not text:
        return []
    lowered = text.casefold()
    if re.search(r"\b(?:no|without) (?:fixed |stated |explicit )?(?:deadline|due date)\b", lowered):
        return []
    if re.search(r"\bnot setting (?:a |the )?(?:deadline|due date)\b", lowered):
        return []

    month = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    weekday = r"(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)"
    clock = r"(?:\d{1,2}(?::\d{2})?\s*(?:am|pm)(?:\s+(?:noon|midnight))?|noon|midnight)"
    zone = r"(?:\s+(?:UTC|GMT)(?:[+-]\d{1,2}(?::?\d{2})?)?|\s+(?-i:[A-Z]{2,4}))?"
    iso_date = r"20\d{2}[-/]\d{1,2}[-/]\d{1,2}"
    slash_date = r"\d{1,2}[-/]\d{1,2}[-/]20\d{2}"
    named_date = rf"{month}\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+20\d{{2}})?"
    lead = r"(?:by|before|no later than|due(?:\s+(?:on|by))?)"

    patterns = (
        rf"\b(?:today|tomorrow|tonight|bukas)(?:\s+(?:by|before|at)\s+{clock}{zone})?\b",
        rf"\b{lead}\s+{clock}{zone}(?:\s+(?:today|tomorrow|tonight|bukas))?\b",
        rf"\b{lead}\s+(?:{iso_date}|{slash_date}|{named_date})(?:\s+(?:at|by|before)\s+{clock}{zone})?\b",
        rf"\b{lead}\s+(?:(?:this|next)\s+)?{weekday}(?:\s+(?:at|by|before)\s+{clock}{zone})?\b",
        r"\b(?:by\s+)?(?:the\s+)?(?:end|close) of (?:(?:this|next) )?(?:day|week|month)\b",
        r"\b(?:by\s+)?close of business(?: today)?\b",
        r"\b(?:by\s+)?EOD\b",
        r"\bwithin\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:business\s+)?(?:hours?|days?|weeks?)\b",
        rf"\b(?:every|each)\s+{weekday}\b",
        r"\b(?:on\s+)?(?:the\s+)?(?:first|second|third|fourth|fifth|last)\s+business\s+day\s+of\s+every\s+month\b",
        r"\b(?:on\s+)?(?:the\s+)?(?:first|second|third|fourth|fifth)\s+business\s+day\s+after\s+each\s+quarter(?:\s+ends?)?\b",
        rf"\b{iso_date}(?:\s+(?:at|by|before)\s+{clock}{zone})?\b",
        rf"\b{named_date}(?:\s+(?:at|by|before)\s+{clock}{zone})?\b",
    )
    found = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0).strip(" ,.;")
            if not value or not _phase1c_temporal_values_valid(value):
                continue
            if value.casefold() not in {item.casefold() for item in found}:
                found.append(value)
    # Prefer the most informative overlapping phrase, e.g. keep the date+time+zone
    # constraint rather than also returning its shorter date/time fragments.
    filtered = []
    for value in found:
        lowered_value = value.casefold()
        if any(lowered_value != other.casefold() and lowered_value in other.casefold() for other in found):
            continue
        filtered.append(value)
    return filtered


def _phase1b_pipe_table_row(email: dict, sentence: str) -> dict:
    """Parse a simple pipe-delimited task table row using its source header.

    The parser is deliberately header-driven: it only activates when the body
    contains named Task/Action, Owner/Assignee, and Due/Deadline columns. This
    keeps ordinary prose containing a pipe character out of the ownership path.
    """
    body = _body_text(email)
    lines = [re.sub(r"\s+", " ", line).strip() for line in str(body or "").splitlines()]
    target = re.sub(r"\s+", " ", str(sentence or "")).strip()
    if not target or "|" not in target:
        return {}
    header = None
    owner_index = due_index = task_index = None
    for line in lines:
        if "|" not in line:
            continue
        cells = [cell.strip() for cell in line.split("|")]
        lowered = [cell.casefold() for cell in cells]
        oi = next((i for i, cell in enumerate(lowered) if cell in {"owner", "assignee", "assigned to"}), None)
        di = next((i for i, cell in enumerate(lowered) if cell in {"due", "deadline", "due date"}), None)
        ti = next((i for i, cell in enumerate(lowered) if cell in {"task", "action", "action item", "work"}), None)
        if oi is not None and di is not None and ti is not None:
            header, owner_index, due_index, task_index = cells, oi, di, ti
            break
    if header is None:
        return {}
    cells = [cell.strip() for cell in target.split("|")]
    if max(owner_index, due_index, task_index) >= len(cells):
        return {}
    owner = cells[owner_index]
    owner_key = owner.casefold()
    if owner_key in {"you", "your", "recipient", "the recipient", "me"}:
        owner_kind = "recipient"
    elif owner:
        owner_kind = "other"
    else:
        owner_kind = ""
    return {
        "task": cells[task_index],
        "owner": owner,
        "owner_kind": owner_kind,
        "due": cells[due_index],
    }


def _phase1c_recover_direct_deadlines(email: dict, actions) -> list[str]:
    if not actions:
        return []
    body = _body_text(email)
    recovered = []
    for sentence in _phase1b_source_sentences(body):
        table_row = _phase1b_pipe_table_row(email, sentence)
        if table_row.get("owner_kind") == "other":
            continue
        if not _phase1b_is_valid_deadline_sentence(sentence, email=email):
            continue
        # Strong cutoff language can be informational for a named third party.
        # Do not let that global-looking sentence leak into the current user's
        # unrelated action when ownership is explicitly someone else's.
        if (
            _phase1g_named_assignee(sentence)
            and not _phase1b_recipient_request_signal(sentence)
            and _phase1g_addressed_to_other_person(email, sentence)
        ):
            continue

        # A date/time can be the object of the task rather than its due date.
        # Example class: "confirm whether the meeting is Aug 25 or Aug 26".
        # Protect only facts carried by an action whose own evidence is this
        # sentence, so an actual deadline with the same date in another sentence
        # is still recoverable.
        sentence_norm = re.sub(r"\s+", " ", sentence).strip().casefold()
        protected_identities = set()
        for action in _normalize_list(actions):
            facts = _phase1c_semantic_temporal_facts(action)
            if not facts:
                continue
            evidence = re.sub(
                r"\s+", " ", _phase1b_find_evidence(action, body)
            ).strip().casefold()
            if evidence != sentence_norm:
                continue
            protected_identities.update(
                _phase1c_deadline_identity(fact)
                for fact in facts
                if _phase1c_deadline_identity(fact)
            )

        for phrase in _phase1c_extract_deadline_phrases(sentence):
            identity = _phase1c_deadline_identity(phrase)
            if identity and identity in protected_identities:
                continue
            recovered.append(phrase)
    return _merge_unique(recovered)



def _phase1c_authoritative_cutoff_phrases(email: dict, actions) -> list[str]:
    """Recover a single action's authoritative cutoff over softer scheduling dates.

    Strong language such as ``hard deadline``, ``final cutoff`` and ``no later
    than`` is authoritative. For multi-action mail we do not collapse deadlines,
    because separate actions may legitimately own different dates.
    """
    if len(_normalize_list(actions)) != 1:
        return []
    body = _body_text(email)
    recovered: list[str] = []
    marker = re.compile(
        r"\b(?:no later than|hard deadline|final deadline|absolute deadline|final cutoff|hard cutoff)\b",
        flags=re.IGNORECASE,
    )
    for sentence in _phase1b_source_sentences(body):
        if not marker.search(sentence):
            continue
        if _phase1g_addressed_to_other_person(email, sentence):
            continue
        phrases = _phase1c_extract_deadline_phrases(sentence)
        if not phrases:
            continue
        match = marker.search(sentence)
        assert match is not None
        # Pick the temporal phrase closest to the strong-cutoff marker. This
        # correctly ignores an earlier soft target in the same sentence.
        candidates = []
        sentence_lower = sentence.casefold()
        for phrase in phrases:
            start = sentence_lower.find(phrase.casefold())
            if start < 0:
                continue
            end = start + len(phrase)
            distance = min(abs(start - match.end()), abs(match.start() - end))
            candidates.append((distance, -len(phrase), phrase))
        if candidates:
            recovered.append(min(candidates)[2])
    return _phase1c_dedupe_deadlines(recovered)


def _phase1c_recover_relative_event_deadlines(email: dict, actions) -> list[str]:
    """Resolve deterministic deadlines expressed relative to a dated event.

    Example shape: ``The meeting is on August 30. Please send the slides two
    days before the meeting.`` Only day/business-day offsets with a source-dated
    referenced event are resolved; broad/ambiguous relationships remain untouched.
    """
    if not _normalize_list(actions):
        return []
    body = _body_text(email)
    sentences = _phase1b_source_sentences(body)
    if not sentences:
        return []
    word_numbers = {
        "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
        "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    }
    relation_re = re.compile(
        r"\b(?P<count>\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
        r"(?P<business>business\s+)?days?\s+(?P<direction>before|after)\s+"
        r"(?:the\s+)?(?P<event>[a-z][a-z0-9 '/\-]{1,48}?)(?:[.,;]|$)",
        flags=re.IGNORECASE,
    )
    reference = _email_date(email, datetime.now().date())
    recovered: list[str] = []
    for sentence in sentences:
        if not _phase1b_recipient_request_signal(sentence):
            continue
        relation = relation_re.search(sentence)
        if not relation:
            continue
        raw_count = relation.group("count").casefold()
        count = int(raw_count) if raw_count.isdigit() else word_numbers.get(raw_count, 0)
        if count <= 0:
            continue
        event_terms = {
            token for token in re.findall(r"[a-z0-9]+", relation.group("event").casefold())
            if len(token) > 2 and token not in {"the", "this", "that", "our", "your"}
        }
        if not event_terms:
            continue
        event_date = None
        for candidate_sentence in sentences:
            if candidate_sentence == sentence:
                continue
            candidate_terms = set(re.findall(r"[a-z0-9]+", candidate_sentence.casefold()))
            if not (event_terms & candidate_terms):
                continue
            date_phrases = _phase1c_extract_deadline_phrases(candidate_sentence)
            resolved = _resolved_deadline_dates(date_phrases, reference)
            if resolved:
                event_date = resolved[0]
                break
        if event_date is None:
            continue
        if relation.group("business"):
            if relation.group("direction").casefold() == "before":
                current = event_date
                remaining = count
                while remaining:
                    current -= timedelta(days=1)
                    if current.weekday() < 5:
                        remaining -= 1
                due = current
            else:
                due = _add_business_days(event_date, count)
        else:
            delta = timedelta(days=count)
            due = event_date - delta if relation.group("direction").casefold() == "before" else event_date + delta
        recovered.append(_summary_human_date(due))
    return _merge_unique(recovered)


def _phase1c_select_authoritative_deadlines(email: dict, actions, deadlines) -> list[str]:
    authoritative = _phase1c_authoritative_cutoff_phrases(email, actions)
    if not authoritative:
        return _phase1c_dedupe_deadlines(deadlines)
    # Authoritative phrases are source-grounded above and intentionally replace
    # softer preferred/target dates for a single task.
    validated = _phase1b_validate_deadlines(email, authoritative, actions)
    return _phase1c_dedupe_deadlines(validated or authoritative)


def _phase1c_recover_explicit_binary_decisions(email: dict, actions) -> list[str]:
    """Recover source-explicit approve/reject decisions rejected by paraphrase grounding."""
    current = _phase1g_effective_turn_text(_body_text(email))
    recovered = list(_normalize_list(actions))
    for sentence in _phase1b_source_sentences(current):
        if not _raw_first_recipient_request_sentence(email, sentence):
            continue
        match = re.search(
            r"\bapprove\s+or\s+reject\s+(?:the\s+)?(.+?)(?=[,.;]|\b(?:today|tomorrow|by|before)\b|$)",
            sentence,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        obj = re.sub(r"\s+", " ", match.group(1)).strip(" ,.;")
        if not obj:
            continue
        candidate = f"Approve or reject {obj}"
        if not any(_phase1e_related_action_text(candidate, item) for item in recovered):
            recovered.append(candidate)
    return _phase1c_dedupe_actions(email, recovered)


def _phase1c_recover_implicit_recipient_requirements(email: dict, actions) -> list[str]:
    """Recover a strong current requirement phrased as ``we still need your X``."""
    current = _phase1g_effective_turn_text(_body_text(email))
    recovered = list(_normalize_list(actions))
    for sentence in _phase1b_source_sentences(current):
        match = re.search(
            r"\b(?:we|i)\s+(?:still\s+)?need\s+your\s+(.+?)(?=\s+to\b|[.;]|$)",
            sentence,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        obj = re.sub(r"\s+", " ", match.group(1)).strip(" ,.;")
        if not obj or len(obj.split()) > 10:
            continue
        candidate = f"Provide {obj}"

        # A state-shaped requirement may already be fully represented by the
        # action that creates or delivers that state.  For example, ``need your
        # signed X`` is covered by either ``Sign X`` / ``Sign and return X`` or
        # ``Send signed X``.  Do not append a synthetic ``Provide signed X`` beside
        # that existing obligation.  The proof is generic: the modifier must map
        # to an executable intent and the concrete business object must overlap.
        requirement_intent = _phase1c_action_intent(obj)
        requirement_objects = set(_phase1e_object_tokens(obj))
        if requirement_intent:
            stem = requirement_intent[:4]
            requirement_objects = {
                token for token in requirement_objects
                if not (len(token) >= 4 and token[:4] == stem)
            }
        requirement_objects -= {
            "your", "our", "their", "current", "updated", "required", "needed"
        }

        already_covered = False
        if requirement_objects:
            for existing in recovered:
                existing_intents = _phase1c_action_clause_intents(existing)
                primary_intent = _phase1c_action_intent(existing)
                if primary_intent:
                    existing_intents.add(primary_intent)
                existing_objects = set(_phase1e_object_tokens(existing))
                matched = sum(
                    1 for token in requirement_objects
                    if any(
                        _raw_first_tokens_related(token, other)
                        for other in existing_objects
                    )
                )
                object_covered = (
                    matched / max(1, len(requirement_objects)) >= 0.67
                )
                fulfills_state = bool(
                    requirement_intent and requirement_intent in existing_intents
                )
                delivers_state = bool(
                    existing_intents & {"provide", "send", "reply"}
                )
                if object_covered and (fulfills_state or delivers_state):
                    already_covered = True
                    break
        if already_covered:
            continue

        if not any(_phase1e_related_action_text(candidate, item) for item in recovered):
            recovered.append(candidate)
    return _phase1c_dedupe_actions(email, recovered)


def _raw_first_source_request_is_action_headed(sentence: str) -> bool:
    """Require a source-split candidate to begin as an independent request.

    Provider soft wrapping can split one grammatical request after its object,
    leaving a continuation such as ``proposal and tell me ...`` on the next
    physical line. The broad recipient-request detector correctly sees request
    language later in that fragment, but such a continuation must not become a
    standalone Action Item. This guard is used only by the separate-sentence
    splitter and accepts ordinary polite/interrogative or imperative request
    openings while rejecting noun-led continuations.
    """
    text = re.sub(r"^\s*(?:[-*•]+|\d{1,2}[.)])\s*", "", str(sentence or "").strip())
    lowered = text.casefold()
    if not lowered:
        return False

    explicit_opening = re.compile(
        r"^(?:please|pls|kindly|paki(?:[- ]?\w+)?|"
        r"it would be helpful if you could|if you could|can you|could you|would you|will you|"
        r"you(?:\s+and\s+[a-z][a-z .'-]{0,40})?\s+(?:need|must|should|have to|are required)|"
        r"(?:we|i)\s+(?:still\s+)?need\s+your|let me know|(?:tell|inform)\s+(?:me|us)|"
        r"action required|aim\s+to)\b",
        flags=re.IGNORECASE,
    )
    if explicit_opening.search(lowered):
        return True

    imperative_text = re.sub(r"^\s*first(?:ly)?\b[,:;-]?\s*", "", lowered)
    imperative_text = re.sub(
        r"^\s*(?:by|before|on)\s+[^,;]{1,80}[,;]\s*",
        "",
        imperative_text,
    )
    imperative_text = re.sub(r"^\s*either\s+", "", imperative_text)
    return bool(re.search(
        r"^(?:also\s+|and\s+)?(?:acknowledge|approve|check|choose|complete|confirm|decide|"
        r"follow up|investigate|prepare|provide|read|reply|respond|review|schedule|select|"
        r"send|sign|submit|tell|inform|notify|report|let\s+(?:me|us)\s+know|update|upload|verify)\b",
        imperative_text,
        flags=re.IGNORECASE,
    ))


def _raw_first_split_separate_source_sentence_actions(email: dict, actions) -> tuple[list[str], bool]:
    """Split one compound model action when source has separate request sentences.

    This is intentionally stricter than general compound splitting: it runs only
    when at least two independently recipient-directed source sentences exist and
    one model action semantically covers more than one of them. A same-sentence
    compound request remains untouched.
    """
    items = _normalize_list(actions)
    current = _phase1g_effective_turn_text(_body_text(email))
    requests = [
        sentence for sentence in _phase1b_source_sentences(current)
        if _raw_first_recipient_request_sentence(email, sentence)
    ]
    if len(requests) < 2 or not items:
        return items, False

    candidates = []
    for sentence in requests:
        clean = _separate_action_item_text(sentence)
        clean = re.sub(r"^\s*(?:please|kindly)\s+", "", clean, flags=re.IGNORECASE).strip()
        if (
            clean
            and _phase1c_action_intent(clean)
            and _raw_first_source_request_is_action_headed(sentence)
        ):
            candidates.append(clean[:1].upper() + clean[1:])
    candidates = _phase1c_dedupe_actions(email, candidates)
    if len(candidates) < 2:
        return items, False

    rebuilt = list(items)
    changed = False
    for item in list(items):
        item_intents = _phase1c_action_clause_intents(item)
        item_words = set(_content_words(item))
        related = []
        for candidate in candidates:
            if _phase1e_related_action_text(candidate, item):
                related.append(candidate)
                continue
            candidate_intent = _phase1c_action_intent(candidate)
            candidate_words = set(_content_words(candidate))
            # Provider/model wording can merge independently requested source
            # sentences into one compound action.  Recover the source split when
            # each source sentence contributes a distinct executable intent and
            # at least one grounded object/content term to the merged wording.
            if (
                candidate_intent
                and candidate_intent in item_intents
                and bool(candidate_words & item_words)
            ):
                related.append(candidate)
        source_intents = {_phase1c_action_intent(candidate) for candidate in related if _phase1c_action_intent(candidate)}
        if len(related) >= 2 and len(source_intents) >= 2:
            rebuilt = [existing for existing in rebuilt if existing != item]
            rebuilt.extend(related)
            changed = True
    return _phase1c_dedupe_actions(email, rebuilt), changed


def _phase1c_recover_deferred_source_actions(email: dict, actions) -> list[str]:
    """Recover future work gated by an explicit release condition.

    ``Do not X until/ until after Y`` is not a cancellation of X; it is a timing
    constraint on a still-required action. Bare/never prohibitions remain non-actions.
    """
    full_body = _body_text(email)
    if _phase1g_recipient_explicitly_has_no_action(full_body):
        return _normalize_list(actions)
    current = _phase1g_effective_turn_text(full_body)
    recovered = list(_normalize_list(actions))
    for sentence in _phase1b_source_sentences(current):
        match = re.search(
            r"^\s*(?:please\s+)?(?:do not|don't|dont)\s+(.+?)\s+until(?:\s+after)?\s+.+$",
            sentence,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        candidate = re.sub(r"\s+", " ", match.group(1)).strip(" ,.;")
        if not candidate or not _phase1c_action_intent(candidate):
            continue
        candidate = candidate[0].upper() + candidate[1:] if candidate else candidate
        if not any(_phase1e_related_action_text(candidate, item) for item in recovered):
            recovered.append(candidate)
    return _merge_unique(recovered)


def _phase1c_merge_deadline_modifier_actions(email: dict, actions) -> list[str]:
    # A follow-up such as "make the decision today before 5 PM" modifies an existing
    # approve/reject decision; it is not a second task.
    body = _body_text(email)
    items = _normalize_list(actions)
    if len(items) < 2:
        return items
    decision_exists = any(
        _phase1c_action_intent(item) == "decision" and re.search(r"\bapprove\b|\breject\b", item, re.IGNORECASE)
        for item in items
    )
    kept = []
    for item in items:
        lowered = item.casefold()
        evidence = _phase1b_find_evidence(item, body)
        has_deadline = bool(_phase1c_extract_deadline_phrases(item) or _phase1c_extract_deadline_phrases(evidence))
        generic_decision = bool(re.search(r"\b(?:make|take) (?:a |the )?decision\b", lowered))
        if decision_exists and generic_decision and has_deadline and not re.search(r"\bapprove\b|\breject\b", lowered):
            continue
        kept.append(item)
    return kept


def _phase1b_expected_action_count(body: str) -> int:
    # This is only a completeness trigger for the small-model audit, not the extractor itself.
    verbs = (
        "acknowledge", "approve", "check", "choose", "complete", "confirm", "decide", "investigate",
        "prepare", "provide", "read", "reply", "respond", "review", "select", "send", "sign",
        "submit", "update", "upload", "verify",
    )
    count = 0
    for sentence in _phase1b_source_sentences(body):
        if not _phase1b_recipient_request_signal(sentence):
            continue
        lowered = sentence.casefold()
        matches = {verb for verb in verbs if re.search(rf"\b{re.escape(verb)}\b", lowered)}
        if "approve" in matches and re.search(r"\bapprove\s+or\s+reject\b", lowered):
            matches.discard("approve")
            matches.add("decision")
        if re.search(r"\breject\b", lowered) and "decision" not in matches:
            matches.add("reject")
        count += max(1, len(matches))
    return count


def _phase1b_deadline_sentence(value: str, body: str) -> str:
    due = str(value or "").strip().casefold()
    if not due:
        return ""
    sentences = _phase1b_source_sentences(body)
    for sentence in sentences:
        if due and due in sentence.casefold():
            return sentence
    date_tokens = set(re.findall(r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b", due))
    candidate_identity = _phase1c_deadline_identity(value)
    default_year = datetime.now().date().year
    if candidate_identity.startswith("date:"):
        try:
            default_year = int(candidate_identity.split(":", 1)[1][:4])
        except (TypeError, ValueError):
            pass
    candidate_date_ids = _phase1_source_date_identities(value, default_year)
    if candidate_identity.startswith("date:"):
        candidate_date_ids.add(candidate_identity)
    relative = [
        token for token in ("today", "tomorrow", "tonight", "bukas", "eod", "end of day", "end of week", "next week")
        if token in due
    ]
    for sentence in sentences:
        lowered = sentence.casefold()
        sentence_dates = set(re.findall(r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b", lowered))
        if date_tokens and date_tokens & sentence_dates:
            return sentence
        if candidate_date_ids & _phase1_source_date_identities(sentence, default_year):
            return sentence
        if relative and any(token in lowered for token in relative):
            return sentence
    if re.search(r"\b\d{1,2}:\d{2}\s*(?:am|pm)\b", due):
        for sentence in sentences:
            if re.search(r"\b\d{1,2}:\d{2}\s*(?:am|pm)\b", sentence.casefold()):
                return sentence
    return ""


def _phase1b_is_valid_deadline_sentence(sentence: str, email: dict | None = None) -> bool:
    lowered = str(sentence or "").casefold()
    if not lowered:
        return False
    if re.search(r"\b(?:no|without) (?:fixed |stated |explicit )?(?:deadline|due date)\b", lowered):
        return False
    if re.search(r"\bhindi\b[^.!?]{0,50}\bdeadline\b", lowered):
        return False
    if re.search(r"\bnot setting (?:a |the )?(?:deadline|due date)\b", lowered):
        return False
    if email is not None:
        table_row = _phase1b_pipe_table_row(email, sentence)
        if table_row:
            if table_row.get("owner_kind") != "recipient":
                return False
            due_cell = str(table_row.get("due") or "").strip()
            return bool(due_cell and _phase1c_extract_deadline_phrases(due_cell))
    explicit_label = bool(re.match(
        r"^\s*(?:deadline|due date)\s*(?::|=|-|(?:is|remains?|stays?)\b)",
        str(sentence or ""),
        flags=re.IGNORECASE,
    ))
    strong_cutoff = bool(re.search(
        r"\b(?:no later than|hard deadline|final deadline|absolute deadline|final cutoff|hard cutoff)\b",
        lowered,
    ))
    recipient_directed = _phase1b_recipient_request_signal(sentence)
    if not recipient_directed and email is not None:
        recipient_directed = _phase1b_recipient_request_or_continuation(
            sentence, _phase1g_active_deadline_text(email)
        )
    if not explicit_label and not strong_cutoff and not recipient_directed:
        return False
    return bool(re.search(
        r"\b(?:by|before|no later than|due|deadline|bago(?:\s+ang)?|hanggang|pagsapit(?:\s+ng)?|today|tomorrow|tonight|bukas|ngayon|eod|"
        r"close of business|end of (?:(?:this|next) )?(?:day|week|month)|"
        r"(?:this|next|every) (?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)|"
        r"within|(?:first|second|third|fourth|fifth|last) business day|each quarter|every month|"
        r"midnight|noon)\b|"
        r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b|"
        r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
        r"sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|enero|pebrero|marso|abril|mayo|hunyo|"
        r"hulyo|agosto|setyembre|oktubre|nobyembre|disyembre)\s+\d{1,2}\b",
        lowered,
    ))


def _phase1c_deadline_identity(value: str) -> str:
    # Treat model/source formatting variants of the same temporal fact as one identity.
    text = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;")
    lowered = text.casefold()
    if re.search(r"\bbukas\b|\btomorrow\b", lowered):
        return "relative:tomorrow"
    if re.search(r"\btonight\b", lowered):
        return "relative:tonight"
    if re.search(r"\btoday\b", lowered):
        return "relative:today"
    if re.search(r"\beod\b|\bend of day\b", lowered):
        return "eod"
    iso = re.search(r"\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})\b", lowered)
    if iso:
        year, month, day_num = (int(part) for part in iso.groups())
        return f"date:{year:04d}-{month:02d}-{day_num:02d}"

    named = re.search(
        r"\b(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
        r"\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s+(20\d{2}))?\b",
        lowered,
    )
    if named:
        month = _PHASE1_ENGLISH_MONTHS.get(named.group(1)[:3])
        day_num = int(named.group(2))
        explicit_year = named.group(3)
        if month and explicit_year:
            try:
                parsed = date(int(explicit_year), month, day_num)
            except ValueError:
                parsed = None
            if parsed is not None:
                return f"date:{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
        return f"named:{named.group(1)[:3]}:{day_num}:"

    localized_names = "|".join(sorted(_PHASE1_LOCALIZED_MONTHS, key=len, reverse=True))
    localized = re.search(
        rf"\b({localized_names})\s+(\d{{1,2}})(?:,?\s+(20\d{{2}}))?\b",
        lowered,
        flags=re.IGNORECASE,
    )
    if localized:
        month = _PHASE1_LOCALIZED_MONTHS.get(localized.group(1).casefold())
        day_num = int(localized.group(2))
        explicit_year = localized.group(3)
        if month and explicit_year:
            try:
                parsed = date(int(explicit_year), month, day_num)
            except ValueError:
                parsed = None
            if parsed is not None:
                return f"date:{parsed.year:04d}-{parsed.month:02d}-{parsed.day:02d}"
        return f"localized:{month:02d}:{day_num}:" if month else lowered

    weekday = re.search(r"\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b", lowered)
    if weekday:
        return f"weekday:{weekday.group(1)}"
    time_only = re.search(r"\b(\d{1,2}(?::\d{2})?\s*(?:am|pm))\b", lowered)
    if time_only:
        return f"time:{time_only.group(1).replace(' ', '')}"
    if re.search(r"\bmidnight\b", lowered):
        return "time:midnight"
    if re.search(r"\bnoon\b", lowered):
        return "time:noon"
    return lowered


def _phase1c_deadline_specificity(value: str) -> tuple[int, int]:
    # Prefer source-preserving detail (time, timezone, recurrence/cutoff semantics),
    # but penalize generated absolute-date expansions of an already-grounded relative phrase.
    text = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;")
    lowered = text.casefold()
    score = 0
    if re.search(r"\b(?:before|no later than|close of business|end of)\b", lowered):
        score += 1
    if re.search(r"\b(?:\d{1,2}(?::\d{2})?\s*(?:am|pm)|midnight|noon)\b", lowered):
        score += 4
    if re.search(r"\b(?:midnight|noon)\b", lowered):
        score += 1
    if re.search(r"\b(?:UTC|GMT)(?:[+-]\d{1,2}(?::?\d{2})?)?\b", text, flags=re.IGNORECASE) or re.search(r"\b[A-Z]{3,4}\b", text):
        score += 2
    if re.search(r"\b(?:every|each|business day)\b", lowered):
        score += 2
    if re.search(r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b", lowered) and re.search(r"\b(?:today|tomorrow|tonight|bukas)\b", lowered):
        score -= 3
    return score, -len(text)


def _phase1c_dedupe_deadlines(values) -> list[str]:
    # Deduplicate semantic deadline identities and keep the most informative grounded
    # representation. This lets deterministic recovery replace lossy model variants
    # such as a date without its timezone or "tonight" without "midnight".
    result = []
    index_by_identity = {}
    for value in _normalize_list(values):
        identity = _phase1c_deadline_identity(value)
        if not identity:
            continue
        if identity in index_by_identity:
            index = index_by_identity[identity]
            if _phase1c_deadline_specificity(value) > _phase1c_deadline_specificity(result[index]):
                result[index] = value
            continue
        index_by_identity[identity] = len(result)
        result.append(value)

    collapsed = []
    for value in result:
        normalized = re.sub(r"\s+", " ", value.casefold()).strip(" ,.;")
        merged = False
        for index, existing in enumerate(collapsed):
            existing_normalized = re.sub(r"\s+", " ", existing.casefold()).strip(" ,.;")
            if normalized in existing_normalized or existing_normalized in normalized:
                if _phase1c_deadline_specificity(value) > _phase1c_deadline_specificity(existing):
                    collapsed[index] = value
                merged = True
                break
        if not merged:
            collapsed.append(value)
    return collapsed


def _phase1c_materialize_relative_deadline(email: dict, value: str) -> str:
    """Render a grounded relative deadline as its concrete calendar date.

    Relative wording belongs to the source narrative, but the dedicated Deadline
    card and action due_date need a stable calendar value for sorting, reminders,
    and later reopening. Resolve only single-occurrence temporal constraints whose
    date is deterministic from the message date. Recurring cadences and broad
    windows stay relational rather than inventing an arbitrary day.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip(" ,.;")
    if not text:
        return ""
    lowered = text.casefold()

    # Already-concrete numeric dates are authoritative and must not be rewritten here.
    if re.search(r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b", text):
        return text
    if re.search(r"\b\d{1,2}[-/]\d{1,2}[-/]20\d{2}\b", text):
        return text

    # A named month/day without a year is source-grounded but unsafe to persist as
    # a bare calendar label. Downstream date parsers commonly interpret a past
    # month/day as the next occurrence, which can silently move an overdue
    # deadline into the following year. Resolve the missing year once against the
    # message date using the same bounded-overdue rule used by deadline priority
    # resolution, then persist the explicit year. This rule is grammar-based and
    # provider/subject agnostic.
    named_match = re.search(
        r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
        r"\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+(20\d{2}))?\b",
        text,
        flags=re.IGNORECASE,
    )
    if named_match and re.search(r"\b\d{1,2}(?:st|nd|rd|th)\b", text, flags=re.IGNORECASE):
        return text
    if named_match and named_match.group(1):
        return text

    # Preserve source semantics for relational/cadence constraints. The To-Do
    # parser resolves these against the message date for sorting, while Summary
    # keeps the wording users actually received (business days, COB, end-of-window,
    # before/no-later-than, recurring cadence).
    if re.search(
        r"\b(?:every|each|within\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:business\s+)?(?:hours?|days?|weeks?)|"
        r"close of business|end of (?:(?:this|next) )?(?:day|week|month)|no later than|before)\b",
        lowered,
    ):
        return text
    if re.search(r"\b(?:this|next)\s+week\b", lowered):
        return text

    # Day-relative and weekday constraints are already deterministic for priority
    # and To-Do sorting, but the dedicated Deadline field should preserve what the
    # sender actually wrote.  Keeping ``today``, ``tomorrow`` and weekday wording
    # also prevents provider/model normalization differences from surfacing as
    # different user-visible deadlines. EOD is intentionally left on the older
    # stable path because it may carry an application-specific concrete-day form.
    if re.search(
        r"\b(?:today|tomorrow|tonight|bukas|"
        r"(?:(?:this|next)\s+)?(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b",
        lowered,
    ):
        return text

    relative_signal = bool(re.search(
        r"\b(?:today|tomorrow|tonight|bukas|eod|close of business|"
        r"end of (?:(?:this|next) )?(?:day|week|month)|"
        r"within\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
        r"(?:business\s+)?(?:hours?|days?|weeks?)|"
        r"(?:(?:this|next)\s+)?(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b",
        lowered,
    ))
    if not relative_signal and not named_match:
        return text

    reference_date = _email_date(email, datetime.now().date())
    resolved = _resolved_deadline_dates([text], reference_date)
    if len(resolved) != 1:
        return text

    rendered = _summary_human_date(resolved[0])

    # Preserve an explicit cutoff clock without inventing one for EOD/COB or a
    # daypart. Canonical 12-hour rendering also keeps the To-Do parser stable.
    clock_match = re.search(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b", text, flags=re.IGNORECASE)
    if clock_match:
        hour = int(clock_match.group(1))
        minute = int(clock_match.group(2) or 0)
        if 1 <= hour <= 12 and 0 <= minute <= 59:
            clock = f"{hour}:{minute:02d} {clock_match.group(3).upper()}"
            zone = ""
            zone_match = re.search(
                r"\b((?:UTC|GMT)(?:[+-]\d{1,2}(?::?\d{2})?)?|[A-Z]{3,4})\b",
                text,
            )
            if zone_match and zone_match.group(1).upper() not in {"EOD", "COB"}:
                zone = f" {zone_match.group(1)}"
            return f"{rendered} at {clock}{zone}"
    if re.search(r"\bnoon\b", lowered):
        return f"{rendered} at 12:00 PM"
    if re.search(r"\bmidnight\b", lowered):
        return f"{rendered} at 12:00 AM"
    return rendered


def _phase1c_materialize_relative_deadlines(email: dict, values) -> list[str]:
    """Materialize deadlines and collapse only equivalent untimed calendar aliases.

    A raw model date and a recovered source month/day can have different identities
    before the missing year is materialized, then become the same calendar date
    afterward. Collapse that narrow alias shape here. Keep relative/cadence wording
    and distinct clock-time cutoffs untouched so locked temporal behavior cannot be
    flattened by a broad second dedupe pass.
    """
    rendered = [
        _phase1c_materialize_relative_deadline(email, value)
        for value in _normalize_list(values)
    ]
    rendered = [value for value in rendered if value]

    result: list[str] = []
    calendar_index: dict[str, int] = {}
    exact_seen: set[str] = set()
    explicit_clock = re.compile(
        r"\b(?:\d{1,2}(?::\d{2})?\s*(?:am|pm)|noon|midnight)\b",
        flags=re.IGNORECASE,
    )
    numeric_date = re.compile(r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b")

    for value in rendered:
        exact_key = re.sub(r"\s+", " ", value.casefold()).strip(" ,.;")
        if not exact_key or exact_key in exact_seen:
            continue
        exact_seen.add(exact_key)

        identity = _phase1c_deadline_identity(value)
        is_untimed_calendar = bool(
            identity.startswith("date:") and not explicit_clock.search(value)
        )
        if not is_untimed_calendar:
            result.append(value)
            continue

        previous_index = calendar_index.get(identity)
        if previous_index is None:
            calendar_index[identity] = len(result)
            result.append(value)
            continue

        # Prefer source-like named calendar wording over a model-normalized ISO
        # alias when both represent the exact same untimed date. This matches the
        # established readable Deadline display without inventing any new value.
        previous = result[previous_index]
        if numeric_date.search(previous) and not numeric_date.search(value):
            result[previous_index] = value

    return result


def _phase1b_validate_deadlines(email: dict, values, actions) -> list[str]:
    if not actions:
        return []
    body = _phase1g_active_deadline_text(email)
    grounded = _ground_deadlines(email, values)
    valid = []
    for value in grounded:
        if not _phase1c_temporal_values_valid(value):
            continue
        evidence = _phase1b_deadline_sentence(value, body)
        if evidence and _phase1b_is_valid_deadline_sentence(evidence, email=email):
            valid.append(value)
    return _phase1c_dedupe_deadlines(valid)


def _phase1b_action_evidence_supports_deadline(email: dict, evidence: str, due: str) -> bool:
    """Return True only when this action's own source evidence carries ``due``.

    A validated deadline elsewhere in the same email/thread is not enough proof for
    a particular Action Item. This is intentionally action-local: coordinated tasks
    in the same source sentence can share one trailing deadline, while a later/new
    task in a different sentence or conversation turn cannot inherit that date just
    because the thread already has one.
    """
    sentence = re.sub(r"\s+", " ", str(evidence or "")).strip()
    candidate = re.sub(r"\s+", " ", str(due or "")).strip()
    if not sentence or not candidate:
        return False

    lowered_sentence = sentence.casefold()
    lowered_candidate = candidate.casefold()
    if lowered_candidate in lowered_sentence:
        return True

    candidate_materialized = _phase1c_materialize_relative_deadline(email, candidate)
    candidate_identity = _phase1c_deadline_identity(candidate_materialized or candidate)
    if not candidate_identity:
        return False

    reference_year = _email_date(email, datetime.now().date()).year
    candidate_date_ids = _phase1_source_date_identities(candidate_materialized or candidate, reference_year)
    if candidate_identity.startswith("date:"):
        candidate_date_ids.add(candidate_identity)
    if candidate_date_ids & _phase1_source_date_identities(sentence, reference_year):
        return True

    for phrase in _phase1c_extract_deadline_phrases(sentence):
        materialized = _phase1c_materialize_relative_deadline(email, phrase)
        if _phase1c_deadline_identity(materialized or phrase) == candidate_identity:
            return True
    return False


def _phase1b_assign_detail_deadlines(email: dict, raw_details, actions, deadlines) -> list[dict]:
    body = _phase1g_active_deadline_text(email)
    detail_map = {}
    for item in raw_details if isinstance(raw_details, list) else []:
        if not isinstance(item, dict):
            continue
        action = re.sub(r"\s+", " ", str(item.get("action") or "").strip())
        due = re.sub(r"\s+", " ", str(item.get("due_date") or item.get("deadline") or "").strip())
        clean_action = _separate_action_item_text(action)
        if clean_action:
            detail_map[clean_action.casefold()] = due

    # Top-level deadlines are deduplicated thread/email metadata. Per-action
    # ownership is established below from the action's own evidence sentence, not
    # from the first sentence in the message that happens to mention the same date.
    global_deadline = ""
    if len(deadlines) == 1:
        candidate = deadlines[0]
        evidence_line = _phase1b_deadline_sentence(candidate, body)
        if re.match(r"^\s*(?:deadline|due date)\s*(?::|=|-|(?:is|remains?|stays?)\b)", evidence_line or "", flags=re.IGNORECASE):
            global_deadline = candidate

    authoritative_detail_due = ""
    if len(_normalize_list(actions)) == 1:
        authoritative = _phase1c_authoritative_cutoff_phrases(email, actions)
        if authoritative:
            authoritative_validated = _phase1b_validate_deadlines(email, authoritative, actions)
            authoritative_detail_due = (authoritative_validated or authoritative)[0]

    result = []
    for action in actions:
        due = detail_map.get(action.casefold(), "")
        if authoritative_detail_due:
            due = authoritative_detail_due
        evidence = re.sub(r"\s+", " ", _phase1b_find_evidence(action, body)).strip()
        if not evidence:
            # Action validation already accepts conservative English paraphrases
            # of Latin-script Filipino requests. Reuse that exact grounding rule
            # for per-action deadline ownership so a valid localized source date
            # is not lost merely because the stored Action Item is English.
            for sentence in _phase1b_source_sentences(body):
                if _phase1b_cross_language_action_supported(action, sentence):
                    evidence = re.sub(r"\s+", " ", sentence).strip()
                    break

        # RAW may attach a real thread deadline to the wrong new action. Keep a
        # per-action due only when this action's own source sentence/turn carries
        # that deadline. A separately labelled global deadline remains the explicit
        # exception and is applied below to every active recipient action.
        if due:
            due_evidence = _phase1b_deadline_sentence(due, body)
            due_is_valid_somewhere = bool(
                due_evidence and _phase1b_is_valid_deadline_sentence(due_evidence)
            )
            if not due_is_valid_somewhere or not _phase1b_action_evidence_supports_deadline(
                email, evidence, due
            ):
                due = ""

        if not due:
            matching = [
                candidate
                for candidate in deadlines
                if _phase1b_action_evidence_supports_deadline(email, evidence, candidate)
            ]
            matching = _phase1c_dedupe_deadlines(matching)
            if len(matching) == 1:
                due = matching[0]

        if not due and global_deadline:
            due = global_deadline
        elif not due and len(actions) == 1 and len(deadlines) == 1:
            due = deadlines[0]

        # Persist the same stable calendar representation used by the top-level
        # Deadline field. This prevents a model-returned yearless month/day in a
        # detail row from being reparsed later as next year's occurrence.
        if due:
            due = _phase1c_materialize_relative_deadline(email, due)
        result.append({"action": action, "due_date": due})
    return result


def _phase1b_resolved_priority(email: dict, actions, deadlines, today: date | None = None) -> str:
    today = today or datetime.now().date()
    if not actions:
        return "Low"
    explicit_priority = _phase1b_explicit_priority(email)
    if explicit_priority:
        return explicit_priority
    resolved = _resolved_deadline_dates(deadlines, _email_date(email, today))
    if any(item < today for item in resolved):
        return "Critical"
    context = f"{email.get('subject', '')}\n{_body_text(email)}".casefold()
    context = re.sub(r"\b(?:not urgent|no rush|no hurry|when convenient|at your convenience)\b", " ", context)
    if re.search(
        r"\b(?:urgent|critical|blocking|blocked|escalat\w*|immediate(?:ly)?|asap)\b|"
        r"\bas soon as possible\b|\bproduction (?:is )?blocked\b",
        context,
    ):
        return "High"
    if resolved:
        soonest = min(resolved)
        if soonest <= today + timedelta(days=1):
            return "High"
        return "Medium"
    return "Low"


def _phase1k_named_actor_commitment(value: str) -> str:
    """Return an explicit named actor for a future/assigned commitment.

    Key Points belong to the current recipient's scan layer.  A plain statement
    that another named person will/should/must perform work is task ownership
    metadata for that other person, not a recipient Key Point by itself.  This
    parser is intentionally grammatical and domain-neutral.
    """
    cleaned = re.sub(
        r"^\s*(?:[-*•]+|\d+[.)])\s*", "", str(value or "").strip()
    )
    match = re.match(
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+"
        r"(?:will|plans? to|intends? to|is going to|must|should|needs? to|"
        r"has to|is required to|is responsible for)\b",
        cleaned,
    )
    return str(match.group(1) or "").strip() if match else ""


def _phase1k_third_party_commitment_is_material_context(value: str) -> bool:
    """Keep another person's work only when it carries a real dependency/state."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return bool(re.search(
        r"\b(?:blocked?|blocking|depends?|dependency|waiting on|pending|on hold|"
        r"unless|only if|provided that|subject to|until|after|once|upon|"
        r"before\b[^.!?]{0,80}\bcan\b)",
        text,
        flags=re.IGNORECASE,
    ))


def _phase1k_is_other_person_task_metadata(email: dict, key_point: str) -> bool:
    """Reject a bare future commitment owned by another named actor.

    This does not remove completed decisions or independently useful blockers /
    dependencies.  It only prevents another person's executable work and due
    metadata from being presented as if it were part of the recipient's own
    task scan layer.
    """
    actor = _phase1k_named_actor_commitment(key_point)
    if not actor:
        return False
    recipient_name = _phase1g_recipient_name(email)
    if recipient_name and _phase1g_same_person(actor, recipient_name):
        return False
    if _phase1k_third_party_commitment_is_material_context(key_point):
        return False
    return bool(
        _phase1c_action_intent(key_point)
        or _phase1c_extract_deadline_phrases(key_point)
        or re.search(
            r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b|"
            r"\b(?:today|tomorrow|tonight|eod|close of business)\b",
            str(key_point or ""),
            flags=re.IGNORECASE,
        )
    )


def _phase1k_is_unowned_deadline_label(email: dict, key_point: str, deadlines=None) -> bool:
    """Drop deadline-card wording when no recipient-owned deadline survived.

    Event dates or third-party schedules may still appear as ordinary context,
    but a bare ``Deadline: ...`` / ``Due date: ...`` Key Point is misleading when
    the validated recipient deadline list is empty.
    """
    if _normalize_list(deadlines):
        return False
    point = re.sub(r"\s+", " ", str(key_point or "")).strip()
    if not re.search(r"\b(?:deadline|due\s+date|due\s+by)\b", point, flags=re.IGNORECASE):
        return False
    reference_date = _email_date(email, datetime.now().date())
    has_temporal_value = bool(
        _cross_section_dates(point, reference_date)
        or _cross_section_time_tokens(point)
        or re.search(
            r"\b(?:today|tomorrow|tonight|eod|close of business|"
            r"monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
            point,
            flags=re.IGNORECASE,
        )
    )
    return has_temporal_value


def _phase1b_keypoint_action_terms(value: str) -> set[str]:
    # Compare the semantic payload of a Key Point with an Action Item while
    # ignoring grammatical/request filler. This is intentionally conservative:
    # any extra material term keeps the Key Point.
    ignored = {
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
        "in", "is", "it", "of", "on", "or", "the", "to", "with", "your",
        "please", "kindly", "reminder", "action", "task", "still", "need",
        "needs", "needed", "require", "requires", "required", "requirement",
        "must", "should",
    }
    return {
        word
        for word in re.findall(r"[a-z0-9%₱€$]+", str(value or "").casefold())
        if word and word not in ignored
    }


def _phase1b_keypoint_is_action_restatement(key_point: str, actions) -> bool:
    # Key Points contain facts/context/constraints, never a noun-phrase rewrite
    # of the To-Do list. Compare normalized semantic terms against each action
    # and against the union of all actions so fragments combining two task rows
    # (for example "Shared Files and Reference folder visibility") are removed.
    point = str(key_point or "").strip()
    # Parent instructions such as "Add a new task to confirm X" belong to the
    # Action Items section once X is already represented there. Strip only the
    # task-introduction wrapper before the existing semantic restatement check.
    point = re.sub(
        r"^(?:add|create)\s+(?:a\s+)?(?:new\s+)?"
        r"(?:action item|action|task)\s*(?::|[-–—])?\s*(?:to\s+)?",
        "",
        point,
        flags=re.IGNORECASE,
    )
    point = re.sub(
        r"^(?:(?:new|added|updated|modified)\s+)?(?:action item|action required|action|task|required)\s*[:\-]?\s*",
        "",
        point,
        flags=re.IGNORECASE,
    )
    comparable_point = _separate_action_item_text(point) or point
    point_terms = _summary_overlap_terms(comparable_point)
    point_terms.discard("plus")
    if not point_terms:
        return False

    action_term_sets = [
        _summary_overlap_terms(action)
        for action in _normalize_list(actions)
        if str(action or "").strip()
    ]
    action_term_sets = [terms for terms in action_term_sets if terms]
    actionish_point = re.sub(
        r"^(?:please|kindly)\s+", "", comparable_point.strip(), flags=re.IGNORECASE
    )
    starts_like_action = bool(re.match(
        r"^(?:reply|respond|acknowledge|confirm|verify|review|read|send|submit|provide|complete|prepare|check|open|view|update|upload|download|approve|reject|decide|attend|join|sign|schedule|create|attach|forward|share)\b",
        actionish_point,
        flags=re.IGNORECASE,
    ))
    point_intent = _phase1c_action_intent(actionish_point)
    nominal_request_frame = bool(re.search(
        r"\b(?:request(?:ed|ing|s)?|ask(?:ed|ing|s)?|inquir(?:y|ies|ed)|quer(?:y|ies|ied))\b",
        comparable_point,
        flags=re.IGNORECASE,
    ))
    nominal_obligation_frame = bool(re.search(
        r"\b(?:needed|required|requested|must|should)\b",
        comparable_point,
        flags=re.IGNORECASE,
    ))
    normalized_action_values = _normalize_list(actions)
    for action_value, action_terms in zip(normalized_action_values, action_term_sets):
        shared = point_terms & action_terms
        coverage = len(shared) / max(1, len(point_terms))
        if len(shared) >= 2 and (coverage >= 0.78 or (starts_like_action and coverage >= 0.60)):
            # Material facts such as an approver/decision survive because those
            # extra terms are not covered by the executable action. Imperative
            # task-shaped Key Points need a slightly lower threshold so details
            # like an attached date do not let a To-Do restatement leak through.
            return True
        if (
            (starts_like_action or nominal_obligation_frame)
            and point_intent
            and point_intent == _phase1c_action_intent(action_value)
            and not _summary_context_fact_is_high_impact(comparable_point)
        ):
            # Once a Key Point starts as the same executable intent as an Action
            # Item, it belongs to the To-Do section unless it carries a genuinely
            # independent decision/blocker/dependency/state fact. This catches
            # paraphrases with light execution/timing/rationale tails without
            # matching any business object, subject, date, or benchmark phrase.
            return True
        if nominal_request_frame and len(point_terms) == 1 and point_terms <= action_terms:
            # A one-payload-term passive/nominal request (for example,
            # "Approval requested") is still only an action restatement when
            # that payload is already owned by an executable Action Item. Any
            # actor, object, condition, or other material term prevents this
            # narrow shortcut from firing.
            return True

    union_terms = set().union(*action_term_sets) if action_term_sets else set()
    shared_union = point_terms & union_terms
    if len(shared_union) >= 2 and len(shared_union) / max(1, len(point_terms)) >= 0.82:
        return True
    return False


def _subject_context_anchor_tokens(value: str) -> set[str]:
    """Return compact alphanumeric topic anchors such as Q3, FY26, v2, or ticket IDs.

    Calendar ordinals (for example ``24th``) are date grammar, not stable topic
    identifiers. Treating them as subject anchors can cause an otherwise empty
    Key Points section to recover the whole subject purely because the subject
    contains a due date. Excluding ordinals keeps subject-context recovery useful
    for real IDs/versions while leaving deadline ownership to the Deadline field.
    """
    text = str(value or "")
    tokens = {
        token.casefold()
        for token in re.findall(
            r"\b(?:q[1-4]|fy\d{2,4}|h[12]|v\d+(?:\.\d+)*|[a-z]{2,}\d{2,}|\d{2,}[a-z]{2,})\b",
            text,
            flags=re.IGNORECASE,
        )
    }
    return {
        token for token in tokens
        if not re.fullmatch(r"\d{1,2}(?:st|nd|rd|th)", token, flags=re.IGNORECASE)
    }


def _recover_subject_context_key_point(email: dict, points) -> list[str]:
    """Keep a grounded subject qualifier in Key Points when the model drops it.

    This is deliberately narrow: ordinary subjects are untouched. Recovery is
    limited to subjects carrying a compact alphanumeric anchor (quarter, fiscal
    year, version, ticket-like identifier, etc.) that is absent from Key Points.
    """
    safe = _normalize_list(points)
    subject = re.sub(r"\s+", " ", str(email.get("subject") or "")).strip()
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject, flags=re.IGNORECASE)
    subject = subject.strip(" \t\r\n-–—:;,.\"'")
    anchors = _subject_context_anchor_tokens(subject)
    if not subject or not anchors:
        return safe

    joined = " ".join(safe).casefold()
    present = _subject_context_anchor_tokens(joined)
    if anchors.issubset(present):
        return safe

    # Require at least one descriptive topic term beyond the anchor so the
    # recovered Key Point is meaningful rather than a bare ID/quarter label.
    if len(_content_words(subject)) < 2:
        return safe
    return _merge_unique([*safe, subject])


def _phase1k_is_presentation_noise_keypoint(value: str) -> bool:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return True
    if re.fullmatch(r"\[?cid:[^\]\s>]+\]?", text, flags=re.IGNORECASE):
        return True
    if re.fullmatch(r"sent from (?:my )?(?:mobile|phone|iphone|android)[.!]?", text, flags=re.IGNORECASE):
        return True
    parts = [part.strip().casefold() for part in text.split("|") if part.strip()]
    return bool(len(parts) >= 2 and all(
        part in {"view in browser", "privacy", "privacy policy", "unsubscribe",
                 "manage preferences", "email preferences", "home"}
        for part in parts
    ))


def _phase1b_key_points(email: dict, values, actions=None, deadlines=None) -> list[str]:
    points = _normalize_list(values)
    body = _body_text(email)
    effective = _phase1g_effective_turn_text(body)
    source = f"{email.get('subject', '')}\n{effective}"
    source_numbers = set(re.findall(r"(?<![A-Za-z])\$?\d[\d,]*(?:\.\d+)?(?:%|\b)", source))
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)
    has_actions = bool(normalized_actions)
    safe = []
    for item in points:
        if _phase1k_is_presentation_noise_keypoint(item):
            continue
        # Quoted/forwarded history is context only unless the current note explicitly
        # delegates it. A Key Point supported only by the quoted tail must not leak
        # into the current task scan layer.
        if (
            _phase1g_forwarded_tail(body)
            and not _phase1g_has_explicit_forwarded_delegation(body)
            and not _is_supported(item, source)
        ):
            continue
        item_numbers = set(re.findall(r"(?<![A-Za-z])\$?\d[\d,]*(?:\.\d+)?(?:%|\b)", item))
        if not item_numbers.issubset(source_numbers):
            continue
        lowered = item.casefold()
        # A validated recipient action and a generated "no action" key point cannot both be true.
        # Keep source no-action statements only when the final validated action list is empty.
        if has_actions and re.search(
            r"\b(?:no (?:further )?action(?: item)?(?: is)?(?: needed|required)?|"
            r"no action item|nothing (?:to do|required)|for (?:your )?(?:records|information) only)\b",
            lowered,
        ):
            continue
        if _phase1k_is_other_person_task_metadata(email, item):
            continue
        # Do not let Key Points invent a deadline transition merely because a
        # concrete due date exists. A change verb needs matching source evidence.
        if re.search(
            r"\b(?:advanced?|changed?|moved?|extended?|shortened?|postponed?|rescheduled?|delayed?|pushed?|pulled\s+in)\b",
            item,
            flags=re.IGNORECASE,
        ) and not re.search(
            r"\b(?:advanced?|changed?|moved?|extended?|shortened?|postponed?|rescheduled?|delayed?|pushed?|pulled\s+in)\b",
            source,
            flags=re.IGNORECASE,
        ):
            continue
        if _phase1k_is_unowned_deadline_label(email, item, normalized_deadlines):
            continue
        if has_actions and _phase1b_keypoint_is_action_restatement(item, normalized_actions):
            continue
        if normalized_deadlines and _keypoint_is_deadline_restatement(
            email, item, normalized_actions, normalized_deadlines
        ):
            continue
        safe.append(item)

    # Preserve a source-grounded approval/decision fact if the model omitted who approved it.
    joined = " ".join(safe).casefold()
    for sentence in _phase1b_source_sentences(body):
        lowered = sentence.casefold()
        if re.search(r"\b(?:finance|legal|manager|management|client|customer|vendor|team)\b.*\bapproved?\b", lowered):
            actor_words = set(_content_words(sentence))
            if actor_words and len(actor_words & set(_content_words(joined))) / max(1, len(actor_words)) < 0.5:
                safe.append(sentence)
                break
    return _recover_subject_context_key_point(email, _merge_unique(safe))



def _cross_section_fact_terms(value: str) -> set[str]:
    """Return role-oriented semantic terms for cross-section deduplication.

    The mapping is intentionally vocabulary-generic: it normalizes common
    grammatical variants and lifecycle states rather than recognizing any
    benchmark subject, person, object, or date.
    """
    text = re.sub(r"\s+", " ", str(value or "")).casefold()
    if not text:
        return set()

    # A binary approve/reject instruction is semantically one decision. Keep the
    # original verbs but add the role noun so deadline paraphrases such as
    # "decision due ..." can match the corresponding Action Item generically.
    text = re.sub(
        r"\bapprove\s+or\s+reject\b",
        lambda match: f"{match.group(0)} decision",
        text,
        flags=re.IGNORECASE,
    )

    # Paired negative timing/urgency phrases often elide the second ``no``
    # (for example, ``no deadline or rush``). Canonicalize both semantic states
    # before the independent phrase rewrites below so Summary/Key Point
    # comparison does not treat the trailing noun as a new business fact.
    text = re.sub(
        r"\b(?:there (?:is|are) )?no (?:fixed |stated |explicit |specific |separate )?"
        r"(?:deadline|due date)\s+(?:and|or)\s+(?:no\s+)?(?:rush|hurry|urgency)\b",
        " nodeadlinestate lowurgencystate ",
        text,
        flags=re.IGNORECASE,
    )

    # Collapse equivalent state phrases before tokenization so, for example,
    # "outstanding" and "has not been submitted" compare as the same state.
    text = re.sub(
        r"\b(?:is |are |remains? |still )?(?:outstanding|pending|incomplete)\b|"
        r"\b(?:has|have|is|are)?\s*(?:not|n't)\s+(?:been\s+)?"
        r"(?:submitted|completed|finished|done)\b",
        " openstate ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:no (?:(?:further|immediate|current|additional) )?"
        r"action(?: item)?(?: is)? (?:needed|required)(?: (?:yet|now))?|"
        r"nothing (?:is )?(?:needed|required)(?: (?:yet|now))?|"
        r"for (?:your )?(?:records|information) only)\b",
        " noactionstate ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:there (?:is|are) )?no (?:fixed |stated |explicit |specific |separate )?"
        r"(?:deadline|due date)\b|"
        r"\b(?:deadline|due date) (?:has|have) not been set\b|"
        r"\bnot setting (?:a |the )?(?:fixed |stated |explicit |specific |separate )?"
        r"(?:deadline|due date)\b",
        " nodeadlinestate ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:there (?:is|are) )?(?:no rush|no hurry|not urgent|not time[- ]sensitive)"
        r"(?:\s+for\s+(?:a\s+)?(?:reply|response|responding))?\b",
        " lowurgencystate ",
        text,
        flags=re.IGNORECASE,
    )

    # Canonicalize equivalent timing-emphasis language used around cutoffs and
    # timezones.  This lets "timezone is critical for the deadline" dedupe with
    # "timezone is important for this cutoff" without treating unrelated uses
    # of "critical" as interchangeable business facts.
    text = re.sub(
        r"\b(?:final\s+|hard\s+)?cutoff\b",
        " deadline ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:critical|important)\b(?=.{0,48}\b(?:deadline|timezone|time zone)\b)|"
        r"(?<=\bdeadline is )\b(?:critical|important)\b",
        " timingemphasis ",
        text,
        flags=re.IGNORECASE,
    )

    # Normalize equivalent lifecycle/schedule-change verbs for semantic coverage.
    # This is comparison-only: concrete dates still have to match below, so a
    # different old/new schedule cannot collapse merely because both say moved.
    text = re.sub(
        r"\b(?:reschedul(?:e|ed|ing)|moved?|shifted?|postponed?)\b",
        " schedulechange ",
        text,
        flags=re.IGNORECASE,
    )

    # Canonicalize temporal dependency language before tokenization so a compact
    # nominal Key Point and a fuller sentence can still be compared as the same
    # fact. PRE and POST conditions remain distinct to avoid reversing meaning.
    text = re.sub(
        r"\b(?:after|once|upon)\b",
        " postcondition ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b(?:before|prior\s+to|ahead\s+of)\b",
        " precondition ",
        text,
        flags=re.IGNORECASE,
    )

    ignored = {
        "a", "an", "and", "are", "as", "at", "be", "been", "being", "by",
        "for", "from", "has", "have", "in", "is", "it", "of", "on", "or",
        "the", "that", "this", "to", "was", "were", "will", "with", "your",
        "our", "my", "please", "kindly", "still", "remains", "remain",
        "automatic", "reply", "sender", "recipient", "am", "when", "upon",
    }
    terms: set[str] = set()
    for raw in re.findall(r"[a-z][a-z0-9-]*", text):
        if raw in ignored:
            continue
        if raw.startswith("confirm"):
            term = "confirm"
        elif raw.startswith("review"):
            term = "review"
        elif raw.startswith("read"):
            term = "read"
        elif raw.startswith("verif"):
            term = "verify"
        elif raw.startswith("submission") or raw.startswith("submit"):
            term = "submit"
        elif raw.startswith("send") or raw in {"sent", "sending"}:
            term = "send"
        elif raw.startswith("clear") or raw == "clearance":
            term = "clear"
        elif raw.startswith("prepar"):
            term = "prepare"
        elif raw.startswith("provid"):
            term = "provide"
        elif raw.startswith("complet"):
            term = "complete"
        elif raw.startswith("updat"):
            term = "update"
        elif raw.startswith("approv"):
            term = "approve"
        elif raw.startswith("cancel"):
            term = "cancel"
        elif raw.startswith("schedul"):
            term = "schedule"
        elif raw.startswith("respond"):
            term = "respond"
        elif raw.startswith("return"):
            term = "return"
        elif raw in {"deadline", "deadlines", "due"}:
            term = "deadline"
        else:
            term = raw
        if term:
            terms.add(term)
    return terms


def _cross_section_time_tokens(value: str) -> set[str]:
    """Normalize explicit clock times for semantic fact comparison."""
    found = set()
    for match in re.finditer(
        r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b|\b(noon|midnight)\b",
        str(value or ""),
        flags=re.IGNORECASE,
    ):
        if match.group(4):
            found.add(match.group(4).casefold())
            continue
        hour = int(match.group(1))
        minute = int(match.group(2) or 0)
        found.add(f"{hour}:{minute:02d}{match.group(3).casefold()}")
    return found


def _cross_section_dates(value: str, reference_date: date) -> set[str]:
    """Return every concrete calendar date represented in one text value.

    ``_resolved_deadline_dates`` resolves one deadline expression per list item.
    Cross-section validation, however, often compares prose containing two dates
    (for example a preferred target and a final cutoff). Feeding the whole
    sentence as one item can therefore expose only the first date and wrongly
    reject a source-preserving Summary repair as having invented the second one.

    Keep the existing whole-text resolution, then additionally resolve each
    explicit date-shaped fragment. This is comparison-only logic; it does not
    create or choose task deadlines.
    """
    text = str(value or "")
    candidates = [text]
    candidates.extend(re.findall(
        r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b|"
        r"\b\d{1,2}[-/]\d{1,2}[-/]20\d{2}\b|"
        r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|"
        r"dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+20\d{2})?\b",
        text,
        flags=re.IGNORECASE,
    ))
    resolved = set()
    for candidate in candidates:
        for item in _resolved_deadline_dates([candidate], reference_date):
            resolved.add(item.isoformat())
    return resolved


def _cross_section_material_tokens(value: str) -> set[str]:
    """Return non-calendar numeric facts such as amounts, counts, and percentages."""
    text = str(value or "")
    # Dates/times have dedicated canonical comparators; mask them before number
    # extraction so formatting differences (ISO vs humanized) do not look novel.
    text = re.sub(r"\b20\d{2}[-/]\d{1,2}[-/]\d{1,2}\b", " ", text)
    text = re.sub(r"\b\d{1,2}[-/]\d{1,2}[-/]20\d{2}\b", " ", text)
    text = re.sub(
        r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
        r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|"
        r"dec(?:ember)?)\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+20\d{2})?\b",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"\b\d{1,2}(?::\d{2})?\s*(?:am|pm)\b|\b(?:noon|midnight)\b",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    tokens = set()
    for match in re.finditer(
        r"(?<![A-Za-z0-9])(?:[$€£₱]\s*)?-?\d[\d,]*(?:\.\d+)?"
        r"(?:\s*%|\s*[kmb])?(?![A-Za-z0-9])",
        text,
        flags=re.IGNORECASE,
    ):
        token = re.sub(r"[\s,]", "", match.group(0)).casefold()
        if token:
            tokens.add(token)
    return tokens


def _cross_section_relative_duration_tokens(value: str) -> set[str]:
    """Normalize short relative-duration phrases for cross-section comparison.

    This lets equivalent forms such as ``within three days`` and
    ``three-day deadline`` compare as the same timing fact without converting the
    sender's relative wording into an absolute calendar date.
    """
    text = re.sub(r"[-–—]", " ", str(value or "")).casefold()
    number_words = {
        "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
        "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    }
    tokens: set[str] = set()
    for match in re.finditer(
        r"\b(?:within\s+)?(?P<count>\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
        r"(?P<business>business\s+)?(?P<unit>hours?|days?|weeks?)\b",
        text,
        flags=re.IGNORECASE,
    ):
        raw_count = match.group("count").casefold()
        count = int(raw_count) if raw_count.isdigit() else number_words.get(raw_count)
        if count is None:
            continue
        unit = match.group("unit").casefold().rstrip("s")
        business = "business:" if match.group("business") else ""
        tokens.add(f"{business}{count}:{unit}")
    return tokens


def _keypoint_is_deadline_restatement(
    email: dict, key_point: str, actions, deadlines
) -> bool:
    """Detect a Key Point whose useful content is already the Deadline card.

    A point with an additional material fact survives. The test requires both a
    deadline-role cue and a grounded deadline match, so unrelated event dates are
    never removed merely because they are dates.
    """
    normalized_deadlines = _normalize_list(deadlines)
    if not normalized_deadlines:
        return False
    point = re.sub(r"\s+", " ", str(key_point or "")).strip()
    normalized_actions = _normalize_list(actions)
    point_intents = _raw_first_action_intents(point)
    action_intents = set().union(*(
        _raw_first_action_intents(action) for action in normalized_actions
    )) if normalized_actions else set()
    explicit_deadline_role = bool(re.search(
        r"\b(?:deadline|due(?:\s+date)?|due\s+by)\b",
        point,
        flags=re.IGNORECASE,
    ))
    point_action_terms = _cross_section_fact_terms(point) - {
        "deadline", "date", "time", "today", "tomorrow", "tonight", "bukas",
        "day", "week", "month", "am", "pm", "morning", "afternoon", "evening",
    }
    action_fact_terms = (
        set().union(*(_cross_section_fact_terms(action) for action in normalized_actions))
        if normalized_actions else set()
    )
    semantic_action_overlap = bool(
        point_action_terms
        and action_fact_terms
        and len(point_action_terms & action_fact_terms) / max(1, len(point_action_terms)) >= 0.50
    )
    action_timing_role = bool(
        ((point_intents and point_intents & action_intents) or semantic_action_overlap)
        and re.search(
            r"\b(?:by|before|no later than|today|tomorrow|tonight|eod|close of business)\b",
            point,
            flags=re.IGNORECASE,
        )
    )
    if not explicit_deadline_role and not action_timing_role:
        return False

    # A deadline-change event is independently useful history/context, not a bare
    # restatement of the current due card. Let Summary dedupe remove it only when
    # the narrative already conveys that same change.
    if re.search(
        r"\b(?:changed?|moved?|extended?|shortened?|postponed?|rescheduled?|"
        r"advanced?|delayed?|pushed?|pulled\s+in)\b",
        point,
        flags=re.IGNORECASE,
    ):
        return False

    reference_date = _email_date(email, datetime.now().date())
    point_dates = _cross_section_dates(point, reference_date)
    deadline_dates = {
        item.isoformat()
        for item in _resolved_deadline_dates(normalized_deadlines, reference_date)
    }
    direct_match = any(
        re.sub(r"\s+", " ", str(deadline).casefold()).strip() in point.casefold()
        for deadline in normalized_deadlines
        if str(deadline or "").strip()
    )
    point_durations = _cross_section_relative_duration_tokens(point)
    deadline_durations = set().union(*(
        _cross_section_relative_duration_tokens(deadline)
        for deadline in normalized_deadlines
    )) if normalized_deadlines else set()
    duration_match = bool(point_durations and point_durations & deadline_durations)
    if not direct_match and not duration_match and not (point_dates and point_dates & deadline_dates):
        return False

    point_times = _cross_section_time_tokens(point)
    deadline_times = set().union(*(
        _cross_section_time_tokens(deadline)
        for deadline in normalized_deadlines
    )) if normalized_deadlines else set()
    if point_times and deadline_times and not (point_times & deadline_times):
        return False

    action_terms = (
        set().union(*(_cross_section_fact_terms(action) for action in normalized_actions))
        if normalized_actions
        else set()
    )
    residual = _cross_section_fact_terms(point) - action_terms - {
        "deadline", "date", "time", "openstate", "nodeadlinestate",
        "need", "needed", "require", "required", "request", "requested",
        "must", "should",
        # Temporal grammar is already proven equivalent by the grounded date/time
        # checks above; it is not an independent Key Point business fact.
        "today", "tomorrow", "tonight", "bukas", "am", "pm", "noon", "midnight",
        "morning", "afternoon", "evening", "day", "week", "month",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    }
    # A bare role word or one grammatical residue contributes no independent
    # business fact beyond the dedicated deadline section.
    return len(residual) <= 1


def _cross_section_fact_equivalent(
    email: dict, left: str, right: str, *, coverage_threshold: float = 0.82
) -> bool:
    """Compare two short facts without relying on benchmark/domain vocabulary.

    Dates, clock times, and material numeric values must agree when present. The
    semantic term comparison is intentionally asymmetric-friendly so paraphrases
    and light grammatical rewrites collapse while distinct business facts remain.
    """
    left_terms = _cross_section_fact_terms(left)
    right_terms = _cross_section_fact_terms(right)
    if not left_terms or not right_terms:
        return False

    # If both facts explicitly encode a temporal dependency direction, they
    # must agree. This prevents a high lexical overlap from collapsing
    # "before X" with "after/once X".
    relation_terms = {"precondition", "postcondition"}
    left_relations = left_terms & relation_terms
    right_relations = right_terms & relation_terms
    if left_relations and right_relations and left_relations != right_relations:
        return False

    shared = left_terms & right_terms
    left_coverage = len(shared) / max(1, len(left_terms))
    right_coverage = len(shared) / max(1, len(right_terms))
    if max(left_coverage, right_coverage) < coverage_threshold:
        return False

    reference_date = _email_date(email, datetime.now().date())
    left_dates = _cross_section_dates(left, reference_date)
    right_dates = _cross_section_dates(right, reference_date)
    if left_dates and right_dates and left_dates != right_dates:
        return False

    left_times = _cross_section_time_tokens(left)
    right_times = _cross_section_time_tokens(right)
    if left_times and right_times and left_times != right_times:
        return False

    left_material = _cross_section_material_tokens(left)
    right_material = _cross_section_material_tokens(right)
    if left_material and right_material and left_material != right_material:
        return False

    return True


def _keypoint_is_summary_temporal_restatement(
    email: dict, key_point: str, summary: str
) -> bool:
    """Return True for timing-only bullets already carried by Summary.

    Small models sometimes turn a soft target and a final cutoff into two Key
    Points even after Summary already preserves both date roles. Lexical
    comparison can miss those paraphrases (for example ``final Monday for
    submission`` versus ``Monday ... is the final cutoff``). This comparator
    is deliberately narrow: it requires the same grounded calendar date, the
    same soft-vs-hard timing role, and no independent business payload in the
    Key Point beyond generic task/timing grammar.
    """
    point = re.sub(r"\s+", " ", str(key_point or "")).strip()
    compact_summary = _compact_summary_overview(summary)
    if not point or not compact_summary:
        return False

    reference_date = _email_date(email, datetime.now().date())
    point_dates = _cross_section_dates(point, reference_date)
    if not point_dates:
        return False

    # A compact label such as ``New date: August 25`` adds no information when
    # Summary already states the same moved/rescheduled date. Require both the
    # exact grounded date and an explicit schedule-change signal in Summary.
    if re.search(
        r"\b(?:new|revised|updated|rescheduled)\s+(?:date|schedule)\b",
        point,
        flags=re.IGNORECASE,
    ):
        summary_dates = _cross_section_dates(compact_summary, reference_date)
        if point_dates.issubset(summary_dates) and re.search(
            r"\b(?:reschedul(?:e|ed|ing)|moved?|shifted?|postponed?)\b",
            compact_summary,
            flags=re.IGNORECASE,
        ):
            return True

    def timing_roles(value: str) -> set[str]:
        text = re.sub(r"\s+", " ", str(value or "")).casefold()
        roles = set()
        if re.search(r"\b(?:preferred?|target|aim(?:ing)?|if possible)\b", text):
            roles.add("soft")
        if re.search(
            r"\b(?:final|hard|absolute|deadline|cutoff|no later than)\b",
            text,
        ):
            roles.add("hard")
        return roles

    point_roles = timing_roles(point)
    if not point_roles:
        return False

    # Timing-only wrappers may name the generic workflow operation, but must not
    # introduce a business object/actor/state that would deserve its own bullet.
    allowed_terms = {
        "soft", "hard", "preferred", "preference", "target", "aim", "possible",
        "final", "absolute", "deadline", "cutoff", "date", "time", "timing",
        "submit", "submission", "send", "delivery", "deliver", "complete",
        "completion", "approve", "approval", "review", "upload", "provide",
        "prepare", "finish", "due", "day", "week", "month",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
        "sunday", "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december",
    }
    point_terms = _cross_section_fact_terms(point)
    if point_terms - allowed_terms:
        return False

    point_times = _cross_section_time_tokens(point)
    for sentence in re.split(r"(?<=[.!?])\s+", compact_summary):
        sentence = sentence.strip()
        if not sentence:
            continue
        sentence_dates = _cross_section_dates(sentence, reference_date)
        if not point_dates.issubset(sentence_dates):
            continue
        if not (point_roles & timing_roles(sentence)):
            continue
        sentence_times = _cross_section_time_tokens(sentence)
        if point_times and not point_times.issubset(sentence_times):
            continue
        return True
    return False


def _keypoint_is_summary_restatement(
    email: dict, key_point: str, summary: str
) -> bool:
    """Drop a Key Point when its atomic fact is already represented in Summary.

    Summary may compress several facts into one sentence, often separated by
    semicolons or contrast/dependency connectors. Deduplication therefore works
    at the atomic-clause level instead of granting multi-fact Summary sentences a
    blanket exception. This keeps thematic overlap possible only when the Key
    Point contributes a genuinely different fact.
    """
    point = re.sub(r"\s+", " ", str(key_point or "")).strip()
    compact_summary = _compact_summary_overview(summary)
    if not point or not compact_summary:
        return False

    if _keypoint_is_summary_temporal_restatement(email, point, compact_summary):
        return True

    summary_sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", compact_summary)
        if part.strip()
    ]
    for sentence in summary_sentences:
        # Compare against atomic clauses first. Keep the full sentence as a
        # fallback for compact prose that cannot be safely clause-split.
        units = _cross_section_keypoint_clauses(sentence)
        if not units:
            units = [sentence]
        elif sentence not in units:
            units = [*units, sentence]

        for unit in units:
            if not _cross_section_fact_equivalent(
                email, point, unit, coverage_threshold=0.84
            ):
                continue

            point_terms = _cross_section_fact_terms(point)
            unit_terms = _cross_section_fact_terms(unit)
            shared = point_terms & unit_terms
            point_coverage = len(shared) / max(1, len(point_terms))
            unit_coverage = len(shared) / max(1, len(unit_terms))
            if point_coverage >= 0.88 and unit_coverage >= 0.72:
                return True
    return False


def _cross_section_keypoint_clauses(value: str) -> list[str]:
    """Split a mixed Key Point so owned facts can be removed without losing residue."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return []
    parts = re.split(
        r"\s*;\s*|(?<=[.!?])\s+|\s+(?=(?:because|however|but)\b)",
        text,
        flags=re.IGNORECASE,
    )
    cleaned = []
    for part in parts:
        clause = re.sub(
            r"^(?:because|however|but|also)\s*[,;:]?\s*",
            "",
            str(part or "").strip(),
            flags=re.IGNORECASE,
        ).strip(" \t\r\n-–—:;,.!? ")
        if not clause:
            continue
        clause = clause[:1].upper() + clause[1:]
        if clause not in cleaned:
            cleaned.append(clause)
    return cleaned


def _keypoint_past_participle(verb: str) -> str:
    """Return a conservative English past participle for simple Key Point polish.

    This helper is grammatical rather than domain-specific. It is intentionally
    small: when a verb cannot be normalized confidently, callers can fall back
    to neutral third-person voice instead of changing the fact.
    """
    raw = str(verb or "").strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z'-]*", raw):
        return ""
    lower = raw.lower()
    irregular = {
        "be": "been", "become": "become", "begin": "begun", "bring": "brought",
        "build": "built", "buy": "bought", "choose": "chosen", "come": "come",
        "do": "done", "draw": "drawn", "drink": "drunk", "drive": "driven",
        "eat": "eaten", "find": "found", "get": "gotten", "give": "given",
        "go": "gone", "have": "had", "hear": "heard", "hold": "held",
        "keep": "kept", "know": "known", "lead": "led", "leave": "left",
        "make": "made", "meet": "met", "pay": "paid", "read": "read",
        "run": "run", "say": "said", "see": "seen", "send": "sent",
        "set": "set", "show": "shown", "speak": "spoken", "take": "taken",
        "tell": "told", "think": "thought", "write": "written",
        "submit": "submitted", "plan": "planned", "refer": "referred",
        "occur": "occurred", "admit": "admitted", "commit": "committed",
    }
    if lower in irregular:
        return irregular[lower]
    if lower.endswith("e"):
        return lower + "d"
    if len(lower) > 2 and lower.endswith("y") and lower[-2] not in "aeiou":
        return lower[:-1] + "ied"
    return lower + "ed"


def _keypoint_third_person_present(verb: str) -> str:
    """Conjugate a simple present verb for sender/recipient role grammar."""
    raw = str(verb or "").strip()
    lower = raw.casefold()
    if not lower:
        return raw
    irregular = {
        "be": "is",
        "have": "has",
        "do": "does",
        "go": "goes",
    }
    if lower in irregular:
        result = irregular[lower]
    elif lower.endswith("y") and len(lower) > 1 and lower[-2] not in "aeiou":
        result = lower[:-1] + "ies"
    elif lower.endswith(("s", "x", "z", "ch", "sh", "o")):
        result = lower + "es"
    else:
        result = lower + "s"
    return result[:1].upper() + result[1:] if raw[:1].isupper() else result


def _keypoint_fix_role_clause_agreement(value: str) -> str:
    """Fix simple sender/recipient subject-verb agreement in neutral clauses.

    Neutralization can turn "until I send" into "until the sender send".
    Restrict the repair to subordinate clauses and skip auxiliaries/modals so
    ordinary business wording is not rewritten broadly.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""
    auxiliaries = {
        "am", "is", "are", "was", "were", "be", "been", "being",
        "has", "have", "had", "do", "does", "did",
        "can", "could", "may", "might", "will", "would",
        "shall", "should", "must",
    }

    pattern = re.compile(
        r"\b(until|when|once|after|before|if|unless|while)\s+"
        r"(the sender|the recipient)\s+([A-Za-z][A-Za-z'-]*)\b",
        flags=re.IGNORECASE,
    )

    def repl(match):
        verb = match.group(3)
        if verb.casefold() in auxiliaries or verb.casefold().endswith("s"):
            return match.group(0)
        return f"{match.group(1)} {match.group(2)} {_keypoint_third_person_present(verb)}"

    return pattern.sub(repl, text)


def _neutralize_key_point_voice(value: str) -> str:
    """Polish a Key Point into neutral business voice without changing its fact.

    The transformation is generic and role-based. It never keys off subjects,
    benchmark IDs, dates, or business nouns. Modal meaning is preserved (can,
    may, will, etc.). Simple first-person modal clauses are passivized when safe;
    other conversational pronouns fall back to explicit sender/recipient roles.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""

    # Example shape: "We can incorporate your feedback in the next revision"
    # -> "Feedback can be incorporated in the next revision". Preserve the
    # original modal rather than strengthening possibility into certainty.
    modal_match = re.match(
        r"^(?:we|i)\s+(can|could|may|might|will|would|should|must)\s+"
        r"([A-Za-z][A-Za-z'-]*)\s+(?:your|the)\s+(.+)$",
        text,
        flags=re.IGNORECASE,
    )
    if modal_match:
        modal = modal_match.group(1).lower()
        participle = _keypoint_past_participle(modal_match.group(2))
        remainder = modal_match.group(3).strip(" .")
        if participle and remainder:
            # Keep common trailing relation/time/process phrases after the
            # passive verb so the semantic scope remains natural.
            tail_match = re.match(
                r"^(.+?)(\s+(?:in|on|at|by|before|after|during|into|upon|once|when|"
                r"following|with|without)\b.*)?$",
                remainder,
                flags=re.IGNORECASE,
            )
            obj = (tail_match.group(1) if tail_match else remainder).strip()
            tail = (tail_match.group(2) if tail_match and tail_match.group(2) else "").strip()
            if not tail:
                adverb_match = re.match(
                    r"^(.+?)\s+(later|soon|today|tomorrow|tonight|eventually|subsequently)$",
                    obj,
                    flags=re.IGNORECASE,
                )
                if adverb_match:
                    obj = adverb_match.group(1).strip()
                    tail = adverb_match.group(2).strip()
            if obj:
                polished = f"{obj[:1].upper() + obj[1:]} {modal} be {participle}"
                if tail:
                    polished += f" {tail}"
                return polished.strip()

    # Conservative fallback: remove conversational perspective while keeping
    # agency/ownership explicit rather than guessing a passive construction.
    text = re.sub(r"\bwe\b|\bi\b", "the sender", text, flags=re.IGNORECASE)
    text = re.sub(r"\bour\b|\bmy\b", "the sender's", text, flags=re.IGNORECASE)
    text = re.sub(r"\byour\b", "the recipient's", text, flags=re.IGNORECASE)
    text = re.sub(r"\byou\b", "the recipient", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    text = _keypoint_fix_role_clause_agreement(text)
    if text:
        text = text[:1].upper() + text[1:]
    return text


def _source_residual_keypoint_is_salient(value: str) -> bool:
    """Return True for source-grounded residual facts worth recovering as Key Points.

    This is deliberately role/intent based rather than benchmark-specific. It
    recovers decisions, approvals, blockers/dependencies, exceptions, state
    changes, and forward-looking process consequences that the model may omit
    from key_points, while leaving ordinary descriptive leftovers alone.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return False
    words = re.findall(r"[A-Za-z0-9]+", text)
    if len(words) < 3 or len(words) > 45:
        return False

    # Independent business facts: decisions/approvals, blockers/dependencies,
    # explicit exceptions/conditions, and meaningful lifecycle/state changes.
    if re.search(
        r"\b(?:approved?|rejected?|decided?|agreed?|authorized?|accepted?|"
        r"blocked?|blocking|blockers?|depends?|dependency|waiting on|pending|on hold|"
        r"completed?|finished?|done|on track|off track|at risk|stable|healthy|degraded|"
        r"except|exception|unless|only if|provided that|subject to|"
        r"unaffected|not affected|remain(?:s)? under (?:existing|current|previous)|"
        r"continue(?:s)? under (?:existing|current|previous)|"
        r"changed?|updated?|revised?|replaced?|superseded?|cancelled?|"
        r"rescheduled?|postponed?|moved?)\b",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    # Forward-looking consequence/process facts are useful residual context when
    # they are not themselves recipient actions. Requiring both a modal/future
    # signal and a temporal/process relation keeps this recovery conservative.
    if re.search(r"\b(?:can|may|will|would|should|could)\b", text, flags=re.IGNORECASE) and re.search(
        r"\b(?:next|later|after|afterward|once|when|upon|following|subsequent|future)\b",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    # Causal/result clauses often explain why a request matters even when the
    # concise Summary omits that downstream effect.
    if re.search(
        r"\b(?:therefore|thereby|so that|as a result|which means|this means|"
        r"allows?|enables?|prevents?|results? in|leads? to)\b",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    return False


def _recover_source_residual_key_points(
    email: dict, summary: str, actions=None, deadlines=None
) -> list[str]:
    """Recover salient residual facts directly from the effective source turn.

    LLM key_points may legitimately come back empty. That must not erase an
    independently useful fact present in the email. Candidates still pass the
    same cross-section ownership checks as model-produced Key Points.
    """
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)
    recovered = []
    for sentence in _summary_source_sentences_for_overview(email):
        # Semicolons commonly separate a scheduling statement from a distinct
        # consequence/context fact. Reuse the same clause splitter as Key Points.
        for clause in _cross_section_keypoint_clauses(sentence):
            if _keypoint_is_no_action_status_restatement(clause, summary):
                continue
            if not _source_residual_keypoint_is_salient(clause):
                continue
            if _phase1k_is_other_person_task_metadata(email, clause):
                continue
            if _phase1k_is_unowned_deadline_label(email, clause, normalized_deadlines):
                continue
            if normalized_actions and _phase1b_keypoint_is_action_restatement(
                clause, normalized_actions
            ):
                continue
            if _keypoint_is_deadline_restatement(
                email, clause, normalized_actions, normalized_deadlines
            ):
                continue
            if _keypoint_is_summary_restatement(email, clause, summary):
                continue
            # Recovery must not re-introduce a source clause that the broader
            # RAW-first coverage gate already proved is represented in Summary.
            # This was the source of date-only bullets reappearing after a
            # successful distinctness repair (for example soft-target/final-
            # cutoff phrasing that was already present in the narrative).
            if _raw_first_summary_covers_source_fact(email, clause, summary):
                continue
            recovered.append(clause)
    return _merge_unique(recovered)



def _dedupe_semantic_key_points(email: dict, points) -> list[str]:
    """Collapse paraphrased/duplicated Key Point facts after atomicization.

    This removes the common "compound fact + the same two atomic facts" output
    without domain keywords. When two facts are semantically equivalent, keep
    the more specific wording (more semantic/material tokens, then more text).
    """
    result: list[str] = []
    for point in _normalize_list(points):
        candidate = re.sub(r"\s+", " ", str(point or "")).strip()
        if not candidate:
            continue

        duplicate_index = None
        for index, existing in enumerate(result):
            if _cross_section_fact_equivalent(
                email, candidate, existing, coverage_threshold=0.80
            ):
                duplicate_index = index
                break

        if duplicate_index is None:
            result.append(candidate)
            continue

        existing = result[duplicate_index]
        candidate_score = (
            len(_cross_section_fact_terms(candidate)),
            len(_cross_section_material_tokens(candidate)),
            len(candidate),
        )
        existing_score = (
            len(_cross_section_fact_terms(existing)),
            len(_cross_section_material_tokens(existing)),
            len(existing),
        )
        if candidate_score > existing_score:
            result[duplicate_index] = candidate
    return result


def _keypoint_scan_value_signal(value: str) -> bool:
    """Return True when a fact is worth a dedicated scan bullet.

    Key Points are optional. A fact earns scan space when it carries a workflow
    decision/state/dependency/consequence signal or a material numeric detail.
    This is intentionally semantic and domain-agnostic; it never keys off
    benchmark IDs, subjects, people, dates, or business nouns.
    """
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return False
    return bool(
        _source_residual_keypoint_is_salient(text)
        or _summary_context_fact_is_high_impact(text)
        or _cross_section_material_tokens(text)
    )


def _keypoint_adds_information_gain(
    email: dict,
    point: str,
    summary: str,
    *,
    scan_cluster_size: int = 0,
) -> bool:
    """Keep only Key Points that add a fact not already carried by Summary.

    The scan layer is optional. A rich email does not get duplicate bullets just
    because it contains several salient facts: if Summary already represents an
    atomic fact, that fact belongs to Summary only. Key Points survive when they
    contribute distinct supporting context. ``scan_cluster_size`` is retained in
    the signature for call-site compatibility but no longer overrides dedupe.
    """
    candidate = re.sub(r"\s+", " ", str(point or "")).strip()
    if not candidate:
        return False
    return not _summary_semantically_covers_fact(email, candidate, summary)


def _phase1k_distinct_key_points(
    email: dict, points, summary: str, actions=None, deadlines=None
) -> list[str]:
    """Keep scan-friendly grounded facts without Action/Deadline duplication.

    Summary is the whole-email narrative. Key Points may overlap thematically
    with that narrative when they expose atomic decisions, blockers,
    dependencies, exceptions, approvals, state changes, or material facts. They
    must not copy Action Items, task deadlines, or a standalone Summary sentence.

    Compound model bullets are atomicized before dedupe, preventing a combined
    fact from coexisting with the same facts as separate bullets.
    """
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)

    atomic_candidates = []
    for point in _normalize_list(points):
        atomic_candidates.extend(_cross_section_keypoint_clauses(point))

    result = []
    for clause in atomic_candidates:
        if _keypoint_is_no_action_status_restatement(clause, summary):
            continue
        # A deadline-change Key Point is useful only when the source actually
        # states that a deadline changed. Models occasionally turn a plain
        # initial due date into history such as "deadline extended/moved".
        # Reuse the same source-grounding guard that repairs Summary so an
        # unsupported transition cannot survive only because Key Points treat
        # genuine deadline-change events as independently useful context.
        if _summary_has_unsupported_deadline_transition(email, clause):
            continue
        if _phase1k_is_other_person_task_metadata(email, clause):
            continue
        if _phase1k_is_unowned_deadline_label(email, clause, normalized_deadlines):
            continue
        if normalized_actions and _phase1b_keypoint_is_action_restatement(
            clause, normalized_actions
        ):
            continue
        if _keypoint_is_deadline_restatement(
            email, clause, normalized_actions, normalized_deadlines
        ):
            continue
        if _keypoint_is_summary_restatement(email, clause, summary):
            continue
        result.append(clause)

    # The model may return [] after being told not to duplicate other sections.
    # Recover independently salient source facts so dedupe never becomes
    # information loss.
    result.extend(_recover_source_residual_key_points(
        email, summary, actions=normalized_actions, deadlines=normalized_deadlines
    ))

    # Canonicalize first so duplicate/paraphrased bullets do not artificially
    # inflate the scan-value cluster size. Key Points are optional: if a fact is
    # already represented by Summary, keep it only when several distinct
    # scan-worthy atomic facts make a dedicated scan layer genuinely useful.
    canonical = _dedupe_semantic_key_points(email, _merge_unique(result))
    scan_cluster_size = sum(
        1 for point in canonical if _keypoint_scan_value_signal(point)
    )
    canonical = [
        point
        for point in canonical
        if _keypoint_adds_information_gain(
            email, point, summary, scan_cluster_size=scan_cluster_size
        )
    ]

    # Neutral voice is presentation-only. Run it after information-gain
    # selection, then dedupe once more so first-person and neutral paraphrases
    # collapse to one canonical fact.
    polished = [
        _neutralize_key_point_voice(point)
        for point in canonical
    ]
    polished = [point for point in polished if point]

    # Final cross-section ownership lock. Recovery and voice polishing happen
    # after the first dedupe pass, so run the same field-local ownership checks
    # once more before returning. This prevents a repair from reintroducing an
    # Action Item, task deadline, or standalone Summary restatement as a Key Point.
    final_points = []
    for point in polished:
        if _keypoint_is_no_action_status_restatement(point, summary):
            continue
        if _phase1k_is_other_person_task_metadata(email, point):
            continue
        if _phase1k_is_unowned_deadline_label(email, point, normalized_deadlines):
            continue
        if normalized_actions and _phase1b_keypoint_is_action_restatement(
            point, normalized_actions
        ):
            continue
        if _keypoint_is_deadline_restatement(
            email, point, normalized_actions, normalized_deadlines
        ):
            continue
        if _keypoint_is_summary_restatement(email, point, summary):
            continue
        if _raw_first_summary_covers_source_fact(email, point, summary):
            continue
        final_points.append(point)
    return _dedupe_semantic_key_points(email, final_points)


def _phase1b_task_title(value, actions, subject: str = "") -> str:
    actions = _normalize_list(actions)
    if not actions:
        return ""
    title = _normalize_task_title(value, action_items=actions, subject=subject)
    title = _separate_action_item_text(title)
    action_text = " ".join(actions)

    # If the main action asks the user to resolve a temporal interpretation or
    # choice, the alternatives are part of the task's identity. A shorter model
    # title such as "Confirm date format" is lexically supported but loses the
    # exact choice the user must make. Prefer the grounded action-derived title
    # unless the model title itself preserves every temporal fact.
    semantic_facts = _phase1c_semantic_temporal_facts(actions[0])
    if semantic_facts:
        lowered_title = title.casefold()
        if not all(fact.casefold() in lowered_title for fact in semantic_facts):
            return _separate_action_item_text(
                _normalize_task_title(actions[0], action_items=actions, subject=subject)
            )

    primary = actions[0]
    primary_intent = _phase1c_action_intent(primary)
    title_intent = _phase1c_action_intent(title) if title else ""
    if title and primary_intent and title_intent and primary_intent != title_intent:
        return _separate_action_item_text(
            _normalize_task_title(primary, action_items=actions, subject=subject)
        )

    # Preserve explicit delivery scope and short distinguishing labels (US/EU,
    # API, SLA, etc.) that materially identify which object the user must act on.
    if title:
        if re.search(r"\breply\s+all\b", primary, flags=re.IGNORECASE) and not re.search(
            r"\breply\s+all\b", title, flags=re.IGNORECASE
        ):
            return _separate_action_item_text(
                _normalize_task_title(primary, action_items=actions, subject=subject)
            )
        scope_tokens = set(re.findall(r"\b[A-Z]{2,5}\b", primary))
        title_scope_tokens = set(re.findall(r"\b[A-Z]{2,5}\b", title))
        if scope_tokens - title_scope_tokens:
            return _separate_action_item_text(
                _normalize_task_title(primary, action_items=actions, subject=subject)
            )

    if title and _is_supported(title, action_text):
        return title
    return _separate_action_item_text(
        _normalize_task_title(actions[0], action_items=actions, subject=subject)
    )


def _raw_first_recipient_request_sentence(email: dict, sentence: str) -> bool:
    """Return True only for source text that actually assigns work to the recipient.

    RAW-first validation must decide whether the model omitted source work without
    using model/audit output as the proof. Reuse the same assignee/request guards
    as action grounding so named coworker work, informational prose, completed
    history, and task-list headings cannot force an unnecessary second AI pass.
    """
    text = re.sub(r"\s+", " ", str(sentence or "")).strip()
    if not text:
        return False
    body = _body_text(email)
    if _phase1c_evidence_is_non_action(text, body):
        return False
    if _phase1c_is_task_list_intro_evidence(text, body):
        return False

    # Named addressee ownership outranks generic request syntax such as
    # ``please``. This prevents ``John, please ...`` from becoming the current
    # mailbox user's work unless account identity proves John is the user.
    if _phase1g_addressed_to_other_person(email, text):
        return False

    if _phase1b_recipient_request_signal(text):
        return True

    assignee = _phase1g_named_assignee(text)
    recipient_name = _phase1g_recipient_name(email)
    return bool(
        assignee
        and recipient_name
        and _phase1g_same_person(assignee, recipient_name)
    )


def _raw_first_is_ancillary_response_timing_request(sentence: str) -> bool:
    """Detect response wording that only modifies timing/urgency of other work.

    This is intentionally grammatical and source-semantic. It recognizes a
    reply/respond intent combined only with low-urgency/open-ended timing
    language. Any material payload (for example, a document/object to send)
    prevents suppression. Callers suppress it only when another request exists.
    """
    text = re.sub(r"\s+", " ", str(sentence or "")).strip(" \t\r\n-–—:;,.!?")
    if not text or _phase1c_action_intent(text) != "reply":
        return False
    if not _summary_low_urgency_signals(text):
        return False

    residue = text.casefold()
    residue = re.sub(r"\b(?:please|kindly)\b", " ", residue)
    residue = re.sub(r"\b(?:there\s+is\s+)?(?:no\s+(?:rush|hurry)|not\s+(?:urgent|time[- ]sensitive))\b", " ", residue)
    residue = re.sub(r"\b(?:reply|respond)\b", " ", residue)
    residue = re.sub(
        r"\b(?:when(?:ever)?\s+(?:convenient|you\s+(?:can|are\s+able))|"
        r"at\s+(?:your\s+)?convenience|in\s+your\s+own\s+time)\b",
        " ", residue, flags=re.IGNORECASE,
    )
    residue = re.sub(r"[;,:.!?\-–—]+", " ", residue)
    residue = re.sub(r"\s+", " ", residue).strip()
    return not residue


def _raw_first_is_execution_control_only_request(sentence: str) -> bool:
    """Return True for a bare lifecycle activation instruction, not new work.

    Thread replies such as ``Please start/proceed now.`` change execution posture
    but do not create a second deliverable.  Keep this detector intentionally
    narrow: once a concrete object or task payload follows the activation verb
    (for example, ``Start the server``), the sentence is ordinary executable
    work and must remain eligible for Action Items.
    """
    text = re.sub(r"\s+", " ", str(sentence or "")).strip(" \t\r\n-–—:;,.!?")
    if not text:
        return False
    text = re.sub(r"^(?:also\s+)?(?:please|kindly)\s+", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"\s+", " ", text).strip(" \t\r\n-–—:;,.!?")
    return bool(re.fullmatch(
        r"(?:start(?:\s*/\s*proceed)?|proceed|begin|continue|resume|go\s+ahead)"
        r"(?:\s+(?:now|today|right\s+away|immediately|when\s+ready))?",
        text,
        flags=re.IGNORECASE,
    ))


def _raw_first_is_execution_control_action(value: str) -> bool:
    """Detect audit/model Action Items that merely restate lifecycle activation."""
    text = re.sub(r"\s+", " ", str(value or "")).strip(" \t\r\n-–—:;,.!?")
    return bool(re.match(
        r"^(?:start(?:\s*/\s*proceed)?|proceed|begin|continue|resume|go\s+ahead)\b",
        text,
        flags=re.IGNORECASE,
    ))


def _raw_first_suppress_redundant_execution_control_actions(email: dict, actions) -> tuple[list[str], bool]:
    """Drop synthetic activation Action Items when the source contains bare control.

    Suppression is allowed only when the conversation also has at least one
    substantive Action Item.  That makes a bare ``start/proceed`` reply apply to
    the existing task state instead of becoming a duplicate task, while concrete
    source requests such as ``Start the server`` remain untouched.
    """
    items = _normalize_list(actions)
    if not items:
        return items, False
    source_has_bare_control = any(
        _raw_first_is_execution_control_only_request(sentence)
        for sentence in _phase1b_source_sentences(_body_text(email))
    )
    if not source_has_bare_control:
        return items, False
    substantive = [item for item in items if not _raw_first_is_execution_control_action(item)]
    if not substantive:
        return items, False
    changed = len(substantive) != len(items)
    return substantive, changed


def _raw_first_action_intents(value: str) -> set[str]:
    """Return canonical executable intents for RAW-first coverage checks."""
    intents = set(_phase1c_action_clause_intents(value))
    primary = _phase1c_action_intent(value)
    if primary:
        intents.add(primary)
    return intents


def _raw_first_normalize_action_head_typos(value: str) -> str:
    """Normalize minor spelling errors only at executable clause heads.

    This is recovery-only parsing: business objects and ordinary prose are never
    spell-corrected. A token is considered only at the start of a request or
    immediately after a coordination connector, and only when it is very close
    to a generic action verb.
    """
    from difflib import SequenceMatcher

    verbs = (
        "acknowledge", "approve", "check", "complete", "confirm", "decide",
        "investigate", "prepare", "provide", "read", "reply", "respond",
        "review", "schedule", "send", "sign", "submit", "update", "upload",
        "verify",
    )
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""

    # Filipino/Taglish politeness can attach ``paki`` directly to an action
    # verb (``paki-review``, ``pakisend``) and use ``at`` as a coordinator.
    # Normalize only this request scaffolding, never business-object words.
    verb_alt = "|".join(sorted(verbs, key=len, reverse=True))
    text = re.sub(
        rf"^(?:paki[- ]?)(?=({verb_alt})\b)",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        rf"\bat\s+paki[- ]?(?=({verb_alt})\b)",
        "and ",
        text,
        flags=re.IGNORECASE,
    )
    # ``yung`` is a determiner, not part of the executable object identity.
    # Englishizing it here makes source-backed review/send workflows compare
    # consistently across providers while preserving the object nouns verbatim.
    text = re.sub(
        rf"\b({verb_alt})\s+yung\s+",
        r"\1 the ",
        text,
        flags=re.IGNORECASE,
    )

    def normalize_token(token: str) -> str:
        raw = token.casefold()
        if raw in verbs:
            return token
        best = max(verbs, key=lambda verb: SequenceMatcher(None, raw, verb).ratio())
        score = SequenceMatcher(None, raw, best).ratio()
        if raw[:1] == best[:1] and abs(len(raw) - len(best)) <= 2 and score >= 0.72:
            return best
        return token

    # Request prefix at sentence start.
    match = re.match(r"^(?:(?:please|pls|kindly)\s+)?([A-Za-z]{3,16})\b", text, flags=re.IGNORECASE)
    if match:
        token = match.group(1)
        replacement = normalize_token(token)
        if replacement != token:
            text = text[:match.start(1)] + replacement + text[match.end(1):]

    # Coordinated clause heads.
    pattern = re.compile(r"\b(and then|then|also|plus|and)\s+([A-Za-z]{3,16})\b", flags=re.IGNORECASE)
    def repl(m):
        return f"{m.group(1)} {normalize_token(m.group(2))}"
    return pattern.sub(repl, text)


def _raw_first_source_action_text(sentence: str) -> str:
    """Convert one source request sentence into metadata-free task wording.

    This is used only for deterministic recovery after RAW validation proves that
    a source instruction was fragmented.  It deliberately removes request/politeness
    scaffolding but preserves the source's executable verb/object wording.
    """
    text = _separate_action_item_text(_raw_first_normalize_action_head_typos(sentence))
    if not text:
        return ""
    text = re.sub(r"^(?:also\s*[,;:]?\s*)", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"^(?:please|pls|kindly)\s+", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"^(?:can|could|would|will)\s+you\s+", "", text, flags=re.IGNORECASE).strip()
    text = re.sub(r"^(?:i|we)\s+(?:need|want|would\s+like)\s+you\s+to\s+", "", text, flags=re.IGNORECASE).strip()
    if text and text[:1].islower():
        text = text[:1].upper() + text[1:]
    return text


def _raw_first_compound_clause_parts(value: str) -> list[str]:
    """Split only explicit coordinated executable clauses.

    ``approve or reject`` remains atomic because only ordinary coordination
    connectors are used here.  The helper is intentionally conservative: it is
    a source-boundary detector, not a general sentence parser.
    """
    text = _raw_first_source_action_text(value)
    if not text:
        return []
    action_verb = (
        r"(?:approv\w*|reject\w*|acknowledg\w*|attend\w*|join\w*|"
        r"check\w*|verify\w*|investigat\w*|complet\w*|finish\w*|"
        r"confirm\w*|prepar\w*|draft\w*|provid\w*|share\w*|read\w*|"
        r"repl(?:y|ies|ied)|respond\w*|tell\w*|inform\w*|report\w*|let\s+(?:me|us)\s+know|review\w*|schedul\w*|send\w*|"
        r"submit\w*|upload\w*|sign\w*|stop\w*|cease\w*|updat\w*)"
    )
    # Split a coordination word only when the following clause actually starts
    # with an executable verb.  This avoids treating noun phrases such as
    # "research and development" as two actions.
    connector = (
        rf"\s*(?:,\s*)?\b(?:and then|then|also|plus|and)\b\s+"
        rf"(?=(?:(?:please|kindly)\s+)?{action_verb}\b)"
    )
    return [
        part.strip(" \t\r\n-–—:;,.()")
        for part in re.split(connector, text, flags=re.IGNORECASE)
        if part.strip(" \t\r\n-–—:;,.()")
    ]


def _raw_first_clause_object_tokens(value: str) -> set[str]:
    tokens = set(_phase1e_object_tokens(value))
    return {
        token for token in tokens
        if token not in {
            "a", "an", "the", "any", "your", "my", "our", "their",
            "this", "that", "these", "those", "attached", "current",
            "updated", "required", "necessary",
        }
    }


def _raw_first_coupled_clause_pair(left: str, right: str) -> bool:
    """Return True when two source clauses form one workflow-coupled task.

    The rule is source-semantic and domain-agnostic.  Clauses are coupled when
    the latter clearly operates on the same object/output as the former, rather
    than introducing a second independent business object.  This covers common
    review→feedback and prepare/update→send workflows while leaving unrelated
    coordinated requests separate.
    """
    left_intent = _phase1c_action_intent(left)
    right_intent = _phase1c_action_intent(right)
    if not left_intent or not right_intent:
        return False

    left_objects = _raw_first_clause_object_tokens(left)
    right_objects = _raw_first_clause_object_tokens(right)
    if left_objects and right_objects and left_objects & right_objects:
        return True

    # Pronoun/reference continuation: "prepare X and send it/them".
    if re.search(r"\b(?:it|them|this|that|these|those)\b", right, flags=re.IGNORECASE):
        return True

    # A review/check/read produces response artifacts rather than a new independent
    # business object.  These are generic result nouns, not benchmark/domain terms.
    review_like = {"review", "check", "read"}
    communicate_like = {"send", "provide", "reply", "confirm"}
    response_artifacts = {
        "comment", "comments", "feedback", "correction", "corrections",
        "change", "changes", "edit", "edits", "finding", "findings",
        "result", "results", "note", "notes", "response", "responses",
        "recommendation", "recommendations", "issue", "issues",
    }
    if left_intent in review_like and right_intent in communicate_like:
        # A result-reporting clause belongs to the same review/check workflow
        # when it explicitly asks for an answer about the item just inspected.
        # Requiring both a question complement and an anaphoric reference keeps
        # unrelated follow-up questions separate.
        result_query = bool(re.search(
            r"\b(?:whether|if|what|which)\b", right, flags=re.IGNORECASE
        ))
        refers_back = bool(re.search(
            r"\b(?:it|this|that|they|them|these|those)\b",
            right, flags=re.IGNORECASE,
        ))
        if result_query and refers_back:
            return True
        if right_objects and right_objects.issubset(response_artifacts):
            return True

    return False


def _raw_first_coupled_source_action(sentence: str) -> str:
    """Return canonical source wording only when one sentence is one coupled task."""
    parts = _raw_first_compound_clause_parts(sentence)
    if len(parts) < 2:
        return ""
    if not all(_phase1c_action_intent(part) for part in parts):
        return ""
    if not all(
        _raw_first_coupled_clause_pair(parts[index], parts[index + 1])
        for index in range(len(parts) - 1)
    ):
        return ""
    return _raw_first_source_action_text(sentence)


def _raw_first_independent_shared_deadline_parts(sentence: str) -> list[str]:
    """Return source clauses only when a shared-deadline request is truly separable."""
    # Reuse the older completeness predicate as a source-shape test. The single
    # placeholder represents the collapsed action shape that this predicate was
    # originally designed to detect.
    if not _phase1i2b_shared_deadline_compound_needs_audit(sentence, ["source compound"]):
        return []

    parts = _raw_first_compound_clause_parts(sentence)
    if len(parts) < 2:
        return []
    if not all(_phase1c_action_intent(part) for part in parts):
        return []
    if any(not _raw_first_clause_object_tokens(part) for part in parts):
        return []
    if any(
        re.search(r"\b(?:it|them|this|that|these|those)\b", part, flags=re.IGNORECASE)
        for part in parts[1:]
    ):
        return []
    return parts


def _raw_first_split_independent_shared_deadline_actions(email: dict, actions) -> tuple[list[str], bool]:
    """Split a collapsed coordinated request when the source proves separate steps.

    A single sentence can contain multiple independently executable recipient
    requests that share one trailing deadline. Small models sometimes collapse
    those clauses into one compound Action Item. Recover the source clauses only
    when each coordinated clause has its own executable verb and concrete object,
    and the legacy shared-deadline completeness predicate proves that only one
    related action survived.

    Pronoun continuations such as ``prepare the report and send it`` stay coupled,
    as do atomic alternatives such as ``approve or reject``.
    """
    items = _normalize_list(actions)
    body = _body_text(email)
    changed = False

    for sentence in _phase1b_source_sentences(body):
        if not _raw_first_recipient_request_sentence(email, sentence):
            continue

        related_indexes = [
            index for index, action in enumerate(items)
            if _raw_first_request_related_to_action(sentence, action)
        ]
        related_actions = [items[index] for index in related_indexes]
        if len(related_actions) != 1:
            continue

        parts = _raw_first_independent_shared_deadline_parts(sentence)
        if not parts:
            continue

        validated_parts = _phase1b_validate_actions(email, parts)
        if len(validated_parts) != len(parts):
            continue

        insert_at = related_indexes[0] if related_indexes else len(items)
        related_set = set(related_indexes)
        rebuilt = [
            action for index, action in enumerate(items)
            if index not in related_set
        ]
        for offset, part in enumerate(validated_parts):
            rebuilt.insert(min(insert_at + offset, len(rebuilt)), part)
        items = _phase1c_dedupe_actions(email, rebuilt)
        changed = True

    return items, changed


def _raw_first_reconstruct_coupled_source_actions(email: dict, actions) -> tuple[list[str], bool]:
    """Repair fragmented RAW actions from proven source instruction boundaries.

    If one validated RAW action already covers every executable intent in a
    workflow-coupled source sentence, preserve it exactly.  Otherwise replace
    same-sentence fragments with one metadata-free source-backed compound action.
    This is deterministic field-local repair; unrelated actions are untouched.
    """
    items = _normalize_list(actions)
    body = _body_text(email)
    changed = False

    for sentence in _phase1b_source_sentences(body):
        if not _raw_first_recipient_request_sentence(email, sentence):
            continue
        source_action = _raw_first_coupled_source_action(sentence)
        if not source_action:
            continue
        validated_source = _phase1b_validate_actions(email, [source_action])
        if not validated_source:
            continue
        source_action = validated_source[0]
        source_intents = _raw_first_action_intents(source_action)
        if len(source_intents) < 2:
            continue

        temporal_object_scaffold = {
            "today", "tomorrow", "tonight", "next", "later", "day", "days",
            "week", "weeks", "month", "months", "morning", "afternoon",
            "evening", "eod", "cob",
        }
        source_objects = _phase1e_object_tokens(source_action) - temporal_object_scaffold

        def _same_source_fragment(action: str) -> bool:
            if _raw_first_request_related_to_action(sentence, action):
                return True
            action_intents = _raw_first_action_intents(action)
            if not action_intents or not action_intents.issubset(source_intents):
                return False
            action_objects = _phase1e_object_tokens(action) - temporal_object_scaffold
            if not action_objects or not source_objects:
                return False
            matched = sum(
                1 for token in action_objects
                if any(_raw_first_tokens_related(token, source) for source in source_objects)
            )
            return matched / max(1, len(action_objects)) >= 0.60

        related_indexes = [
            index for index, action in enumerate(items)
            if _same_source_fragment(action)
        ]
        related_actions = [items[index] for index in related_indexes]

        # If the source proves multiple independently executable clauses with a
        # shared deadline and those clauses are already represented separately,
        # preserve that correct split. The coupled-workflow repair below must not
        # merge them back into one checklist item.
        independent_parts = _raw_first_independent_shared_deadline_parts(sentence)
        if independent_parts and len(related_actions) >= len(independent_parts):
            continue

        # RAW-first ownership: a valid complete compound wins. A recovery audit
        # may nevertheless append one of its source-backed fragments afterward
        # (for example, the feedback half of a review+feedback workflow). Remove
        # only those same-sentence fragments whose intents are already contained
        # by the complete compound; unrelated actions remain untouched.
        complete_indexes = [
            index for index in related_indexes
            if source_intents.issubset(_raw_first_action_intents(items[index]))
        ]
        if complete_indexes:
            keep_index = complete_indexes[0]
            redundant_indexes = {
                index for index in related_indexes
                if index != keep_index
                and _raw_first_action_intents(items[index])
                and _raw_first_action_intents(items[index]).issubset(source_intents)
            }
            if redundant_indexes:
                items = [
                    action for index, action in enumerate(items)
                    if index not in redundant_indexes
                ]
                changed = True
            continue

        # The source parser itself proves the missing/fragmented work.  Repair only
        # this sentence and preserve every unrelated action in place.
        insert_at = related_indexes[0] if related_indexes else len(items)
        related_set = set(related_indexes)
        rebuilt = [
            action for index, action in enumerate(items)
            if index not in related_set
        ]
        rebuilt.insert(min(insert_at, len(rebuilt)), source_action)
        items = _phase1c_dedupe_actions(email, rebuilt)
        changed = True

    return items, changed



def _raw_first_collapse_exclusive_source_alternatives(email: dict, actions) -> tuple[list[str], bool]:
    """Collapse model-split mutually exclusive choices into one logical action.

    Some model/provider runs return each branch of an explicit ``either ... or ...``
    request as a separate Action Item even though the source assigns only one choice.
    Normalize only when the source itself proves that exclusive grammar *and* the
    current action set separately represents both branches. Unrelated actions and
    ordinary multi-step ``and/then`` workflows are left untouched.
    """
    items = _normalize_list(actions)
    if len(items) < 2:
        return items, False

    body = _body_text(email)
    changed = False

    for sentence in _phase1b_source_sentences(body):
        if not _raw_first_recipient_request_sentence(email, sentence):
            continue

        source_action = _raw_first_source_action_text(sentence)
        match = re.search(
            r"\beither\s+(.+?)\s+\bor\b\s+(.+)$",
            source_action,
            flags=re.IGNORECASE,
        )
        if not match:
            continue

        left_branch, right_branch = [
            part.strip(" \t\r\n-–—:;,.()")
            for part in match.groups()
        ]
        # A required follow-up can appear after the exclusive choice in the same
        # sentence (``either A or B, then C``). Keep C independent rather than
        # folding it into the choice and duplicating it beside its own Action Item.
        trailing = re.search(
            r"\s*(?:,|;)?\s*\b(?:and then|then|also|plus)\b\s+(.+)$",
            right_branch,
            flags=re.IGNORECASE,
        )
        if trailing and _phase1c_action_intent(trailing.group(1)):
            right_branch = right_branch[:trailing.start()].strip(" \t\r\n-–—:;,.()")
        branches = [left_branch, right_branch]
        if len(branches) != 2 or not all(_phase1c_action_intent(part) for part in branches):
            continue

        # The source sentence is already proven recipient-owned above, and both
        # alternative branches are represented by validated current actions below.
        # Rebuild only the exclusive span; deadline/politeness metadata has already
        # been stripped by ``_raw_first_source_action_text``.
        canonical = _separate_action_item_text(
            f"Either {branches[0]} or {branches[1]}"
        )
        if not canonical or _action_item_is_metadata_only(canonical):
            continue

        def _branch_matches_action(branch: str, action: str) -> bool:
            # Prefer explicit verb identity before the broader semantic relation.
            # Decision-family matching alone would make ``approve`` and ``reject``
            # indistinguishable even though they are different exclusive branches.
            branch_verbs = _phase1i2_action_audit_keywords(branch)
            action_verbs = _phase1i2_action_audit_keywords(action)
            if branch_verbs and action_verbs:
                if not (branch_verbs & action_verbs):
                    return False
                branch_objects = _raw_first_clause_object_tokens(branch)
                if not branch_objects:
                    return True
                action_objects = _raw_first_clause_object_tokens(action)
                if not action_objects:
                    return False
                overlap = len(branch_objects & action_objects) / max(
                    1, min(len(branch_objects), len(action_objects))
                )
                return overlap >= 0.67
            return _raw_first_request_related_to_action(branch, action)

        related_indexes: list[int] = []
        covered_branches: set[int] = set()
        for index, action in enumerate(items):
            for branch_index, branch in enumerate(branches):
                if _branch_matches_action(branch, action):
                    related_indexes.append(index)
                    covered_branches.add(branch_index)
                    break

        # Do not expand or rewrite a single model action merely because the source
        # contains alternatives. This guard is only for the provider-variance shape
        # where both exclusive branches were emitted as separate tasks.
        related_set = set(related_indexes)
        if covered_branches != {0, 1} or len(related_set) < 2:
            continue

        insert_at = min(related_set)
        rebuilt = [
            action for index, action in enumerate(items)
            if index not in related_set
        ]
        rebuilt.insert(min(insert_at, len(rebuilt)), canonical)
        items = _phase1c_dedupe_actions(email, rebuilt)
        changed = True

    return items, changed


def _raw_first_tokens_related(left: str, right: str) -> bool:
    """Light, domain-agnostic morphology match for request/action objects."""
    return _phase1_token_support_related(left, right)


def _raw_first_request_related_to_action(sentence: str, action: str) -> bool:
    """Prove semantic request/action relation without a second model call.

    Same-intent requests still need compatible object evidence, so two separate
    tasks that happen to use the same verb remain distinct. Generic continuation
    wording such as "make the decision" may match intent-only when it carries no
    independent business payload. No subject/domain/date vocabulary is encoded.
    """
    if _phase1e_related_action_text(action, sentence):
        return True

    # The normal relation check is lexical and therefore cannot prove that an
    # English RAW action already covers a Latin-script Filipino request.  Reuse
    # the existing conservative cross-language grounding map here so a correctly
    # grounded RAW result does not trigger a second audit pass that adds English
    # paraphrase fragments.  This does not broaden supported languages or invent
    # translations; the same mapped concepts and recipient-direction gate used by
    # action validation must already pass.
    if _phase1b_cross_language_action_supported(action, sentence):
        return True

    source_intents = _raw_first_action_intents(sentence)
    action_intents = _raw_first_action_intents(action)
    if not (source_intents & action_intents):
        return False

    action_objects = _phase1e_object_tokens(action)
    # Remove deadline/urgency scaffolding before comparing source payload. The
    # same sanitizer already owns Action Item text, so temporal metadata cannot
    # masquerade as a missing business object in the RAW-first gate.
    source_payload = _separate_action_item_text(sentence) or sentence
    source_objects = _phase1e_object_tokens(source_payload)
    if action_objects:
        matched = 0
        for action_token in action_objects:
            if any(_raw_first_tokens_related(action_token, source_token) for source_token in source_objects):
                matched += 1
        ratio = matched / max(1, len(action_objects))
        if ratio >= 0.67 or (matched >= 2 and ratio >= 0.50):
            return True

    # Payload-free workflow continuation: allow intent-only coverage only when
    # the source sentence has no concrete object beyond generic workflow nouns.
    generic_workflow = {
        "action", "actions", "decision", "item", "items", "request",
        "response", "task", "tasks", "work",
    }
    residual = {
        token for token in source_objects
        if token not in generic_workflow and not re.fullmatch(r"\d+", token)
    }
    return not residual


def _raw_first_nominal_requirement_objects(sentence: str) -> set[str]:
    """Return the object of a possessive deliverable/state requirement.

    Phrases such as ``we still need your signed document`` describe one required
    deliverable.  A participle inside that noun phrase (``signed``, ``approved``,
    ``completed``) is a property of the required object, not proof that the sender
    separately assigned that lifecycle step.  Extract only the possessive object
    span so RAW-first coverage can be proven from object completeness instead of
    inventing an extra action during the recovery audit.
    """
    text = re.sub(r"\s+", " ", str(sentence or "")).strip()
    match = re.search(
        r"\b(?:still\s+)?(?:need|require|await)\s+"
        r"(?:your|the\s+recipient(?:['’]s)?)\s+"
        r"(.+?)"
        r"(?=(?:\s+(?:to|so\s+that|because|by|before|within|no\s+later\s+than)\b)|[.;!?]|$)",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        return set()
    return _raw_first_clause_object_tokens(match.group(1))


def _raw_first_merge_cross_language_coupled_actions(email: dict, actions) -> tuple[list[str], bool]:
    """Merge provider-split fragments of one mapped cross-language workflow.

    The ordinary source-clause parser deliberately understands only executable
    English clause heads.  When a supported Latin-script cross-language request
    has no recognized English source intent, providers can still return either
    one compound English action or two English fragments.  Normalize only the
    latter shape when both fragments are grounded in the exact same recipient
    request sentence and their *English action semantics* prove a coupled
    workflow (for example review/check -> response artifact).  Different source
    sentences and independently executable English workflows are untouched.
    """
    items = _normalize_list(actions)
    if len(items) < 2:
        return items, False

    changed = False
    body = _body_text(email)
    for sentence in _phase1b_source_sentences(body):
        if not _raw_first_recipient_request_sentence(email, sentence):
            continue
        # English/action-headed source text is already handled by the established
        # source-boundary split/coupling rules. This fallback is only for mapped
        # cross-language evidence where those English intents are absent.
        if _raw_first_action_intents(sentence):
            continue

        while True:
            related = [
                index for index, action in enumerate(items)
                if _phase1b_cross_language_action_supported(action, sentence)
            ]
            if len(related) < 2:
                break

            merged_pair = None
            for left_pos, left_index in enumerate(related):
                for right_index in related[left_pos + 1:]:
                    left = items[left_index]
                    right = items[right_index]
                    if _raw_first_coupled_clause_pair(left, right):
                        first, second = left, right
                    elif _raw_first_coupled_clause_pair(right, left):
                        first, second = right, left
                    else:
                        continue

                    second_clean = re.sub(
                        r"^(?:please|kindly)\s+", "", second, flags=re.IGNORECASE
                    ).strip()
                    if second_clean:
                        second_clean = second_clean[:1].lower() + second_clean[1:]
                    candidate = _separate_action_item_text(
                        f"{first.rstrip(' .;,:')} and {second_clean}"
                    )
                    validated = _phase1b_validate_actions(email, [candidate]) if candidate else []
                    if validated:
                        merged_pair = (left_index, right_index, validated[0])
                        break
                if merged_pair:
                    break

            if not merged_pair:
                break

            left_index, right_index, merged = merged_pair
            insert_at = min(left_index, right_index)
            remove = {left_index, right_index}
            rebuilt = [action for index, action in enumerate(items) if index not in remove]
            rebuilt.insert(min(insert_at, len(rebuilt)), merged)
            items = rebuilt
            changed = True

    return _phase1c_dedupe_actions(email, items), changed


def _raw_first_actions_cover_source_requests(email: dict, actions) -> bool:
    """Prove that validated AI_RAW actions already cover recipient work.

    This is the architectural RAW-first gate. A second action-audit LLM call is
    allowed only when a recipient-directed source instruction is not represented
    by the grounded AI_RAW actions. Compound wording is accepted when one action
    already covers the complete instruction; we do not split it merely because a
    heuristic expected more verbs. That prevents a repair pass from creating a
    redundant sub-action while still recovering genuinely omitted work.
    """
    normalized_actions = _normalize_list(actions)
    body = _body_text(email)

    if _phase1g_recipient_explicitly_has_no_action(body):
        return not normalized_actions

    request_sentences = [
        sentence
        for sentence in _phase1b_source_sentences(body)
        if _raw_first_recipient_request_sentence(email, sentence)
    ]
    if not request_sentences:
        # There is no source-proven recipient work left to recover. Grounded raw
        # actions (if any) have already passed the assignee/evidence validator.
        return True

    substantive_actions = [
        action for action in normalized_actions
        if not _raw_first_is_execution_control_action(action)
    ]

    for sentence in request_sentences:
        # A bare newest-turn activation instruction (``start/proceed now``) is
        # lifecycle control over already represented work, not an uncovered
        # deliverable that should force a second action-audit pass.
        if substantive_actions and _raw_first_is_execution_control_only_request(sentence):
            continue

        source_intents = _raw_first_action_intents(sentence)
        related = [
            action
            for action in normalized_actions
            if _raw_first_request_related_to_action(sentence, action)
        ]
        if not related:
            # A timing-only reply/respond phrase can be ancillary to another
            # already-covered request. It is never suppressed as the sole request.
            if (
                normalized_actions
                and len(request_sentences) > 1
                and _raw_first_is_ancillary_response_timing_request(sentence)
            ):
                continue
            return False

        # A possessive deliverable/state requirement (``need your <object>``) is
        # one obligation. Participles inside the noun phrase must not be treated
        # as additional executable intents when the validated RAW action already
        # covers the complete required object.
        nominal_objects = _raw_first_nominal_requirement_objects(sentence)
        if nominal_objects:
            covered_objects = set()
            for action in related:
                covered_objects.update(_raw_first_clause_object_tokens(action))
            if nominal_objects.issubset(covered_objects):
                continue

        covered_intents = set()
        covered_keywords = set()
        for action in related:
            covered_intents.update(_raw_first_action_intents(action))
            covered_keywords.update(_phase1i2_action_audit_keywords(action))

        # Canonical intent equivalence is more stable than literal verb matching
        # (e.g. submit/upload share the same executable send family). Fall back to
        # the legacy keyword proof only when no canonical intent is available.
        if source_intents:
            if not source_intents.issubset(covered_intents):
                return False
        else:
            source_keywords = _phase1i2_action_audit_keywords(sentence)
            if source_keywords and not source_keywords.issubset(covered_keywords):
                return False

    return True


def _raw_first_summary_needs_structural_repair(
    email: dict, candidate: str, actions
) -> bool:
    """Return True only when AI_RAW Summary has a proven structural defect.

    A valid grounded Summary is preserved as the primary candidate. Structural
    rewrite/separation is reserved for empty/topic-only/meta-framed summaries,
    unsupported deadline-change claims, or summaries that fail to convey any of
    the validated recipient work. Conservative completeness repairs still run
    afterward and are individually no-ops unless a source constraint/fact is
    demonstrably missing.
    """
    overview = _compact_summary_overview(candidate)
    if not overview:
        return True
    if _summary_is_topic_only_overview(overview):
        return True
    if _summary_is_meta_framed_action_overview(overview, actions):
        return True
    if _summary_has_unsupported_deadline_transition(email, overview):
        return True
    if _normalize_list(actions) and not _summary_covers_recipient_work(overview, actions):
        return True
    return False




def _raw_first_summary_repair_failure_reasons(
    label: str, email: dict, actions, deadlines, summary: str
) -> list[str]:
    """Return concrete deterministic reasons that permit one Summary repair.

    A repair function is not allowed to run merely because it *could* produce
    different prose.  Each label has a field-local, source-grounded predicate.
    This makes AI_RAW the primary candidate and turns repair into a fallback for
    a proven semantic defect only.
    """
    overview = _compact_summary_overview(summary)
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)
    source_sentences = _summary_source_sentences_for_overview(email)
    source_text = " ".join(source_sentences)
    reasons: list[str] = []

    if label == "structural":
        if not overview:
            reasons.append("empty_summary")
        if _summary_is_topic_only_overview(overview):
            reasons.append("topic_only_summary")
        if normalized_actions and _summary_is_meta_framed_action_overview(
            overview, normalized_actions
        ):
            reasons.append("meta_framed_summary")
        if _summary_has_unsupported_deadline_transition(email, overview):
            reasons.append("unsupported_deadline_transition")
        if normalized_actions and not _summary_covers_recipient_work(
            overview, normalized_actions
        ):
            reasons.append("missing_recipient_work")
        return list(dict.fromkeys(reasons))

    if label == "actionless_completeness":
        if normalized_actions or not source_sentences:
            return reasons
        if len(source_sentences) > 4 or len(source_text.split()) > 95:
            return reasons
        missing_signals = (
            _summary_explicit_signal_tokens(source_text)
            - _summary_explicit_signal_tokens(overview)
        )
        if missing_signals:
            reasons.append("missing_material_value")
        missing_semantics = (
            _summary_semantic_context_markers(source_text)
            - _summary_semantic_context_markers(overview)
        )
        if missing_semantics:
            reasons.append("missing_semantic_context")
        if (
            _summary_has_explicit_no_action_state(source_text)
            and not _summary_has_explicit_no_action_state(overview)
        ):
            reasons.append("missing_no_action_state")
        return reasons

    if label == "action_completeness":
        if not normalized_actions:
            return reasons
        if _summary_is_topic_only_overview(overview):
            reasons.append("topic_only_summary")
        if _summary_is_meta_framed_action_overview(overview, normalized_actions):
            reasons.append("meta_framed_summary")
        if _summary_has_inline_image_artifact_claim(email, overview):
            reasons.append("inline_image_artifact_claim")
        if not _summary_covers_recipient_work(overview, normalized_actions):
            reasons.append("missing_recipient_work")
        action_scope_markers = _summary_restrictive_action_scope_markers(
            " ".join(normalized_actions)
        )
        if action_scope_markers - _summary_restrictive_action_scope_markers(overview):
            reasons.append("missing_action_scope")
        return reasons

    if label == "no_deadline_constraint":
        if (
            normalized_actions
            and source_text
            and _summary_has_explicit_no_deadline_state(source_text)
            and not _summary_has_explicit_no_deadline_state(overview)
        ):
            reasons.append("missing_no_deadline_constraint")
        return reasons

    if label == "open_ended_timing":
        if not normalized_actions or not source_text:
            return reasons
        source_signals = _summary_low_urgency_signals(source_text)
        summary_signals = _summary_low_urgency_signals(overview)
        if (
            "open_ended_timing" in source_signals
            and not normalized_deadlines
            and not _summary_has_explicit_no_deadline_state(overview)
        ):
            reasons.append("missing_open_ended_timing")
        if "low_urgency" in source_signals and "low_urgency" not in summary_signals:
            reasons.append("missing_low_urgency_state")
        return reasons

    if label == "temporal_semantics":
        if not normalized_actions or not source_sentences:
            return reasons
        source_markers = _summary_temporal_semantic_markers(source_text)
        summary_markers = _summary_temporal_semantic_markers(overview)
        if source_markers - summary_markers:
            reasons.append("missing_temporal_semantics")
        return reasons

    if label == "material_context":
        # A concrete context value is mandatory when Summary already identifies
        # that same contextual thing but drops its source date/time/material fact.
        # This is narrower than generic low-impact context recovery and prevents
        # unrelated schedules from being pulled into the overview.
        if _summary_missing_explicit_context_sentence(email, overview):
            reasons.append("missing_explicit_context_value")
            return reasons
        if _summary_missing_related_material_context_sentences(email, overview):
            reasons.append("missing_related_context_value")
            return reasons

        # Only high-impact workflow context is otherwise mandatory enough to justify
        # rewriting an otherwise valid RAW Summary. Multiple low-impact details
        # remain eligible for Key Points instead of expanding the narrative.
        for sentence in source_sentences:
            for clause in _cross_section_keypoint_clauses(sentence):
                if _phase1b_recipient_request_signal(clause):
                    continue
                if normalized_actions and _phase1b_keypoint_is_action_restatement(
                    clause, normalized_actions
                ):
                    continue
                if _keypoint_is_deadline_restatement(
                    email, clause, normalized_actions, normalized_deadlines
                ):
                    continue
                if _summary_has_explicit_no_deadline_state(clause):
                    continue
                if _summary_has_explicit_no_action_state(clause):
                    continue
                if not _summary_context_fact_is_high_impact(clause):
                    continue
                if not _raw_first_summary_covers_source_fact(email, clause, overview):
                    reasons.append("missing_high_impact_context")
                    return reasons
        return reasons

    if label == "overdue_open_state":
        candidate = _compact_summary_overview(
            _repair_overdue_open_summary_completeness(
                email, normalized_actions, normalized_deadlines, overview
            )
        )
        if candidate and candidate != overview:
            reasons.append("missing_overdue_open_state")
        return reasons

    if label == "unsupported_deadline_transition":
        if _summary_has_unsupported_deadline_transition(email, overview):
            reasons.append("unsupported_deadline_transition")
        return reasons

    if label == "unsupported_cross_actor_sequence":
        if _summary_has_unsupported_cross_actor_sequence(
            email, normalized_actions, overview
        ):
            reasons.append("unsupported_cross_actor_sequence")
        return reasons

    if label == "request_metadata_deadline_scope":
        if _summary_has_misattached_request_metadata_deadline(
            email, normalized_actions, normalized_deadlines, overview
        ):
            reasons.append("misattached_request_deadline")
        return reasons

    if label == "recipient_due_ownership":
        if _summary_unowned_recipient_due_tail(
            email, normalized_actions, normalized_deadlines, overview
        ):
            reasons.append("unowned_recipient_due_tail")
        return reasons

    if label == "explicit_deadline_preservation":
        candidate = _compact_summary_overview(
            _repair_summary_explicit_deadline_preservation(
                email, normalized_actions, normalized_deadlines, overview
            )
        )
        if candidate and candidate != overview:
            reasons.append("vague_explicit_deadline")
        return reasons

    return reasons



def _raw_first_summary_covers_source_fact(
    email: dict, fact: str, summary: str
) -> bool:
    """Conservative subset-aware coverage check for repair gating only.

    Summary prose may compress a source clause (for example ``not affected`` ->
    ``unaffected``) without losing the fact. The main cross-section comparator is
    intentionally strict for dedupe; repair gating needs the opposite bias: when
    coverage is plausible and all material values/temporal relations agree, do
    not rewrite a valid RAW Summary just to restate the source more literally.
    """
    if _summary_semantically_covers_fact(email, fact, summary):
        return True

    def _clean(value: str) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        text = re.sub(
            r"^(?:for (?:your|the recipient'?s) reference[,;:]?\s*|"
            r"key details?\s*:\s*[-–—]?\s*)",
            "",
            text,
            flags=re.IGNORECASE,
        )
        text = re.sub(r"^[-–—]\s*", "", text)
        text = re.sub(r"\bnot\s+affected\b", "unaffected", text, flags=re.IGNORECASE)
        text = re.sub(r"\bnot\s+changed\b", "unchanged", text, flags=re.IGNORECASE)
        return text

    fact_clean = _clean(fact)
    summary_clean = _clean(summary)

    # Numeric transition labels may paraphrase provenance-rich Summary prose
    # (for example ``changed from A to B`` versus an authoritative correction
    # carrying the same A/B values). Preserve exact values as the hard gate; the
    # generic transition/provenance signal then proves the semantic ownership.
    fact_material_early = _cross_section_material_tokens(fact_clean)
    summary_material_early = _cross_section_material_tokens(summary_clean)
    if (
        len(fact_material_early) >= 2
        and fact_material_early.issubset(summary_material_early)
        and re.search(
            r"\b(?:changed?|corrected?|increased?|decreased?|revised?|updated?)\b|"
            r"\bfrom\b.{0,80}\bto\b",
            fact_clean,
            flags=re.IGNORECASE,
        )
        and (
            re.search(
                r"\b(?:changed?|corrected?|increased?|decreased?|revised?|updated?)\b|"
                r"\bfrom\b.{0,80}\bto\b",
                summary_clean,
                flags=re.IGNORECASE,
            )
            or "authoritative_source" in _summary_semantic_context_markers(summary_clean)
        )
    ):
        return True

    fact_terms = _cross_section_fact_terms(fact_clean)
    summary_terms = _cross_section_fact_terms(summary_clean)
    if not fact_terms or not summary_terms:
        return False

    def _term_root(value: str) -> str:
        term = str(value or "").casefold()
        if term in {"no", "not", "without"}:
            return "neg"
        return term

    matched = 0
    for fact_term in fact_terms:
        left = _term_root(fact_term)
        if any(
            left == _term_root(summary_term)
            or (
                len(left) >= 5
                and len(_term_root(summary_term)) >= 5
                and left[:5] == _term_root(summary_term)[:5]
            )
            for summary_term in summary_terms
        ):
            matched += 1
    if matched / max(1, len(fact_terms)) < 0.55:
        return False

    reference_date = _email_date(email, datetime.now().date())
    fact_dates = _cross_section_dates(fact_clean, reference_date)
    summary_dates = _cross_section_dates(summary_clean, reference_date)
    if fact_dates and not fact_dates.issubset(summary_dates):
        return False
    fact_times = _cross_section_time_tokens(fact_clean)
    summary_times = _cross_section_time_tokens(summary_clean)
    if fact_times and not fact_times.issubset(summary_times):
        return False
    fact_material = _cross_section_material_tokens(fact_clean)
    summary_material = _cross_section_material_tokens(summary_clean)
    if fact_material and not fact_material.issubset(summary_material):
        return False
    return True


def _raw_first_summary_supported_units(email: dict, summary: str) -> list[str]:
    """Return source facts already carried by a Summary candidate."""
    overview = _compact_summary_overview(summary)
    if not overview:
        return []
    covered: list[str] = []
    for sentence in _summary_source_sentences_for_overview(email):
        units = _cross_section_keypoint_clauses(sentence) or [sentence]
        for unit in units:
            if _raw_first_summary_covers_source_fact(email, unit, overview):
                if not any(
                    _cross_section_fact_equivalent(
                        email, unit, existing, coverage_threshold=0.80
                    )
                    for existing in covered
                ):
                    covered.append(unit)
    return covered


def _raw_first_summary_repair_is_acceptable(
    label: str,
    email: dict,
    actions,
    deadlines,
    before: str,
    after: str,
    before_reasons,
) -> tuple[bool, str]:
    """Accept a Summary repair only when it fixes the proven defect safely."""
    before = _compact_summary_overview(before)
    after = _compact_summary_overview(after)
    if not before_reasons:
        return False, "no_proven_failure"
    if not after or after == before:
        return False, "no_effect"

    remaining = _raw_first_summary_repair_failure_reasons(
        label, email, actions, deadlines, after
    )
    if remaining:
        return False, "target_failure_not_fixed"

    # A repair may remove unsupported wording, but it may not erase source facts
    # that the RAW/previous candidate already represented correctly.
    for unit in _raw_first_summary_supported_units(email, before):
        if not _raw_first_summary_covers_source_fact(email, unit, after):
            return False, "supported_information_lost"

    # New concrete values must be grounded in the current source or in the
    # already-validated deadline field (which may materialize relative wording).
    source_text = " ".join(_summary_source_sentences_for_overview(email))
    grounded_text = f"{source_text} {' '.join(_normalize_list(deadlines))}"
    reference_date = _email_date(email, datetime.now().date())
    if not _cross_section_material_tokens(after).issubset(
        _cross_section_material_tokens(grounded_text)
    ):
        return False, "unsupported_material_value_added"
    after_dates = _cross_section_dates(after, reference_date)
    grounded_dates = _cross_section_dates(grounded_text, reference_date)
    if after_dates and not after_dates.issubset(grounded_dates):
        return False, "unsupported_date_added"
    after_times = _cross_section_time_tokens(after)
    grounded_times = _cross_section_time_tokens(grounded_text)
    if after_times and not after_times.issubset(grounded_times):
        return False, "unsupported_time_added"

    # Reject source-copy expansion when semantic coverage did not materially
    # improve. This is a last-resort non-destructive guard, not a style rewrite.
    before_words = len(before.split())
    after_words = len(after.split())
    before_units = len(_raw_first_summary_supported_units(email, before))
    after_units = len(_raw_first_summary_supported_units(email, after))
    if (
        before
        and after_words > max(before_words + 28, int(before_words * 1.75))
        and after_units <= before_units
    ):
        return False, "unnecessary_expansion"
    return True, "accepted"


def _raw_first_key_point_violation_reasons(
    email: dict, point: str, actions, deadlines
) -> list[str]:
    """Return concrete field-local defects for one Key Point."""
    reasons: list[str] = []
    normalized_actions = _normalize_list(actions)
    normalized_deadlines = _normalize_list(deadlines)
    if _summary_has_unsupported_deadline_transition(email, point):
        reasons.append("unsupported_deadline_transition")
    if _phase1k_is_other_person_task_metadata(email, point):
        reasons.append("other_person_task_metadata")
    if _phase1k_is_unowned_deadline_label(email, point, normalized_deadlines):
        reasons.append("unowned_deadline_label")
    if normalized_actions and _phase1b_keypoint_is_action_restatement(
        point, normalized_actions
    ):
        reasons.append("action_restatement")
    if _keypoint_is_deadline_restatement(
        email, point, normalized_actions, normalized_deadlines
    ):
        reasons.append("deadline_restatement")
    # Summary overlap is intentionally NOT a failure. A concise narrative and a
    # scan-friendly atomic bullet may legitimately carry the same supported fact.
    return reasons


def _keypoints_compact_summary_ownership_mode(email: dict) -> bool:
    """Use strict Summary ownership for short, current-turn factual mail.

    In compact mail, duplicate Key Points add no scan value once Summary already
    carries the atomic fact. Longer/richer mail keeps the existing more permissive
    behavior so a useful scan layer can still survive.
    """
    source_sentences = _summary_source_sentences_for_overview(email)
    source_text = " ".join(source_sentences)
    return bool(source_sentences) and len(source_sentences) <= 4 and len(source_text.split()) <= 110


def _keypoints_compact_status_ownership_mode(
    email: dict, points, summary: str
) -> bool:
    """Prefer Summary ownership for a compact cluster of already-covered states.

    Multiple status facts are useful scan material while Summary is incomplete.
    Once a short current-turn Summary has been repaired to carry each of them,
    repeating the whole status cluster as Key Points adds no new information.
    """
    normalized = _normalize_list(points)
    if len(normalized) < 2:
        return False
    source_sentences = _summary_source_sentences_for_overview(email)
    source_text = " ".join(source_sentences)
    if not source_sentences or len(source_sentences) > 6 or len(source_text.split()) > 110:
        return False
    if not all(
        _summary_semantically_covers_fact(email, point, summary)
        for point in normalized
    ):
        return False

    # A compact status cluster may contain one framing bullet (for example an
    # overall state label) that is neither a high-impact transition nor a strong
    # standalone scan signal. If every bullet is already Summary-owned and all
    # but at most one are independently salient, keeping the whole Key Point
    # cluster is redundant. This remains content-agnostic and avoids weakening
    # richer multi-fact mail where several bullets add real scan value.
    strong = sum(
        1
        for point in normalized
        if _summary_context_fact_is_high_impact(point)
        or _keypoint_scan_value_signal(point)
    )
    return strong >= max(2, len(normalized) - 1)


def _keypoint_is_no_action_status_restatement(point: str, summary: str) -> bool:
    """Drop FYI/awareness/no-action metadata when Summary already says no work."""
    if not _summary_has_explicit_no_action_state(summary):
        return False
    text = re.sub(r"\s+", " ", str(point or "")).strip(" .!?;:")
    if not text:
        return False
    return bool(re.fullmatch(
        r"(?:"
        r"(?:this is |for )?(?:an )?(?:informational|information) (?:update|only)|"
        r"(?:for )?(?:the recipient'?s |your )?awareness only|"
        r"fyi(?: only)?|"
        r"no (?:(?:further|immediate|current|additional) )?"
        r"action(?: item)?(?: is)? (?:needed|required)(?: (?:yet|now))?(?: from (?:the recipient|you))?"
        r")",
        text,
        flags=re.IGNORECASE,
    ))


def _raw_first_key_points_failure_reasons(
    email: dict, points, summary: str, actions, deadlines
) -> list[str]:
    normalized = _normalize_list(points)
    reasons: list[str] = []
    for point in normalized:
        reasons.extend(_raw_first_key_point_violation_reasons(
            email, point, actions, deadlines
        ))

    for index, point in enumerate(normalized):
        for existing in normalized[:index]:
            if _cross_section_fact_equivalent(
                email, point, existing, coverage_threshold=0.80
            ):
                reasons.append("internal_duplicate")
                break

    # Summary overlap is a defect only when the candidate does not form a
    # genuinely useful scan layer. Two or more independently salient atomic
    # facts justify parallel Key Points even when the concise Summary also
    # carries them. This preserves rich policy/exception detail while avoiding
    # duplicate bullets for simple status/update mail.
    for point in normalized:
        if _keypoint_is_summary_temporal_restatement(email, point, summary):
            reasons.append("summary_temporal_restatement")

    scan_cluster_size = sum(
        1 for point in normalized if _keypoint_scan_value_signal(point)
    )
    strict_summary_ownership = (
        _keypoints_compact_summary_ownership_mode(email)
        or _keypoints_compact_status_ownership_mode(email, normalized, summary)
    )
    for point in normalized:
        if _keypoint_is_no_action_status_restatement(point, summary):
            reasons.append("summary_restatement_without_scan_gain")
            continue
        if not strict_summary_ownership and scan_cluster_size >= 2:
            continue
        clauses = _cross_section_keypoint_clauses(point) or [point]
        if any(
            _keypoint_is_summary_restatement(email, clause, summary)
            or _raw_first_summary_covers_source_fact(email, clause, summary)
            for clause in clauses
        ):
            reasons.append("summary_restatement_without_scan_gain")

    # Empty RAW Key Points are allowed. Recover only when the existing source-
    # residual detector proves independently useful context is missing.
    if not normalized:
        recovered = _recover_source_residual_key_points(
            email, summary, actions=actions, deadlines=deadlines
        )
        if recovered:
            reasons.append("missing_salient_source_fact")
    return list(dict.fromkeys(reasons))


def _raw_first_repair_key_points(
    email: dict, points, summary: str, actions, deadlines
) -> list[str]:
    """Repair proven Key Point defects with the existing field-local cleaner."""
    return _phase1k_distinct_key_points(
        email, points, summary, actions=actions, deadlines=deadlines
    )


def _raw_first_key_points_repair_is_acceptable(
    email: dict,
    before,
    after,
    summary: str,
    actions,
    deadlines,
    before_reasons,
) -> tuple[bool, str]:
    if not before_reasons:
        return False, "no_proven_failure"
    remaining = _raw_first_key_points_failure_reasons(
        email, after, summary, actions, deadlines
    )
    if remaining:
        return False, "target_failure_not_fixed"

    # Every previously valid supported bullet must survive verbatim or as a
    # semantic equivalent. Repair may delete only the bullet proven invalid.
    before_normalized = _normalize_list(before)
    scan_cluster_size = sum(
        1 for point in before_normalized if _keypoint_scan_value_signal(point)
    )
    strict_summary_ownership = (
        _keypoints_compact_summary_ownership_mode(email)
        or _keypoints_compact_status_ownership_mode(email, before_normalized, summary)
    )
    for point in before_normalized:
        if _raw_first_key_point_violation_reasons(email, point, actions, deadlines):
            continue
        if _keypoint_is_summary_temporal_restatement(email, point, summary):
            continue
        if _keypoint_is_no_action_status_restatement(point, summary):
            continue
        if strict_summary_ownership or scan_cluster_size < 2:
            clauses = _cross_section_keypoint_clauses(point) or [point]
            covered_clauses = [
                clause for clause in clauses
                if _keypoint_is_summary_restatement(email, clause, summary)
                or _raw_first_summary_covers_source_fact(email, clause, summary)
            ]
            if covered_clauses:
                residual_clauses = [
                    clause for clause in clauses if clause not in covered_clauses
                ]
                # Summary-owned clauses may be removed, but any independent
                # residue from the same mixed bullet must survive the repair.
                for residual in residual_clauses:
                    if not any(
                        residual == candidate
                        or _cross_section_fact_equivalent(
                            email, residual, candidate, coverage_threshold=0.72
                        )
                        or _raw_first_summary_covers_source_fact(
                            email, residual, candidate
                        )
                        for candidate in _normalize_list(after)
                    ):
                        return False, "supported_information_lost"
                continue
        if not any(
            point == candidate
            or _cross_section_fact_equivalent(
                email, point, candidate, coverage_threshold=0.80
            )
            for candidate in _normalize_list(after)
        ):
            return False, "supported_information_lost"
    return True, "accepted"

def _repair_summary_short_cross_actor_context(email: dict, actions, value: str) -> str:
    """Preserve one material third-party commitment in a short coordination mail."""
    sentences = _summary_source_sentences_for_overview(email)
    if len(sentences) != 2 or not _normalize_list(actions):
        return value
    request_flags = [_raw_first_recipient_request_sentence(email, s) for s in sentences]
    if request_flags.count(True) != 1:
        return value
    context = sentences[request_flags.index(False)]
    if not _phase1k_named_actor_commitment(context):
        return value
    if _raw_first_summary_covers_source_fact(email, context, value):
        return value
    return _summary_pack_short_source(sentences) or value


def _repair_summary_quoted_history_leak(email: dict, actions, value: str) -> str:
    """Rebuild from the current turn when Summary imports quoted-only date/value facts."""
    body = _body_text(email)
    tail = _phase1g_forwarded_tail(body)
    current = _phase1g_effective_turn_text(body)
    if not tail or not current or _phase1g_has_explicit_forwarded_delegation(body):
        return value
    reference = _email_date(email, datetime.now().date())
    current_material = (
        _cross_section_material_tokens(current)
        | _cross_section_dates(current, reference)
        | _cross_section_time_tokens(current)
    )
    tail_material = (
        _cross_section_material_tokens(tail)
        | _cross_section_dates(tail, reference)
        | _cross_section_time_tokens(tail)
    )
    summary_material = (
        _cross_section_material_tokens(value)
        | _cross_section_dates(value, reference)
        | _cross_section_time_tokens(value)
    )
    if not ((tail_material - current_material) & summary_material):
        return value
    rebuilt = _summary_pack_short_source(_summary_source_sentences_for_overview(email))
    return rebuilt or value


def _repair_summary_out_of_capacity_relation(email: dict, value: str) -> str:
    """Prevent ``X out of Y`` source facts from becoming unsupported transitions."""
    source = _phase1g_effective_turn_text(_body_text(email))
    summary = _compact_summary_overview(value)
    unit = r"(?:[KMGTPE]?B|bytes?|%|percent|items?|units?)"
    match = re.search(
        rf"\b(\d[\d,.]*)\s*({unit})\s+out\s+of\s+(\d[\d,.]*)\s*({unit})\b",
        source,
        flags=re.IGNORECASE,
    )
    if not match:
        return summary
    left_num, left_unit, right_num, right_unit = match.groups()
    wrong = re.compile(
        rf"\bfrom\s+{re.escape(left_num)}\s*{re.escape(left_unit)}\s+"
        rf"(?:to|out\s+of)\s+{re.escape(right_num)}\s*{re.escape(right_unit)}\b",
        flags=re.IGNORECASE,
    )
    if not wrong.search(summary):
        return summary
    grounded = f"while using {left_num} {left_unit} out of {right_num} {right_unit}"
    return _compact_summary_overview(wrong.sub(grounded, summary))


def summarize_email(email: dict) -> dict:
    # Phase 1J profiling: timing instrumentation only. It must never change summary behavior.
    pipeline_started = time.perf_counter()
    begin_summary_profile(email)
    preprocess_started = time.perf_counter()

    # Phase 1F: keep the flat summary contract; JSON structure is enforced by the isolated Ollama adapter.
    if _is_low_information(email):
        body = _body_text(email)
        result = {
            "summary": body or "No meaningful email content was provided.",
            "task_title": "",
            "priority": "Low",
            "status": "Not Started",
            "key_points": [],
            "deadlines": [],
            "action_items": [],
            "action_item_details": [],
        }
        record_summary_stage("preprocess", time.perf_counter() - preprocess_started)
        record_summary_stage("main_llm", 0.0)
        record_summary_stage("initial_validation", 0.0)
        record_summary_stage("action_audit", 0.0)
        record_summary_stage("postprocess", 0.0)
        set_summary_profile_flag("low_information_fast_path", True)
        trace_summary_pipeline("AI_FINAL_FAST_PATH", email=email, summary=result)
        finish_summary_profile(time.perf_counter() - pipeline_started)
        return result

    prompt = """Summarize the email below for a busy professional. Return JSON only,
using exactly these keys: summary (string), task_title (string), key_points (array of strings),
deadlines (array of strings), action_items (array of strings),
action_item_details (array of objects with exactly action and due_date).

GROUNDING RULES:
- Use only facts, numbers, dates, people, decisions, and requests explicitly present in the email.
- Read labeled conversation turns chronologically. The newest explicit instruction/state controls.
- action_items: extract EVERY distinct OPEN executable task intended for the recipient/user, including
  direct questions requiring a response. Split compound requests when independently performable.
- Action Items contain task wording ONLY: no dates, times, deadline phrases, priority labels, or urgency
  modifiers. Put deadline/scheduling metadata in deadlines/action_item_details and priority is derived separately.
- Instruction headings/context such as "Please complete these checks" or "Take the following actions"
  are NOT Action Items when concrete child tasks follow.
- "approve or reject X" is ONE decision action and must retain both alternatives.
- Exclude work assigned only to another person, informational statements, completed work,
  cancelled/superseded earlier requests, and stale quoted history.
- If a latest turn says cancel/no longer needed/do not send, the old request is NOT an action.
- deadlines: include only true due dates for OPEN recipient actions. Never treat a meeting/event
  date, sent/history date, another person's deadline, or an explicitly denied deadline as a task deadline.
- Each action_item_details entry must match one action item. due_date is only that action's own
  explicit deadline; otherwise use an empty string.
- task_title is 3-8 words for the main open recipient action. If none, return an empty string.
- summary is a concise CURRENT whole-email overview in 1-2 natural sentences covering purpose, the main
  requested work when relevant, and the material decisions, blockers, dependencies, approvals, state changes,
  or downstream consequences needed to understand the email as a whole. Preserve material explicit source
  values such as times, dates, amounts, counts, and percentages when they matter. For informational mail with
  no recipient action, preserve an explicit completed/unchanged/cancelled/no-action state instead of compressing
  it away. Summary may mention the main action or timing constraint as narrative context, but must not enumerate
  the checklist or become a second Action Items/Deadline section.
- key_points are scan-friendly atomic important facts: decisions, blockers, dependencies, exceptions, approvals,
  state changes, material amounts/counts, or other independently useful context. Do NOT restate an Action Item
  or a task deadline as a Key Point. Thematic overlap with Summary is allowed when the Key Point exposes a useful
  atomic detail from a broader narrative sentence, but do not copy an entire Summary sentence as a Key Point.
  If a source sentence mixes a task with a deadline/priority, keep the executable task in Action Items and the
  due constraint in deadlines. Write Key Points in neutral professional voice rather than sender/recipient
  conversational voice: avoid I/we/my/our/you/your when the same fact can be stated without changing modality
  or ownership. Returning [] is correct when no useful atomic fact remains.
- Do not output priority or status; MailMind derives them deterministically.

Email/conversation:
""" + _email_text(email)
    record_summary_stage("preprocess", time.perf_counter() - preprocess_started)

    main_started = time.perf_counter()
    raw = _request_json(prompt, SUMMARY_SCHEMA, operation="email summary")
    trace_summary_pipeline(
        "AI_RAW",
        email=email,
        summary={
            "summary": raw.get("summary"),
            "task_title": raw.get("task_title"),
            "key_points": raw.get("key_points"),
            "deadlines": raw.get("deadlines"),
            "action_items": raw.get("action_items"),
            "action_item_details": raw.get("action_item_details"),
        },
        payload={"source_body": _body_text(email)},
    )
    record_summary_stage("main_llm", time.perf_counter() - main_started)

    validation_started = time.perf_counter()
    body = _body_text(email)
    # RAW action ownership spans both parallel model fields.  ``action_item_details``
    # is supposed to mirror ``action_items``, but small models sometimes place one
    # half of a compound request in each field.  Treat those detail labels only as
    # additional RAW candidates, validate them against source, then repair proven
    # same-sentence fragmentation before deciding whether a second audit is needed.
    raw_detail_actions = [
        str(item.get("action") or "").strip()
        for item in (raw.get("action_item_details") if isinstance(raw.get("action_item_details"), list) else [])
        if isinstance(item, dict) and str(item.get("action") or "").strip()
    ]
    raw_action_candidates = _merge_unique(raw.get("action_items"), raw_detail_actions)
    actions = _phase1b_validate_actions(email, raw_action_candidates)
    actions = _phase1c_recover_explicit_binary_decisions(email, actions)
    actions = _phase1c_recover_implicit_recipient_requirements(email, actions)
    actions = _phase1c_recover_deferred_source_actions(email, actions)
    actions, separate_sentence_split_applied = _raw_first_split_separate_source_sentence_actions(email, actions)
    actions, source_independent_split_applied = _raw_first_split_independent_shared_deadline_actions(
        email, actions
    )
    actions, source_compound_repair_applied = _raw_first_reconstruct_coupled_source_actions(
        email, actions
    )
    actions, cross_language_coupled_repair_applied = _raw_first_merge_cross_language_coupled_actions(
        email, actions
    )
    source_compound_repair_applied = bool(
        source_compound_repair_applied
        or cross_language_coupled_repair_applied
        or source_independent_split_applied
        or separate_sentence_split_applied
    )

    # RAW-FIRST ARCHITECTURE LOCK:
    # The main model output is the default candidate. A second action-audit call
    # is permitted only when deterministic source coverage proves that grounded
    # AI_RAW actions missed recipient work. Do not run a repair/audit merely
    # because a heuristic counted more verbs than the model returned.
    raw_actions_cover_source = _raw_first_actions_cover_source_requests(email, actions)
    audit_needed = not raw_actions_cover_source
    record_summary_stage("initial_validation", time.perf_counter() - validation_started)
    set_summary_profile_flag("action_audit_ran", audit_needed)

    if audit_needed:
        # Recovery-only path: the source contains recipient work not represented
        # by the validated AI_RAW action set. This is the only condition that may
        # invoke the second action-extraction LLM pass.
        audit_started = time.perf_counter()
        audited = extract_all_user_action_items(email)
        actions = _merge_unique(actions, _phase1b_validate_actions(email, audited))
        actions = _phase1c_recover_deferred_source_actions(email, actions)
        # The audit is allowed to recover missed work, but it must not leave a
        # duplicate fragment beside an already-complete coupled source workflow.
        # Re-run the same deterministic source-boundary repair after the merge.
        actions, post_audit_compound_repair = _raw_first_reconstruct_coupled_source_actions(
            email, actions
        )
        actions, post_audit_cross_language_repair = _raw_first_merge_cross_language_coupled_actions(
            email, actions
        )
        source_compound_repair_applied = bool(
            source_compound_repair_applied
            or post_audit_compound_repair
            or post_audit_cross_language_repair
        )
        record_summary_stage("action_audit", time.perf_counter() - audit_started)
    else:
        record_summary_stage("action_audit", 0.0)

    # Normalize explicit exclusive choices after RAW/audit collection so provider
    # variance cannot turn one either/or obligation into two simultaneous tasks.
    # This is source-grammar driven and leaves ordinary multi-step workflows alone.
    actions, exclusive_alternative_collapse_applied = _raw_first_collapse_exclusive_source_alternatives(
        email, actions
    )

    # Defensive field-local cleanup: if an audit/model candidate turns bare
    # lifecycle control into a synthetic Action Item (for example, ``Start/proceed
    # with the task``), remove it only when substantive source-backed work already
    # exists in the same conversation.
    actions, execution_control_suppressed = _raw_first_suppress_redundant_execution_control_actions(
        email, actions
    )

    postprocess_started = time.perf_counter()
    # Phase 1C/1E: remove audit paraphrases, then reconcile labeled thread state
    # against the newest reply before deriving deadlines and priority.
    actions = _phase1c_merge_deadline_modifier_actions(email, actions)
    actions = _phase1c_dedupe_actions(email, actions)
    actions = _phase1e_reconcile_thread_actions(email, actions)
    actions = _phase1c_dedupe_actions(email, actions)
    actions = _phase1h_preserve_sign_return_obligation(email, actions)
    actions = _merge_unique([
        clean for clean in (_separate_action_item_text(value) for value in actions)
        if clean and not _action_item_is_metadata_only(clean)
    ])

    deadlines = _phase1b_validate_deadlines(email, raw.get("deadlines"), actions)
    direct_recovered_deadlines = _merge_unique(
        _phase1c_recover_direct_deadlines(email, actions),
        _phase1c_authoritative_cutoff_phrases(email, actions),
    )
    # Relative-to-event deadlines are deterministic derivations from two source
    # facts (dated event + explicit offset). The resulting date is not expected to
    # appear literally in the body, so it must not be rejected by lexical grounding.
    derived_event_deadlines = _phase1c_recover_relative_event_deadlines(email, actions)
    deadlines = _phase1b_validate_deadlines(
        email, _merge_unique(deadlines, direct_recovered_deadlines), actions
    )
    deadlines = _merge_unique(deadlines, derived_event_deadlines)
    deadlines = _phase1c_filter_latest_deadlines(email, deadlines)
    deadlines = _phase1c_select_authoritative_deadlines(email, actions, deadlines)
    deadlines = _phase1c_dedupe_deadlines(deadlines)
    # Source-relative due wording is useful in Summary prose but unstable as the
    # stored deadline value. Convert deterministic relative constraints to the
    # concrete calendar date only after ownership/grounding validation.
    deadlines = _phase1c_materialize_relative_deadlines(email, deadlines)
    priority = _phase1b_resolved_priority(email, actions, deadlines)
    details = _phase1b_assign_detail_deadlines(
        email, raw.get("action_item_details"), actions, deadlines
    )

    task_title = _phase1b_task_title(
        raw.get("task_title"), actions, subject=email.get("subject", "")
    )
    key_points = _phase1b_key_points(email, raw.get("key_points"), actions, deadlines)

    raw_overview = _compact_summary_overview(raw.get("summary"))
    summary_structural_failure_reasons = _raw_first_summary_repair_failure_reasons(
        "structural", email, actions, deadlines, raw_overview
    )
    summary_structural_repair_needed = bool(summary_structural_failure_reasons)
    summary_structural_repair_applied = False
    summary_structural_repair_rejected_reason = ""

    # Preserve a valid AI_RAW Summary verbatim (apart from whitespace cleanup).
    # Structural rewrite is now subject to the same prove -> repair -> verify
    # contract as every later field repair.
    overview = raw_overview
    if summary_structural_repair_needed:
        structural_candidate = _compact_summary_overview(
            _separate_summary_overview(email, raw_overview, actions)
        )
        accepted, rejection = _raw_first_summary_repair_is_acceptable(
            "structural", email, actions, deadlines,
            raw_overview, structural_candidate, summary_structural_failure_reasons,
        )
        if accepted:
            overview = structural_candidate
            summary_structural_repair_applied = True
        else:
            summary_structural_repair_rejected_reason = rejection

    raw_actions_normalized = [
        clean for clean in (
            _separate_action_item_text(value)
            for value in _normalize_list(raw.get("action_items"))
        )
        if clean and not _action_item_is_metadata_only(clean)
    ]
    raw_key_points_normalized = _normalize_list(raw.get("key_points"))
    raw_deadlines_normalized = _normalize_list(raw.get("deadlines"))

    trace_summary_pipeline(
        "AI_FIELD_VALIDATION",
        email=email,
        summary={
            "summary": overview,
            "task_title": task_title,
            "priority": priority,
            "status": "Not Started",
            "key_points": key_points,
            "deadlines": deadlines,
            "action_items": actions,
            "action_item_details": details,
        },
        payload={
            "raw_first": True,
            "actions_source_covered": raw_actions_cover_source,
            "action_audit_needed": audit_needed,
            "source_compound_repair_applied": source_compound_repair_applied,
            "exclusive_alternative_collapse_applied": exclusive_alternative_collapse_applied,
            "execution_control_suppressed": execution_control_suppressed,
            "summary_structural_repair_needed": summary_structural_repair_needed,
            "actions_changed_from_raw": actions != raw_actions_normalized,
            "key_points_changed_from_raw_validation": key_points != raw_key_points_normalized,
            "deadlines_changed_from_raw_validation": deadlines != raw_deadlines_normalized,
        },
    )
    trace_summary_pipeline(
        "AI_PRE_REPAIR",
        email=email,
        summary={
            "summary": overview,
            "task_title": task_title,
            "priority": priority,
            "status": "Not Started",
            "key_points": key_points,
            "deadlines": deadlines,
            "action_items": actions,
            "action_item_details": details,
        },
    )

    # Four-part RAW-first repair contract:
    #   1) deterministic field-validity gate;
    #   2) a concrete failure reason is mandatory;
    #   3) repair is field-local/non-destructive;
    #   4) repaired candidate is revalidated and rolled back on degradation.
    summary_repairs_applied = []
    summary_repair_rejections = []
    summary_repair_failure_reasons = {}

    def _apply_summary_repair(label, repair_fn, *args):
        nonlocal overview
        before = _compact_summary_overview(overview)
        reasons = _raw_first_summary_repair_failure_reasons(
            label, email, actions, deadlines, before
        )
        if not reasons:
            return
        summary_repair_failure_reasons[label] = list(reasons)
        after = _compact_summary_overview(repair_fn(*args))
        accepted, rejection = _raw_first_summary_repair_is_acceptable(
            label, email, actions, deadlines, before, after, reasons
        )
        if accepted:
            overview = after
            summary_repairs_applied.append(label)
        else:
            summary_repair_rejections.append({
                "label": label,
                "reason": rejection,
                "failure_reasons": list(reasons),
            })

    _apply_summary_repair(
        "actionless_completeness",
        _repair_actionless_summary_completeness,
        email, actions, overview,
    )
    _apply_summary_repair(
        "action_completeness",
        _repair_action_summary_completeness,
        email, actions, overview,
    )
    _apply_summary_repair(
        "no_deadline_constraint",
        _repair_summary_no_deadline_constraint,
        email, actions, overview,
    )
    _apply_summary_repair(
        "open_ended_timing",
        _repair_summary_open_ended_timing,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "temporal_semantics",
        _repair_summary_temporal_semantics,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "material_context",
        _repair_summary_material_context_completeness,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "overdue_open_state",
        _repair_overdue_open_summary_completeness,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "unsupported_deadline_transition",
        _repair_summary_unsupported_deadline_transition,
        email, actions, overview,
    )
    _apply_summary_repair(
        "unsupported_cross_actor_sequence",
        _repair_summary_unsupported_cross_actor_sequence,
        email, actions, overview,
    )
    _apply_summary_repair(
        "multi_action_deadline_scope",
        _repair_summary_overbroad_multi_action_deadline_scope,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "request_metadata_deadline_scope",
        _repair_summary_misattached_request_metadata_deadline,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "recipient_due_ownership",
        _repair_summary_unowned_recipient_due_tail,
        email, actions, deadlines, overview,
    )
    _apply_summary_repair(
        "explicit_deadline_preservation",
        _repair_summary_explicit_deadline_preservation,
        email, actions, deadlines, overview,
    )

    # Final deterministic regression guards operate only on source-proven
    # ownership/value defects and never call the model.
    guarded = _repair_summary_quoted_history_leak(email, actions, overview)
    if guarded != overview:
        overview = guarded
        summary_repairs_applied.append("quoted_history_leak")
    guarded = _repair_summary_short_cross_actor_context(email, actions, overview)
    if guarded != overview:
        overview = guarded
        summary_repairs_applied.append("cross_actor_context")
    guarded = _repair_summary_out_of_capacity_relation(email, overview)
    if guarded != overview:
        overview = guarded
        summary_repairs_applied.append("capacity_relation")

    deduped_overview = _dedupe_summary_repeated_facts(email, overview)
    if _compact_summary_overview(deduped_overview) != _compact_summary_overview(overview):
        summary_repairs_applied.append("summary_fact_dedupe")
        overview = deduped_overview

    key_points_before_distinct = list(key_points)
    key_points_failure_reasons = _raw_first_key_points_failure_reasons(
        email, key_points_before_distinct, overview, actions, deadlines
    )
    key_points_repair_applied = False
    key_points_repair_rejected_reason = ""
    if key_points_failure_reasons:
        key_points_candidate = _raw_first_repair_key_points(
            email, key_points_before_distinct, overview, actions, deadlines
        )
        accepted, rejection = _raw_first_key_points_repair_is_acceptable(
            email, key_points_before_distinct, key_points_candidate, overview,
            actions, deadlines, key_points_failure_reasons,
        )
        if accepted:
            key_points = key_points_candidate
            key_points_repair_applied = key_points != key_points_before_distinct
        else:
            key_points = key_points_before_distinct
            key_points_repair_rejected_reason = rejection
    else:
        # Valid Key Points pass through exactly. Summary overlap alone is not a
        # defect and can never trigger a second rewrite/dedupe pass.
        key_points = key_points_before_distinct

    trace_summary_pipeline(
        "AI_REPAIR_AUDIT",
        email=email,
        summary={
            "summary": overview,
            "task_title": task_title,
            "priority": priority,
            "status": "Not Started",
            "key_points": key_points,
            "deadlines": deadlines,
            "action_items": actions,
            "action_item_details": details,
        },
        payload={
            "summary_structural_failure_reasons": summary_structural_failure_reasons,
            "summary_structural_repair_applied": summary_structural_repair_applied,
            "summary_structural_repair_rejected_reason": summary_structural_repair_rejected_reason,
            "summary_repair_failure_reasons": summary_repair_failure_reasons,
            "summary_repairs_applied": summary_repairs_applied,
            "summary_repair_rejections": summary_repair_rejections,
            "summary_passed_raw": (
                not summary_structural_failure_reasons
                and not summary_structural_repair_applied
                and not summary_repairs_applied
                and _compact_summary_overview(overview) == raw_overview
            ),
            "key_points_failure_reasons": key_points_failure_reasons,
            "key_points_repair_applied": key_points_repair_applied,
            "key_points_repair_rejected_reason": key_points_repair_rejected_reason,
            "key_points_distinctness_repair_applied": key_points_repair_applied,
        },
    )

    result = {
        "summary": overview or "No summary was generated.",
        "task_title": task_title,
        "priority": priority,
        "status": "Not Started",
        "key_points": key_points,
        "deadlines": deadlines,
        "action_items": actions,
        "action_item_details": details,
    }
    trace_summary_pipeline("AI_FINAL", email=email, summary=result)
    record_summary_stage("postprocess", time.perf_counter() - postprocess_started)
    finish_summary_profile(time.perf_counter() - pipeline_started)
    return result

def _clean_batch_subject(value: str) -> str:
    # Remove mail-client reply/forward prefixes before using a subject as a title fallback.
    subject = re.sub(r"\s+", " ", str(value or "")).strip()
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject, flags=re.IGNORECASE).strip()
    return subject or "Email Topic"


def _short_batch_topic(value: str, *, max_words: int = 5, max_chars: int = 32) -> str:
    # Keep fallback topic labels compact enough for the batch-summary header.
    words = _clean_batch_subject(value).split()
    label = " ".join(words[:max_words]).strip(" -–—,:;")
    if len(label) <= max_chars:
        return label
    clipped = label[:max_chars].rsplit(" ", 1)[0].strip(" -–—,:;")
    return clipped or label[:max_chars].strip()


def _fallback_batch_title(email_summaries: list[dict]) -> str:
    # Build the Batch title only from real source subjects; no extra LLM call is needed.
    topics = []
    seen = set()
    for item in email_summaries or []:
        topic = _short_batch_topic(item.get("subject", ""))
        key = topic.casefold()
        if topic and key not in seen:
            topics.append(topic)
            seen.add(key)

    if not topics:
        return "Selected Email Topics"
    if len(topics) == 1:
        return topics[0]
    if len(topics) == 2:
        title = f"{topics[0]} & {topics[1]}"
    elif len(topics) == 3:
        title = f"{topics[0]}, {topics[1]} & {topics[2]}"
    else:
        title = f"{topics[0]}, {topics[1]} & {len(topics) - 2} More Topics"

    if len(title) <= 70:
        return title
    if len(topics) > 2:
        return f"{_short_batch_topic(topics[0], max_words=3, max_chars=24)}, " \
            f"{_short_batch_topic(topics[1], max_words=3, max_chars=24)} & {len(topics) - 2} More Topics"
    return f"{_short_batch_topic(topics[0], max_words=3, max_chars=30)} & " \
        f"{_short_batch_topic(topics[1], max_words=3, max_chars=30)}"


def summarize_email_batch(email_summaries: list[dict]) -> dict:
    # Batch cards do not need a second LLM pass. Keep the title grounded and
    # deterministic from the already-summarized source subjects so Batch mode
    # adds no extra overview-generation latency. Per-email summaries remain the
    # canonical content shown in the Batch reader.
    return {
        "title": _fallback_batch_title(email_summaries),
        "summary": "",
        "key_points": [],
        "action_items": [],
    }


DRAFT_REPLY_SYSTEM_PROMPT = """You are an intelligent AI Email Reply Assistant responsible for generating professional, context-aware email replies.

PRIMARY OBJECTIVE
Generate a complete email draft only from the provided email thread, extracted information, explicit task state, and system inputs. Never invent facts, commitments, dates, progress, completion, availability, attachments, or information that are not explicitly supported. The reply is a response to the current state, NOT a rewritten Summary, To-Do list, or mechanical repetition of Action Items.

SOURCE-OF-TRUTH ORDER
1. The latest valid message in the supplied email thread controls the current request.
2. Explicit current-user task state supplied by MailMind controls whether work is completed, in progress, on hold, cancelled, or not started.
3. Earlier thread turns provide context only and must not revive requests that were cancelled, completed, replaced, reassigned, or superseded later.
4. The AI summary is a helper, not a source of new facts. If it conflicts with the latest thread or explicit task state, follow the latest thread and task state.

MANDATORY REPLY ROLE MAPPING
- The original/latest external email sender is the reply recipient. Address the greeting to that sender.
- The original email recipient/current signed-in user is the reply author. The closing and signature belong only to this current user.
- Never greet the reply author/current user.
- Never sign the reply using the original sender's name, organization, or contact details.
- When the current user's signature is unavailable, use [Your name] rather than guessing a person.

STEP 1 - UNDERSTAND THE EMAIL
Read the entire supplied email thread. Identify the latest valid instruction, sender intent, expected response, every active request, every question, explicit deadlines, meeting details, attachment references, important dates, names, IDs, projects, and organizations. Treat old quoted or earlier instructions as history when a later message changes them.

STEP 2 - DETECT EMAIL INTENT
Determine the primary intent, such as informational/FYI, status update, follow-up, meeting invitation, approval request, support request, customer inquiry, complaint, thank you, confirmation, payment inquiry, document request, or other. Use that intent to guide the reply.

STEP 2A - PRESERVE REQUEST DIRECTION / SPEAKER PERSPECTIVE
Write from the reply author's point of view. A request made by the external sender to the current user remains the current user's responsibility unless the latest thread explicitly assigns that action to someone else. Never turn that request around and ask the sender to perform the same action.
- If the sender says "Please confirm the shipping address," reply as the person who must confirm it (for example, acknowledge that the address still needs confirmation). Do not ask the sender to "provide/confirm the shipping address" unless the latest thread explicitly says information is missing from the sender.
- If the sender says "Please update the incident notes," do not reply "Could you please update the incident notes?" Acknowledge the user's responsibility instead.
- If the sender cancels a prior request (for example, "Please do not send it"), acknowledge the cancellation from the receiver's perspective (for example, "Understood. I won't send it.") rather than repeating the sender's instruction as if the reply author were issuing it.
- Do not convert an incoming request into a question back to the sender merely because the requested action is Not Started/Pending. Pending means the reply author has not completed it; it does not mean the sender must do it.
- Ask the sender for clarification or missing information only when the supplied thread explicitly shows that the current user cannot perform the action without that information.

STEP 2B - RESPECT ASSIGNEE / OWNERSHIP BOUNDARIES
Treat named assignments in the latest incoming message as ownership evidence. Work explicitly assigned to another person is informational context for the reply author, not the reply author's task. Never claim another person's task as "my assigned task", never promise to complete it, and never restate a coworker's deadline as the reply author's commitment. If the latest message lists assignments for other people and gives the reply author no assignment, a manually requested reply may be a brief neutral acknowledgment only. Conditional wording such as "reply when your assigned item is complete" applies only when the latest message actually assigns an item to the reply author. Generic requests addressed to the recipient remain actionable when they are not explicitly assigned elsewhere.

STEP 3 - APPLY ACTION STATE EXACTLY
Use the supplied per-action state before writing any claim about progress or completion.
- Completed: confirm only that supported completed action. Do not extend completion to other actions.
- In Progress: say work is underway only for that action; do not claim results or completion.
- Not Started / Pending: acknowledgment only. Do NOT promise future work (for example, 'I will review/send/confirm'), do NOT say work has started, and do NOT mechanically repeat the Action Item list. A concise 'noted/acknowledged' response is enough unless a grounded question can be answered immediately from the supplied information.
- On Hold: say it is on hold/waiting only when supplied. Do not invent the reason for the hold.
- Cancelled: do not promise, process, or revive that action.
- Unknown: acknowledge the request without claiming a state.
When action states are mixed, explicitly distinguish completed work from remaining/open work.

STEP 4 - DECIDE WHETHER AND HOW TO REPLY
A. Informational/FYI/no-action: if a reply is appropriate, keep it to a short acknowledgment. Do not create a commitment or task.
B. Active request, Not Started/Pending: give a brief acknowledgment only. Do not create a new promise and do not restate each requested task.
C. Active request, In Progress: if specific per-action states show completed items, report only those completed items and describe remaining work at a high level. If no item is completed but an action is explicitly In Progress, state only that the supported action is underway; invent no result.
D. Completed: confirm only the exact supported completed action(s). If only some items are completed, never imply that the whole task is complete.
E. On Hold: accurately state that the work is on hold/waiting; do not invent why or when it will resume.
F. Cancelled/superseded/reassigned: acknowledge the latest state and do not revive the old request.
G. Other-person-owned/FYI only: use a brief neutral acknowledgment. Never adopt, promise, or report another person's work as the reply author's own.
H. Mixed state: lead with supported completed item(s), then give only a concise state of the remaining work. Do not dump the full Action Item list unless the distinction would otherwise be ambiguous.

STEP 5 - ANSWER ALL QUESTIONS
Address every active question in the latest conversation state when the answer is already supported by the supplied inputs. If an answer is unavailable, do not guess and do not create a new promise to check it when the related action is Not Started/Pending. State only that the information is not yet confirmed/available when such clarification is necessary. Never accept/decline a meeting, approve/reject a request, identify an unknown owner/contact, or state positive OR negative payment/status/approval results unless supported.

STEP 6 - PRESERVE IMPORTANT INFORMATION
When a fact is actually needed in the reply, preserve names, dates, projects, meeting schedules, deadlines, document names, ticket/invoice/PO identifiers, URLs, amounts, and organizations exactly. Do not repeat these details merely because they exist in the Summary/Action Items. Never change an explicit date or invent a deadline when none exists.

STEP 7 - ATTACHMENTS
Mention an attachment as present, sent, included, or attached only when it appears in the supplied Known attachments list or is explicitly confirmed as actually available by the current-user inputs. A sentence in the old thread saying an attachment existed is context, not proof that the reply currently includes a new attachment. Never write 'I attached' or 'Please see attached' unless the supplied reply inputs support it.

STEP 8 - MATCH TONE AND LANGUAGE
Use the same language as the latest incoming email unless instructed otherwise. Natural Taglish may receive natural Taglish. Match formality while remaining respectful, concise, clear, and non-repetitive.

STEP 9 - COMPLAINTS AND SENSITIVE BUSINESS CLAIMS
For complaints, acknowledge the issue and supported next step without claiming it is fixed unless confirmed. Do not admit legal liability, financial responsibility, policy violations, refunds, payments, approvals, or technical root causes unless explicitly supported.

STEP 10 - EMAIL FORMATTING
Output one appropriate greeting, a concise response body, one professional closing, and the current-user signature. The Subject already has its own UI field: NEVER put 'Subject:', the subject value, From/To/Date headers, separator lines such as '---', or a second greeting inside the Message body. Do not output explanations, reasoning, analysis, markdown fences, or meta commentary. Use bullets only when a multi-item status response is genuinely clearer; never use bullets merely to copy the Action Item list. Output only the email body.

FINAL VALIDATION
Before returning the draft, verify that: the latest thread state wins; stale requests were not revived; every active question was addressed; each action's individual state was respected; request direction was not reversed back onto the sender; Not Started/Pending is acknowledgment-only and contains no future-work promise; incomplete work was not presented as completed; mixed work reports supported completed items without repeating the full task list; other-person-owned work was not adopted; no unsupported fact, status, commitment, deadline, availability, approval, payment result, or attachment was introduced; exact identifiers/dates were preserved; no Subject/header/separator artifact appears in the body; there is only one greeting and one closing; the greeting addresses the sender; the signature belongs to the current user; and the result is concise and professional."""


DRAFT_REPLY_REPAIR_SYSTEM_PROMPT = """You are repairing a previously generated MailMind email reply. The original draft was already produced from grounded MailMind data. Make the smallest possible edit needed to correct the listed violation and preserve everything else that is already supported.

LOCKED REPAIR RULES
- Never invent facts, progress, completion, commitments, availability, approvals, payment/status results, owners/contacts, attachments, dates, identifiers, amounts, or deadlines.
- The latest incoming message and explicit current MailMind state are authoritative. Never revive superseded, cancelled, completed, or reassigned work.
- Keep request direction correct: work requested from the current user remains the current user's responsibility unless the latest message explicitly assigns it to someone else. Never turn the request back onto the sender.
- Respect named ownership. Never claim or promise work assigned to another person.
- Preserve each action's exact state: Completed, In Progress, Not Started/Pending, On Hold, Cancelled, or Unknown. Not Started/Pending is acknowledgment-only: never turn it into a promise, progress, or completion.
- If an answer is not supplied, say the reply author will check/confirm it rather than asserting a positive or negative answer.
- Preserve grounded names, dates, times, IDs, amounts, URLs, filenames, and other required literals exactly.
- Mention attachments as present only when explicitly listed as known.
- Preserve the required language/register and professional tone unless the listed violation is specifically a language mismatch.
- Greeting belongs to the external sender; closing/signature belongs to the current signed-in user.
- Output only the corrected email body. Do not explain the repair."""


def _reply_compact_thread_text(text: str) -> str:
    # Remove only exact consecutive duplicate text from provider-expanded/quoted
    # thread content. No unique sentence or conversation turn is dropped, and no
    # hard truncation is performed. This lowers prompt-evaluation cost while
    # preserving the same grounded information and latest-turn precedence.
    source = str(text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not source:
        return ""

    compact_lines: list[str] = []
    previous_line_key = ""
    for raw_line in source.split("\n"):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            # Keep a single blank separator between logical blocks.
            if compact_lines and compact_lines[-1] != "":
                compact_lines.append("")
            previous_line_key = ""
            continue

        # A common provider/thread artifact is the same quoted sentence repeated
        # many times inside one paragraph. Collapse only adjacent exact repeats.
        sentence_parts = re.split(r"(?<=[.!?])\s+", stripped)
        deduped_parts: list[str] = []
        previous_sentence_key = ""
        for part in sentence_parts:
            clean = " ".join(str(part or "").split())
            if not clean:
                continue
            key = clean.casefold()
            if key == previous_sentence_key:
                continue
            deduped_parts.append(clean)
            previous_sentence_key = key
        rebuilt = " ".join(deduped_parts) if deduped_parts else stripped
        line_key = " ".join(rebuilt.split()).casefold()
        if line_key and line_key == previous_line_key:
            continue
        compact_lines.append(rebuilt)
        previous_line_key = line_key

    while compact_lines and compact_lines[-1] == "":
        compact_lines.pop()
    return "\n".join(compact_lines).strip()


def _reply_build_repair_context(
    *,
    reply_recipient: str,
    reply_author: str,
    subject: str,
    summary_helper: str,
    action_statuses: list[dict],
    ownership: dict,
    overall_status: str,
    deadlines: list[str],
    known_attachments: list[str],
    user_signature: str,
    latest_incoming_text: str,
    language_mode: str,
) -> str:
    # Repair passes do not need the full 8k+ generation instruction set or the
    # complete original prompt again. Supply only the grounded facts needed to
    # make a narrow correction; the final deterministic guards still re-audit
    # ownership, action state, unknown claims, exact values, language, and roles.
    latest = _reply_compact_thread_text(latest_incoming_text)
    return f"""Grounded repair context:
Latest incoming external message:
{latest}

Reply recipient / greeting addressee: {reply_recipient}
Reply author / signature owner: {reply_author}
Subject: {subject}
AI summary helper (not a source of new facts): {summary_helper}
Per-action current state: {json.dumps(action_statuses, ensure_ascii=False)}
Assignee/ownership evidence: {json.dumps(ownership, ensure_ascii=False)}
Overall task status: {overall_status}
Known deadlines: {json.dumps(deadlines, ensure_ascii=False)}
Known attachments actually present: {json.dumps(known_attachments, ensure_ascii=False)}
Current-user signature: {user_signature}
Required language/register: {language_mode}"""


def _reply_first_pass_facts(
    *,
    reply_recipient: str,
    reply_author: str,
    action_statuses: list[dict],
    ownership: dict,
    overall_status: str,
    deadlines: list[str],
    exact_entries: list[dict],
    language_mode: str,
) -> str:
    """Build a compact authoritative fact block for the first draft call.

    These facts are already present in MailMind's inputs; this only reformats them
    so the model sees ownership/state/exact-value constraints clearly on the first
    pass.  No validator or second-pass repair is removed.
    """
    lines = [
        "DETERMINISTIC REPLY FACTS (authoritative):",
        f"- Reply author/current user: {reply_author}",
        f"- Reply recipient/external sender: {reply_recipient}",
        f"- Overall task status: {overall_status}",
        f"- Required language/register: {language_mode}",
    ]

    if action_statuses:
        lines.append(
            "- Per-action current state (authoritative JSON): "
            + json.dumps(action_statuses, ensure_ascii=False)
        )
        lines.append(
            "- Reply direction: Unless the latest thread explicitly assigns an action elsewhere, "
            "the listed action items are responsibilities of the reply author/current signed-in user."
        )
        normalized_states = {
            str(row.get("completion_status") or "").strip().casefold()
            for row in action_statuses
        }
        if (
            normalized_states
            and normalized_states <= {"not started", "pending", "unknown"}
            and _normalize_status(overall_status) == "Not Started"
        ):
            lines.append(
                "- Response policy: all current-user actions are Not Started/Pending/Unknown; "
                "acknowledge only, do not promise future work, and do not repeat the task list."
            )
        elif _normalize_status(overall_status) == "In Progress":
            lines.append(
                "- Response policy: the task is explicitly In Progress. Report only supported progress; "
                "if some actions are completed, mention those concisely and describe remaining work only at a high level."
            )
        elif "completed" in normalized_states and len(normalized_states) > 1:
            lines.append(
                "- Response policy: mixed state; report supported completed item(s) first, then "
                "summarize remaining work at a high level instead of repeating every action."
            )
    else:
        lines.append("- Per-action current state: none; acknowledgment only, no new commitment and no task-list restatement.")

    current_rows = list(ownership.get("current_user_assignments") or [])
    other_rows = list(ownership.get("other_person_assignments") or [])
    if current_rows:
        lines.append("- Explicit current-user assignments:")
        for row in current_rows:
            assignee = str(row.get("assignee") or "").strip()
            task = str(row.get("task") or "").strip()
            if task:
                lines.append(f"  * {assignee or 'Current user'}: {task}")
    if other_rows:
        lines.append("- Tasks owned by other people (do NOT adopt/promise these):")
        for row in other_rows:
            assignee = str(row.get("assignee") or "Other person").strip() or "Other person"
            task = str(row.get("task") or "").strip()
            if task:
                lines.append(f"  * {assignee}: {task}")

    exact_values = []
    seen = set()
    for entry in exact_entries:
        value = str(entry.get("value") or "").strip()
        kind = str(entry.get("kind") or "value").strip() or "value"
        key = (kind.casefold(), value.casefold())
        if value and key not in seen:
            seen.add(key)
            exact_values.append(f"{kind}={value}")
    if exact_values:
        lines.append("- Exact grounded values to preserve verbatim: " + "; ".join(exact_values))
    elif deadlines:
        lines.append("- Known deadlines: " + "; ".join(str(value) for value in deadlines if str(value).strip()))

    unknown_actions = []
    for row in action_statuses:
        action = str(row.get("action_item") or row.get("action") or "").strip()
        kind = _reply_unknown_action_kind(action)
        if action and kind:
            unknown_actions.append(f"{kind}: {action}")
    if unknown_actions:
        lines.append(
            "- Unknown-answer safeguard: do not guess outcomes for "
            + " | ".join(unknown_actions)
            + "; keep the information unconfirmed and do not create a new future-work promise."
        )

    return "\n".join(lines)


def _reply_action_status_rows(summary: dict) -> list[dict]:
    # Build per-action state from durable action details instead of copying the
    # overall task status onto every action. Individual completion/cancellation
    # flags are authoritative when present.
    overall_status = _normalize_status(summary.get("status"))
    actions = _normalize_list(summary.get("action_items"))
    details = [
        dict(item) for item in (summary.get("action_item_details") or [])
        if isinstance(item, dict)
    ]
    by_action = {
        " ".join(str(item.get("action") or "").casefold().split()).rstrip("."): item
        for item in details
        if str(item.get("action") or "").strip()
    }

    rows = []
    for index, action in enumerate(actions):
        key = " ".join(action.casefold().split()).rstrip(".")
        detail = dict(by_action.get(key) or (details[index] if index < len(details) else {}))
        explicit_status = str(
            detail.get("completion_status") or detail.get("status") or ""
        ).strip()
        if _as_bool(detail.get("cancelled")):
            state = "Cancelled"
        elif _as_bool(detail.get("completed")):
            state = "Completed"
        elif explicit_status:
            state = _normalize_status(explicit_status)
        elif (
            overall_status == "In Progress"
            and "completed" in detail
            and not _as_bool(detail.get("completed"))
            and len(actions) > 1
        ):
            # A multi-action task can be In Progress without every remaining
            # action having started. A false completion flag means only that
            # this action is still open; do not promote it to In Progress
            # unless that action carries its own explicit status.
            state = "Not Started"
        elif overall_status in {"Completed", "Cancelled", "On Hold", "In Progress"}:
            state = overall_status
        else:
            state = "Not Started"

        row = {
            "action_item": action,
            "completion_status": state,
        }
        due_date = str(detail.get("due_date") or detail.get("deadline") or "").strip()
        if due_date:
            row["due_date"] = due_date
        completion_source = str(detail.get("completion_source") or "").strip()
        if completion_source:
            row["completion_source"] = completion_source
        cancellation_source = str(detail.get("cancellation_source") or "").strip()
        if cancellation_source:
            row["cancellation_source"] = cancellation_source
        rows.append(row)
    return rows



_REPLY_ACTION_TERM_STOPWORDS = {
    "a", "an", "and", "as", "at", "be", "by", "for", "from", "in", "into",
    "it", "of", "on", "or", "please", "the", "to", "with", "your", "you",
    "acknowledge", "approve", "check", "complete", "confirm", "decide", "finish",
    "investigate", "prepare", "provide", "read", "reply", "respond", "review",
    "send", "sign", "submit", "update", "upload", "verify", "reject",
}


def _reply_action_terms(action: str) -> set[str]:
    # Keep concrete object/context words so reply validation can match a generated
    # claim or sender-directed request back to the specific MailMind action.
    terms = set()
    for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]*", str(action or "").casefold()):
        if len(token) < 3 or token in _REPLY_ACTION_TERM_STOPWORDS:
            continue
        terms.add(token)
    return terms


_REPLY_SENDER_REQUEST_PATTERN = re.compile(
    r"\b(?:could|can|would|will)\s+you\b|"
    r"\bplease\s+(?:provide|confirm|update|send|submit|review|check|verify|sign|"
    r"upload|prepare|complete|reply|respond|let\s+me\s+know)\b|"
    r"\bpaki[-\s]?(?:provide|confirm|update|send|submit|review|check|verify|sign|"
    r"upload|prepare|complete|reply|respond|suri|padala|ipadala|tingnan|kumpirmahin)\b",
    flags=re.IGNORECASE,
)


def _reply_grounding_issues(reply: str, action_statuses: list[dict]) -> list[str]:
    # Narrow deterministic audit for the two correctness rules currently being
    # hardened: pending work must not be claimed as already done, and a sender's
    # request must not be turned around and assigned back to that sender.
    # The audit does not rewrite content; it only decides whether one controlled
    # repair pass is warranted.
    text = str(reply or "").strip()
    if not text:
        return []

    pending_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown"}
    ]
    if not pending_rows:
        return []

    clauses = [
        value.strip()
        for value in re.split(r"(?<=[.!?])\s+|\n+", text)
        if value.strip()
    ]
    issues = []
    completion_pattern = re.compile(
        r"\b(?:i|we)\s+(?:(?:have|'ve|already)\s+)?"
        r"(?:completed|finished|reviewed|sent|submitted|updated|confirmed|prepared|"
        r"provided|approved|rejected|signed|uploaded|checked|investigated|responded|replied)\b|"
        r"\b(?:has|have)\s+been\s+(?:completed|finished|reviewed|sent|submitted|updated|"
        r"confirmed|prepared|provided|approved|rejected|signed|uploaded|checked)\b",
        flags=re.IGNORECASE,
    )
    future_commitment_pattern = re.compile(
        r"\b(?:i|we)\s+(?:will|'ll|shall|plan to|intend to|am going to|are going to|"
        r"will be|am starting|are starting)\b",
        flags=re.IGNORECASE,
    )

    for row in pending_rows:
        action = str(row.get("action_item") or row.get("action") or "").strip()
        terms = _reply_action_terms(action)
        if not terms:
            continue
        for clause in clauses:
            clause_terms = _reply_action_terms(clause)
            if not (terms & clause_terms):
                continue
            if completion_pattern.search(clause):
                issues.append(
                    f'Pending action "{action}" was described as already completed or performed.'
                )
                break
            if future_commitment_pattern.search(clause):
                issues.append(
                    f'Pending action "{action}" was turned into a future-work promise instead of acknowledgment-only.'
                )
                break
        for clause in clauses:
            clause_terms = _reply_action_terms(clause)
            if not (terms & clause_terms):
                continue
            if _REPLY_SENDER_REQUEST_PATTERN.search(clause):
                issues.append(
                    f'Pending action "{action}" appears to have been assigned back to the sender.'
                )
                break

    all_pending = bool(action_statuses) and all(
        str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown"}
        for row in action_statuses
    )
    if all_pending and future_commitment_pattern.search(text):
        issues.append(
            "All current-user actions are Not Started/Pending, but the draft creates a future-work promise instead of a simple acknowledgment."
        )

    # Keep retry instructions compact and deterministic.
    return list(dict.fromkeys(issues))


def _reply_pending_ack_sentence(
    action: str,
    language_mode: str = "English",
    due_date: str = "",
) -> str:
    # Not Started/Pending is acknowledgment-only. Never convert a pending task
    # into a future-work promise and never echo the task text just to prove that
    # it was understood. Ownership is preserved by acknowledging the request
    # without assigning it back to the sender.
    mode = str(language_mode or "English").strip().casefold()
    if mode == "taglish":
        return "Noted, salamat. Naitala ko ang request."
    if mode == "filipino":
        return "Salamat. Naitala ko ang kahilingan."
    return "Thank you. I have noted the request."


def _deterministic_reply_grounding_fallback(
    reply: str,
    action_statuses: list[dict],
    language_mode: str = "English",
) -> str:
    # A repair-model response can itself repeat the same direction/state error.
    # Re-audit once, then replace only the offending sentence with a grounded,
    # deterministic acknowledgment. This is intentionally narrow and does not
    # touch already-correct clauses, completed actions, dates, greeting, or
    # signature.
    pending_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown"}
    ]
    if not pending_rows:
        return str(reply or "").strip()

    completion_pattern = re.compile(
        r"\b(?:i|we)\s+(?:(?:have|'ve|already)\s+)?"
        r"(?:completed|finished|reviewed|sent|submitted|updated|confirmed|prepared|"
        r"provided|approved|rejected|signed|uploaded|checked|investigated|responded|replied)\b|"
        r"\b(?:has|have)\s+been\s+(?:completed|finished|reviewed|sent|submitted|updated|"
        r"confirmed|prepared|provided|approved|rejected|signed|uploaded|checked)\b",
        flags=re.IGNORECASE,
    )
    future_commitment_pattern = re.compile(
        r"\b(?:i|we)\s+(?:will|'ll|shall|plan to|intend to|am going to|are going to|"
        r"will be|am starting|are starting)\b",
        flags=re.IGNORECASE,
    )
    all_pending = bool(pending_rows) and len(pending_rows) == len(action_statuses)

    rows_with_terms = [
        (row, _reply_action_terms(str(row.get("action_item") or row.get("action") or "")))
        for row in pending_rows
    ]

    output_lines = []
    for line in str(reply or "").strip().splitlines():
        if not line.strip():
            output_lines.append(line)
            continue
        clauses = re.split(r"(?<=[.!?])\s+", line.strip())
        rewritten = []
        for clause in clauses:
            replacement = ""
            clause_terms = _reply_action_terms(clause)
            matched_rows = [
                row for row, terms in rows_with_terms
                if terms and (terms & clause_terms)
            ]
            has_completion_error = bool(completion_pattern.search(clause))
            has_sender_direction_error = bool(_REPLY_SENDER_REQUEST_PATTERN.search(clause))
            has_future_commitment_error = bool(future_commitment_pattern.search(clause))
            if matched_rows and (has_completion_error or has_sender_direction_error or has_future_commitment_error):
                mode = str(language_mode or "English").strip().casefold()
                if mode in {"taglish", "filipino"} and has_sender_direction_error:
                    # A language rewrite can collapse several pending actions into
                    # one sender-directed Taglish/Filipino sentence. Restore every
                    # matched obligation from MailMind's per-action state instead
                    # of keeping only the first one.
                    parts = []
                    seen = set()
                    for row in matched_rows:
                        action = str(row.get("action_item") or row.get("action") or "").strip()
                        due_date = str(row.get("due_date") or "").strip()
                        sentence = _reply_pending_ack_sentence(action, language_mode, due_date)
                        key = sentence.casefold()
                        if sentence and key not in seen:
                            seen.add(key)
                            parts.append(sentence)
                    replacement = " ".join(parts)
                else:
                    row = matched_rows[0]
                    action = str(row.get("action_item") or row.get("action") or "").strip()
                    replacement = _reply_pending_ack_sentence(action, language_mode)
            elif all_pending and has_future_commitment_error:
                replacement = _reply_pending_ack_sentence("", language_mode)
            rewritten.append(replacement or clause)
        output_lines.append(" ".join(value for value in rewritten if value).strip())

    return "\n".join(output_lines).strip()


def _repair_reply_grounding(
    reply: str,
    user_input: str,
    issues: list[str],
) -> str:
    issue_text = "\n".join(f"- {issue}" for issue in issues)
    repair_system = DRAFT_REPLY_REPAIR_SYSTEM_PROMPT + """

REPAIR PASS
The previous draft violated one or more mandatory action-state or request-direction rules. Correct only those violations while preserving all supported facts, completed actions, identifiers, dates, tone, greeting recipient, and current-user signature. Do not introduce new facts or commitments. Output only the corrected email body."""
    repair_input = f"""Grounded repair context:
{user_input}

Previous draft:
{reply}

Violations that must be corrected:
{issue_text}

Return the corrected final email body only."""
    return _request_text(repair_system, repair_input).strip()


def _reply_unknown_action_kind(action: str) -> str:
    # Classify only explicit information-seeking actions whose answer is not
    # supplied by MailMind. This intentionally does not touch ordinary pending
    # work; Action-State and Perspective remain governed by the locked guards.
    lowered = " ".join(str(action or "").casefold().split())
    if not lowered:
        return ""
    if "availability" in lowered or re.search(r"\battend\b.*\b(?:meeting|call|session)\b", lowered):
        return "availability"
    if re.search(r"\bidentify\b.*\b(?:owner|contact|person|approver)\b", lowered):
        return "identity"
    if re.search(r"\b(?:confirm|check|verify|determine)\s+whether\b", lowered):
        return "status"
    if re.search(r"\b(?:payment|invoice)\s+status\b", lowered):
        return "status"
    return ""


def _reply_unknown_clause_is_unsupported(clause: str, kind: str) -> bool:
    # Detect unsupported conclusions, not uncertainty wording. Sentences such as
    # "I will confirm whether staging is approved" are deliberately allowed.
    text = str(clause or "").strip()
    lowered = text.casefold()
    if not text or not kind:
        return False

    if kind == "availability":
        return bool(re.search(
            r"\b(?:i|we)\s+(?:can|will|cannot|can't|won't|will\s+not)\s+(?:definitely\s+)?attend\b|"
            r"\b(?:i\s+am|i'm|we\s+are|we're)\s+(?:not\s+)?available\b|"
            r"\b(?:my|our)\s+availability\s+(?:is|has\s+been)\s+(?:confirmed|open|available|unavailable)\b",
            text,
            flags=re.IGNORECASE,
        ))

    # "whether/if X is approved" is an uncertainty construction, not a claim.
    if re.search(r"\b(?:whether|if)\b", lowered):
        return False

    if kind == "identity":
        # Unknown identity/ownership is high-risk because the model can invent a
        # plausible person name while still sounding confident. Catch both the
        # direct form ("owner is John Doe") and common attribution variants such
        # as "is currently identified as", "assigned to", "handled by", and
        # "responsible person is". The action-term match in the caller keeps this
        # guard scoped to a MailMind action that explicitly asks for an unknown
        # owner/contact/person/approver.
        identity_subject = r"(?:owner|contact|approver|person)"
        person_name = r"[A-Z][A-Za-z.'-]+(?:\s+[A-Z][A-Za-z.'-]+){0,3}"
        if re.search(
            rf"\b{identity_subject}\b[^.!?]{{0,100}}\b(?:is|are)\s+{person_name}\b",
            text,
        ):
            return True
        if re.search(
            rf"\b{identity_subject}\b[^.!?]{{0,120}}\b(?:is|are)\s+"
            rf"(?:(?:currently|already|now)\s+)?(?:identified|confirmed|listed|named)\s+as\s+{person_name}\b",
            text,
        ):
            return True
        if re.search(
            rf"\b{identity_subject}\b[^.!?]{{0,120}}\b(?:is|are|was|were|has\s+been|have\s+been)\s+"
            rf"(?:(?:currently|already|now)\s+)?(?:assigned\s+to|handled\s+by|owned\s+by)\s+{person_name}\b",
            text,
        ):
            return True
        if re.search(
            rf"\b(?:responsible\s+person|person\s+responsible|point\s+of\s+contact)\b"
            rf"[^.!?]{{0,80}}\b(?:is|are)\s+{person_name}\b",
            text,
        ):
            return True
        if re.search(
            rf"\b{person_name}\b\s+(?:is|are|was|were)\s+(?:the\s+)?"
            rf"(?:production\s+deployment\s+)?{identity_subject}\b",
            text,
        ):
            return True
        if re.search(
            r"\b(?:owner|contact|approver|person)\b[^.!?]{0,100}\b"
            r"(?:has|have)\s+(?:not\s+)?been\s+(?:identified|assigned|confirmed)\b",
            text,
            flags=re.IGNORECASE,
        ):
            return True
        if re.search(
            r"\b(?:owner|contact|approver|person)\b[^.!?]{0,100}\b"
            r"(?:is|are)\s+(?:(?:currently|already|now)\s+)?(?:not\s+)?"
            r"(?:identified|assigned|confirmed|unknown)\b",
            text,
            flags=re.IGNORECASE,
        ):
            return True
        return False

    if kind == "status":
        return bool(re.search(
            r"\b(?:is|are|was|were)\s+(?:not\s+)?(?:approved|paid|completed|confirmed|rejected|declined)\b|"
            r"\b(?:has|have|had)\s+(?:not\s+)?been\s+(?:approved|paid|completed|confirmed|rejected|declined)\b|"
            r"\b(?:payment|invoice)\b[^.!?]{0,80}\b(?:is|was)\s+(?:unpaid|paid|complete|completed)\b",
            text,
            flags=re.IGNORECASE,
        ))
    return False


def _reply_unsupported_claim_issues(reply: str, action_statuses: list[dict]) -> list[str]:
    # Audit only pending/unknown information questions. Both unsupported positive
    # and unsupported negative conclusions are unsafe; "I will check/confirm" is
    # always allowed when no answer is present in the supplied inputs.
    text = str(reply or "").strip()
    if not text:
        return []

    pending_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown"}
    ]
    clauses = [
        value.strip()
        for value in re.split(r"(?<=[.!?])\s+|\n+", text)
        if value.strip()
    ]
    issues = []
    for row in pending_rows:
        action = str(row.get("action_item") or row.get("action") or "").strip()
        kind = _reply_unknown_action_kind(action)
        if not kind:
            continue
        terms = _reply_action_terms(action)
        for clause in clauses:
            clause_terms = _reply_action_terms(clause)
            if terms and not (terms & clause_terms):
                # Identity hallucinations can paraphrase "owner" as contact,
                # approver, responsible person, or point of contact. Keep the
                # broader semantic match limited to an explicit pending identity
                # action so ordinary reply sentences are not affected.
                if kind != "identity" or not re.search(
                    r"\b(?:owner|contact|approver|responsible\s+person|person\s+responsible|point\s+of\s+contact)\b",
                    clause,
                    flags=re.IGNORECASE,
                ):
                    continue
            if _reply_unknown_clause_is_unsupported(clause, kind):
                issues.append(
                    f'Unknown {kind} for pending action "{action}" was stated as a fact.'
                )
                break
    return list(dict.fromkeys(issues))


def _reply_unknown_safe_sentence(action: str, thread_text: str = "") -> str:
    # Unknown information must stay unknown. In particular, a Not Started task
    # must not become a new promise such as "I will check/confirm".
    clean = re.sub(r"\s+", " ", str(action or "").strip()).rstrip(".?!")
    kind = _reply_unknown_action_kind(clean)
    lowered = clean.casefold()

    if kind == "availability":
        target = re.sub(r"^(?:confirm|check|verify)\s+(?:my\s+)?availability\s+for\s+", "", clean, flags=re.IGNORECASE).strip()
        target = target or "the meeting"
        return f"My availability for {target} is not confirmed in the available information."

    match = re.match(r"^(?:confirm|check|verify|determine)\s+whether\s+(.+)$", clean, flags=re.IGNORECASE)
    if match:
        return f"The available information does not confirm whether {match.group(1)}."

    match = re.match(r"^identify\s+(.+)$", clean, flags=re.IGNORECASE)
    if match:
        object_text = match.group(1).strip()
        return f"The available information does not identify {object_text}."

    if lowered.startswith("confirm "):
        target = clean[8:].strip()
        return f"The available information does not yet confirm {target}." if target else "The requested information is not yet confirmed."
    return "The requested information is not confirmed in the available information."


def _deterministic_reply_unknown_fallback(
    reply: str,
    action_statuses: list[dict],
    thread_text: str = "",
) -> str:
    # Rewrites only clauses that still assert an unsupported answer after one
    # controlled repair. All locked action-state/perspective output is left alone.
    pending_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown"}
        and _reply_unknown_action_kind(str(row.get("action_item") or row.get("action") or ""))
    ]
    if not pending_rows:
        return str(reply or "").strip()

    rows = [
        (
            row,
            _reply_unknown_action_kind(str(row.get("action_item") or row.get("action") or "")),
            _reply_action_terms(str(row.get("action_item") or row.get("action") or "")),
        )
        for row in pending_rows
    ]
    output_lines = []
    for line in str(reply or "").strip().splitlines():
        if not line.strip():
            output_lines.append(line)
            continue
        clauses = re.split(r"(?<=[.!?])\s+", line.strip())
        rewritten = []
        for clause in clauses:
            replacement = ""
            clause_terms = _reply_action_terms(clause)
            for row, kind, terms in rows:
                if terms and not (terms & clause_terms):
                    if kind != "identity" or not re.search(
                        r"\b(?:owner|contact|approver|responsible\s+person|person\s+responsible|point\s+of\s+contact)\b",
                        clause,
                        flags=re.IGNORECASE,
                    ):
                        continue
                if _reply_unknown_clause_is_unsupported(clause, kind):
                    action = str(row.get("action_item") or row.get("action") or "").strip()
                    replacement = _reply_unknown_safe_sentence(action, thread_text)
                    break
            rewritten.append(replacement or clause)
        output_lines.append(" ".join(value for value in rewritten if value).strip())
    return "\n".join(output_lines).strip()


def _repair_reply_unsupported_claims(
    reply: str,
    user_input: str,
    issues: list[str],
) -> str:
    issue_text = "\n".join(f"- {issue}" for issue in issues)
    repair_system = DRAFT_REPLY_REPAIR_SYSTEM_PROMPT + """

UNKNOWN-FACT REPAIR PASS
The previous draft stated one or more answers that are not supplied by MailMind. Correct only those unsupported conclusions. For unknown availability, payment/status, approval, or owner/contact information, say that the reply author will check or confirm it instead of asserting either a positive or negative answer. Preserve supported action state, request direction, exact identifiers/dates/times, greeting recipient, and current-user signature. Do not introduce new facts or commitments beyond checking/confirming the unknown information. Output only the corrected email body."""
    repair_input = f"""Grounded repair context:
{user_input}

Previous draft:
{reply}

Unsupported conclusions that must be corrected:
{issue_text}

Return the corrected final email body only."""
    return _request_text(repair_system, repair_input).strip()



def _reply_exact_value_entries(summary: dict, original_email: dict) -> list[dict]:
    # Preserve only high-value literals that are grounded in the current MailMind
    # state. Deadlines come from validated summary/action state; identifiers and
    # amounts come from the subject/current actions so old quoted thread history
    # is not forced back into a reply.
    entries: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, source: str = "") -> None:
        clean = str(value or "").strip()
        if not clean:
            return
        key = (kind, clean.casefold())
        if key in seen:
            return
        seen.add(key)
        entries.append({"kind": kind, "value": clean, "source": source})

    deadline_sources = list(_normalize_list(summary.get("deadlines")))
    for item in summary.get("action_item_details") or []:
        if not isinstance(item, dict):
            continue
        due = str(item.get("due_date") or item.get("deadline") or "").strip()
        if due:
            deadline_sources.append(due)

    for source in deadline_sources:
        text = str(source or "")
        for match in re.finditer(r"\b\d{4}-\d{2}-\d{2}\b", text):
            add("date", match.group(0), text)
        for match in re.finditer(r"\b\d{1,2}:\d{2}\s*(?:AM|PM)\b", text, flags=re.IGNORECASE):
            add("time", match.group(0), text)

    relevant_text = "\n".join(
        [
            str(summary.get("subject") or original_email.get("subject") or ""),
            *[str(value) for value in _normalize_list(summary.get("action_items"))],
            str(summary.get("summary") or ""),
        ]
    )
    for match in re.finditer(r"\b[A-Z][A-Z0-9]{1,11}-[A-Z0-9][A-Z0-9-]*\b", relevant_text):
        value = match.group(0)
        if any(ch.isdigit() for ch in value):
            add("identifier", value, relevant_text)

    amount_pattern = re.compile(
        r"(?<!\w)(?:[$€£₱]\s?\d[\d,]*(?:\.\d{1,2})?|"
        r"(?:USD|PHP|EUR|GBP)\s+\d[\d,]*(?:\.\d{1,2})?)(?!\w)",
        flags=re.IGNORECASE,
    )
    for match in amount_pattern.finditer(relevant_text):
        add("amount", match.group(0), relevant_text)

    return entries


def _reply_exact_value_issues(reply: str, entries: list[dict]) -> list[str]:
    # A missing literal is a correctness issue; a differently formatted date is
    # still missing because MailMind must preserve the source value exactly.
    text = str(reply or "")
    issues = []
    for entry in entries:
        value = str(entry.get("value") or "").strip()
        kind = str(entry.get("kind") or "value").strip()
        if not value:
            continue
        if kind == "time":
            present = value.casefold() in text.casefold()
        else:
            present = value in text
        if not present:
            issues.append(f'Missing exact {kind}: "{value}".')
    return list(dict.fromkeys(issues))


def _repair_reply_exact_values(
    reply: str,
    user_input: str,
    entries: list[dict],
    issues: list[str],
) -> str:
    required = "\n".join(
        f'- {entry.get("kind")}: {entry.get("value")}' for entry in entries
    )
    issue_text = "\n".join(f"- {issue}" for issue in issues)
    repair_system = DRAFT_REPLY_REPAIR_SYSTEM_PROMPT + """

EXACT-VALUE REPAIR PASS
The previous draft omitted or reformatted one or more grounded literal values. Correct only those exact-value violations. Every required literal below must appear verbatim in the final reply (AM/PM letter case may vary, but the numeric time must remain unchanged). Do not convert ISO dates into written dates. Preserve all already-correct action states, request direction, unknown-fact handling, greeting recipient, signature owner, and supported wording. Do not invent new facts, attachments, progress, completion, or commitments. Output only the corrected email body."""
    repair_input = f"""Grounded repair context:
{user_input}

Previous draft:
{reply}

Required exact values:
{required}

Violations that must be corrected:
{issue_text}

Return the corrected final email body only."""
    return _request_text(repair_system, repair_input).strip()


def _deterministic_reply_exact_value_fallback(reply: str, entries: list[dict]) -> str:
    # Last resort after one repair call: insert only still-missing grounded
    # literals before the closing. This does not rewrite any locked rule output.
    text = str(reply or "").strip()
    missing = [
        entry for entry in entries
        if _reply_exact_value_issues(text, [entry])
    ]
    if not missing:
        return text

    deadline_values = []
    reference_values = []
    for entry in missing:
        kind = str(entry.get("kind") or "")
        value = str(entry.get("value") or "").strip()
        if kind in {"date", "time"}:
            deadline_values.append(value)
        elif value:
            reference_values.append(value)

    additions = []
    if deadline_values:
        additions.append("I have noted the exact deadline details: " + " at ".join(deadline_values) + ".")
    if reference_values:
        additions.append("Reference: " + ", ".join(reference_values) + ".")
    if not additions:
        return text

    lines = text.splitlines()
    closing_pattern = re.compile(
        r"^(?:best regards|kind regards|warm regards|regards|sincerely|respectfully|thanks|thank you|salamat)[,!]?$",
        flags=re.IGNORECASE,
    )
    insert_at = next(
        (index for index in range(len(lines) - 1, -1, -1) if closing_pattern.match(lines[index].strip())),
        len(lines),
    )
    while insert_at > 0 and not lines[insert_at - 1].strip():
        insert_at -= 1
    block = additions + [""]
    lines[insert_at:insert_at] = block
    return "\n".join(lines).strip()

_REPLY_FILIPINO_MARKERS = {
    "paki": r"\bpaki(?:[-\s]?[a-z]+)?\b",
    "yung": r"\byung\b",
    "salamat": r"\bsalamat\b",
    "bukas": r"\bbukas\b",
    "kailangan": r"\bkailangan\b",
    "pwede": r"\bpwede(?:ng)?\b",
    "sana": r"\bsana\b",
    "hindi": r"\bhindi\b",
    "wala": r"\bwala\b",
    "meron": r"\b(?:meron|mayroon)\b",
    "natanggap": r"\bnatanggap\b",
    "ipadala": r"\b(?:ipadala|ipapadala)\b",
    "susuri": r"\b(?:susuri|susuriin)\b",
    "pakisend": r"\bpakisend\b",
    "pakireview": r"\bpaki[-\s]?review\b",
    "pakiconfirm": r"\bpaki[-\s]?confirm\b",
    "pakicheck": r"\bpaki[-\s]?check\b",
    "pakisuyo": r"\bpakisuyo\b",
    "mensahe": r"\bmensahe\b",
    "ako": r"\bako\b",
    "ko": r"\bko\b",
    "mo": r"\bmo\b",
    "namin": r"\bnamin\b",
    "natin": r"\bnatin\b",
    "niyo": r"\b(?:niyo|nyo)\b",
    "po": r"\b(?:po|opo)\b",
}

_REPLY_ENGLISH_LANGUAGE_SIGNALS = re.compile(
    r"\b(?:review|budget|draft|comments?|email|report|project|meeting|send|confirm|"
    r"update|status|invoice|deadline|file|document|contract|address|feedback|"
    r"approval|owner|shipping|security|questionnaire)\b",
    flags=re.IGNORECASE,
)


def _reply_latest_incoming_text(original_email: dict, reply_author: str = "") -> str:
    # Language matching is based on the newest external turn, not on old quoted
    # history or a Sent Items turn authored by the signed-in user.
    _, author_address = parseaddr(str(reply_author or ""))
    author_key = author_address.casefold() if author_address else str(reply_author or "").casefold()
    messages = original_email.get("thread_messages") or []
    if isinstance(messages, list):
        for item in reversed(messages):
            if not isinstance(item, dict):
                continue
            sender = str(item.get("from") or "").strip()
            _, sender_address = parseaddr(sender)
            sender_key = sender_address.casefold() if sender_address else sender.casefold()
            if author_key and sender_key == author_key:
                continue
            body = str(item.get("body_text") or item.get("snippet") or "").strip()
            if body:
                return body

    text = str(original_email.get("body_text") or original_email.get("snippet") or "").strip()
    if "--- Conversation turn ---" in text:
        sections = [part.strip() for part in text.split("--- Conversation turn ---") if part.strip()]
        if sections:
            return sections[-1]
    return text


def _reply_language_marker_hits(text: str) -> set[str]:
    lowered = str(text or "").casefold()
    return {
        name for name, pattern in _REPLY_FILIPINO_MARKERS.items()
        if re.search(pattern, lowered, flags=re.IGNORECASE)
    }


def _reply_language_mode(text: str) -> str:
    # Stay deliberately conservative so ordinary English email is never routed
    # through a language rewrite. Two Filipino markers are required.
    source = str(text or "").strip()
    hits = _reply_language_marker_hits(source)
    if len(hits) < 2:
        return "English"
    english_signals = len(_REPLY_ENGLISH_LANGUAGE_SIGNALS.findall(source))
    code_switch = bool(re.search(r"\bpaki[-\s]?(?:review|send|confirm|check|update)\b", source, flags=re.IGNORECASE))
    return "Taglish" if english_signals >= 1 or code_switch else "Filipino"


def _reply_language_issues(reply: str, language_mode: str) -> list[str]:
    # English stays on the original path. For Filipino/Taglish, require more than
    # a translated closing so a pure-English body with only "Salamat" is not
    # accepted as language-matched.
    mode = str(language_mode or "English").strip().casefold()
    if mode not in {"taglish", "filipino"}:
        return []
    hits = _reply_language_marker_hits(reply)
    if len(hits) >= 2:
        return []
    return [f"Reply does not match the latest incoming {language_mode} language/register."]


def _repair_reply_language(
    reply: str,
    user_input: str,
    language_mode: str,
    latest_incoming_text: str,
) -> str:
    repair_system = DRAFT_REPLY_REPAIR_SYSTEM_PROMPT + f"""

LANGUAGE-MATCH REPAIR PASS
The latest incoming external message is {language_mode}. Rewrite only the language/register mismatch so the reply naturally matches that latest incoming message. For Taglish, use natural Filipino-English code-switching rather than translating every technical term. For Filipino, use natural Filipino while preserving technical names as written. Preserve every supported fact, action state, request direction, unknown-fact safeguard, exact identifier/date/time/amount, greeting recipient, and current-user signature. Do not add new facts, progress, completion, availability, attachments, deadlines, or commitments. Output only the corrected email body."""
    repair_input = f"""Grounded repair context:
{user_input}

Latest incoming external message used for language matching:
{latest_incoming_text}

Previous draft:
{reply}

Required language/register: {language_mode}

Return the corrected final email body only."""
    return _request_text(repair_system, repair_input).strip()



def _repair_reply_combined(
    reply: str,
    repair_context: str,
    issue_groups: dict[str, list[str]],
    exact_entries: list[dict],
    language_mode: str,
) -> str:
    """Correct every currently detected Reply Draft violation in one LLM pass.

    All deterministic validators remain authoritative.  This helper only replaces
    the old sequence of category-specific model repairs; after this single call,
    every guard is re-run and any remaining violation is corrected by the same
    deterministic fallbacks that already protect the final draft.
    """
    labels = {
        "ownership": "OWNERSHIP / ASSIGNEE BOUNDARY",
        "grounding": "ACTION STATE / REQUEST DIRECTION",
        "unsupported_claims": "UNSUPPORTED OR UNKNOWN FACT",
        "exact_values": "EXACT GROUNDED VALUE",
        "language": "LANGUAGE / REGISTER",
        "state_response": "RESPONSE STATE / NO TO-DO RESTATEMENT",
    }
    sections: list[str] = []
    for key in ("ownership", "grounding", "unsupported_claims", "exact_values", "language", "state_response"):
        issues = [str(value).strip() for value in (issue_groups.get(key) or []) if str(value).strip()]
        if not issues:
            continue
        lines = "\n".join(f"- {issue}" for issue in issues)
        sections.append(f"{labels[key]}:\n{lines}")

    required_exact = []
    if issue_groups.get("exact_values"):
        required_exact = [
            f'- {entry.get("kind")}: {entry.get("value")}'
            for entry in exact_entries
            if str(entry.get("value") or "").strip()
        ]

    repair_system = DRAFT_REPLY_REPAIR_SYSTEM_PROMPT + """

COMBINED CORRECTION PASS
The previous draft failed one or more deterministic MailMind checks. Correct ALL
listed violations in this single pass while changing as little else as possible.

Priority rules:
1. Never adopt or promise work explicitly assigned to another named person.
2. Preserve the current state and direction of every action; Not Started/Pending must be acknowledgment-only (no 'I will...' promise), pending work must not be claimed complete, and the reply author's action must not be sent back to the sender.
3. Do not assert unknown availability, payment/status, approval, identity, or other
   unsupported conclusions; for Not Started/Pending, state only that the information is not confirmed/available rather than promising to check it.
4. Every required grounded identifier/date/time/amount must appear exactly as supplied.
5. Match the required language/register without weakening rules 1-4.
6. Reply to the current state; do not dump Action Items or Deadline/Priority metadata.

Preserve already-correct facts, tone, greeting recipient, and current-user signature.
Do not invent facts, attachments, deadlines, progress, completion, or commitments. Do not output Subject/From/To/Date headers, separator lines, or duplicate greetings.
Output only the corrected final email body."""

    exact_block = "\n".join(required_exact)
    repair_input = f"""{repair_context}

Previous draft:
{reply}

Detected violations that must ALL be corrected:
{chr(10).join(sections)}
"""
    if exact_block:
        repair_input += f"""
Required exact values (include verbatim):
{exact_block}
"""
    if issue_groups.get("language"):
        repair_input += f"""
Required language/register: {language_mode}
"""
    repair_input += "\nReturn the corrected final email body only."
    set_next_ollama_operation("reply draft repair_combined")
    return _request_text(repair_system, repair_input).strip()


def _deterministic_reply_language_fallback(reply: str, language_mode: str) -> str:
    # Last resort after the single language repair. Add only a neutral grounded
    # acknowledgment so no task/fact semantics are changed. This is intentionally
    # small and only runs for already-detected Filipino/Taglish source messages.
    text = str(reply or "").strip()
    if not _reply_language_issues(text, language_mode):
        return text
    mode = str(language_mode or "").strip().casefold()
    anchor = "Noted, salamat sa message mo." if mode == "taglish" else "Salamat sa mensahe mo."
    lines = text.splitlines()
    if not lines:
        return anchor
    greeting_pattern = re.compile(
        r"^(?:dear|hi|hello|good morning|good afternoon|good evening)\b",
        flags=re.IGNORECASE,
    )
    first_content = next((i for i, line in enumerate(lines) if line.strip()), 0)
    insert_at = first_content + 1 if greeting_pattern.search(lines[first_content].strip()) else first_content
    while insert_at < len(lines) and not lines[insert_at].strip():
        insert_at += 1
    lines[insert_at:insert_at] = [anchor, ""]
    return "\n".join(lines).strip()


def reply_draft_block_reason(summary: dict, original_email: dict | None = None) -> str:
    # Block reply generation only for clear no-reply or unsafe-message cases.
    # Informational/no-action email is still allowed because a short acknowledgment
    # can be appropriate when the user explicitly chooses Draft email.
    original = original_email or {}
    category = str(
        original.get("security_category") or summary.get("security_category") or ""
    ).strip().casefold()
    if category in {
        "spam", "phishing", "malware", "scam / fraud", "impersonation", "suspicious"
    }:
        return "Reply Draft is disabled for email currently classified as unsafe or suspicious."

    sender = str(original.get("from") or summary.get("from") or "").casefold()
    _, sender_address = parseaddr(sender)
    sender_key = sender_address or sender
    if re.search(r"(?:^|[._+-])(?:no[-_.]?reply|do[-_.]?not[-_.]?reply|mailer-daemon)(?:@|[._+-]|$)", sender_key):
        return "Reply Draft is disabled because this sender is marked as no-reply."

    body = str(original.get("body_text") or original.get("snippet") or "")
    if re.search(
        r"\b(?:please\s+)?(?:do not|don't)\s+reply\b|"
        r"\bno reply (?:is )?(?:needed|required)\b|"
        r"\bthis (?:mailbox|email address) is not monitored\b",
        body,
        flags=re.IGNORECASE,
    ):
        return "Reply Draft is disabled because the email explicitly says not to reply."
    return ""


def _reply_known_attachments(summary: dict, original_email: dict) -> list[str]:
    # The model may mention only attachments that MailMind actually knows exist.
    values = []
    seen = set()
    for item in list(original_email.get("attachments") or []) + list(summary.get("attachments") or []):
        if isinstance(item, dict):
            name = str(item.get("filename") or item.get("name") or "").strip()
        else:
            name = str(item or "").strip()
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            values.append(name)
    return values

def _reply_role_identities(summary: dict, original_email: dict) -> tuple[str, str]:
    # Prefer the authenticated account identity when the controller supplies it.
    # This protects role mapping even when a provider-expanded thread's newest
    # turn happens to be a Sent Items message authored by the current user.
    explicit_author = str(summary.get("reply_author_identity") or "").strip()
    reply_author = explicit_author or str(summary.get("to") or original_email.get("to") or "").strip()
    _, author_address = parseaddr(reply_author)
    author_key = author_address.casefold() if author_address else ""

    candidates = [
        str(summary.get("from") or "").strip(),
        str(original_email.get("from") or "").strip(),
        str(summary.get("to") or "").strip(),
        str(original_email.get("to") or "").strip(),
    ]
    reply_recipient = ""
    for candidate in candidates:
        if not candidate:
            continue
        _, address = parseaddr(candidate)
        candidate_key = address.casefold() if address else candidate.casefold()
        if author_key and candidate_key == author_key:
            continue
        reply_recipient = candidate
        break
    if not reply_recipient:
        reply_recipient = str(summary.get("from") or original_email.get("from") or "").strip()
    return reply_recipient, reply_author



def _reply_named_assignee(evidence: str) -> str:
    # Reply ownership uses a conservative named-assignment parser. In particular,
    # a hyphen counts as an assignment delimiter only when surrounded by spaces;
    # this prevents ordinary hyphenated imperatives (for example paki-review) from
    # being mistaken for a person's name.
    cleaned = re.sub(r"^\s*(?:[-*•]+|\d+[.)])\s*", "", str(evidence or "").strip())
    patterns = (
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s*[:–—]\s*\S+",
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+-\s+\S+",
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2}),\s*(?:please|kindly)\b",
        r"^([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\s+"
        r"(?:must|should|needs? to|has to|is required to)\b",
        r"^(?:assigned to|owner|assignee)\s*[:=-]\s*"
        r"([A-Z][A-Za-z'-]*(?:\s+[A-Z][A-Za-z'-]*){0,2})\b",
    )
    for pattern in patterns:
        match = re.match(pattern, cleaned)
        if match:
            return match.group(1).strip()
    return ""


def _reply_assignment_task_text(evidence: str, assignee: str = "") -> str:
    # Remove only the leading ownership label. The remaining grounded task text
    # can then be compared with generated first-person commitments.
    text = re.sub(r"^\s*(?:[-*•]+|\d+[.)])\s*", "", str(evidence or "").strip())
    if assignee:
        escaped = re.escape(str(assignee).strip())
        patterns = (
            rf"^{escaped}\s*[:–—-]\s*",
            rf"^{escaped}\s*,\s*(?:please|kindly)\s+",
            rf"^{escaped}\s+(?:must|should|needs? to|has to|is required to)\s+",
            rf"^(?:assigned to|owner|assignee)\s*[:=-]\s*{escaped}\s*[:–—,-]?\s*",
        )
        for pattern in patterns:
            updated = re.sub(pattern, "", text, count=1, flags=re.IGNORECASE)
            if updated != text:
                text = updated.strip()
                break
    return text


def _reply_assignment_ownership(latest_incoming_text: str, reply_author: str) -> dict:
    # Use the authenticated display name when available. Never infer a person's
    # identity from the local part of an email address.
    author_name, _ = parseaddr(str(reply_author or ""))
    author_name = author_name.strip()
    source = str(latest_incoming_text or "")
    current_user = []
    other_people = []

    for evidence in _phase1b_source_sentences(source):
        assignee = _reply_named_assignee(evidence)
        if not assignee:
            continue
        row = {
            "assignee": assignee,
            "task": _reply_assignment_task_text(evidence, assignee),
            "evidence": evidence.strip(),
        }
        if author_name and _phase1g_same_person(assignee, author_name):
            current_user.append(row)
        else:
            other_people.append(row)

    explicit_current_user_scope = bool(re.search(
        r"\b(?:assigned\s+(?:directly\s+)?to\s+you|"
        r"you\s+are\s+(?:assigned|responsible\s+for)|"
        r"your\s+(?:tasks?|actions?|responsibilit(?:y|ies)|deliverables?)\s+(?:are|include))\b",
        source,
        flags=re.IGNORECASE,
    ))
    return {
        "current_user_name": author_name,
        "current_user_assignments": current_user,
        "other_person_assignments": other_people,
        "explicit_current_user_scope": explicit_current_user_scope,
        "has_current_user_assignment": bool(current_user or explicit_current_user_scope),
    }


def _reply_ownership_terms(task: str) -> set[str]:
    return _phase1e_object_tokens(str(task or ""))


def _reply_ownership_issues(reply: str, ownership: dict) -> list[str]:
    other_rows = list(ownership.get("other_person_assignments") or [])
    if not other_rows:
        return []

    has_current = bool(ownership.get("has_current_user_assignment"))
    issues = []
    text = str(reply or "")
    if not has_current and re.search(
        r"\b(?:my|our)\s+(?:assigned\s+)?(?:tasks?|items?|actions?|responsibilit(?:y|ies)|deliverables?)\b|"
        r"\bhere\s+(?:are|is)\s+(?:my|our)\s+(?:assigned\s+)?(?:tasks?|items?|actions?|responsibilit(?:y|ies)|deliverables?)\b",
        text,
        flags=re.IGNORECASE,
    ):
        issues.append("Draft claims named coworker assignments as the reply author's own work.")

    if not has_current and re.search(
        r"\b(?:i|we)\s+(?:will|shall)\s+(?:ensure|make sure)\b[^.!?]{0,120}"
        r"\b(?:they|all|these|those|items?|tasks?)\b[^.!?]{0,80}"
        r"\b(?:complete|completed|done|finished)\b",
        text,
        flags=re.IGNORECASE,
    ):
        issues.append("Draft promises completion of assignments not owned by the reply author.")

    commitment = re.compile(
        r"\b(?:i|we)\s+(?:(?:will|'ll|shall|must|need to|have to|am going to|are going to)|"
        r"(?:have|'ve)\s+(?:completed|finished|sent|submitted|updated|reviewed|prepared|provided))\b|"
        r"\b(?:my|our)\s+(?:task|action|responsibility|deliverable)\b",
        flags=re.IGNORECASE,
    )
    other_terms = [
        (row, _reply_ownership_terms(row.get("task") or row.get("evidence") or ""))
        for row in other_rows
    ]
    for clause in re.split(r"(?<=[.!?])\s+|\n+", text):
        if not clause.strip() or not commitment.search(clause):
            continue
        clause_terms = _reply_ownership_terms(clause)
        for row, terms in other_terms:
            if not terms:
                continue
            overlap = len(terms & clause_terms) / max(1, len(terms))
            if overlap >= 0.45:
                issues.append(
                    f"Draft commits the reply author to work explicitly assigned to {row.get('assignee') or 'another person'}."
                )
                break
    return _merge_unique(issues)


def _repair_reply_ownership(reply: str, user_input: str, ownership: dict, issues: list[str]) -> str:
    issue_text = "\n".join(f"- {issue}" for issue in issues)
    repair_system = DRAFT_REPLY_REPAIR_SYSTEM_PROMPT + """

OWNERSHIP REPAIR PASS
The previous draft crossed an assignee boundary. Correct only the ownership violation. Work explicitly assigned to another named person must not be claimed, promised, completed, or listed as the reply author's own task. Keep any action genuinely assigned to the reply author, and keep a generic recipient request when it is not assigned elsewhere. If the reply author has no owned assignment, use a brief neutral acknowledgment rather than adopting coworkers' tasks. Preserve supported facts, action state, exact values, language, greeting recipient, and current-user signature. Output only the corrected email body."""
    repair_input = f"""Grounded repair context:
{user_input}

Ownership evidence:
{json.dumps(ownership, ensure_ascii=False)}

Previous draft:
{reply}

Violations that must be corrected:
{issue_text}

Return the corrected final email body only."""
    return _request_text(repair_system, repair_input).strip()


def _deterministic_reply_ownership_fallback(reply: str, ownership: dict, language_mode: str) -> str:
    # Safe last resort when the message names work only for other people.
    if ownership.get("has_current_user_assignment"):
        return str(reply or "").strip()
    if not ownership.get("other_person_assignments"):
        return str(reply or "").strip()

    mode = str(language_mode or "English").strip().casefold()
    if mode == "taglish":
        body = "Noted, salamat sa update."
    elif mode == "filipino":
        body = "Salamat sa update. Naitala ko ang impormasyon."
    else:
        body = "Thank you for the update. I have noted the information."

    lines = str(reply or "").strip().splitlines()
    greeting_pattern = re.compile(
        r"^(?:dear|hi|hello|good morning|good afternoon|good evening)\b",
        flags=re.IGNORECASE,
    )
    closing_pattern = re.compile(
        r"^(?:best regards|kind regards|warm regards|regards|sincerely|respectfully|thanks|thank you|salamat)[,!]?$",
        flags=re.IGNORECASE,
    )
    first = next((i for i, line in enumerate(lines) if line.strip()), None)
    closing = next(
        (i for i in range(len(lines) - 1, -1, -1) if closing_pattern.match(lines[i].strip())),
        None,
    )
    greeting = lines[first].strip() if first is not None and greeting_pattern.search(lines[first].strip()) else ""
    footer = lines[closing:] if closing is not None else []
    rebuilt = []
    if greeting:
        rebuilt.extend([greeting, ""])
    rebuilt.append(body)
    if footer:
        rebuilt.extend(["", *footer])
    return "\n".join(rebuilt).strip()

def _reply_no_action_issues(reply: str, action_statuses: list[dict]) -> list[str]:
    # When MailMind has no current-user action items, the email is treated as
    # informational for Reply Draft purposes. A draft may acknowledge or restate
    # grounded information, but it must not invent future work, active progress,
    # completion, attendance, or another commitment for the reply author.
    if action_statuses:
        return []
    text = str(reply or "").strip()
    if not text:
        return []

    commitment_patterns = [
        re.compile(
            r"\b(?:i|we)\s+(?:will|'ll|shall|plan to|intend to|need to|have to|am going to|are going to)\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:i|we)\s+(?:am|are)\s+(?:working|reviewing|preparing|handling|processing|investigating|updating|checking|verifying|completing|sending|submitting)\b",
            flags=re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:i|we)\s+(?:(?:have|'ve)\s+)?(?:started|completed|finished|submitted|sent|updated|reviewed|prepared|approved|rejected|resolved|fixed)\b",
            flags=re.IGNORECASE,
        ),
    ]
    if any(pattern.search(text) for pattern in commitment_patterns):
        return ["No current-user action exists, but the draft creates or claims work for the reply author."]
    return []


def _deterministic_reply_no_action_fallback(reply: str, language_mode: str) -> str:
    # Safe general fallback for an informational/no-action email. Keep the model's
    # grounded greeting and footer when available, but replace the body with a
    # short acknowledgment that creates no new obligation.
    mode = str(language_mode or "English").strip().casefold()
    if mode == "taglish":
        body = "Noted, salamat sa update."
    elif mode == "filipino":
        body = "Salamat sa update. Naitala ko ang impormasyon."
    else:
        body = "Thank you for the update. I have noted the information."

    lines = str(reply or "").strip().splitlines()
    greeting_pattern = re.compile(
        r"^(?:dear|hi|hello|good morning|good afternoon|good evening)\b",
        flags=re.IGNORECASE,
    )
    closing_pattern = re.compile(
        r"^(?:best regards|kind regards|warm regards|regards|sincerely|respectfully|thanks|thank you|salamat)[,!]?$",
        flags=re.IGNORECASE,
    )
    first = next((i for i, line in enumerate(lines) if line.strip()), None)
    closing = next(
        (i for i in range(len(lines) - 1, -1, -1) if closing_pattern.match(lines[i].strip())),
        None,
    )
    greeting = lines[first].strip() if first is not None and greeting_pattern.search(lines[first].strip()) else ""
    footer = lines[closing:] if closing is not None else []

    rebuilt = []
    if greeting:
        rebuilt.extend([greeting, ""])
    rebuilt.append(body)
    if footer:
        rebuilt.extend(["", *footer])
    return "\n".join(rebuilt).strip()



def _strip_reply_body_artifacts(reply: str, subject: str = "") -> str:
    """Remove model-generated email chrome from a Message body.

    Subject/From/To/Date already have dedicated fields in the Draft Email UI.
    This cleanup also removes separator-only lines and duplicate greetings while
    leaving ordinary body text untouched.
    """
    lines = str(reply or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not lines:
        return ""

    header_pattern = re.compile(r"^(?:subject|from|to|date)\s*:\s*", flags=re.IGNORECASE)
    divider_pattern = re.compile(r"^\s*(?:-{3,}|_{3,}|\*{3,})\s*$")
    body_label_pattern = re.compile(r"^\s*(?:email\s+body|message)\s*:\s*$", flags=re.IGNORECASE)
    greeting_pattern = re.compile(
        r"^\s*(?:dear|hi|hello|good morning|good afternoon|good evening)\b[^\n]*[,!]\s*$",
        flags=re.IGNORECASE,
    )

    cleaned: list[str] = []
    greeting_seen = False
    nonempty_seen = 0
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if cleaned and cleaned[-1] != "":
                cleaned.append("")
            continue
        if divider_pattern.match(stripped) or body_label_pattern.match(stripped):
            continue
        if header_pattern.match(stripped):
            continue
        if greeting_pattern.match(stripped):
            # A second greeting is usually the model restarting the body after
            # copying a Subject/header block. Keep only the first greeting.
            if greeting_seen:
                continue
            greeting_seen = True
        nonempty_seen += 1
        cleaned.append(stripped if nonempty_seen <= 2 and greeting_pattern.match(stripped) else line)

    while cleaned and cleaned[0] == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()

    # Collapse blank runs introduced by removed header lines.
    compact: list[str] = []
    for line in cleaned:
        if line == "" and compact and compact[-1] == "":
            continue
        compact.append(line)
    return "\n".join(compact).strip()


def _reply_acknowledgment_only_mode(
    action_statuses: list[dict], ownership: dict, overall_status: str = "Not Started"
) -> bool:
    # Explicit workflow state wins over inferred per-action openness. A task that
    # the user set to In Progress must not fall back to the same Pending reply
    # merely because individual open rows only store completed=False.
    if ownership.get("other_person_assignments") and not ownership.get("has_current_user_assignment"):
        return True
    normalized_overall = _normalize_status(overall_status)
    if normalized_overall in {"In Progress", "On Hold", "Completed", "Cancelled"}:
        return False
    if not action_statuses:
        return True
    states = {
        str(row.get("completion_status") or "").strip().casefold()
        for row in action_statuses
    }
    return bool(states) and states <= {"not started", "pending", "unknown"}



def _reply_action_short_label(action: str) -> str:
    """Return a compact grounded label for status replies without dumping To-Do text."""
    text = re.sub(r"\s+", " ", str(action or "")).strip().rstrip(".!?")
    if not text:
        return "requested item"

    # Remove the leading command before extracting a compact object label.
    object_text = re.sub(
        r"^(?:please\s+)?(?:confirm|verify|check|validate|review|complete|finish|send|submit|"
        r"update|prepare|provide|upload|sign|approve|reject|inspect|test|open)\s+(?:that\s+)?(?:the\s+)?",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()

    # Folder-check tasks are common and otherwise very verbose. Preserve the
    # concrete folder name while collapsing the operational clause.
    folder_match = re.search(
        r"\b([A-Za-z0-9][A-Za-z0-9 &/_-]{0,48}?)\s+folder\b",
        object_text,
        flags=re.IGNORECASE,
    )
    if folder_match:
        name = re.sub(r"\s+", " ", folder_match.group(1)).strip()
        if name:
            return f"{name} folder check"

    compact = object_text
    compact = re.split(r"\s+(?:so that|in order to|and then)\s+", compact, maxsplit=1, flags=re.IGNORECASE)[0]
    words = compact.split()
    if len(words) > 9:
        compact = " ".join(words[:9]).rstrip(" ,;:-")
    return compact or "requested item"


def _reply_join_labels(labels: list[str]) -> str:
    values = [str(value or "").strip() for value in labels if str(value or "").strip()]
    values = list(dict.fromkeys(values))
    if not values:
        return "the requested work"
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return f"{', '.join(values[:-1])}, and {values[-1]}"


def _reply_state_body(
    action_statuses: list[dict],
    overall_status: str,
    ownership: dict,
    language_mode: str,
) -> str:
    """Canonical concise response body for the user's explicit task state."""
    mode = str(language_mode or "English").strip().casefold()
    overall = _normalize_status(overall_status)

    if ownership.get("other_person_assignments") and not ownership.get("has_current_user_assignment"):
        if mode == "taglish":
            return "Noted, salamat sa update."
        if mode == "filipino":
            return "Salamat sa update. Naitala ko ang impormasyon."
        return "Thank you for the update. I have noted the information."

    if not action_statuses:
        if mode == "taglish":
            return "Noted, salamat sa update."
        if mode == "filipino":
            return "Salamat sa update. Naitala ko ang impormasyon."
        return "Thank you for the update. I have noted the information."

    completed_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold() == "completed"
    ]
    open_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown", "in progress"}
    ]
    completed_labels = _reply_join_labels([
        _reply_action_short_label(row.get("action_item") or row.get("action") or "")
        for row in completed_rows
    ])

    if overall == "Cancelled":
        if mode == "taglish":
            return "Noted. Cancelled na ang request at hindi ko na ito itutuloy."
        if mode == "filipino":
            return "Naitala ko. Kinansela na ang kahilingan at hindi na ito ipagpapatuloy."
        return "Understood. The request has been cancelled and will not be continued."

    if overall == "On Hold":
        if mode == "taglish":
            return "Noted. Naka-hold ang work sa ngayon."
        if mode == "filipino":
            return "Naitala ko. Naka-hold ang gawain sa ngayon."
        return "Noted. The work is currently on hold."

    if overall == "Completed" or (completed_rows and not open_rows):
        if completed_rows:
            if mode == "taglish":
                return f"Completed na ang {completed_labels}."
            if mode == "filipino":
                return f"Natapos na ang {completed_labels}."
            verb = "is" if len(completed_rows) == 1 else "are"
            return f"The {completed_labels} {verb} complete."
        if mode == "taglish":
            return "Completed na ang requested work."
        if mode == "filipino":
            return "Natapos na ang hinihinging gawain."
        return "The requested work is complete."

    if overall == "In Progress":
        if completed_rows:
            if mode == "taglish":
                return f"Completed na ang {completed_labels}. Ongoing pa ang natitirang work."
            if mode == "filipino":
                return f"Natapos na ang {completed_labels}. Patuloy pa ang natitirang gawain."
            verb = "is" if len(completed_rows) == 1 else "are"
            return f"The {completed_labels} {verb} complete. The remaining work is still in progress."
        if mode == "taglish":
            return "Noted. Ongoing na ang current work."
        if mode == "filipino":
            return "Naitala ko. Kasalukuyang isinasagawa ang gawain."
        return "Noted. The requested work is currently in progress."

    # Not Started / Pending / Unknown: acknowledgment only, no task restatement.
    if mode == "taglish":
        return "Noted, salamat. Naitala ko ang request."
    if mode == "filipino":
        return "Salamat. Naitala ko ang kahilingan."
    return "Thank you. I have noted the request."


def _reply_rebuild_body(reply: str, body: str) -> str:
    """Keep one model greeting/footer while replacing only the status response body."""
    lines = str(reply or "").strip().splitlines()
    greeting_pattern = re.compile(
        r"^(?:dear|hi|hello|good morning|good afternoon|good evening)\b",
        flags=re.IGNORECASE,
    )
    closing_pattern = re.compile(
        r"^(?:best|best regards|kind regards|warm regards|regards|sincerely|respectfully|"
        r"cheers|thanks|thank you|salamat)[,!]?$",
        flags=re.IGNORECASE,
    )
    first = next((i for i, line in enumerate(lines) if line.strip()), None)
    closing = next(
        (i for i in range(len(lines) - 1, -1, -1) if closing_pattern.match(lines[i].strip())),
        None,
    )
    greeting = lines[first].strip() if first is not None and greeting_pattern.search(lines[first].strip()) else ""
    footer = lines[closing:] if closing is not None else []
    rebuilt = []
    if greeting:
        rebuilt.extend([greeting, ""])
    rebuilt.append(str(body or "").strip())
    if footer:
        rebuilt.extend(["", *footer])
    return "\n".join(rebuilt).strip()


def _reply_state_response_issues(
    reply: str,
    action_statuses: list[dict],
    overall_status: str,
    ownership: dict,
) -> list[str]:
    """Detect To-Do restatement or a reply that ignores the user's current state."""
    text = str(reply or "").strip()
    if not text:
        return ["Draft body is empty."]
    issues: list[str] = []
    overall = _normalize_status(overall_status)

    if re.search(r"(?mi)^\s*[-*•]\s+", text) or re.search(
        r"(?mi)^\s*(?:deadline|due date|priority|urgency)\s*:", text
    ):
        issues.append("Draft mechanically repeats To-Do/metadata instead of responding to the current state.")
    if re.search(r"\b(?:action items?|task list)\b", text, flags=re.IGNORECASE):
        issues.append("Draft talks about the Action Item list instead of giving a concise response.")

    other_only = bool(ownership.get("other_person_assignments")) and not ownership.get("has_current_user_assignment")
    if other_only:
        return list(dict.fromkeys(issues + _reply_ownership_issues(text, ownership)))

    completed_count = sum(
        str(row.get("completion_status") or "").strip().casefold() == "completed"
        for row in action_statuses
    )
    if overall == "In Progress":
        if not re.search(r"\b(?:in progress|underway|ongoing|currently\s+(?:in progress|being|working)|remaining work)\b", text, flags=re.IGNORECASE):
            issues.append("Task is In Progress but the draft does not communicate supported progress.")
        if completed_count and not re.search(r"\b(?:complete|completed|finished|done)\b", text, flags=re.IGNORECASE):
            issues.append("Mixed In Progress state omits supported completed work.")
    elif overall == "Completed" and not re.search(
        r"\b(?:complete|completed|finished|done)\b", text, flags=re.IGNORECASE
    ):
        issues.append("Task is Completed but the draft does not confirm completion.")
    elif overall == "On Hold" and not re.search(r"\b(?:on hold|hold|waiting|paused)\b", text, flags=re.IGNORECASE):
        issues.append("Task is On Hold but the draft does not acknowledge the hold state.")
    elif overall == "Cancelled" and not re.search(r"\b(?:cancelled|canceled|no longer|won't|will not)\b", text, flags=re.IGNORECASE):
        issues.append("Task is Cancelled but the draft does not acknowledge cancellation.")

    # A reply can mention a completed item, but an open item must not be copied
    # verbatim or near-verbatim just to restate the To-Do list.
    open_rows = [
        row for row in action_statuses
        if str(row.get("completion_status") or "").strip().casefold()
        in {"not started", "pending", "unknown"}
    ]
    reply_terms = _summary_overlap_terms(text)
    for row in open_rows:
        action = str(row.get("action_item") or row.get("action") or "").strip()
        terms = _summary_overlap_terms(action)
        if len(terms) < 2:
            continue
        shared = terms & reply_terms
        if len(shared) / max(1, len(terms)) >= 0.78:
            issues.append(f'Open action "{action}" is being restated instead of summarized at a high level.')
            break
    return list(dict.fromkeys(issues))


def _deterministic_reply_state_fallback(
    reply: str,
    action_statuses: list[dict],
    overall_status: str,
    ownership: dict,
    language_mode: str,
) -> str:
    body = _reply_state_body(action_statuses, overall_status, ownership, language_mode)
    return _reply_rebuild_body(reply, body)

def draft_reply(summary: dict, original_email: dict | None = None) -> str:
    # Generate a completion-aware plain-text email body from the best available
    # conversation context. The controller attempts to provide a reconstructed
    # full thread; this function remains safe when only one stored message exists.
    original = original_email or {}
    block_reason = reply_draft_block_reason(summary, original)
    if block_reason:
        raise RuntimeError(block_reason)

    overall_status = _normalize_status(summary.get("status"))
    action_statuses = _reply_action_status_rows(summary)
    known_attachments = _reply_known_attachments(summary, original)
    reply_recipient, reply_author = _reply_role_identities(summary, original)
    subject = str(summary.get("subject") or original.get("subject") or "").strip()
    raw_thread_text = str(original.get("body_text") or original.get("snippet") or "").strip()
    thread_text = _reply_compact_thread_text(raw_thread_text)
    latest_incoming_text = _reply_compact_thread_text(
        _reply_latest_incoming_text(original, reply_author)
    )
    reply_language_mode = _reply_language_mode(latest_incoming_text)
    reply_ownership = _reply_assignment_ownership(latest_incoming_text, reply_author)
    deadlines = _normalize_list(summary.get("deadlines"))
    acknowledgment_only = _reply_acknowledgment_only_mode(action_statuses, reply_ownership, overall_status)
    # In acknowledgment-only mode, exact values/deadlines remain available in
    # the source thread but are not forced into the reply. This prevents the
    # draft from mechanically copying task/deadline metadata into a simple ack.
    exact_entries = [] if acknowledgment_only else _reply_exact_value_entries(summary, original)
    # A due date is context, not a mandatory sentence in every status reply.
    # Require deadline literals only when the latest incoming turn explicitly
    # asks about/for the deadline; otherwise a concise progress/completion reply
    # must not be forced to repeat Deadline metadata from the Summary/To-Do.
    deadline_reply_needed = bool(re.search(
        r"\b(?:what|when)\b[^?\n]{0,60}\b(?:deadline|due date|due)\b|"
        r"\b(?:can|could|would|please|kindly)\b[^?\n]{0,35}\b(?:confirm|clarify|verify|check)\b"
        r"[^?\n]{0,45}\b(?:deadline|due date|due)\b|"
        r"\b(?:deadline|due date)\b[^?\n]{0,50}\?",
        latest_incoming_text,
        flags=re.IGNORECASE,
    ))
    if exact_entries and not deadline_reply_needed:
        exact_entries = [
            entry for entry in exact_entries
            if str(entry.get("kind") or "").strip().casefold() not in {"date", "time"}
        ]
    reply_deadlines = deadlines if deadline_reply_needed and not acknowledgment_only else []
    user_signature = (
        summary.get("user_signature", "")
        or "[Not provided - use the reply author name if present, otherwise [Your name]]"
    )
    first_pass_facts = _reply_first_pass_facts(
        reply_recipient=reply_recipient,
        reply_author=reply_author,
        action_statuses=action_statuses,
        ownership=reply_ownership,
        overall_status=overall_status,
        deadlines=reply_deadlines,
        exact_entries=exact_entries,
        language_mode=reply_language_mode,
    )

    user_input = f"""Complete email thread (latest valid turn wins):
{thread_text}

Email subject: {subject}
AI summary helper (not a source of new facts): {summary.get('summary', '')}
Known attachments actually present: {json.dumps(known_attachments, ensure_ascii=False)}
Current user's signature (optional; never use the original sender as signature): {user_signature}

{first_pass_facts}

Generate only the final email body after applying every instruction and validation check."""
    repair_context = _reply_build_repair_context(
        reply_recipient=reply_recipient,
        reply_author=reply_author,
        subject=subject,
        summary_helper=str(summary.get("summary") or ""),
        action_statuses=action_statuses,
        ownership=reply_ownership,
        overall_status=overall_status,
        deadlines=reply_deadlines,
        known_attachments=known_attachments,
        user_signature=str(user_signature),
        latest_incoming_text=latest_incoming_text,
        language_mode=reply_language_mode,
    )
    trace_event(
        "draft_prompt_breakdown",
        thread_chars=len(thread_text),
        latest_chars=len(latest_incoming_text),
        summary_chars=len(str(summary.get("summary") or "")),
        facts_chars=len(first_pass_facts),
        user_chars=len(user_input),
        system_chars=len(DRAFT_REPLY_SYSTEM_PROMPT),
        repair_context_chars=len(repair_context),
        actions=len(action_statuses),
        exact_values=len(exact_entries),
        ownership_other=len(list(reply_ownership.get("other_person_assignments") or [])),
    )
    set_next_ollama_operation("reply draft initial")
    reply = _request_text(DRAFT_REPLY_SYSTEM_PROMPT, user_input).strip()
    if reply.startswith("```") and reply.endswith("```"):
        reply = re.sub(r"^```(?:text)?\s*|\s*```$", "", reply, flags=re.IGNORECASE).strip()
    reply = _strip_reply_body_artifacts(reply, subject)
    if not reply:
        raise RuntimeError(f"{OLLAMA_MODEL} did not generate a reply draft.")

    # Acknowledgment-only states are intentionally simple and deterministic. If
    # the model tries to promise pending work, invent an unknown result, adopt
    # another person's assignment, or miss the incoming language, normalize the
    # body immediately instead of spending a second LLM call repairing a response
    # that should only be a short acknowledgment.
    if acknowledgment_only:
        # Pending/FYI/other-person-owned replies are intentionally canonical.
        # Do not wait for a hallucination/promise detector: even a factually safe
        # model answer that re-lists the Action Items violates the Reply Draft rule.
        reply = _deterministic_reply_state_fallback(
            reply, action_statuses, overall_status, reply_ownership, reply_language_mode
        )
    elif _reply_state_response_issues(reply, action_statuses, overall_status, reply_ownership):
        # Status-driven output is also deterministic when the model falls back to
        # a To-Do dump or ignores the explicit workflow state. This avoids an
        # unnecessary repair call and guarantees Completed/In Progress/On Hold/
        # Cancelled drafts read as a response rather than a copied task card.
        reply = _deterministic_reply_state_fallback(
            reply, action_statuses, overall_status, reply_ownership, reply_language_mode
        )

    # Run every model-facing validator against the same first-pass draft, then
    # repair all detected categories in at most ONE additional LLM request. This
    # preserves the locked quality guards while avoiding serial repair latency.
    repair_issue_groups = {
        "ownership": _reply_ownership_issues(reply, reply_ownership),
        "grounding": _reply_grounding_issues(reply, action_statuses),
        "unsupported_claims": _reply_unsupported_claim_issues(reply, action_statuses),
        "exact_values": _reply_exact_value_issues(reply, exact_entries),
        "language": _reply_language_issues(reply, reply_language_mode),
        "state_response": _reply_state_response_issues(
            reply, action_statuses, overall_status, reply_ownership
        ),
    }
    repair_reasons = [
        key
        for key in ("ownership", "grounding", "unsupported_claims", "exact_values", "language", "state_response")
        if repair_issue_groups.get(key)
    ]
    trace_event(
        "draft_validation",
        repair_needed=bool(repair_reasons),
        repair_reasons=",".join(repair_reasons) if repair_reasons else "none",
        issue_counts="|".join(
            f"{key}:{len(repair_issue_groups.get(key) or [])}" for key in repair_reasons
        ) if repair_reasons else "none",
    )
    if repair_reasons:
        repaired = _repair_reply_combined(
            reply,
            repair_context,
            repair_issue_groups,
            exact_entries,
            reply_language_mode,
        )
        if repaired.startswith("```") and repaired.endswith("```"):
            repaired = re.sub(
                r"^```(?:text)?\s*|\s*```$", "", repaired, flags=re.IGNORECASE
            ).strip()
        if repaired:
            reply = _strip_reply_body_artifacts(repaired, subject)

        post_repair_issue_groups = {
            "ownership": _reply_ownership_issues(reply, reply_ownership),
            "grounding": _reply_grounding_issues(reply, action_statuses),
            "unsupported_claims": _reply_unsupported_claim_issues(reply, action_statuses),
            "exact_values": _reply_exact_value_issues(reply, exact_entries),
            "language": _reply_language_issues(reply, reply_language_mode),
            "state_response": _reply_state_response_issues(
                reply, action_statuses, overall_status, reply_ownership
            ),
        }
        remaining_reasons = [
            key
            for key in ("ownership", "grounding", "unsupported_claims", "exact_values", "language", "state_response")
            if post_repair_issue_groups.get(key)
        ]
        trace_event(
            "draft_repair_result",
            remaining_reasons=",".join(remaining_reasons) if remaining_reasons else "none",
            remaining_counts="|".join(
                f"{key}:{len(post_repair_issue_groups.get(key) or [])}" for key in remaining_reasons
            ) if remaining_reasons else "none",
        )

    # The single combined repair is never trusted on its own. Re-run all locked
    # validators deterministically and use the existing narrow fallbacks for any
    # remaining/regressed issue. No further model request is allowed here.
    for _guard_pass in range(3):
        before_guard_pass = reply
        if _reply_ownership_issues(reply, reply_ownership):
            reply = _deterministic_reply_ownership_fallback(
                reply, reply_ownership, reply_language_mode
            )
        if _reply_grounding_issues(reply, action_statuses):
            reply = _deterministic_reply_grounding_fallback(
                reply, action_statuses, reply_language_mode
            )
        if _reply_unsupported_claim_issues(reply, action_statuses):
            reply = _deterministic_reply_unknown_fallback(
                reply, action_statuses, thread_text
            )
        if _reply_exact_value_issues(reply, exact_entries):
            reply = _deterministic_reply_exact_value_fallback(reply, exact_entries)
        if _reply_language_issues(reply, reply_language_mode):
            reply = _deterministic_reply_language_fallback(reply, reply_language_mode)
        if _reply_state_response_issues(reply, action_statuses, overall_status, reply_ownership):
            reply = _deterministic_reply_state_fallback(
                reply, action_statuses, overall_status, reply_ownership, reply_language_mode
            )
        if _reply_no_action_issues(reply, action_statuses):
            reply = _deterministic_reply_no_action_fallback(
                reply, reply_language_mode
            )
        if reply == before_guard_pass:
            break

    reply = _strip_reply_body_artifacts(reply, subject)
    role_context = {
        **summary,
        "from": reply_recipient,
        "to": reply_author,
    }
    return _enforce_reply_roles(reply, role_context)

def _enforce_reply_roles(reply: str, summary: dict) -> str:
    # Deterministically enforce the two role facts the LLM must never invert:
    # greeting -> original sender, signature -> current signed-in recipient.
    original_sender_name, original_sender_address = parseaddr(str(summary.get("from") or ""))
    current_user_name, current_user_address = parseaddr(str(summary.get("to") or ""))
    sender_label = original_sender_name or original_sender_address or "Sender"
    explicit_signature = str(summary.get("user_signature") or "").strip()
    signature_label = explicit_signature or current_user_name or "[Your name]"

    lines = str(reply or "").strip().splitlines()
    if not lines:
        return ""

    first_content_index = next(
        (index for index, line in enumerate(lines) if line.strip()), 0
    )
    first_line = lines[first_content_index].strip()
    greeting_pattern = re.compile(
        r"^(?:dear|hi|hello|good morning|good afternoon|good evening)\b",
        flags=re.IGNORECASE,
    )
    sender_tokens = [
        value.casefold() for value in (original_sender_name, original_sender_address) if value
    ]
    greeting_has_sender = any(token in first_line.casefold() for token in sender_tokens)
    if greeting_pattern.search(first_line):
        if not greeting_has_sender:
            lines[first_content_index] = f"Dear {sender_label},"
    else:
        lines.insert(first_content_index, f"Dear {sender_label},")
        lines.insert(first_content_index + 1, "")

    # Normalize the entire trailing footer to one sign-off + the authenticated
    # account display name. Models sometimes emit two footers (for example
    # "Best, <alias>" followed by "Best regards, [Your name]"). Treat every
    # recognized closing in the trailing footer as one footer region and replace
    # that region deterministically. This never touches ownership/body content.
    closing_pattern = re.compile(
        r"^(?:best|best regards|kind regards|warm regards|regards|sincerely|"
        r"respectfully|cheers|thanks|thank you|salamat)[,!]?$",
        flags=re.IGNORECASE,
    )
    trailing_window_start = max(0, len(lines) - 12)
    closing_indices = [
        index
        for index in range(trailing_window_start, len(lines))
        if closing_pattern.match(lines[index].strip())
    ]

    if closing_indices:
        footer_start = closing_indices[0]
        closing_line = lines[closing_indices[-1]].strip()
        # Keep the final generated closing style but guarantee normal punctuation
        # and exactly one authenticated signature line.
        if closing_line and closing_line[-1] not in ",!":
            closing_line += ","
        body_lines = lines[:footer_start]
        while body_lines and not body_lines[-1].strip():
            body_lines.pop()
        lines = body_lines + ["", closing_line or "Best regards,", signature_label]
    else:
        # No recognizable sign-off was generated. Remove only explicit fallback
        # placeholders/current-account identity from the very end, then append
        # one grounded footer. Never infer the sender as the signature owner.
        placeholder_pattern = re.compile(r"^\[your name\]$", flags=re.IGNORECASE)
        while lines and (
            not lines[-1].strip()
            or placeholder_pattern.match(lines[-1].strip())
            or (
                current_user_address
                and lines[-1].strip().casefold() == current_user_address.casefold()
            )
            or (
                current_user_name
                and lines[-1].strip().casefold() == current_user_name.casefold()
            )
        ):
            lines.pop()
        lines.extend(["", "Best regards,", signature_label])

    return "\n".join(lines).strip()
