# Provider-neutral helpers for distinguishing restored mailbox items from new mail.
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime

from email_handler.thread_identity import message_ids


def _normalize_uid(value) -> str:
    return str(value or "").strip()


def _normalize_text(value) -> str:
    return " ".join(str(value or "").casefold().split())


def _mailbox_address(value) -> str:
    _name, address = parseaddr(str(value or ""))
    return (address or str(value or "")).strip().casefold()


def _message_datetime(value):
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(text)
            except (TypeError, ValueError, OverflowError):
                return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def same_message_identity(current: dict, previous: dict) -> bool:
    # Recognize the same physical provider message when its local/provider UID
    # changes. This is shared by mailbox RESTORED classification and manual/auto
    # duplicate protection so all four summary modes make the same decision.
    current_message_ids = message_ids(current.get("message_id", ""))
    previous_message_ids = message_ids(previous.get("message_id", ""))
    if current_message_ids and previous_message_ids:
        return current_message_ids[0] == previous_message_ids[0]

    current_subject = _normalize_text(current.get("subject"))
    previous_subject = _normalize_text(previous.get("subject"))
    if not current_subject or current_subject in {"(no subject)", "no subject"}:
        return False
    if current_subject != previous_subject:
        return False

    current_sender = _mailbox_address(current.get("from") or current.get("sender"))
    previous_sender = _mailbox_address(previous.get("from") or previous.get("sender"))
    if not current_sender or current_sender != previous_sender:
        return False

    current_recipient = _mailbox_address(current.get("to") or current.get("recipient"))
    previous_recipient = _mailbox_address(previous.get("to") or previous.get("recipient"))
    if current_recipient and previous_recipient and current_recipient != previous_recipient:
        return False

    current_thread = str(current.get("canonical_thread_id") or "").strip().casefold()
    previous_thread = str(previous.get("canonical_thread_id") or "").strip().casefold()
    if current_thread and previous_thread and current_thread != previous_thread:
        return False

    try:
        current_count = int(
            current.get("thread_count") or current.get("provider_thread_count") or 1
        )
    except (TypeError, ValueError):
        current_count = 1
    try:
        previous_count = int(previous.get("thread_count") or 1)
    except (TypeError, ValueError):
        previous_count = 1
    if (
        current_thread
        and previous_thread
        and current_thread == previous_thread
        and current_count > previous_count
    ):
        return False

    current_snippet = _normalize_text(current.get("snippet"))
    previous_snippet = _normalize_text(previous.get("snippet"))
    if current_snippet and previous_snippet and current_snippet != previous_snippet:
        return False

    current_date = _message_datetime(current.get("date") or current.get("date_value"))
    previous_date = _message_datetime(previous.get("date") or previous.get("date_value"))
    if current_date is None or previous_date is None:
        return False

    return abs((current_date - previous_date).total_seconds()) <= 120


def classify_restored_arrivals(
    candidate_headers: list[dict],
    unavailable_uids_before,
    existing_summary_records: list[dict] | None = None,
) -> tuple[set[str], set[str], list[tuple[str, str]]]:
    # Split newly-visible mailbox rows into RESTORED and genuinely NEW items.
    # Same-UID restoration is proven by the local unavailable state. If a
    # provider changed the UID during restore/move, match against saved summary
    # identity so the old summary can be relinked instead of queued again.
    unavailable = {
        _normalize_uid(uid) for uid in (unavailable_uids_before or set())
        if _normalize_uid(uid)
    }
    records = [dict(item) for item in (existing_summary_records or []) if isinstance(item, dict)]
    claimed_old_uids: set[str] = set()
    restored: set[str] = set()
    genuine_new: set[str] = set()
    relinks: list[tuple[str, str]] = []

    for header in candidate_headers or []:
        current_uid = _normalize_uid(header.get("uid"))
        if not current_uid:
            continue

        if current_uid in unavailable:
            restored.add(current_uid)
            continue

        match = next(
            (
                record for record in records
                if _normalize_uid(record.get("uid")) in unavailable
                and _normalize_uid(record.get("uid")) not in claimed_old_uids
                and same_message_identity(header, record)
            ),
            None,
        )
        if match is None:
            genuine_new.add(current_uid)
            continue

        old_uid = _normalize_uid(match.get("uid"))
        restored.add(current_uid)
        claimed_old_uids.add(old_uid)
        if old_uid and old_uid != current_uid:
            relinks.append((old_uid, current_uid))

    return restored, genuine_new, relinks
