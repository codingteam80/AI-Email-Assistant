# Provider-neutral helpers for recognizing Inbox <-> Spam/Junk moves when a
# provider changes the local message identifier during the folder move.
from dataclasses import dataclass, field

from services.restoration_service import same_message_identity


@dataclass(frozen=True)
class ProviderLocationTransitions:
    moved_to_inbox: set[str] = field(default_factory=set)
    moved_to_spam: set[str] = field(default_factory=set)
    consumed_arrival_uids: set[str] = field(default_factory=set)
    consumed_missing_uids: set[str] = field(default_factory=set)
    relinks: tuple[tuple[str, str], ...] = ()


def detect_cross_uid_provider_moves(
    arrival_headers: list[dict],
    missing_headers: list[dict],
) -> ProviderLocationTransitions:
    # Outlook normally keeps an immutable Graph message ID when a message moves
    # between Inbox and Junk, so storage can update its provider_spam flag in
    # place. IMAP providers such as Gmail can expose a different folder-scoped
    # UID for that same physical message. Match those old/new rows by the same
    # provider-neutral identity contract used by restoration and summary dedupe.
    arrivals = [dict(item) for item in (arrival_headers or []) if isinstance(item, dict)]
    missing = [dict(item) for item in (missing_headers or []) if isinstance(item, dict)]

    claimed_old: set[str] = set()
    moved_to_inbox: set[str] = set()
    moved_to_spam: set[str] = set()
    consumed_arrivals: set[str] = set()
    consumed_missing: set[str] = set()
    relinks: list[tuple[str, str]] = []

    for current in arrivals:
        new_uid = str(current.get("uid") or "").strip()
        if not new_uid:
            continue
        new_provider_spam = bool(current.get("provider_spam"))

        match = next(
            (
                previous
                for previous in missing
                if str(previous.get("uid") or "").strip() not in claimed_old
                and str(previous.get("uid") or "").strip() != new_uid
                and bool(previous.get("provider_spam")) != new_provider_spam
                and same_message_identity(current, previous)
            ),
            None,
        )
        if match is None:
            continue

        old_uid = str(match.get("uid") or "").strip()
        claimed_old.add(old_uid)
        consumed_arrivals.add(new_uid)
        consumed_missing.add(old_uid)
        relinks.append((old_uid, new_uid))

        if new_provider_spam:
            moved_to_spam.add(new_uid)
        else:
            moved_to_inbox.add(new_uid)

    return ProviderLocationTransitions(
        moved_to_inbox=moved_to_inbox,
        moved_to_spam=moved_to_spam,
        consumed_arrival_uids=consumed_arrivals,
        consumed_missing_uids=consumed_missing,
        relinks=tuple(relinks),
    )
