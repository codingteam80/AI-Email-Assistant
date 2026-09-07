# Detect emails removed from an IMAP folder and persist their availability.

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class ReconciliationResult:
    # Outcome of one complete remote/local UID comparison.

    success: bool
    remote_uids: List[str] = field(default_factory=list)
    missing_uids: List[str] = field(default_factory=list)
    moved_to_inbox_uids: List[str] = field(default_factory=list)
    moved_to_spam_uids: List[str] = field(default_factory=list)
    error: str = ""


def reconcile_folder(client, store, folder: str = "INBOX") -> ReconciliationResult:
    # Compare stable remote UIDs with the cache without downloading messages.
    try:
        remote_uids = client.list_uids(folder, refresh=True)
        missing_uids = store.reconcile_remote_uids(folder, remote_uids)

        moved_to_inbox = set()
        moved_to_spam = set()
        location_snapshot = getattr(client, "get_security_location_snapshot", None)
        update_locations = getattr(store, "update_provider_locations", None)
        if callable(location_snapshot) and callable(update_locations):
            changes = update_locations(folder, location_snapshot()) or {}
            moved_to_inbox.update(changes.get("moved_to_inbox", set()))
            moved_to_spam.update(changes.get("moved_to_spam", set()))

        return ReconciliationResult(
            success=True,
            remote_uids=remote_uids,
            missing_uids=missing_uids,
            moved_to_inbox_uids=sorted(moved_to_inbox),
            moved_to_spam_uids=sorted(moved_to_spam),
        )
    except Exception as error:
        # A network failure must not be interpreted as mailbox deletion.
        return ReconciliationResult(success=False, error=str(error))


def check_uid_availability(client, uid: str, folder: str = "INBOX") -> dict:
    # Validate one stable UID while distinguishing failure from absence.
    try:
        return {
            "success": True,
            "available": bool(client.uid_exists(folder, str(uid))),
            "error": "",
        }
    except Exception as error:
        return {"success": False, "available": None, "error": str(error)}
