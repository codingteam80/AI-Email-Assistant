# Apply confirmed external mailbox deletions to Streamlit UI state.

import streamlit as st

from services.deletion_detection_service import reconcile_folder
from ui.notification_center import record_notification


def build_deletion_notice(count: int) -> str:
    noun = "email" if count == 1 else "emails"
    return f"{count} {noun} deleted from Inbox."


def _deleted_email_notification_details(unavailable_uids, folder: str = "INBOX") -> tuple[list[str], str]:
    # Capture deleted-email context before live UI state is cleared.
    unavailable = {str(uid) for uid in unavailable_uids if str(uid)}
    if not unavailable:
        return [], ""

    by_uid = {}
    for item in list(st.session_state.get("emails", [])) + list(st.session_state.get("search_results", [])):
        uid = str(item.get("uid") or "")
        if uid in unavailable and uid not in by_uid:
            by_uid[uid] = item

    store = st.session_state.get("email_store")
    if store is not None:
        for uid in unavailable:
            if uid in by_uid:
                continue
            try:
                item = store.get_email(folder, uid, include_unavailable=True)
            except Exception:
                item = None
            if item:
                by_uid[uid] = item

    details = []
    items = list(by_uid.values())
    items.sort(key=lambda item: str(item.get("date") or item.get("date_display") or ""), reverse=True)
    for item in items[:5]:
        subject = str(item.get("subject") or "(No Subject)").strip()
        sender = str(item.get("from") or "Unknown sender").strip()
        details.append(f"{subject} — From {sender}")
    if len(items) > 5:
        details.append(f"+{len(items) - 5} more deleted emails")
    entity_id = str(items[0].get("uid") or "") if len(items) == 1 else ""
    return details, entity_id


def clear_unavailable_email_state(unavailable_uids) -> int:
    # Remove confirmed missing UIDs from all live inbox-related UI state.
    unavailable = {str(uid) for uid in unavailable_uids if str(uid)}
    if not unavailable:
        return 0

    st.session_state.checked_uids = set(
        st.session_state.get("checked_uids", set())
    ).difference(unavailable)
    st.session_state.new_email_uids = set(
        st.session_state.get("new_email_uids", set())
    ).difference(unavailable)

    if str(st.session_state.get("selected_uid")) in unavailable:
        st.session_state.selected_uid = None

    st.session_state.emails = [
        email
        for email in st.session_state.get("emails", [])
        if str(email.get("uid")) not in unavailable
    ]
    st.session_state.inbox_total = max(
        0,
        int(st.session_state.get("inbox_total", 0)) - len(unavailable),
    )
    old_results = st.session_state.get("search_results", [])
    st.session_state.search_results = [
        email
        for email in old_results
        if str(email.get("uid")) not in unavailable
    ]
    st.session_state.search_total = max(
        0,
        int(st.session_state.get("search_total", 0))
        - (len(old_results) - len(st.session_state.search_results)),
    )

    bodies = st.session_state.get("email_bodies", {})
    for cache_key in list(bodies):
        try:
            cached_uid = str(cache_key[2])
        except (IndexError, TypeError):
            continue
        if cached_uid in unavailable:
            bodies.pop(cache_key, None)

    for uid in unavailable:
        st.session_state.pop(f"chk_{uid}", None)
    return len(unavailable)


def apply_confirmed_deletions(unavailable_uids) -> int:
    # Update live state and prepare one user-facing notice.
    details, entity_id = _deleted_email_notification_details(unavailable_uids)
    removed = clear_unavailable_email_state(unavailable_uids)
    if removed:
        notice = build_deletion_notice(removed)
        st.session_state.email_deletion_notice = notice
        record_notification(
            title="Email deleted" if removed == 1 else "Emails deleted",
            message=notice,
            kind="info",
            workspace="inbox",
            details=details,
            event_type="email-deleted",
            entity_id=entity_id,
        )
    return removed


def reconcile_mailbox_state(client, store, folder: str = "INBOX"):
    # Run the service-layer comparison and apply confirmed deletions.
    result = reconcile_folder(client, store, folder)
    if result.success:
        apply_confirmed_deletions(result.missing_uids)
    return result
