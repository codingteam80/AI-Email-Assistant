import time

import streamlit as st

from controllers.deletion_controller import apply_confirmed_deletions
from controllers.inbox_controller import (
    clear_sidebar_activity,
    finish_sidebar_activity,
    start_sidebar_activity,
    update_sidebar_activity,
)
from services.deletion_detection_service import check_uid_availability
from services.thread_service import (
    build_thread_email,
    filter_thread_email_for_workspace,
    resolve_thread_headers,
)
from services.network_status_service import (
    is_network_error,
    mark_provider_connection_issue,
)
from ui.inbox_notifications import push_inbox_toast


_WORKSPACE_EMPTY_THREAD_ERROR = (
    "No messages in this thread are available in the current MailMind workspace."
)


def _clear_stale_workspace_selection(uid: str) -> None:
    """Drop a reader selection that Security routing moved out of this workspace.

    Catch-up/new-mail classification can update SQLite after the Inbox page was
    already projected.  A card from that stale projection may therefore still
    be clickable for one render even though its message/thread now belongs to
    Spam/Detected.  Clearing only the transient reader selection is the safe
    boundary: the next Inbox render reloads from SQLite and the message remains
    available in its newly routed Security workspace.
    """
    uid = str(uid or "").strip()
    if uid and str(st.session_state.get("selected_uid") or "").strip() == uid:
        st.session_state.selected_uid = None
    if uid and str(st.session_state.get("inbox_read_pinned_uid") or "").strip() == uid:
        st.session_state.inbox_read_pinned_uid = ""
    st.session_state.inbox_loaded_view_signature = None


def _is_workspace_empty_thread_error(error: Exception) -> bool:
    return _WORKSPACE_EMPTY_THREAD_ERROR in str(error or "")


def _handle_confirmed_missing(uid: str, folder: str):
    st.session_state.email_store.mark_remote_unavailable(folder, [uid])
    apply_confirmed_deletions([uid])
    st.rerun()


# Load the selected email from SQLite or IMAP when needed.
def load_selected_message(
    list_source, activity_slot, folder: str = "INBOX", spam_view: bool = False
):
    selected_uid = str(st.session_state.get("selected_uid") or "")
    selected_header = next(
        (
            email_item
            for email_item in list_source
            if str(email_item.get("uid")) == selected_uid
        ),
        None,
    )
    # Match AI Summary -> Unviewed behavior: after a successfully opened Inbox
    # email becomes read, its card can leave the Unread-filtered list while the
    # already opened content remains visible in the reader pane.
    if (
        selected_header is None
        and selected_uid
        and str(st.session_state.get("inbox_filter") or "all").casefold()
        in {"unread", "unread_with_attachment"}
    ):
        selected_header = st.session_state.email_store.get_email(folder, selected_uid)

    selected_message = None
    if selected_header:
        uid = str(selected_header["uid"])

        # Security catch-up/new-mail routing can move the selected physical row
        # to Spam after this Inbox page was already loaded.  Re-check the
        # authoritative local row before opening a stale Inbox card so standalone
        # mail and threaded mail both fail closed without crashing or flashing
        # detected content in the normal Inbox reader.
        if not spam_view:
            current_row = st.session_state.email_store.get_email(folder, uid)
            if current_row is not None and bool(int(current_row.get("is_spam") or 0)):
                _clear_stale_workspace_selection(uid)
                return None

        cache_key = (st.session_state.active_store_account, folder, uid)
        body_cached = cache_key in st.session_state.email_bodies

        # Opening an email is local-first. Mailbox deletion is reconciled during
        # login/refresh, so a provider UID-existence request must not block every
        # normal reader click. If loading an uncached body actually fails, we do
        # one remote availability check only then to distinguish deletion from a
        # transient/provider error.
        if not body_cached:
            stored_email = st.session_state.email_store.get_email(folder, uid) or {}
            full_body_cached = bool(stored_email.get("is_full"))
            preview_progress = start_sidebar_activity(
                activity_slot, "Opening email...", 0.12
            )
            update_sidebar_activity(
                preview_progress,
                0.34,
                "Loading saved email..." if full_body_cached else "Loading email...",
            )
            try:
                full_email = build_thread_email(
                    st.session_state.imap_client,
                    st.session_state.email_store,
                    selected_header,
                    folder,
                    prefer_local=full_body_cached,
                    reader_projection=True,
                )
                body_result = {"success": True, "email": full_email}
            except RuntimeError as error:
                body_result = {"success": False, "error": str(error)}
                if not full_body_cached:
                    validation = check_uid_availability(
                        st.session_state.imap_client, uid, folder=folder
                    )
                    if validation.get("success") and not validation.get("available"):
                        body_result["missing"] = True

            update_sidebar_activity(
                preview_progress, 0.84, "Preparing email preview..."
            )
            if body_result["success"]:
                full_email = body_result["email"]
                attachments = full_email.pop("attachments", None)
                if attachments is None:
                    attachments = st.session_state.email_store.get_attachments(
                        folder, uid
                    )
                st.session_state.email_bodies[cache_key] = {
                    "email": full_email,
                    "attachments": attachments or [],
                }
                finish_sidebar_activity(preview_progress, "Email ready")
            elif body_result.get("missing"):
                clear_sidebar_activity(activity_slot)
                _handle_confirmed_missing(uid, folder)
            elif is_network_error(body_result.get("error")):
                # Opening an uncached email is a user-triggered action, so a
                # transient provider outage follows the simple notification rule:
                # Toast only. Do not leave a persistent red workspace banner that
                # looks like the email itself is corrupt or missing.
                mark_provider_connection_issue(body_result.get("error"))
                push_inbox_toast(
                    "Could not load this email because the email provider is unreachable. "
                    "Restore your connection and try again.",
                    "warning",
                    title="Connection issue",
                    event_type="email-open-network-failed",
                    entity_id=uid,
                    notify_bell=False,
                )
            else:
                st.error(f"Could not load email: {body_result['error']}")

            clear_sidebar_activity(activity_slot)

        selected_message = st.session_state.email_bodies.get(cache_key)
        if selected_message is not None and not spam_view:
            # Keep the cached provider conversation intact, then derive a fresh
            # workspace-scoped display copy on every render. This prevents a
            # newly Security-routed Spam reply from leaking into an already
            # cached Inbox thread, while also allowing a later restored message
            # to reappear without forcing a provider refetch.
            raw_email = dict(selected_message.get("email") or {})
            try:
                display_email = (
                    filter_thread_email_for_workspace(
                        raw_email,
                        st.session_state.email_store,
                        folder,
                        spam_view=False,
                    )
                    if raw_email.get("thread_messages")
                    else raw_email
                )
            except RuntimeError as error:
                if not _is_workspace_empty_thread_error(error):
                    raise
                # All provider-expanded turns were legitimately routed out of
                # the Inbox after this selection was cached.  Treat that as a
                # stale UI selection, not an application failure.
                _clear_stale_workspace_selection(uid)
                return None

            # A reader body can be cached before a later safe reply is published.
            # The Inbox card/count then correctly advances to (2), while the old
            # cached one-message body would otherwise stay stuck at (1). Compare
            # the cached display against the Security-finalized local thread index
            # and refresh only when published Inbox members have advanced. The
            # rebuild path reconciles stale provider conversation caches with all
            # local members, and the workspace filter below still excludes every
            # Spam/Security-routed turn.
            try:
                local_headers = resolve_thread_headers(
                    st.session_state.email_store, selected_header, folder
                )
            except (AttributeError, RuntimeError, ValueError):
                local_headers = [selected_header]
            published_inbox_count = sum(
                1
                for header in local_headers
                if not bool(int(header.get("is_spam") or 0))
            )
            cached_inbox_count = int(
                display_email.get("workspace_thread_count")
                or display_email.get("thread_count")
                or 1
            )
            if published_inbox_count > cached_inbox_count:
                try:
                    refreshed_email = build_thread_email(
                        st.session_state.imap_client,
                        st.session_state.email_store,
                        selected_header,
                        folder,
                        reader_projection=True,
                    )
                    refreshed_attachments = refreshed_email.pop("attachments", None)
                    if refreshed_attachments is None:
                        refreshed_attachments = st.session_state.email_store.get_attachments(
                            folder, uid
                        )
                    st.session_state.email_bodies[cache_key] = {
                        "email": refreshed_email,
                        "attachments": refreshed_attachments or [],
                    }
                    selected_message = st.session_state.email_bodies[cache_key]
                    raw_email = dict(selected_message.get("email") or {})
                    display_email = filter_thread_email_for_workspace(
                        raw_email,
                        st.session_state.email_store,
                        folder,
                        spam_view=False,
                    )
                except RuntimeError as error:
                    if _is_workspace_empty_thread_error(error):
                        # The thread crossed the Security routing boundary while
                        # the reader refresh was in progress.  Never retain the
                        # old Inbox projection, because that would momentarily
                        # re-expose content that is now Spam/Detected.
                        _clear_stale_workspace_selection(uid)
                        return None
                    # Keep the already cached message visible if an unrelated
                    # best-effort thread refresh cannot complete. Normal
                    # provider/network handling remains on the uncached open path.
                    pass

            visible_uids = {
                str(value or "").strip()
                for value in (display_email.get("source_uids") or [])
                if str(value or "").strip()
            }
            if not visible_uids and uid:
                # Standalone cached mail has no synthetic source_uids list. Keep
                # its own attachments visible exactly as before this refresh guard.
                visible_uids.add(uid)
            display_attachments = []
            for attachment in (
                st.session_state.email_bodies.get(cache_key, {}).get("attachments") or []
            ):
                message_uid = str(attachment.get("message_uid") or "").strip()
                if not message_uid or message_uid in visible_uids:
                    display_attachments.append(dict(attachment))
            selected_message = {
                "email": display_email,
                "attachments": display_attachments,
            }

        if selected_message is not None:
            unread_uids = {
                str(value).strip()
                for value in st.session_state.get("new_email_uids", set())
                if str(value).strip()
            }
            if unread_uids:
                # Normal card clicks consume the full thread in ui.inbox. Keep
                # this reader-side path as a defensive fallback for direct or
                # programmatic selections that bypass that callback. Because the
                # reader exposes the conversation as one unit, clear every unread
                # non-Spam member of the selected thread in one action as well.
                store = st.session_state.get("email_store")
                try:
                    thread_headers = (
                        list(resolve_thread_headers(store, selected_header, folder) or [])
                        if store is not None
                        else []
                    )
                except (AttributeError, RuntimeError, ValueError):
                    thread_headers = [selected_header]
                thread_uids = {
                    str(item.get("uid") or "").strip()
                    for item in thread_headers
                    if str(item.get("uid") or "").strip()
                    and not bool(int(item.get("is_spam") or 0))
                }
                if not thread_uids:
                    thread_uids = {uid}
                consumed_unread = unread_uids.intersection(thread_uids)
                if consumed_unread:
                    if store is not None:
                        mark_read = getattr(store, "mark_mailmind_read", None)
                        if callable(mark_read):
                            mark_read(folder, consumed_unread)
                    unread_uids.difference_update(consumed_unread)
                    st.session_state.new_email_uids = unread_uids
                    # Match the Spam/Detected review UX: inside Unread, keep the
                    # just-opened conversation visible while selected even though
                    # its complete unread membership has been consumed.
                    if (
                        str(st.session_state.get("inbox_filter") or "all").casefold()
                        in {"unread", "unread_with_attachment"}
                    ):
                        st.session_state.inbox_read_pinned_uid = uid
                    # Do not force a second full-app rerun here. This fallback can
                    # continue painting the already-loaded reader immediately.
                    st.session_state.inbox_loaded_view_signature = None

    return selected_message


