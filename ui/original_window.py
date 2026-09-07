# Original-email reader used by the in-app AI Summary dialog.
import html

import streamlit as st

from config import UI_FOREGROUND_SETTLE_SECONDS

from storage.summary_store import SUMMARY_FOLDER, LEGACY_SUMMARY_FOLDER
from services.white_stale_trace_service import trace_action

from email_handler.thread_identity import message_ids
from services.thread_service import (
    build_thread_email,
    filter_thread_email_for_workspace,
)
from services.ui_interaction_service import arm_foreground_interaction
from ui.reader import (
    _collapsible_cc_html,
    _collapsible_to_html,
    render_reader,
    render_reader_attachments,
    render_reader_content,
    _thread_display_message,
)


_EMPTY_META_VALUES = {"", "none", "n/a", "na", "null", "[]", "{}"}
_ORIGINAL_THREAD_SCROLL_SEEN_PREFIX = "_original_thread_auto_scroll_seen_"
_ORIGINAL_THREAD_SCROLL_REQUEST_KEY = "_original_thread_auto_scroll_request_seq"


def _clear_original_thread_scroll_state() -> None:
    # The Original Email reader should auto-position only once per open. Clear
    # the per-open guard on Close, but keep the monotonic request sequence so
    # main.js can distinguish a later reopen of the same thread.
    for key in list(st.session_state.keys()):
        if str(key).startswith(_ORIGINAL_THREAD_SCROLL_SEEN_PREFIX):
            st.session_state.pop(key, None)


def _summary_source_uids(summary_store, folder: str, uid: str) -> list[str]:
    # Return saved source UIDs for an individual or batch-child summary.
    #
    # Summary rows live in ALL_MAIL in current builds. ``folder`` here is the
    # mailbox folder used by the reader (usually INBOX), so looking up summary
    # metadata only in that folder can falsely report a live thread as deleted.
    if summary_store is None:
        return []

    summary_folders = []
    for value in (SUMMARY_FOLDER, folder, LEGACY_SUMMARY_FOLDER):
        value = str(value or "").strip()
        if value and value not in summary_folders:
            summary_folders.append(value)

    for summary_folder in summary_folders:
        try:
            summaries = summary_store.load_all(summary_folder)
        except Exception:
            continue
        for summary in summaries:
            candidates = [summary, *(summary.get("email_breakdowns") or [])]
            for candidate in candidates:
                if str(candidate.get("uid") or "") == uid:
                    values = [
                        str(value).strip()
                        for value in (candidate.get("source_uids") or [uid])
                        if str(value or "").strip()
                    ]
                    # Preserve order while removing duplicates.
                    return list(dict.fromkeys(values))
    return []


def _candidate_mailbox_folders(preferred_folder: str) -> list[str]:
    folders = []
    for value in (preferred_folder, "INBOX", "ALL_MAIL", "SPAM", "JUNK"):
        value = str(value or "").strip()
        if value and value not in folders:
            folders.append(value)
    return folders


def _candidate_original_uids(uid: str, folder: str) -> list[str]:
    values = [str(uid or "").strip()]
    values.extend(
        _summary_source_uids(st.session_state.get("summary_store"), folder, uid)
    )
    return [value for value in dict.fromkeys(values) if value]


def _email_is_remotely_available(email: dict) -> bool:
    remote_available = email.get("remote_available")
    if remote_available is None:
        return not bool(email.get("remote_unavailable_at"))
    try:
        return int(remote_available or 0) == 1
    except (TypeError, ValueError):
        return not bool(email.get("remote_unavailable_at"))


def _resolve_available_original_email(uid: str, folder: str = "INBOX") -> tuple[dict | None, str]:
    # Prefer a live source member in the requested mailbox folder, then fall
    # back to other indexed mailbox views. This is thread-aware: a task/summary
    # UID can represent a reply while an earlier source message remains live.
    store = st.session_state.get("email_store")
    if store is None:
        return None, str(folder or "INBOX")

    candidate_uids = _candidate_original_uids(uid, folder)
    for mailbox_folder in _candidate_mailbox_folders(folder):
        for candidate_uid in candidate_uids:
            try:
                email = store.get_email(mailbox_folder, candidate_uid)
            except Exception:
                email = None
            if email:
                return email, mailbox_folder
    return None, str(folder or "INBOX")


def is_original_email_deleted(uid: str, folder: str = "INBOX") -> bool:
    # Match AI Summary semantics: disable Open original only when MailMind has
    # positive evidence that every known source member is remotely unavailable.
    # If the cache has no matching record, leave the action enabled rather than
    # falsely labeling the source as deleted.
    store = st.session_state.get("email_store")
    if store is None or not str(uid or "").strip():
        return False

    found_any = False
    for mailbox_folder in _candidate_mailbox_folders(folder):
        for candidate_uid in _candidate_original_uids(uid, folder):
            try:
                email = store.get_email(
                    mailbox_folder, candidate_uid, include_unavailable=True
                )
            except TypeError:
                try:
                    email = store.get_email(mailbox_folder, candidate_uid)
                except Exception:
                    email = None
            except Exception:
                email = None
            if not email:
                continue
            found_any = True
            if _email_is_remotely_available(email):
                return False
    return found_any


def _clear_email_dialog_state(
    state_key: str,
    return_workspace: str,
    return_task_uid: str = "",
) -> None:
    trace_action(
        "email-dialog-close",
        dialog=str(state_key or "original_dialog_uid"),
        return_workspace=str(return_workspace or "summary"),
        return_task=bool(str(return_task_uid or "").strip()),
    )
    # Close an email modal and explicitly restore the workspace that opened it.
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
    _clear_original_thread_scroll_state()
    st.session_state.pop(str(state_key or "original_dialog_uid"), None)
    st.session_state.active_workspace = str(return_workspace or "summary")

    task_uid = str(return_task_uid or "").strip()
    if task_uid and str(return_workspace or "").strip().casefold() == "todo":
        st.session_state.todo_dialog_uid = task_uid

    if str(state_key or "") == "original_dialog_uid":
        st.session_state.pop("original_dialog_return_workspace", None)
        st.session_state.pop("original_dialog_return_todo_uid", None)


def _clear_original_dialog_state() -> None:
    # Original Email is opened from AI Summary. Explicitly restoring the
    # workspace prevents a dialog-fragment rerun from leaving only the sidebar
    # visible on rare close/rerun races.
    _clear_email_dialog_state("original_dialog_uid", "summary")


def _security_single_message_view(
    raw_email: dict,
    selected_email: dict,
    store,
    folder: str,
) -> dict:
    """Return only the exact Spam/Security message selected by the user.

    Spam cards are message-scoped, even when several unsafe replies belong to
    one provider/RFC thread. The Security modal must follow the same identity:
    opening one card shows one physical email only, never sibling unsafe turns.
    """
    raw_email = dict(raw_email or {})
    selected_email = dict(selected_email or {})
    target_uid = str(selected_email.get("uid") or "").strip()
    target_message_ids = {
        str(value or "").strip().casefold()
        for value in message_ids(selected_email.get("message_id", ""))
        if str(value or "").strip()
    }

    candidates = [dict(item) for item in (raw_email.get("thread_messages") or [])]
    if not candidates and raw_email:
        candidates = [dict(raw_email)]

    exact = None
    for item in candidates:
        item_uid = str(item.get("uid") or "").strip()
        if target_uid and item_uid == target_uid:
            exact = item
            break
        item_message_ids = {
            str(value or "").strip().casefold()
            for value in message_ids(item.get("message_id", ""))
            if str(value or "").strip()
        }
        if target_message_ids and target_message_ids & item_message_ids:
            exact = item
            break

    # Provider conversation expansion can occasionally omit the exact local
    # row while MailMind still has the Security-finalized message cached. Fall
    # back only to that selected UID; never backfill sibling thread members.
    if exact is None and target_uid:
        try:
            local = store.get_email(folder, target_uid)
        except Exception:
            local = None
        if local:
            exact = dict(local)

    if exact is None:
        exact = dict(selected_email or raw_email)

    # Preserve Security metadata from the persisted selected card while taking
    # the hydrated body/HTML from the exact provider/local message when present.
    single = dict(selected_email)
    single.update(exact)
    if target_uid:
        single["uid"] = target_uid

    visible_uid = str(single.get("uid") or target_uid).strip()
    single.pop("thread_messages", None)
    single.pop("source_uids", None)
    single["body_text"] = str(single.get("body_text") or single.get("snippet") or "")

    # Match the existing Inbox thread-reader presentation contract exactly:
    # each reply card shows only the content authored in that physical message,
    # not the provider-copied history below it. This reuses the same display-only
    # projection as Inbox so Gmail soft-wrapped ``On ... wrote:`` attributions,
    # Gmail/Yahoo quote containers, and Outlook From/Sent/To/Subject blocks are
    # handled consistently. The source/provider payload, Security classification,
    # routing, thread state, Summary, Todo, and reply behavior remain untouched.
    single = _thread_display_message(single)

    single["source_uids"] = [visible_uid] if visible_uid else []
    single["thread_count"] = 1
    single["workspace_thread_count"] = 1
    turn = dict(single)
    turn.pop("thread_messages", None)
    single["thread_messages"] = [turn]
    return single


def _valid_cached_message(value) -> bool:
    # Reject partial/stale reader cache entries before opening the dialog.
    if not isinstance(value, dict):
        return False
    email = value.get("email")
    if not isinstance(email, dict) or not email:
        return False
    return bool(
        str(email.get("body_text") or "").strip()
        or str(email.get("body_html") or "").strip()
        or list(email.get("thread_messages") or [])
        or list(value.get("attachments") or [])
    )


def _clean_meta(value, fallback: str = "") -> str:
    text = str(value or "").strip()
    if not text or text.casefold() in _EMPTY_META_VALUES:
        return fallback
    return text


def _meta_icon(kind: str) -> str:
    paths = {
        "subject": '<path d="M6 3.75h7.2L18 8.55v11.7H6z"/><path d="M13.2 3.75v4.8H18"/>',
        "from": '<circle cx="12" cy="8" r="3.25"/><path d="M5.5 20c.45-4.1 2.6-6.15 6.5-6.15S18.05 15.9 18.5 20"/>',
        "to": '<path d="M3.7 11.4 20.3 4.7l-6.7 16.6-2.2-7.3z"/><path d="m11.4 14 8.9-9.3"/>',
        "cc": '<circle cx="9" cy="8.4" r="2.7"/><circle cx="16.3" cy="9.2" r="2.2"/><path d="M3.8 19c.4-3.45 2.15-5.2 5.2-5.2s4.85 1.75 5.25 5.2"/><path d="M14.1 14.25c2.9-.15 4.7 1.35 5.15 4.2"/>',
        "date": '<circle cx="12" cy="12" r="8"/><path d="M12 7.5v5l3.2 1.8"/>',
    }
    return (
        '<svg class="original-meta-icon" viewBox="0 0 24 24" aria-hidden="true" '
        'fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" '
        f'stroke-linejoin="round">{paths.get(kind, "")}</svg>'
    )


def _render_dialog_metadata(
    email_data: dict,
    *,
    note_text: str = "This is the original email message.",
    shell_class: str = "original-modal-shell",
) -> None:
    subject = _clean_meta(email_data.get("subject"), "(No Subject)")
    sender = _clean_meta(email_data.get("from"), "Unknown sender")
    recipient = _clean_meta(email_data.get("to"), "Unknown recipient")
    cc_value = _clean_meta(email_data.get("cc"))
    date_display = _clean_meta(email_data.get("date_display"), "Unknown")

    rows = [
        ("subject", "Subject", html.escape(subject), subject),
        ("from", "From", html.escape(sender), sender),
        ("to", "To", _collapsible_to_html(recipient), recipient),
    ]
    if cc_value:
        rows.append(("cc", "Cc", _collapsible_cc_html(cc_value), cc_value))
    rows.append(("date", "Date", html.escape(date_display), date_display))

    rows_html = "".join(
        '<div class="original-meta-row">'
        f'<span class="original-meta-icon-wrap">{_meta_icon(kind)}</span>'
        f'<span class="original-meta-label">{html.escape(label)}</span>'
        f'<span class="original-meta-value" title="{html.escape(title, quote=True)}">{value_html}</span>'
        '</div>'
        for kind, label, value_html, title in rows
    )

    st.markdown(
        f'<div class="{html.escape(shell_class, quote=True)}">'
        '<div class="original-modal-note">'
        '<span class="original-modal-note-icon">i</span>'
        f'<span>{html.escape(note_text)}</span>'
        '</div>'
        f'<div class="original-meta-card">{rows_html}</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _render_original_email_content(
    uid: str,
    folder: str = "INBOX",
    *,
    in_dialog: bool = False,
    dialog_state_key: str = "original_dialog_uid",
    return_workspace: str = "summary",
    return_task_uid: str = "",
    note_text: str = "This is the original email message.",
    embedded_overlay: bool = False,
    security_safe_view: bool = False,
) -> None:
    uid = str(uid or "").strip()
    if not uid:
        st.error("No original email was selected.")
        return

    store = st.session_state.email_store
    email, resolved_folder = _resolve_available_original_email(uid, folder)
    if not email:
        st.error("The original email thread is no longer available in the inbox.")
        return

    cache_uid = str(email.get("uid") or uid)
    cache_key = (st.session_state.active_store_account, resolved_folder, cache_uid)
    selected_message = st.session_state.email_bodies.get(cache_key)
    if not _valid_cached_message(selected_message):
        st.session_state.email_bodies.pop(cache_key, None)
        selected_message = None
    if selected_message is None:
        with st.spinner("Opening the email..." if security_safe_view else "Opening the original email thread..."):
            try:
                full_email = build_thread_email(
                    st.session_state.imap_client,
                    store,
                    email,
                    resolved_folder,
                    reader_projection=True,
                )
            except RuntimeError as error:
                st.error(f"Could not load the original email thread: {error}")
                return
        attachments = full_email.pop("attachments", None)
        if attachments is None:
            attachments = store.get_attachments(resolved_folder, cache_uid)
        selected_message = {"email": full_email, "attachments": attachments or []}
        st.session_state.email_bodies[cache_key] = selected_message

    if not in_dialog:
        st.markdown(
            '<div class="original-window-heading">Original Email</div>'
            '<div class="original-window-note">Original thread opened from AI Summary.</div>',
            unsafe_allow_html=True,
        )
        try:
            render_reader(selected_message)
        except Exception as error:
            st.session_state.email_bodies.pop(cache_key, None)
            st.error(f"Could not display the original email. Reopen it to retry: {error}")
        return

    # Spam/Security cards are message-scoped. Even when multiple unsafe replies
    # belong to one real provider thread, opening one Spam card must show only
    # that exact physical email. Inbox/Summary/To-Do keep their existing thread
    # behavior; this projection is exclusive to the Security modal.
    if security_safe_view:
        raw_email = dict(selected_message.get("email") or {})
        security_email = _security_single_message_view(
            raw_email,
            email,
            store,
            resolved_folder,
        )
        visible_uid = str(security_email.get("uid") or cache_uid).strip()
        security_attachments = [
            {**dict(attachment), "message_uid": visible_uid}
            for attachment in (security_email.get("attachments") or [])
        ]

        # Reconcile the selected message's locally cached attachments only.
        # Never import attachments from sibling replies in the same thread.
        attachment_loader = getattr(store, "get_attachments", None)
        if callable(attachment_loader) and visible_uid:
            existing_keys = {
                (str(item.get("filename") or ""), str(item.get("attachment_id") or ""))
                for item in security_attachments
            }
            try:
                local_attachments = list(attachment_loader(resolved_folder, visible_uid) or [])
            except Exception:
                local_attachments = []
            for attachment in local_attachments:
                item = {**dict(attachment), "message_uid": visible_uid}
                key = (str(item.get("filename") or ""), str(item.get("attachment_id") or ""))
                if key not in existing_keys:
                    security_attachments.append(item)
                    existing_keys.add(key)

        selected_message = {
            "email": security_email,
            "attachments": security_attachments,
        }

    # AI Summary and To-Do must show the same safe conversation projection that
    # was eligible to remain in the normal Inbox/task flow. Provider thread
    # expansion may include turns that MailMind later routed to Spam/Security;
    # those turns are useful in the Security workspace but must never reappear
    # under "View Original Email" for a saved Summary/Task. This shared path
    # covers Individual/Batch and Manual/Automatic summaries because both
    # workspaces reuse this original-email renderer.
    source_workspace = str(return_workspace or "").strip().casefold()
    if in_dialog and not security_safe_view and source_workspace in {"summary", "todo"}:
        raw_email = dict(selected_message.get("email") or {})
        try:
            source_email = filter_thread_email_for_workspace(
                raw_email,
                store,
                resolved_folder,
                spam_view=False,
            )
        except RuntimeError:
            # Fail closed for a Summary/To-Do source reader. If provider thread
            # reconstruction cannot produce a safe projection, fall back only to
            # the locally selected non-Spam source message -- never to the raw
            # provider conversation that may contain detected unsafe turns.
            local_selected = dict(email or {})
            if int(local_selected.get("is_spam") or 0) == 1:
                st.error("No safe source email is available for this saved Summary/Task.")
                return
            local_uid = str(local_selected.get("uid") or uid).strip()
            local_selected["thread_messages"] = [dict(local_selected)]
            local_selected["source_uids"] = [local_uid] if local_uid else []
            local_selected["thread_count"] = 1
            local_selected["workspace_thread_count"] = 1
            source_email = local_selected

        visible_uids = {
            str(value or "").strip()
            for value in (source_email.get("source_uids") or [])
            if str(value or "").strip()
        }
        source_attachments = []
        for attachment in (selected_message.get("attachments") or []):
            message_uid = str(attachment.get("message_uid") or "").strip()
            if not message_uid or message_uid in visible_uids:
                source_attachments.append(dict(attachment))
        selected_message = {
            "email": source_email,
            "attachments": source_attachments,
        }

    email_data = selected_message.get("email") or {}
    thread_messages = list(email_data.get("thread_messages") or [])
    is_thread = len(thread_messages) > 1

    # Summary and To-Do reuse the Inbox conversation presentation contract:
    # oldest turn first, newest turn last and expanded by default. The physical
    # thread payload remains untouched; this is a reader-only projection.
    inbox_style_thread = (
        is_thread
        and not security_safe_view
        and source_workspace in {"summary", "todo"}
    )
    auto_scroll_latest = False
    scroll_request_seq = int(
        st.session_state.get(_ORIGINAL_THREAD_SCROLL_REQUEST_KEY, 0) or 0
    )
    if inbox_style_thread:
        scroll_seen_key = (
            f"{_ORIGINAL_THREAD_SCROLL_SEEN_PREFIX}{source_workspace}_{cache_uid}"
        )
        if not bool(st.session_state.get(scroll_seen_key)):
            st.session_state[scroll_seen_key] = True
            scroll_request_seq += 1
            st.session_state[_ORIGINAL_THREAD_SCROLL_REQUEST_KEY] = scroll_request_seq
            auto_scroll_latest = True

    dialog_shell_class = (
        "todo-original-overlay-shell" if embedded_overlay else "original-modal-shell"
    )
    if not embedded_overlay and source_workspace == "todo" and is_thread:
        dialog_shell_class += " todo-original-thread-modal-shell"

    # One keyed layout owns the complete modal body. This gives CSS a stable
    # flex column to size against the viewport, so extra metadata (Cc),
    # attachments, or a long HTML email can only reduce the message pane --
    # they can never push the footer/Close action below the viewport.
    with st.container(border=False, key="original_modal_layout"):
        _render_dialog_metadata(
            email_data,
            note_text=note_text,
            shell_class=dialog_shell_class,
        )

        # The modal owns one adaptive message pane. Unlike the Inbox reader,
        # this container has no fixed Streamlit height: CSS applies only a
        # max-height, so short messages stay compact while long messages and
        # attachments scroll inside this pane alone.
        try:
            reader_key = (
                "todo_original_thread_reader"
                if (not embedded_overlay and source_workspace == "todo" and is_thread)
                else "original_modal_reader"
            )
            with st.container(border=False, key=reader_key):
                render_reader_content(
                    selected_message,
                    include_attachments=is_thread,
                    attachment_key_prefix=f"original_{cache_uid}_thread",
                    disable_external_actions=security_safe_view,
                    inbox_thread_oldest_first=inbox_style_thread,
                )
                if auto_scroll_latest:
                    st.html(
                        '<template data-mailmind-reader-scroll-latest="'
                        + html.escape(reader_key, quote=True)
                        + '" data-mailmind-scroll-request="'
                        + str(scroll_request_seq)
                        + '"></template>',
                        width="content",
                    )

            # A standalone message keeps the approved separate attachment
            # section below the body. Threaded mail renders each attachment
            # inside the exact conversation turn that originally carried it.
            if not is_thread and selected_message.get("attachments"):
                with st.container(border=False, key="original_modal_attachments"):
                    render_reader_attachments(
                        selected_message,
                        key_prefix=f"original_{cache_uid}_attachments",
                        disabled_for_security=security_safe_view,
                    )
        except Exception as error:
            st.session_state.email_bodies.pop(cache_key, None)
            st.error(f"Could not display the original email. Close and reopen it to retry: {error}")

        with st.container(key="original_modal_actions"):
            spacer, close_col = st.columns([1, 0.13], gap="small")
            with spacer:
                st.empty()
            with close_col:
                if embedded_overlay:
                    close_clicked = st.button(
                        "Close",
                        icon=":material/close:",
                        key=f"original_modal_close_{dialog_state_key}_{uid}",
                        type="secondary",
                        use_container_width=True,
                    )
                    if close_clicked:
                        trace_action("todo-original-email-close", uid=uid)
                        _clear_original_thread_scroll_state()
                        st.session_state.pop(dialog_state_key, None)
                        st.rerun(scope="fragment")
                else:
                    close_clicked = st.button(
                        "Close",
                        icon=":material/close:",
                        key=f"original_modal_close_{dialog_state_key}_{uid}",
                        type="secondary",
                        use_container_width=True,
                        on_click=_clear_email_dialog_state,
                        args=(dialog_state_key, return_workspace, return_task_uid),
                    )
                    if close_clicked:
                        # st.dialog is a fragment. Make the full-app rerun explicit
                        # so the Summary workspace is rebuilt immediately.
                        st.rerun(scope="app")


@st.dialog(
    "Original email",
    width="large",
    icon=":material/mail:",
    dismissible=False,
)
def render_original_email_dialog(uid: str, folder: str = "INBOX") -> None:
    # Open the original email/thread without leaving the current page. The same
    # reader is shared by AI Summary and To-Do; callers may request a return to
    # the Task actions dialog after Close.
    return_workspace = str(
        st.session_state.get("original_dialog_return_workspace") or "summary"
    )
    return_task_uid = str(
        st.session_state.get("original_dialog_return_todo_uid") or ""
    )
    _render_original_email_content(
        uid,
        folder,
        in_dialog=True,
        return_workspace=return_workspace,
        return_task_uid=return_task_uid,
    )


@st.dialog(
    "Email message",
    width="large",
    icon=":material/mail:",
    dismissible=False,
)
def render_spam_email_dialog(uid: str, folder: str = "ALL_MAIL") -> None:
    # Spam/Security workspace reuses the approved Original Email modal UI.
    _render_original_email_content(
        uid,
        folder,
        in_dialog=True,
        dialog_state_key="spam_email_dialog_uid",
        return_workspace="spam",
        note_text=(
            "Email opened from MailMind Security Analysis. "
            "Links and attachments are disabled for safety."
        ),
        security_safe_view=True,
    )


def render_original_email_window(uid: str, folder: str = "INBOX") -> None:
    # Legacy standalone renderer kept for old bookmarked action URLs.
    _render_original_email_content(uid, folder, in_dialog=False)
