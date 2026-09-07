# The original Inbox workspace, now hosted inside a tab.
from functools import partial

import streamlit as st
from config import MAX_EMAILS_FETCH, UI_DEBOUNCE_PAGINATION_SECONDS, UI_FOREGROUND_SETTLE_SECONDS
from controllers.inbox_controller import (
    inbox_view_signature,
    load_local_page,
)
from controllers.reader_controller import load_selected_message
from ui.inbox import render_inbox
from ui.inbox_summary_toolbar import render_inbox_summary_toolbar
from ui.reader import render_reader
from ui.security_panel import render_security_assessment
from services.ui_interaction_service import (
    claim_foreground_interaction,
)
from services.white_stale_trace_service import trace_action


def _ensure_cached_view_page(folder: str) -> None:
    # Reload page 1 when search/filter/sort state changes.
    #
    # The database applies the active query and filters to the complete saved
    # inbox before returning the first ten rows.
    search_mode = bool(st.session_state.get("search_active"))
    query = (
        str(st.session_state.get("inbox_search_query", "") or "").strip()
        if search_mode
        else ""
    )
    signature = inbox_view_signature(search_mode=search_mode, query=query)
    if st.session_state.get("inbox_loaded_view_signature") == signature:
        return

    load_local_page(
        0,
        folder,
        search_mode=search_mode,
        query=query,
    )


def _paginate_inbox(direction: str, folder: str) -> None:
    """Queue one page change without doing render work inside the callback.

    Streamlit widget callbacks execute before the normal app render. Keeping the
    callback lightweight avoids loading SQLite data and re-keying the large Inbox
    list while the previous browser tree is still being torn down.
    """
    direction = str(direction or "").casefold()
    if direction not in {"prev", "next"}:
        return
    if not claim_foreground_interaction(
        "inbox-pagination", debounce_seconds=UI_DEBOUNCE_PAGINATION_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("inbox-pagination-click", direction=direction)
    # Checkbox selection is intentionally UID-scoped, not page-scoped. Moving
    # between pages must preserve the selected UID set so users can build one
    # manual Individual/Batch selection across multiple Inbox pages. The next
    # page simply renders its own visible rows from that persisted set; when the
    # user returns to an earlier page, those rows are checked again.
    st.session_state.inbox_pending_page_direction = direction


def _apply_pending_inbox_pagination(folder: str) -> None:
    """Consume queued pagination during the protected root app render."""
    direction = str(
        st.session_state.pop("inbox_pending_page_direction", "") or ""
    ).casefold()
    if direction not in {"prev", "next"}:
        return

    trace_action("inbox-pagination-apply", direction=direction, search_mode=bool(st.session_state.get("search_active")))
    st.session_state.selected_uid = None
    st.session_state.inbox_read_pinned_uid = ""
    st.session_state.spam_reviewed_pinned_uid = ""

    page_size = MAX_EMAILS_FETCH
    search_mode = bool(st.session_state.get("search_active"))
    if search_mode:
        current = max(0, int(st.session_state.get("inbox_search_offset", 0) or 0))
        target = (
            current + page_size
            if direction == "next"
            else max(0, current - page_size)
        )
        st.session_state.inbox_search_page_size = page_size
        load_local_page(
            target,
            folder,
            search_mode=True,
            query=str(st.session_state.get("inbox_search_query") or ""),
        )
    else:
        current = max(0, int(st.session_state.get("inbox_offset", 0) or 0))
        target = (
            current + page_size
            if direction == "next"
            else max(0, current - page_size)
        )
        load_local_page(target, folder)

    # Preserve PaginationTop without re-keying/destroying the Inbox list DOM.
    st.session_state.inbox_list_scroll_reset_pending = True


def _apply_expanded_thread_count(list_source: list[dict], selected_message) -> None:
    # Keep the Inbox badge scoped to the current MailMind workspace after reader expansion.
    email_data = (selected_message or {}).get("email") or {}
    selected_uid = str(st.session_state.get("selected_uid") or "")
    if not email_data or not selected_uid:
        return

    expanded_count = int(
        email_data.get("workspace_thread_count")
        or email_data.get("thread_count")
        or 1
    )
    for email_item in list_source:
        if str(email_item.get("uid") or "") == selected_uid:
            email_item["thread_count"] = expanded_count
            break


def render_inbox_tab(activity_slot, folder: str = "INBOX", spam_view: bool | None = None):
    if spam_view is None:
        spam_view = str(st.session_state.get("inbox_filter") or "all").casefold() == "spam"
    with st.container(border=False, key="mail_workspace"):
        _ensure_cached_view_page(folder)
        _apply_pending_inbox_pagination(folder)
        if st.session_state.search_active:
            list_source = list(st.session_state.search_results)
            display_total = int(st.session_state.search_total)
            display_offset = int(st.session_state.inbox_search_offset)
            can_prev = display_offset > 0
            can_next = display_offset + MAX_EMAILS_FETCH < display_total
        else:
            list_source = list(st.session_state.emails)
            display_total = int(st.session_state.inbox_total)
            display_offset = int(st.session_state.inbox_offset)
            can_prev = display_offset > 0
            can_next = bool(st.session_state.inbox_has_more)

        # Inbox Unread follows the same selected-card behavior as the other
        # attention views: once the opened message is successfully marked read,
        # its counter/attention state is consumed immediately, but the selected
        # card stays visible until another email is chosen or the filter/tab is
        # left. This does not make the email unread again.
        if (
            not spam_view
            and str(st.session_state.get("inbox_filter") or "all").casefold()
            in {"unread", "unread_with_attachment"}
        ):
            pinned_uid = str(st.session_state.get("inbox_read_pinned_uid") or "")
            selected_uid = str(st.session_state.get("selected_uid") or "")
            if pinned_uid and pinned_uid == selected_uid and not any(
                str(item.get("uid") or "") == pinned_uid for item in list_source
            ):
                pinned = st.session_state.email_store.get_email(folder, pinned_uid)
                if pinned is not None and int(pinned.get("is_spam") or 0) == 0:
                    # The Unread query is message-qualified but the Inbox UI is
                    # thread-projected. After opening the newest unread reply,
                    # that physical message is marked read immediately. If an
                    # older reply in the same thread is still unread, SQLite now
                    # returns that older reply as the qualifying thread card.
                    # Do not insert the selected/read message as a second card:
                    # replace the existing representative for the same thread so
                    # the Unread view always remains one card per conversation.
                    pinned_thread_id = str(
                        pinned.get("canonical_thread_id") or ""
                    ).strip()
                    same_thread_index = next(
                        (
                            index
                            for index, item in enumerate(list_source)
                            if pinned_thread_id
                            and str(item.get("canonical_thread_id") or "").strip()
                            == pinned_thread_id
                        ),
                        None,
                    )

                    # Keep the card badge conversation-scoped while the selected
                    # card is pinned. The unread membership decides whether the
                    # thread qualifies for this view; ``(N)`` still represents
                    # the messages in the visible Inbox conversation, not N
                    # separate cards.
                    get_thread_members = getattr(
                        st.session_state.email_store, "get_thread_members", None
                    )
                    if pinned_thread_id and callable(get_thread_members):
                        try:
                            members = list(
                                get_thread_members(folder, pinned_thread_id) or []
                            )
                            visible_members = [
                                member
                                for member in members
                                if int(member.get("is_spam") or 0) == 0
                            ]
                            if visible_members:
                                pinned["thread_count"] = len(visible_members)
                        except Exception:
                            # Pinning is a presentation convenience. A failed
                            # count refresh must not prevent the selected message
                            # from remaining visible.
                            pass

                    if same_thread_index is not None:
                        list_source[same_thread_index] = pinned
                    else:
                        # The opened message was the last unread member of its
                        # thread. Keep that one selected card visible until the
                        # user leaves Unread/chooses another email, matching the
                        # existing attention-view behavior.
                        list_source.insert(0, pinned)
                        display_total += 1
        elif not spam_view:
            # A pinned read card only belongs to the active Unread view.
            st.session_state.inbox_read_pinned_uid = ""

        # Newly detected mirrors the approved Unviewed behavior: opening a
        # security finding marks it reviewed immediately, but the currently
        # selected card stays visible until the user chooses another item or
        # leaves the filter. This is UI-only and does not alter classification.
        if (
            spam_view
            and bool(st.session_state.get("spam_detected_only", False))
        ):
            pinned_uid = str(st.session_state.get("spam_reviewed_pinned_uid") or "")
            selected_uid = str(st.session_state.get("selected_uid") or "")
            if pinned_uid and pinned_uid == selected_uid and not any(
                str(item.get("uid") or "") == pinned_uid for item in list_source
            ):
                pinned = st.session_state.email_store.get_email(folder, pinned_uid)
                if pinned is not None and int(pinned.get("is_spam") or 0) == 1:
                    list_source.insert(0, pinned)
                    display_total += 1

        if spam_view:
            selected_header = next(
                (
                    email_item
                    for email_item in list_source
                    if str(email_item.get("uid") or "")
                    == str(st.session_state.get("selected_uid") or "")
                ),
                None,
            )
            selected_message = (
                {"email": dict(selected_header), "attachments": []}
                if selected_header
                else None
            )
        else:
            selected_message = load_selected_message(
                list_source, activity_slot, folder=folder, spam_view=False
            )
            _apply_expanded_thread_count(list_source, selected_message)

        spam_category_counts = {}

        col_list, col_content = st.columns([0.43, 0.57], gap="medium")

        with col_list:
            with st.container(key="inbox_outer_pane"):
                render_inbox_summary_toolbar(spam_view=spam_view, folder=folder)
                actions = render_inbox(
                    list_source,
                    total=display_total,
                    offset=display_offset,
                    loading=st.session_state.loading,
                    checked_uids=st.session_state.checked_uids,
                    search_active=st.session_state.search_active,
                    search_total=display_total,
                    can_prev=can_prev,
                    can_next=can_next,
                    spam_view=spam_view,
                    spam_category_counts=spam_category_counts,
                    show_spam_dashboard=False,
                    folder=folder,
                    on_prev=partial(_paginate_inbox, "prev", folder),
                    on_next=partial(_paginate_inbox, "next", folder),
                )
                st.session_state.checked_uids = actions["checked_uids"]
        with col_content:
            with st.container(key="email_content_outer_pane"):
                if not spam_view:
                    st.markdown(
                        '<div class="mailmind-workspace-header">'
                        '<div class="mailmind-workspace-title">Email Content</div>'
                        '<div class="mailmind-workspace-controls mailmind-workspace-controls-empty"></div>'
                        '</div>',
                        unsafe_allow_html=True,
                    )
                    render_reader(selected_message, spam_view=False, folder=folder)
                else:
                    st.markdown(
                        '<div class="mailmind-workspace-header mailmind-workspace-header-todo spam-analysis-header">'
                        '<div class="mailmind-workspace-title">Security Analysis</div>'
                        '</div>',
                        unsafe_allow_html=True,
                    )
                    render_security_assessment(selected_message, folder=folder)
    return actions, list_source
