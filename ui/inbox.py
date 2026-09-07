import hashlib
import html as html_lib

import streamlit as st

from config import (
    INBOX_LIST_HEIGHT,
    UI_DEBOUNCE_FAST_SECONDS,
    UI_DEBOUNCE_FILTER_SECONDS,
    UI_DEBOUNCE_REFRESH_SECONDS,
    UI_FOREGROUND_SETTLE_SECONDS,
)

from datetime import datetime, timedelta
from email.utils import parseaddr
from email_handler.display_time import to_display_datetime
from ui.markup import security_badge
from ui.scripts import emit_scroll_reset_marker
from services.ui_interaction_service import (
    arm_foreground_interaction,
    claim_foreground_interaction,
    workspace_callback_allowed,
    workspace_interaction_allowed,
)
from services.white_stale_trace_service import trace_action
from services.thread_service import resolve_thread_headers
from ui.loading import set_app_loading_state


def _consume_thread_unread(folder: str, uid: str) -> set[str]:
    """Mark every MailMind-unread message in the opened Inbox thread as read.

    Inbox cards are conversation-level once threading is active. A single card
    click therefore represents viewing the whole visible conversation, not just
    the representative row that happened to qualify the list query. Keep the
    durable MailMind unread store and the same-rerun sidebar set in sync.
    """
    uid = str(uid or "").strip()
    unread_uids = {
        str(value).strip()
        for value in st.session_state.get("new_email_uids", set())
        if str(value).strip()
    }
    if not uid or not unread_uids:
        return set()

    store = st.session_state.get("email_store")
    if store is None:
        return set()

    selected = store.get_email(folder, uid) or {"uid": uid}
    try:
        headers = list(resolve_thread_headers(store, selected, folder) or [])
    except (AttributeError, RuntimeError, ValueError):
        headers = [selected]

    thread_uids = {
        str(item.get("uid") or "").strip()
        for item in headers
        if str(item.get("uid") or "").strip()
        and not bool(int(item.get("is_spam") or 0))
    }
    if not thread_uids:
        thread_uids = {uid}

    consumed = unread_uids.intersection(thread_uids)
    if not consumed:
        return set()

    mark_read = getattr(store, "mark_mailmind_read", None)
    if callable(mark_read):
        mark_read(folder, consumed)

    unread_uids.difference_update(consumed)
    st.session_state.new_email_uids = unread_uids
    return consumed



def _queue_inbox_refresh() -> None:
    """Claim Refresh before the expensive provider round-trip starts.

    Streamlit callbacks run before the normal full-app render.  Arming the
    foreground guard and loading state here lets that render paint one stable
    disabled workspace + loader before ``handle_inbox_actions`` performs remote
    mailbox work.  Timed fragments therefore see the guard and cannot interrupt
    the refresh halfway through, which was the source of stale/blank Inbox DOM
    states after a long refresh.
    """
    if not workspace_callback_allowed("inbox", "spam"):
        return
    if st.session_state.get("inbox_refresh_requested", False):
        trace_action("inbox-refresh", outcome="ignored-already-requested")
        return
    if not claim_foreground_interaction(
        "inbox-refresh",
        debounce_seconds=UI_DEBOUNCE_REFRESH_SECONDS,
        settle_seconds=UI_FOREGROUND_SETTLE_SECONDS,
    ):
        return

    st.session_state.inbox_refresh_requested = True
    st.session_state.loading = True
    st.session_state.inbox_list_scroll_reset_pending = True
    set_app_loading_state(
        "Please wait...",
        "Checking for mailbox changes...",
        "0%",
    )
    trace_action("inbox-refresh-click")

_AVATAR_CLASS_COUNT = 8

_SPAM_CATEGORY_METRICS = (
    ("all", "All", "all", ":material/grid_view:"),
    ("spam", "Spam", "Spam", ":material/mail:"),
    ("phishing", "Phishing", "Phishing", ":material/phishing:"),
    ("malware", "Malware", "Malware", ":material/bug_report:"),
    ("scam_fraud", "Scam / Fraud", "Scam / Fraud", ":material/gpp_bad:"),
    ("impersonation", "Impersonation", "Impersonation", ":material/person_search:"),
    ("suspicious", "Suspicious", "Suspicious", ":material/help:"),
    ("safe_misclassified", "Safe", "Safe / Misclassified", ":material/verified_user:"),
)


def _sender_avatar(sender: str):
    name, address = parseaddr(sender or "")
    label = (name or address or sender or "?").strip().strip('"')
    initial = (label[:1] or "?").upper()
    tone_index = sum(ord(ch) for ch in (sender or "")) % _AVATAR_CLASS_COUNT
    return initial, f"avatar-tone-{tone_index}"


def _display_sender(sender: str) -> str:
    name, address = parseaddr(sender or "")
    return (name or address or sender or "Unknown sender").strip()


def _mail_row_card_html(
    *,
    selected_class: str,
    unread_class: str,
    avatar_class: str,
    avatar_initial: str,
    subject: str,
    sender: str,
    time_label: str,
    thread_count: int = 1,
    security_category: str = "",
    security_confidence: int = 0,
    has_attachment: bool = False,
) -> str:
    # Build compact HTML that Streamlit cannot parse as a Markdown code block.
    count = max(1, int(thread_count or 1))
    count_label = ""
    if count > 1:
        count_label = (
            '<span class="mail-row-thread-count" '
            f'title="{count} emails in this card" '
            f'aria-label="{count} emails in this card">({count})</span>'
        )
    badge_html = security_badge(security_category, security_confidence)
    attachment_html = ""
    if has_attachment:
        attachment_html = (
            '<span class="mail-row-attachment-icon" aria-hidden="true">'
            '<svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">'
            '<path d="M20.5 11.5 11.3 20.7a5.1 5.1 0 0 1-7.2-7.2l9.9-9.9a3.6 3.6 0 0 1 5.1 5.1l-9.9 9.9a2.1 2.1 0 0 1-3-3l9.2-9.2"/>'
            '</svg>'
            '</span>'
        )
    sender_html = f'<div class="mail-row-sender">{html_lib.escape(sender)}</div>'
    security_class = " has-security-meta" if badge_html else ""
    if badge_html:
        time_html = (
            '<div class="mail-row-time mail-row-time-security">'
            f'<span class="mail-row-time-label">{html_lib.escape(time_label)}{count_label}</span>'
            f'{badge_html}'
            '</div>'
        )
    else:
        time_html = f'<div class="mail-row-time">{html_lib.escape(time_label)}{count_label}</div>'
    return (
        f'<div class="mail-row-card{selected_class}{unread_class}{security_class}">'
        f'<div class="mail-row-avatar {html_lib.escape(avatar_class)}">'
        f'{html_lib.escape(avatar_initial)}</div>'
        '<div class="mail-row-copy">'
        f'<div class="mail-row-subject">{html_lib.escape(subject)}</div>'
        f'{sender_html}'
        '</div>'
        f'{time_html}'
        f'{attachment_html}'
        '</div>'
    )


def _inbox_time_label(email_item: dict) -> str:
    date_value = str(email_item.get("date") or "").strip()
    try:
        dt = to_display_datetime(date_value) if date_value else None
    except Exception:
        dt = None

    if not dt:
        raw = str(email_item.get("date_display") or "").strip()
        return raw or "Unknown"

    try:
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    except Exception:
        now = datetime.now()

    today = now.date()
    item_day = dt.date()
    if item_day == today:
        return dt.strftime("%I:%M %p").lstrip("0")
    if item_day == (today - timedelta(days=1)):
        return "Yesterday"
    if item_day.year == today.year:
        return dt.strftime("%b %d").replace(" 0", " ")
    return dt.strftime("%b %d, %Y").replace(" 0", " ")


# Update search actions when the query changes.
def _handle_search_input_change():
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("inbox", "spam"):
        trace_action("workspace-callback-ignored", source="inbox", callback="_handle_search_input_change")
        return
    trace_action("inbox-search-change", query_len=len(str(st.session_state.get("inbox_search_query", "") or "")))
    # Search changes trigger a full Streamlit rerun. Arm the same one-render
    # foreground guard used by email selection/pagination so background mailbox,
    # Security catch-up, and Auto Summary timers cannot race the workspace rerender.
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction()
    st.session_state.pop("inbox_pending_page_direction", None)
    st.session_state.inbox_search_offset = 0
    st.session_state.inbox_list_scroll_reset_pending = True
    query = st.session_state.get("inbox_search_query", "").strip()
    st.session_state.inbox_search_submit = bool(query)
    st.session_state.inbox_search_clear = not bool(query)


def _page_selection_key(visible_uids, search_active: bool, offset: int) -> str:
    # Return a stable, compact widget key for the current ten-row page.
    signature = "\x1f".join(str(uid) for uid in visible_uids)
    digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:12]
    mode = "search" if search_active else "inbox"
    return f"select_page_{mode}_{max(0, int(offset))}_{digest}"


def _toggle_current_page_selection(select_key: str, visible_uids) -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("inbox", "spam"):
        trace_action("workspace-callback-ignored", source="inbox", callback="_toggle_current_page_selection")
        return
    # Select or clear only the emails displayed on the current page.
    arm_foreground_interaction()
    select_page = bool(st.session_state.get(select_key, False))
    trace_action("inbox-select-page", selected=select_page, visible_count=(len(visible_uids) if hasattr(visible_uids, "__len__") else None))
    selected = {str(uid) for uid in st.session_state.get("checked_uids", set())}

    if select_page:
        selected.update(str(uid) for uid in visible_uids)
    else:
        selected.difference_update(str(uid) for uid in visible_uids)

    st.session_state.checked_uids = selected
    for uid in visible_uids:
        st.session_state[f"chk_{uid}"] = select_page


def _sync_one_email_selection(uid: str, select_key: str, visible_uids) -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("inbox", "spam"):
        trace_action("workspace-callback-ignored", source="inbox", callback="_sync_one_email_selection")
        return
    # Keep the saved set and page-level checkbox aligned with one row toggle.
    arm_foreground_interaction()
    uid = str(uid)
    trace_action("inbox-select-one", checked=bool(st.session_state.get(f"chk_{uid}", False)))
    selected = {str(item) for item in st.session_state.get("checked_uids", set())}
    if bool(st.session_state.get(f"chk_{uid}", False)):
        selected.add(uid)
    else:
        selected.discard(uid)

    st.session_state.checked_uids = selected
    visible = tuple(str(item) for item in visible_uids)
    st.session_state[select_key] = bool(visible) and all(
        item in selected for item in visible
    )


def _process_inbox_search_value_without_callback(query: str) -> None:
    """Process the current search value during the normal render rerun.

    Streamlit can invoke ``on_change`` callbacks for text inputs while a widget
    tree is being removed during workspace navigation. Keeping the search input
    callback-free avoids those synthetic cross-workspace callbacks entirely; a
    real edit already causes the normal Streamlit rerun, so the new value can be
    handled safely here instead.
    """
    current = str(query or "")
    tracker_key = "_inbox_search_processed_value"
    if tracker_key not in st.session_state:
        st.session_state[tracker_key] = current
        return

    previous = str(st.session_state.get(tracker_key, "") or "")
    if current == previous:
        return

    # Consume programmatic/session-transition changes without treating them as
    # foreground user input. The active Inbox/Spam render will reconcile the
    # resulting view state normally.
    if not workspace_interaction_allowed():
        st.session_state[tracker_key] = current
        return

    st.session_state[tracker_key] = current
    trace_action("inbox-search-change", query_len=len(current))
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction()
    st.session_state.pop("inbox_pending_page_direction", None)
    st.session_state.inbox_search_offset = 0
    st.session_state.inbox_list_scroll_reset_pending = True
    normalized = current.strip()
    st.session_state.inbox_search_submit = bool(normalized)
    st.session_state.inbox_search_clear = not bool(normalized)


def _reconcile_inbox_selection_without_callbacks(
    checked_uids, visible_uids_ordered, select_page_key: str
):
    """Render checkbox state from the already-synchronized UID selection.

    Selection changes are consumed once before the sidebar is rendered by
    ``sync_checked_uids_from_widgets``.  This render-stage helper is deliberately
    passive: it never infers a user action from a checkbox value during a
    background/full-app rerun.  That prevents stale widget state from clearing or
    recreating selections when Streamlit remounts the Inbox tree.
    """
    selected = {str(uid) for uid in checked_uids}
    visible = tuple(str(uid) for uid in visible_uids_ordered)
    all_selected = bool(visible) and all(uid in selected for uid in visible)

    # Publish the exact page metadata used by the next pre-sidebar rerun.  The
    # summary button is mounted before the Inbox body, so this durable metadata
    # lets the next checkbox interaction be consumed before Generate Summary is
    # evaluated without requiring checkbox callbacks.
    st.session_state.inbox_selection_page_key = select_page_key
    st.session_state.inbox_selection_visible_uids = visible

    # Recreate every visible widget from the persisted UID set.  These assignments
    # occur before the corresponding widgets are instantiated in this run.
    for uid in visible:
        st.session_state[f"chk_{uid}"] = uid in selected
    st.session_state[select_page_key] = all_selected
    st.session_state.inbox_selection_processed_page_key = select_page_key
    st.session_state.inbox_selection_processed_page_value = all_selected
    return selected


def _inbox_filter_flags(value: str | None = None) -> tuple[bool, bool]:
    # Inbox supports two independent filter dimensions while retaining the
    # historical single ``inbox_filter`` state key for compatibility elsewhere.
    normalized = str(
        value if value is not None else st.session_state.get("inbox_filter", "all")
    ).strip().casefold()
    return (
        normalized in {"unread", "unread_with_attachment"},
        normalized in {"with_attachment", "unread_with_attachment"},
    )


def _compose_inbox_filter(*, unread: bool, with_attachment: bool) -> str:
    if unread and with_attachment:
        return "unread_with_attachment"
    if unread:
        return "unread"
    if with_attachment:
        return "with_attachment"
    return "all"


# Apply one Inbox/Spam menu choice. Unread + With Attachment and Spam Detected +
# classification are intentionally composable; All Mail / All Spam clears the
# corresponding filter group.
def _set_filter_menu_value(state_key: str, value):
    if not claim_foreground_interaction(
        "inbox-filter", debounce_seconds=UI_DEBOUNCE_FILTER_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("inbox-filter-detail", state_key=state_key, value=value)
    # Filter / Arrange / Sort choices are foreground navigation events. Guard the
    # next root render so a timer fragment cannot unmount the workspace midway
    # through the popover-triggered rerun (the observed full white-screen flash).
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction()
    st.session_state.pop("inbox_pending_page_direction", None)
    st.session_state.inbox_search_offset = 0
    st.session_state.inbox_offset = 0
    st.session_state.inbox_list_scroll_reset_pending = True

    if state_key == "inbox_filter" and value in {"all", "unread", "with_attachment"}:
        if value == "all":
            st.session_state.inbox_filter = "all"
        else:
            unread, with_attachment = _inbox_filter_flags()
            if value == "unread":
                unread = not unread
            else:
                with_attachment = not with_attachment
            st.session_state.inbox_filter = _compose_inbox_filter(
                unread=unread, with_attachment=with_attachment
            )
    elif state_key == "spam_detected_only":
        st.session_state.spam_detected_only = not bool(
            st.session_state.get("spam_detected_only", False)
        )
    elif state_key == "spam_category_filter":
        normalized_value = str(value).casefold()
        if normalized_value == "all":
            st.session_state.spam_category_filter = "all"
            st.session_state.spam_detected_only = False
        else:
            current = str(
                st.session_state.get("spam_category_filter") or "all"
            ).casefold()
            # Clicking the active classification removes only that category and
            # leaves Detected intact, so Filter (2) can naturally return to (1).
            st.session_state.spam_category_filter = (
                "all" if current == normalized_value else value
            )
    else:
        st.session_state[state_key] = value

    # Force the next non-search render to reload the correctly filtered/sorted
    # SQLite page instead of reusing the previous page's rows.
    st.session_state.inbox_loaded_view_signature = None

    # A changed view can make the currently open email disappear.
    st.session_state.selected_uid = None
    if state_key in {"spam_category_filter", "spam_detected_only"}:
        st.session_state.spam_reviewed_pinned_uid = ""


def _active_inbox_filter_count(spam_view: bool = False) -> int:
    # Count only actual narrowing filters. Arrange By and Sort do not contribute.
    if spam_view:
        category_active = (
            str(st.session_state.get("spam_category_filter") or "all").casefold()
            != "all"
        )
        return int(bool(st.session_state.get("spam_detected_only", False))) + int(category_active)
    unread, with_attachment = _inbox_filter_flags()
    return int(unread) + int(with_attachment)


def _menu_button(label: str, key: str, state_key: str, value, *, active=None):
    if active is None:
        active = st.session_state.get(state_key) == value
    # Keep every menu item as a secondary Streamlit button. The active state is
    # carried by the keyed CSS hook instead, avoiding Streamlit's dark primary
    # background while preserving the original light-blue selected style.
    visual_key = f"{key}_selected" if active else f"{key}_normal"
    st.button(
        label,
        key=visual_key,
        type="secondary",
        use_container_width=True,
        on_click=_set_filter_menu_value,
        args=(state_key, value),
    )


def _render_filter_menu(loading: bool = False, spam_view: bool = False):
    # Streamlit 1.50 has no key parameter on st.popover, so a keyed
    # container provides a stable CSS hook for the trigger button.
    with st.container(key="inbox_filter_popover"):
        filter_count = _active_inbox_filter_count(spam_view=spam_view)
        label = f"Filter ({filter_count})" if filter_count else "Filter"
        # Streamlit >=1.60 supports a real popover key. Keep the popover identity
        # stable while its label/count changes instead of forcing portal teardown
        # with an invisible label mutation during the same widget rerun.
        with st.popover(
            label,
            key="inbox_filter_menu",
            icon=":material/filter_alt:",
            use_container_width=True,
            disabled=loading,
        ):
            if spam_view:
                st.markdown(
                    '<div class="inbox-filter-menu-title">FILTER</div>'
                    '<div class="inbox-filter-menu-spacer"></div>',
                    unsafe_allow_html=True,
                )
                spam_category = str(
                    st.session_state.get("spam_category_filter") or "all"
                ).casefold()
                spam_detected = bool(
                    st.session_state.get("spam_detected_only", False)
                )
                _menu_button(
                    "All Spam",
                    "inbox_filter_item_security_all",
                    "spam_category_filter",
                    "all",
                    active=(spam_category == "all" and not spam_detected),
                )
                _menu_button(
                    "Detected",
                    "inbox_filter_item_security_newly_detected",
                    "spam_detected_only",
                    True,
                    active=spam_detected,
                )
                st.markdown(
                    '<div class="inbox-filter-menu-divider"></div>'
                    '<div class="inbox-filter-menu-title">CATEGORY</div>'
                    '<div class="inbox-filter-menu-spacer"></div>',
                    unsafe_allow_html=True,
                )
                category_items = (
                    ("Spam", "Spam", "spam"),
                    ("Promotional", "Promotional", "promotional"),
                    ("Phishing", "Phishing", "phishing"),
                    ("Malware", "Malware", "malware"),
                    ("Scam / Fraud", "Scam / Fraud", "scam_fraud"),
                    ("Impersonation", "Impersonation", "impersonation"),
                    ("Suspicious", "Suspicious", "suspicious"),
                    ("Safe / Misclassified", "Safe / Misclassified", "safe_misclassified"),
                )
                for label_text, value, key_suffix in category_items:
                    _menu_button(
                        label_text,
                        f"inbox_filter_item_security_{key_suffix}",
                        "spam_category_filter",
                        value,
                    )
            else:
                st.markdown(
                    '<div class="inbox-filter-menu-title">FILTER</div>'
                    '<div class="inbox-filter-menu-spacer"></div>',
                    unsafe_allow_html=True,
                )
                unread_active, attachment_active = _inbox_filter_flags()
                _menu_button(
                    "All Mail",
                    "inbox_filter_item_all",
                    "inbox_filter",
                    "all",
                    active=not unread_active and not attachment_active,
                )
                _menu_button(
                    "Unread",
                    "inbox_filter_item_unread",
                    "inbox_filter",
                    "unread",
                    active=unread_active,
                )
                _menu_button(
                    "With Attachment",
                    "inbox_filter_item_with_attachment",
                    "inbox_filter",
                    "with_attachment",
                    active=attachment_active,
                )

                st.markdown(
                    '<div class="inbox-filter-menu-divider"></div>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    '<div class="inbox-filter-menu-title">ARRANGE BY</div>'
                    '<div class="inbox-filter-menu-spacer"></div>',
                    unsafe_allow_html=True,
                )
                _menu_button("Date", "inbox_filter_item_arrange_date", "inbox_arrange_by", "date")
                _menu_button("From", "inbox_filter_item_arrange_from", "inbox_arrange_by", "from")

                st.markdown(
                    '<div class="inbox-filter-menu-divider"></div>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    '<div class="inbox-filter-menu-title">SORT</div>'
                    '<div class="inbox-filter-menu-spacer"></div>',
                    unsafe_allow_html=True,
                )
                _menu_button(
                    "Newest First",
                    "inbox_filter_item_sort_newest",
                    "inbox_sort_order",
                    "newest",
                )
                _menu_button(
                    "Oldest First",
                    "inbox_filter_item_sort_oldest",
                    "inbox_sort_order",
                    "oldest",
                )


def _set_spam_category_metric(value: str) -> None:
    if not claim_foreground_interaction(
        "spam-dashboard-filter", debounce_seconds=UI_DEBOUNCE_FILTER_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("spam-dashboard-filter-detail", value=value)
    # Dashboard category clicks also rerun the whole workspace, so protect them
    # with the same one-render navigation guard as the Inbox filter popover.
    st.session_state.foreground_navigation_guard = True
    # Apply one Spam security-category filter and reload page 1 from SQLite.
    st.session_state.spam_category_filter = value
    st.session_state.pop("inbox_pending_page_direction", None)
    st.session_state.inbox_offset = 0
    st.session_state.inbox_search_offset = 0
    st.session_state.inbox_list_scroll_reset_pending = True
    st.session_state.inbox_loaded_view_signature = None
    st.session_state.selected_uid = None


def _render_spam_category_dashboard(category_counts: dict, loading: bool = False) -> None:
    counts = dict(category_counts or {})
    active = str(st.session_state.get("spam_category_filter") or "all").strip()
    with st.container(key="spam_category_dashboard"):
        st.markdown(
            '<div class="spam-category-dashboard-title">Security Categories</div>',
            unsafe_allow_html=True,
        )
        cells = st.columns(len(_SPAM_CATEGORY_METRICS), gap="small")
        for cell, (metric_key, label, value, icon) in zip(cells, _SPAM_CATEGORY_METRICS):
            count = int(counts.get(value, 0) or 0)
            selected = active.casefold() == value.casefold()
            visual_key = (
                f"spam_category_metric_{metric_key}_selected"
                if selected
                else f"spam_category_metric_{metric_key}_normal"
            )
            with cell:
                st.button(
                    f"**{count:,}**\n{label}",
                    key=visual_key,
                    type="secondary",
                    icon=icon,
                    use_container_width=True,
                    disabled=loading,
                    on_click=_set_spam_category_metric,
                    args=(value,),
                )


def _open_email_card(
    uid: str, spam_view: bool, is_security_unreviewed: bool, folder: str = "ALL_MAIL"
) -> None:
    uid = str(uid or "")
    if not uid:
        return
    if not claim_foreground_interaction(
        f"inbox-open:{uid}", debounce_seconds=UI_DEBOUNCE_FAST_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("inbox-card-open", spam_view=bool(spam_view), security_unreviewed=bool(is_security_unreviewed))

    previous_pin = str(st.session_state.get("spam_reviewed_pinned_uid") or "")
    previous_unread_pin = str(
        st.session_state.get("inbox_read_pinned_uid") or ""
    )
    st.session_state.selected_uid = uid

    if not spam_view and previous_unread_pin and previous_unread_pin != uid:
        st.session_state.inbox_read_pinned_uid = ""
        st.session_state.inbox_loaded_view_signature = None

    if not spam_view:
        # A threaded Inbox card represents the whole visible conversation. One
        # click therefore consumes every MailMind-unread member in that thread
        # in the same interaction (for example 2 unread -> 0), rather than
        # clearing only the representative UID and requiring repeated clicks.
        consumed_unread = _consume_thread_unread(folder, uid)
        if consumed_unread:
            # In the Unread view, keep the newly opened conversation pinned as
            # the current selection even though all of its unread membership was
            # consumed now. This is presentation-only; the sidebar count has
            # already dropped by len(consumed_unread).
            if (
                str(st.session_state.get("inbox_filter") or "all").casefold()
                in {"unread", "unread_with_attachment"}
            ):
                st.session_state.inbox_read_pinned_uid = uid
            st.session_state.inbox_loaded_view_signature = None

    if spam_view:
        if previous_pin and previous_pin != uid:
            st.session_state.spam_reviewed_pinned_uid = ""
        if bool(is_security_unreviewed):
            store = st.session_state.get("email_store")
            if store is not None:
                store.mark_security_reviewed(folder, uid)
            st.session_state.spam_reviewed_pinned_uid = uid
            st.session_state.inbox_loaded_view_signature = None


# Render the inbox toolbar and email list.
def render_inbox(emails, total: int = 0, offset: int = 0,
                  loading: bool = False, checked_uids=None,
                  search_active: bool = False, search_total: int = 0,
                  can_prev: bool = None, can_next: bool = None,
                  spam_view: bool = False, spam_category_counts=None,
                  show_spam_dashboard: bool = True, folder: str = "ALL_MAIL",
                  on_prev=None, on_next=None) -> dict:
    # Keep one stable bounded-list identity across pagination/filter reruns.
    # Destroying/recreating this large DOM subtree was a white-screen trigger
    # under rapid interactions. Client JS handles the one-shot scroll-to-top.
    scroll_reset_requested = bool(
        st.session_state.pop("inbox_list_scroll_reset_pending", False)
    )
    scroll_epoch = int(st.session_state.get("inbox_list_scroll_epoch", 0) or 0)
    scroll_key = f"inbox_list_scroll_{scroll_epoch}"

    if checked_uids is None:
        checked_uids = set()
    checked_uids = {str(uid) for uid in checked_uids}

    visible_uids_ordered = tuple(
        str(email_item.get("uid", ""))
        for email_item in emails
        if str(email_item.get("uid", ""))
    )
    visible_uids = set(visible_uids_ordered)
    select_page_key = _page_selection_key(
        visible_uids_ordered, search_active, offset
    )
    checked_uids = _reconcile_inbox_selection_without_callbacks(
        checked_uids, visible_uids_ordered, select_page_key
    )

    with st.container(key="inbox_toolbar"):
        with st.container(key="inbox_search_row"):
            col_query, col_filter = st.columns([0.78, 0.22], gap="small")
            with col_query:
                query = st.text_input(
                    "Search",
                    key="inbox_search_query",
                    placeholder="Search mail",
                    label_visibility="collapsed",
                    disabled=loading,
                )
                _process_inbox_search_value_without_callback(query)
            with col_filter:
                _render_filter_menu(loading=loading, spam_view=spam_view)

        submitted_by_input = st.session_state.pop("inbox_search_submit", False)
        cleared_by_input = st.session_state.pop("inbox_search_clear", False)

        refresh_clicked = False
        prev_clicked = False
        next_clicked = False

        display_total = search_total if search_active else total
        start = offset + 1 if display_total > 0 and emails else 0
        end = offset + len(emails)
        prev_allowed = can_prev if can_prev is not None else offset > 0
        next_allowed = (
            can_next
            if can_next is not None
            else offset + len(emails) < display_total
        )
        pagination_key = (
            "inbox_search_pagination_row"
            if search_active
            else "inbox_pagination_row"
        )

        # Keep the page-level Select all control in Inbox. The selected-email
        # count stays in the results row below so both controls remain clear.
        # No help tooltip is attached here because Streamlit renders it as an
        # extra circular icon beside the label.
        if not spam_view:
            with st.container(key="inbox_select_all_row"):
                with st.container(key="inbox_page_select_all"):
                    st.checkbox(
                        "Select all",
                        key=select_page_key,
                        disabled=(loading or not visible_uids_ordered),
                    )

        selected_count = len(checked_uids) if not spam_view else 0

        with st.container(key=pagination_key):
            col_range, col_refresh, col_prev, col_next = st.columns([0.64, 0.12, 0.12, 0.12], gap=None)
            with col_range:
                selected_suffix = ""
                if selected_count > 0:
                    noun = "email" if selected_count == 1 else "emails"
                    selected_suffix = (
                        f'<span class="inbox-selection-count">'
                        f'{selected_count} {noun} selected</span>'
                    )
                st.markdown(
                    f'<div class="item-meta inbox-range-label pagination-results-label">'
                    f'<span>Showing {start}–{end} of {display_total:,} emails</span>'
                    f'{selected_suffix}</div>',
                    unsafe_allow_html=True,
                )
            with col_refresh:
                # Queue Refresh in a callback so the next root render already
                # owns the foreground lane and paints the loader/disabled
                # controls *before* provider I/O begins.
                st.button(
                    "↻",
                    key="refresh_inbox_icon",
                    use_container_width=True,
                    disabled=loading,
                    on_click=_queue_inbox_refresh,
                )
            with col_prev:
                if callable(on_prev):
                    st.button(
                        "‹",
                        key="inbox_prev_page",
                        use_container_width=True,
                        disabled=(loading or not prev_allowed),
                        on_click=on_prev,
                    )
                else:
                    prev_clicked = st.button(
                        "‹",
                        key="inbox_prev_page",
                        use_container_width=True,
                        disabled=(loading or not prev_allowed),
                    )
            with col_next:
                if callable(on_next):
                    st.button(
                        "›",
                        key="inbox_next_page",
                        use_container_width=True,
                        disabled=(loading or not next_allowed),
                        on_click=on_next,
                    )
                else:
                    next_clicked = st.button(
                        "›",
                        key="inbox_next_page",
                        use_container_width=True,
                        disabled=(loading or not next_allowed),
                    )


    actions = {
        "refresh": refresh_clicked,
        "prev": prev_clicked,
        "next": next_clicked,
        "search": submitted_by_input,
        "clear_search": cleared_by_input,
        "query": query,
        "checked_uids": set(checked_uids),
    }

    if not emails:
        if spam_view:
            spam_filter = str(st.session_state.get("spam_category_filter") or "all").casefold()
            detected_only = bool(st.session_state.get("spam_detected_only", False))
            if detected_only and spam_filter != "all":
                empty_msg = "No detected emails match the selected security category."
            elif detected_only:
                empty_msg = "No detected security findings need review."
            elif spam_filter != "all":
                empty_msg = "No emails match the selected security category."
            else:
                empty_msg = "No emails are currently in the Spam workspace."
        else:
            empty_msg = (
                "No emails match the current search or filter."
                if search_active or st.session_state.get("inbox_filter") != "all"
                else "No emails are available in the local inbox yet."
            )
        with st.container(height=INBOX_LIST_HEIGHT, border=False, key=scroll_key):
            st.markdown(
                f'<div class="empty-state inbox-empty-state">{empty_msg}</div>',
                unsafe_allow_html=True,
            )
        if scroll_reset_requested:
            emit_scroll_reset_marker("inbox")
        return actions

    # Preserve choices from other inbox pages while the current page changes.
    new_checked = set(checked_uids) if spam_view else set(checked_uids) - visible_uids
    with st.container(height=INBOX_LIST_HEIGHT, border=False, key=scroll_key):
        for email_item in emails:
            uid = str(email_item.get("uid", ""))
            is_selected = st.session_state.get("selected_uid") == uid
            is_unread = uid in st.session_state.get("new_email_uids", set())
            is_security_unreviewed = bool(
                spam_view and int(email_item.get("security_reviewed", 1) or 0) == 0
            )

            if spam_view:
                col_row = st.container()
            else:
                col_check, col_row = st.columns([0.038, 0.962], gap="small")
                with col_check:
                    checkbox_key = f"chk_{uid}"
                    # Avoid Streamlit's "default value + Session State" warning.
                    # On the widget's first render, initialize it from the saved
                    # checked_uids set with ``value=``. On later reruns, omit
                    # ``value`` completely and let the widget's own Session State
                    # key remain authoritative. This preserves Select All,
                    # pagination, and Batch Summary selection without two sources
                    # trying to initialize the same widget in one render.
                    checkbox_args = dict(
                        label="Select",
                        key=checkbox_key,
                        disabled=loading,
                        label_visibility="collapsed",
                    )
                    if checkbox_key not in st.session_state:
                        checkbox_args["value"] = uid in checked_uids
                    checked = st.checkbox(**checkbox_args)
                    if checked:
                        new_checked.add(uid)

            sender_text = _display_sender(email_item.get("from", ""))
            avatar_initial, avatar_class = _sender_avatar(email_item.get("from", ""))
            subject = email_item.get("subject") or "(No Subject)"
            thread_count = max(1, int(email_item.get("thread_count") or 1))
            time_label = _inbox_time_label(email_item)
            selected_class = " is-selected" if is_selected else ""
            new_class = (
                " is-security-unreviewed" if is_security_unreviewed
                else (" is-unread" if (is_unread and not spam_view) else "")
            )

            with col_row:
                with st.container(key=f"inbox_card_{uid}"):
                    card_html = _mail_row_card_html(
                        selected_class=selected_class,
                        unread_class=new_class,
                        avatar_class=avatar_class,
                        avatar_initial=avatar_initial,
                        subject=subject,
                        sender=sender_text,
                        time_label=time_label,
                        thread_count=thread_count,
                        security_category=(
                            email_item.get("security_category", "") if spam_view else ""
                        ),
                        security_confidence=(
                            email_item.get("security_confidence", 0) if spam_view else 0
                        ),
                        has_attachment=(
                            bool(email_item.get("has_attachment")) and not spam_view
                        ),
                    )
                    st.markdown(
                        card_html,
                        unsafe_allow_html=True,
                    )
                    st.button(
                        "Open email",
                        key=f"email_{uid}",
                        use_container_width=True,
                        disabled=loading,
                        on_click=_open_email_card,
                        args=(uid, spam_view, is_security_unreviewed, folder),
                    )

        # Keep the final card above the scroll container edge.
        st.markdown(
            '<div class="inbox-list-bottom-spacer" aria-hidden="true"></div>',
            unsafe_allow_html=True,
        )

    actions["checked_uids"] = new_checked
    if scroll_reset_requested:
        emit_scroll_reset_marker("inbox")
    return actions
