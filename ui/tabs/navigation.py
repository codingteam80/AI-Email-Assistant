# Sidebar navigation for the MailMind AI workspaces.
import streamlit as st

from config import UI_DEBOUNCE_FAST_SECONDS, UI_FOREGROUND_SETTLE_SECONDS

# Native Streamlit can replay the same sidebar button callback more than once
# while the workspace tree is being replaced. Keep the normal fast global lane
# for switching to a different destination, but reject a replay of the exact
# same navigation action for a little longer than one browser rerender.
WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS = max(UI_DEBOUNCE_FAST_SECONDS, 0.75)

from ui.summary_metrics import todo_task_count
from services.todo_service import todo_active_deadline_count
from services.ui_interaction_service import (
    arm_foreground_interaction,
    claim_foreground_interaction,
)

INBOX_TAB = "inbox"
SPAM_TAB = "spam"
SUMMARY_TAB = "summary"
TODO_TAB = "todo"


def _arm_foreground_navigation_guard() -> None:
    # Every accepted sidebar navigation action owns the next workspace/view
    # handoff, including same-workspace shortcuts such as Unread, Detected,
    # Unviewed, Due Today, and Overdue. Dismiss the root-owned notification
    # flyout here so those shortcuts cannot carry an open panel into the newly
    # filtered view. Only non-widget notification flags are touched; the mounted
    # notification filter widget state remains unchanged.
    st.session_state.notification_center_open = False
    st.session_state.notification_center_expanded = False
    st.session_state.notification_center_root_reconcile = False
    st.session_state.pop("notification_center_workspace", None)

    # Sidebar workspace changes are foreground user navigation. Pause timed
    # mailbox/security/auto-summary maintenance for the stabilizing app rerun so
    # switching tabs cannot race a background rerun and flash a blank workspace.
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction()


def _clear_inbox_selection_state() -> None:
    # A workspace/view change always starts with no selected/open Inbox email and
    # no batch-selection checkboxes carried over from the previous view.
    st.session_state.selected_uid = None
    st.session_state.checked_uids = set()
    for key in list(st.session_state.keys()):
        if str(key).startswith(("chk_", "select_page_")):
            st.session_state.pop(key, None)
    for key in (
        "inbox_selection_page_key",
        "inbox_selection_visible_uids",
        "inbox_selection_processed_page_key",
        "inbox_selection_processed_page_value",
    ):
        st.session_state.pop(key, None)


def _reset_inbox_view(*, spam_view: bool = False) -> None:
    _clear_inbox_selection_state()
    st.session_state.inbox_search_query = ""
    st.session_state.inbox_search_submit = False
    st.session_state.inbox_search_clear = False
    st.session_state.search_active = False
    st.session_state.search_results = []
    st.session_state.search_total = 0
    st.session_state.pop("inbox_pending_page_direction", None)
    st.session_state.inbox_offset = 0
    st.session_state.inbox_search_offset = 0
    st.session_state.inbox_arrange_by = "date"
    st.session_state.inbox_sort_order = "newest"
    st.session_state.inbox_filter = "spam" if spam_view else "all"
    st.session_state.spam_category_filter = "all"
    st.session_state.spam_detected_only = False
    st.session_state.spam_reviewed_pinned_uid = ""
    st.session_state.inbox_read_pinned_uid = ""
    st.session_state.inbox_loaded_view_signature = None
    # The bounded email list should also start at its first visible item.
    st.session_state.inbox_list_scroll_reset_pending = True


def _reset_summary_view() -> None:
    st.session_state.selected_summary_uid = None
    st.session_state.summary_search_query = ""
    st.session_state.summary_filter = "all"
    st.session_state.summary_task_filter = None
    st.session_state.summary_unread_only = False
    st.session_state.summary_type_filter = None
    st.session_state.summary_status_filter = None
    st.session_state.summary_priority_filter = None
    st.session_state.summary_arrange_by = "activity"
    st.session_state.summary_sort_order = "newest"
    st.session_state.summary_sort_user_selected = False
    st.session_state.pop("summary_pending_page_direction", None)
    st.session_state.summary_offset = 0
    st.session_state.summary_list_scroll_reset_pending = True


def _reset_todo_view() -> None:
    # Entering To-Do from another workspace already mounts a fresh task-list
    # surface at page 1, so scheduling the browser scroll-reset helper during
    # that cross-workspace DOM swap is redundant. Keep the helper only for
    # resets that happen while To-Do is already mounted (same-tab shortcuts,
    # filters/pagination), where preserving the old scrollTop is possible.
    todo_already_mounted = st.session_state.get("active_workspace") == TODO_TAB

    _clear_todo_status_confirmation_state()
    st.session_state.pop("todo_dialog_uid", None)
    st.session_state.todo_search_query = ""
    st.session_state.todo_status_filter = None
    st.session_state.todo_priority_filter = None
    st.session_state.todo_deadline_filter = None
    st.session_state.todo_action_needed_only = False
    st.session_state.todo_sort_by = "latest_activity"
    st.session_state.todo_sort_user_selected = False
    st.session_state.pop("todo_pending_page_direction", None)
    st.session_state.todo_offset = 0
    if todo_already_mounted:
        st.session_state.todo_list_scroll_reset_pending = True
    else:
        st.session_state.pop("todo_list_scroll_reset_pending", None)


def _render_nav_item(
    key: str,
    icon: str,
    label: str,
    active: bool,
    count: int | None = None,
    *,
    on_click=None,
    args=(),
) -> None:
    # Render one native Streamlit workspace link with a total-count badge.
    with st.container(key=f"sidebar_nav_row_{key}"):
        st.button(
            f"{icon}  {label}",
            key=f"sidebar_nav_{key}",
            use_container_width=True,
            type="primary" if active else "tertiary",
            on_click=on_click,
            args=args,
        )
        if count is not None:
            st.markdown(
                f'<span class="sidebar-nav-count">{int(count):,}</span>',
                unsafe_allow_html=True,
            )



def _render_subitem_filter(
    workspace: str,
    label: str,
    count: int,
    active: bool,
    *,
    key_suffix: str | None = None,
    on_click=None,
    args=(),
) -> None:
    # Render one native borderless sidebar subitem with a count pill.
    #
    # The existing unread key namespace is retained internally so the proven
    # sidebar CSS remains isolated and stable; only the visible labels/behavior
    # differ by workspace.
    state = "active" if active else "idle"
    key_scope = f"{workspace}_{key_suffix}" if key_suffix else workspace
    with st.container(key=f"sidebar_unread_row_{key_scope}_{state}"):
        st.button(
            label,
            key=f"sidebar_unread_filter_{key_scope}",
            type="tertiary",
            use_container_width=True,
            on_click=on_click,
            args=args,
        )
        st.markdown(
            f'<span class="sidebar-unread-count">{int(count):,}</span>',
            unsafe_allow_html=True,
        )



def _show_inbox_all() -> None:
    if not claim_foreground_interaction("workspace-navigation:inbox", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_inbox_view(spam_view=False)
    st.session_state.active_workspace = INBOX_TAB


def _show_inbox_unread() -> None:
    if not claim_foreground_interaction("workspace-navigation:inbox-unread", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_inbox_view(spam_view=False)
    st.session_state.active_workspace = INBOX_TAB
    st.session_state.inbox_filter = "unread"
    st.session_state.inbox_loaded_view_signature = None


def _show_spam() -> None:
    if not claim_foreground_interaction("workspace-navigation:spam", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_inbox_view(spam_view=True)
    st.session_state.active_workspace = SPAM_TAB


def _show_spam_newly_detected() -> None:
    if not claim_foreground_interaction("workspace-navigation:spam-detected", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_inbox_view(spam_view=True)
    st.session_state.active_workspace = SPAM_TAB
    st.session_state.spam_detected_only = True
    st.session_state.inbox_loaded_view_signature = None


def _show_summary_all() -> None:
    if not claim_foreground_interaction("workspace-navigation:summary", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_summary_view()
    _clear_inbox_selection_state()
    st.session_state.active_workspace = SUMMARY_TAB


def _show_summary_unread() -> None:
    if not claim_foreground_interaction("workspace-navigation:summary-unviewed", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_summary_view()
    _clear_inbox_selection_state()
    st.session_state.active_workspace = SUMMARY_TAB
    st.session_state.summary_unread_only = True


def _clear_todo_status_confirmation_state() -> None:
    # Entering To-Do from sidebar navigation is not a status-change action.
    # Clear any stale confirmation request left by a previous rerun/session state
    # so Restore/Cancel/Reopen dialogs can only be opened by a fresh task action.
    for key in (
        "todo_status_confirmation_armed",
        "todo_pending_cancel_transition",
        "todo_pending_reopen_transition",
    ):
        st.session_state.pop(key, None)


def _show_todo_all() -> None:
    if not claim_foreground_interaction("workspace-navigation:todo", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    _arm_foreground_navigation_guard()
    _reset_todo_view()
    _clear_inbox_selection_state()
    st.session_state.selected_summary_uid = None
    st.session_state.active_workspace = TODO_TAB


def _show_todo_deadline(deadline_filter: str) -> None:
    if not claim_foreground_interaction(f"workspace-navigation:todo-{deadline_filter}", debounce_seconds=WORKSPACE_NAV_SAME_ACTION_DEBOUNCE_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS):
        return
    # Open one active-task deadline shortcut from a clean To-Do view. The
    # shortcut itself is the only filter retained after navigation.
    if deadline_filter not in {"due_today", "overdue"}:
        return
    _arm_foreground_navigation_guard()
    _reset_todo_view()
    _clear_inbox_selection_state()
    st.session_state.selected_summary_uid = None
    st.session_state.active_workspace = TODO_TAB
    st.session_state.todo_action_needed_only = True
    st.session_state.todo_deadline_filter = deadline_filter




def _render_summary_type_status() -> None:
    # Read-only mirror of the account-persistent Summary Settings. The sidebar
    # intentionally shows the two user-facing choices directly instead of
    # describing implementation-specific manual/auto combinations.
    auto_enabled = bool(st.session_state.get("auto_summary_enabled", False))
    generation_mode = "Automatic" if auto_enabled else "Manual"

    summary_type = str(
        st.session_state.get("auto_summary_type_choice") or "Individual"
    )
    if summary_type not in {"Individual", "Batch"}:
        summary_type = "Individual"

    st.markdown(
        '<div class="sidebar-summary-type-block">'
        '<div class="sidebar-summary-type-title">Summary Settings</div>'
        '<div class="sidebar-summary-type-row">'
        '<span class="sidebar-summary-type-dot is-manual"></span>'
        f'<span>Mode: {generation_mode}</span>'
        '</div>'
        '<div class="sidebar-summary-type-row">'
        '<span class="sidebar-summary-type-dot is-manual"></span>'
        f'<span>Type: {summary_type}</span>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

def render_sidebar_navigation() -> str:
    # Render workspace links and their compact Unread subfilters.
    active = st.session_state.get("active_workspace", INBOX_TAB)
    emails = st.session_state.get("emails", [])
    unread_uids = {
        str(uid) for uid in st.session_state.get("new_email_uids", set()) if str(uid)
    }

    # Keep the Inbox total independent from the active Inbox filter.
    # `inbox_total` is the current view total, so it becomes the unread count
    # when the Unread subfilter is active. `inbox_all_total` is maintained by
    # the inbox controller from the full mailbox/remote count instead.
    store = st.session_state.get("email_store")
    inbox_count = store.get_count("ALL_MAIL") if store is not None else int(
        st.session_state.get("inbox_all_total", st.session_state.get("inbox_total", len(emails))) or 0
    )
    summaries = st.session_state.get("summaries", [])
    summary_count = len(summaries)
    summary_unread_count = sum(
        not bool(item.get("is_read", False)) for item in summaries
    )
    task_count = todo_task_count(summaries)
    due_today_count = todo_active_deadline_count(summaries, "due_today")
    overdue_count = todo_active_deadline_count(summaries, "overdue")
    inbox_unread_count = len(store.exclude_spam_uids("ALL_MAIL", unread_uids)) if store is not None else len(unread_uids)
    spam_count = store.get_spam_count("ALL_MAIL") if store is not None else 0
    spam_newly_detected_count = (
        store.get_security_unreviewed_count("ALL_MAIL") if store is not None else 0
    )

    inbox_unread_active = (
        active == INBOX_TAB
        and str(st.session_state.get("inbox_filter") or "all").casefold()
        in {"unread", "unread_with_attachment"}
    )
    spam_newly_detected_active = (
        active == SPAM_TAB
        and bool(st.session_state.get("spam_detected_only", False))
    )
    summary_unread_active = (
        active == SUMMARY_TAB
        and bool(st.session_state.get("summary_unread_only", False))
    )
    todo_deadline_shortcut_active = (
        active == TODO_TAB
        and bool(st.session_state.get("todo_action_needed_only", False))
    )
    todo_due_today_active = (
        todo_deadline_shortcut_active
        and st.session_state.get("todo_deadline_filter") == "due_today"
    )
    todo_overdue_active = (
        todo_deadline_shortcut_active
        and st.session_state.get("todo_deadline_filter") == "overdue"
    )

    _render_nav_item(
        INBOX_TAB,
        "✉",
        "Inbox",
        active == INBOX_TAB,
        inbox_count,
        on_click=_show_inbox_all,
    )

    _render_subitem_filter(
        INBOX_TAB, "unread", inbox_unread_count, inbox_unread_active,
        on_click=_show_inbox_unread,
    )

    _render_nav_item(
        SPAM_TAB,
        "⚠",
        "Spam",
        active == SPAM_TAB,
        spam_count,
        on_click=_show_spam,
    )

    _render_subitem_filter(
        SPAM_TAB,
        "detected",
        spam_newly_detected_count,
        spam_newly_detected_active,
        on_click=_show_spam_newly_detected,
    )

    _render_nav_item(
        SUMMARY_TAB,
        "✨",
        "AI Summary",
        active == SUMMARY_TAB,
        summary_count,
        on_click=_show_summary_all,
    )

    _render_subitem_filter(
        SUMMARY_TAB, "unviewed", summary_unread_count, summary_unread_active,
        on_click=_show_summary_unread,
    )

    _render_nav_item(
        TODO_TAB,
        "☑",
        "Todo List",
        active == TODO_TAB,
        task_count,
        on_click=_show_todo_all,
    )

    _render_subitem_filter(
        TODO_TAB,
        "due today",
        due_today_count,
        todo_due_today_active,
        key_suffix="due_today",
        on_click=_show_todo_deadline,
        args=("due_today",),
    )

    _render_subitem_filter(
        TODO_TAB,
        "overdue",
        overdue_count,
        todo_overdue_active,
        key_suffix="overdue",
        on_click=_show_todo_deadline,
        args=("overdue",),
    )

    _render_summary_type_status()

    return st.session_state.get("active_workspace", active)
