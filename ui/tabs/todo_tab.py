# Functional To-Do workspace backed by AI-extracted summary action items.
from __future__ import annotations

import hashlib
import html
import re
import time as time_module
from datetime import date, datetime, time, timedelta
import streamlit as st

from config import (
    TODO_ACTION_SCROLL_HEIGHT_DEFAULT,
    TODO_ACTION_SCROLL_HEIGHT_WITH_DEADLINES,
    TODO_PAGE_SIZE,
    UI_DEBOUNCE_FAST_SECONDS,
    UI_DEBOUNCE_FILTER_SECONDS,
    UI_DEBOUNCE_PAGINATION_SECONDS,
    UI_DEBOUNCE_REFRESH_SECONDS,
    UI_DEBOUNCE_TODO_STATUS_SECONDS,
    UI_FOREGROUND_SETTLE_SECONDS,
)

from storage.summary_store import SUMMARY_FOLDER
from ui.summary_metrics import is_task_ready
from ui.original_window import _render_original_email_content, is_original_email_deleted
from ui.scripts import emit_scroll_reset_marker
from ui.notification_center import record_notification, claim_notification_marker
from services.task_status import (
    CLOSED_TASK_STATUSES,
    TASK_STATUSES,
    normalize_task_status,
    task_status_slug,
)
from services.ui_interaction_service import (
    arm_foreground_interaction,
    claim_foreground_interaction,
    workspace_callback_allowed,
    workspace_interaction_allowed,
)
from services.white_stale_trace_service import trace_action
from ui.draft_state import invalidate_reply_draft
from services.todo_service import (
    _PRIORITY_RANK,
    ACTIVE_TASK_STATUSES,
    ACTION_NEEDED_STATUSES,
    _EMPTY_ITEM_MARKERS,
    _DEADLINE_MATCH_STOPWORDS,
    _clean_list,
    _status,
    _priority,
    _normalize_task_record,
    _task_records,
    _search_text,
    _parse_clock,
    _email_reference_date,
    _parse_deadline_text,
    _deadline_candidates,
    _deadline_match_tokens,
    _action_item_rows,
    _action_deadline_entries,
    _deadline_entries,
    _valid_extracted_deadline,
    _invalid_extracted_deadline_note,
    _estimated_deadline,
    _resolved_deadline,
    _parse_deadline,
    _is_action_needed,
    _format_deadline,
    _due_label,
    _due_source,
    _due_state_class,
    _email_reference_datetime,
    _format_created_datetime,
    _deadline_matches_filter,
    _deadline_sort_number,
    _task_latest_activity_key,
    _task_oldest_activity_key,
    _task_newest_created_key,
    _task_oldest_created_key,
    _task_activity_label,
    _due_soonest_key,
    _due_latest_key,
    _persist_status,
    _append_task_change_history,
    _persist_action_item_completion,
    _persist_all_action_items_completion,
    _auto_status_for_action_progress,
    _requires_cancel_confirmation,
    _requires_reopen_confirmation,
    _reopen_deadline_preview,
    _metric_counts,
)


_FOLDER = SUMMARY_FOLDER


def _safe_key(value) -> str:
    return hashlib.sha1(str(value or "").encode("utf-8")).hexdigest()[:14]


def _status_badge_html(status: str) -> str:
    status_class = _status_css_class(status)
    # Keep the list badge wrapper-free. Older table CSS used .todo-status-cell
    # as a layout hook and could accidentally turn the current 5-column
    # Streamlit row into a 4-column CSS grid. The row now owns alignment via
    # native st.columns() + .todo-current-badge-cell only.
    return f'<span class="todo-status-badge {status_class}">{html.escape(status)}</span>'

def _sender_name(task: dict) -> str:
    return str(task.get("from") or "Unknown sender").strip()


def _sender_parts(task: dict) -> tuple[str, str]:
    raw = _sender_name(task)
    match = re.match(r"^\s*(.*?)\s*<([^<>]+)>\s*$", raw)
    if match:
        display_name = match.group(1).strip().strip('\"') or match.group(2).strip()
        return display_name, match.group(2).strip()
    if "@" in raw and " " not in raw:
        return raw.split("@", 1)[0], raw
    return raw, ""


def _sender_initials(task: dict) -> str:
    sender = _sender_name(task)
    parts = [
        part
        for part in sender.replace("<", " ").replace(">", " ").split()
        if part and "@" not in part
    ]
    if not parts and sender:
        parts = [sender]
    initials = "".join(part[0] for part in parts[:2]).upper()
    return initials or "?"


def _sender_hue(task: dict) -> str:
    palette = ["teal", "purple", "blue", "green", "indigo"]
    return palette[hash(_sender_name(task)) % len(palette)]


def _ensure_todo_filter_state() -> None:
    # Initialize the independent To-Do filter and sorting state.
    status = st.session_state.get("todo_status_filter")
    st.session_state.todo_status_filter = (
        status if status in TASK_STATUSES else None
    )

    priority = st.session_state.get("todo_priority_filter")
    st.session_state.todo_priority_filter = (
        priority if priority in {"Critical", "High", "Medium", "Low"} else None
    )

    deadline = st.session_state.get("todo_deadline_filter")
    st.session_state.todo_deadline_filter = (
        deadline
        if deadline in {"due_today", "this_week", "this_month", "overdue"}
        else None
    )

    # Activity filtering was removed. Clear any stale value left in a hot
    # Streamlit session so an old hidden filter can never keep tasks out of view.
    st.session_state.pop("todo_activity_filter", None)

    sort_by = str(st.session_state.get("todo_sort_by") or "").strip().casefold()
    valid_sorts = {
        "latest_activity",
        "oldest_activity",
        "created_newest",
        "created_oldest",
        "due_soonest",
        "due_latest",
        "priority_high_low",
        "priority_low_high",
    }
    # Latest Activity is the new default. A hot Streamlit session can still carry
    # the old Due Soonest/legacy default after patching, so migrate that state
    # once. After the user explicitly chooses a Sort option, preserve it.
    policy_version = int(st.session_state.get("todo_activity_sort_policy_version") or 0)
    user_selected_sort = bool(st.session_state.get("todo_sort_user_selected", False))
    if policy_version < 3 and not user_selected_sort:
        sort_by = "latest_activity"
    st.session_state.todo_sort_by = (
        sort_by if sort_by in valid_sorts else "latest_activity"
    )
    st.session_state.todo_activity_sort_policy_version = 3


def _arm_foreground_navigation_guard() -> None:
    # Any To-Do interaction that causes a full-app rerun must pause mailbox,
    # Security catch-up, and Auto Summary maintenance for the stabilizing run.
    # app.py already consumes this one-shot flag at the end of that render.
    # Without it, a timed background rerun can overlap a dashboard/filter/status
    # click and briefly unmount the Streamlit workspace as a blank white frame.
    st.session_state.foreground_navigation_guard = True
    arm_foreground_interaction()


def _active_todo_filter_count() -> int:
    return sum(
        bool(st.session_state.get(key))
        for key in (
            "todo_status_filter",
            "todo_priority_filter",
            "todo_deadline_filter",
        )
    )


def _finish_todo_filter_change() -> None:
    _arm_foreground_navigation_guard()
    st.session_state.pop("todo_pending_page_direction", None)
    st.session_state.todo_offset = 0
    st.session_state.todo_list_scroll_reset_pending = True


def _reset_todo_filters() -> None:
    # Clear sidebar/menu task filters while preserving Sort.
    st.session_state.todo_status_filter = None
    st.session_state.todo_priority_filter = None
    st.session_state.todo_deadline_filter = None
    st.session_state.todo_action_needed_only = False
    _finish_todo_filter_change()


def _set_todo_menu_value(state_key: str, value) -> None:
    if not claim_foreground_interaction(
        "todo-filter", debounce_seconds=UI_DEBOUNCE_FILTER_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("todo-filter-detail", state_key=state_key, value=value)
    if state_key == "todo_reset_filters":
        _reset_todo_filters()
        return

    if state_key == "todo_sort_by":
        # Sort always keeps exactly one selected option. Once the user chooses
        # one, do not override it with the default activity policy on reruns.
        st.session_state.todo_sort_by = value
        st.session_state.todo_sort_user_selected = True
    else:
        # Status, Priority, and Deadline each allow at most one selection.
        current_value = st.session_state.get(state_key)
        st.session_state[state_key] = None if current_value == value else value
    _finish_todo_filter_change()


def _todo_menu_button(
    label: str,
    key: str,
    state_key: str,
    value,
    *,
    active: bool | None = None,
) -> None:
    if active is None:
        active = st.session_state.get(state_key) == value
    visual_key = f"{key}_selected" if active else f"{key}_normal"
    st.button(
        label,
        key=visual_key,
        type="secondary",
        use_container_width=True,
        on_click=_set_todo_menu_value,
        args=(state_key, value),
    )


def _todo_menu_section(title: str) -> None:
    st.markdown(
        f'<div class="todo-filter-section-heading">{title}</div>',
        unsafe_allow_html=True,
    )


def _render_todo_filter_menu() -> None:
    _ensure_todo_filter_state()
    filter_count = _active_todo_filter_count()
    with st.container(key="todo_filter_popover"):
        label = f"Filter ({filter_count})" if filter_count else "Filter"
        with st.popover(
            label,
            key="todo_filter_menu",
            icon=":material/filter_alt:",
            use_container_width=True,
        ):
            st.markdown(
                '<div class="todo-filter-menu-marker" aria-hidden="true"></div>'
                '<div class="todo-filter-section-heading is-first">FILTER</div>',
                unsafe_allow_html=True,
            )
            _todo_menu_button(
                "All Tasks",
                "todo_filter_item_all",
                "todo_reset_filters",
                "all",
                active=filter_count == 0,
            )

            _todo_menu_section("STATUS")
            for value in TASK_STATUSES:
                _todo_menu_button(
                    value,
                    f"todo_filter_item_status_{value.casefold().replace(' ', '_')}",
                    "todo_status_filter",
                    value,
                )

            _todo_menu_section("PRIORITY")
            for value in ("Critical", "High", "Medium", "Low"):
                _todo_menu_button(
                    value,
                    f"todo_filter_item_priority_{value.casefold()}",
                    "todo_priority_filter",
                    value,
                )

            _todo_menu_section("DEADLINE")
            for value, label in (
                ("due_today", "Due Today"),
                ("this_week", "This Week"),
                ("this_month", "This Month"),
                ("overdue", "Overdue"),
            ):
                _todo_menu_button(
                    label,
                    f"todo_filter_item_deadline_{value}",
                    "todo_deadline_filter",
                    value,
                )

            _todo_menu_section("SORT")
            for value, label in (
                ("latest_activity", "Latest Activity"),
                ("oldest_activity", "Oldest Activity"),
                ("created_newest", "Newest Created"),
                ("created_oldest", "Oldest Created"),
                ("due_soonest", "Due Soonest"),
                ("due_latest", "Due Latest"),
                ("priority_high_low", "Priority: High to Low"),
                ("priority_low_high", "Priority: Low to High"),
            ):
                _todo_menu_button(
                    label,
                    f"todo_filter_item_sort_{value}",
                    "todo_sort_by",
                    value,
                )


def _apply_filters(tasks: list[dict]) -> list[dict]:
    # Filter first, then search only inside the filtered task set.
    _ensure_todo_filter_state()
    status_filter = st.session_state.get("todo_status_filter")
    priority_filter = st.session_state.get("todo_priority_filter")
    deadline_filter = st.session_state.get("todo_deadline_filter")
    query = str(st.session_state.get("todo_search_query", "") or "").strip().casefold()

    visible = list(tasks)
    if bool(st.session_state.get("todo_action_needed_only", False)):
        visible = [item for item in visible if _is_action_needed(item)]
    if status_filter:
        visible = [item for item in visible if item["status"] == status_filter]

    # Priority and Deadline filters represent active workload, matching the
    # dashboard counters. Closed tasks must not reappear just because they still
    # carry an old priority or deadline. If the user explicitly filters by the
    # Completed/Cancelled status first, preserve that intentional closed-task
    # view and allow the additional filter to narrow it.
    explicit_closed_status = status_filter in CLOSED_TASK_STATUSES
    if (priority_filter or deadline_filter) and not explicit_closed_status:
        visible = [
            item for item in visible
            if _status(item.get("status")) in ACTIVE_TASK_STATUSES
        ]

    if priority_filter:
        visible = [item for item in visible if item["priority"] == priority_filter]
    if deadline_filter:
        visible = [
            item for item in visible
            if _deadline_matches_filter(item, deadline_filter)
        ]
    if query:
        visible = [item for item in visible if query in _search_text(item)]

    sort_by = st.session_state.get("todo_sort_by", "latest_activity")
    if sort_by == "oldest_activity":
        visible.sort(key=_task_oldest_activity_key)
    elif sort_by == "created_newest":
        visible.sort(key=_task_newest_created_key)
    elif sort_by == "created_oldest":
        visible.sort(key=_task_oldest_created_key)
    elif sort_by == "due_soonest":
        visible.sort(key=_due_soonest_key)
    elif sort_by == "due_latest":
        visible.sort(key=_due_latest_key)
    elif sort_by == "priority_high_low":
        visible.sort(
            key=lambda item: (
                _PRIORITY_RANK[item["priority"]],
                *_due_soonest_key(item)[:2],
            )
        )
    elif sort_by == "priority_low_high":
        visible.sort(
            key=lambda item: (
                -_PRIORITY_RANK[item["priority"]],
                *_due_soonest_key(item)[:2],
            )
        )
    else:
        visible.sort(key=_task_latest_activity_key)
    return visible


def _reload_summaries() -> None:
    store = st.session_state.get("summary_store")
    if store is not None:
        st.session_state.summaries = store.load_all(_FOLDER)


def _display_task_title(task: dict) -> str:
    # Return the persisted LLM title, falling back to the existing task text.
    saved = str(task.get("task_title") or "").strip()
    if saved:
        return saved
    actions = task.get("action_items") or []
    return str(actions[0] if actions else task.get("subject") or "Untitled task").strip()


def _task_notification_details(task: dict | None, extra=None) -> list[str]:
    details = []
    if isinstance(task, dict):
        details.append(f"Task: {_display_task_title(task)}")
        subject = str(task.get("subject") or "").strip()
        if subject and subject != _display_task_title(task):
            details.append(f"Email: {subject}")
    details.extend(
        str(value or "").strip()
        for value in (extra or [])
        if str(value or "").strip()
    )
    return details


def _push_todo_toast(
    message: str,
    kind: str = "info",
    *,
    task: dict | None = None,
    details=None,
    title: str | None = None,
    event_type: str = "task-update",
    notify_bell: bool = False,
) -> None:
    # Show immediate To-Do feedback. Bell persistence is opt-in for background alerts.
    # A browser can occasionally deliver the same button event twice while an overlay
    # is closing. Suppress only the *same* task/event/message inside a very short
    # window so one real status change can never create two identical toasts.
    clean_message = str(message or "").strip()
    normalized_kind = str(kind or "info").strip().casefold()
    clean_title = str(title or "").strip()
    entity_uid = str((task or {}).get("uid") or "")
    toast_signature = _safe_key(
        f"{event_type}|{entity_uid}|{normalized_kind}|{clean_title}|{clean_message}"
    )
    now = time_module.monotonic()
    last_signature = str(st.session_state.get("todo_last_toast_signature") or "")
    try:
        last_at = float(st.session_state.get("todo_last_toast_monotonic", 0.0) or 0.0)
    except (TypeError, ValueError):
        last_at = 0.0
    if toast_signature == last_signature and now - last_at < 1.0:
        trace_action(
            "todo-toast-duplicate-suppressed",
            event_type=event_type,
            entity_id=entity_uid,
        )
        return

    st.session_state.todo_last_toast_signature = toast_signature
    st.session_state.todo_last_toast_monotonic = now
    toast_id = _safe_key(
        f"{clean_message}-{datetime.now().isoformat(timespec='microseconds')}"
    )
    queue = list(st.session_state.get("todo_toasts", []))
    queue.append(
        {
            "id": toast_id,
            "message": clean_message,
            "kind": normalized_kind,
            "title": clean_title,
        }
    )
    st.session_state.todo_toasts = queue[-5:]
    if notify_bell:
        record_notification(
            title=title or _todo_toast_title(clean_message, normalized_kind),
            message=clean_message,
            kind=normalized_kind,
            workspace="todo",
            details=_task_notification_details(task, details),
            event_type=event_type,
            entity_id=entity_uid,
        )


def _dismiss_todo_toast(toast_id: str) -> None:
    st.session_state.todo_toasts = [
        item
        for item in st.session_state.get("todo_toasts", [])
        if str(item.get("id")) != str(toast_id)
    ]


def _todo_toast_title(message: str, kind: str) -> str:
    # Return the short professional heading shown above toast detail.
    normalized = str(message or "").strip().casefold()
    if normalized == "task cancelled.":
        return "Task cancelled"
    if normalized.startswith("task moved to"):
        return "Status updated"
    if kind == "complete":
        return "Task completed"
    if kind == "due":
        return "Deadline updated"
    if kind == "update":
        return "Task updated"
    if kind == "error":
        return "Update failed"
    return "Task notification"


def _render_todo_toasts() -> None:
    # Render the newest To-Do notification with Streamlit's native toast.
    #
    # ``st.toast`` lives in Streamlit's overlay layer, so showing or dismissing a
    # notification cannot resize, push, or reflow the To-Do table and surrounding
    # containers. Only the newest queued notification is displayed.
    toasts = list(st.session_state.get("todo_toasts", []))
    if not toasts:
        return

    # Consume first so unrelated reruns never replay an old notification. If two
    # legitimate task events land before this root render, keep the UI quiet and
    # show only the newest one (the function contract above already promises that).
    st.session_state.todo_toasts = []
    toast = toasts[-1]
    raw_message = str(toast.get("message") or "").strip()
    kind = str(toast.get("kind") or "info").strip().casefold()
    title = str(toast.get("title") or "").strip() or _todo_toast_title(raw_message, kind)
    if not raw_message:
        return

    normalized = raw_message.casefold()
    if normalized == "task cancelled.":
        icon = ":material/cancel:"
    elif kind == "error":
        icon = ":material/error:"
    elif kind == "due":
        icon = ":material/event:"
    elif kind in {"progress", "complete", "update"} or normalized.startswith("task moved to"):
        icon = ":material/check_circle:"
    else:
        icon = ":material/info:"

    st.toast(
        f"**{title}**  \n{raw_message}",
        icon=icon,
        duration="short",
    )


def render_todo_toasts() -> None:
    # Global root renderer so background deadline alerts show on any workspace.
    _render_todo_toasts()


def _action_checkbox_key(key_id: str, index: int) -> str:
    return f"todo_dialog_action_done_{key_id}_{index}"


def _action_widget_snapshot_key(key_id: str) -> str:
    return f"todo_dialog_action_snapshot_{key_id}"


def _action_widget_snapshot(task: dict) -> list[dict]:
    # Stable identity/content snapshot used to distinguish a real email-driven
    # action update from ordinary Streamlit reruns while Task Actions stays open.
    return [
        {
            "action_id": str(row.get("action_id") or ""),
            "action": " ".join(str(row.get("action") or "").casefold().split()).rstrip("."),
            "completed": bool(row.get("completed")),
            "cancelled": bool(row.get("cancelled")),
        }
        for row in _action_item_rows(task)
    ]


def _sync_changed_action_widgets(task: dict, key_id: str) -> None:
    # A thread summary can update while this dialog is already open. Streamlit
    # otherwise keeps the old checkbox session_state by numeric index, which can
    # leave a newly updated action visually struck through/completed.
    #
    # Sync only changed/new action identities. Unchanged action widgets keep the
    # user's current draft value, so unrelated completed progress is preserved.
    marker_key = _action_widget_snapshot_key(key_id)
    current = _action_widget_snapshot(task)
    previous = st.session_state.get(marker_key)
    if not isinstance(previous, list):
        st.session_state[marker_key] = current
        return
    if previous == current:
        return

    previous_by_id = {
        str(item.get("action_id") or ""): item
        for item in previous
        if isinstance(item, dict) and str(item.get("action_id") or "")
    }
    previous_index_by_id = {
        str(item.get("action_id") or ""): index
        for index, item in enumerate(previous)
        if isinstance(item, dict) and str(item.get("action_id") or "")
    }
    current_ids = {
        str(item.get("action_id") or "")
        for item in current
        if str(item.get("action_id") or "")
    }

    for index, item in enumerate(current):
        action_id = str(item.get("action_id") or "")
        old = previous_by_id.get(action_id) if action_id else None
        changed_persisted_action = (
            old is None
            or str(old.get("action") or "") != str(item.get("action") or "")
            or bool(old.get("completed")) != bool(item.get("completed"))
            or bool(old.get("cancelled")) != bool(item.get("cancelled"))
            or (action_id and previous_index_by_id.get(action_id) != index)
        )
        if changed_persisted_action:
            st.session_state[_action_checkbox_key(key_id, index)] = bool(item.get("completed"))

    # Remove stale trailing widget keys when an action was archived/removed so a
    # later shorter/longer list cannot inherit an old index value.
    if len(previous) > len(current) or any(
        str(item.get("action_id") or "") and str(item.get("action_id") or "") not in current_ids
        for item in previous if isinstance(item, dict)
    ):
        for index in range(len(current), len(previous)):
            st.session_state.pop(_action_checkbox_key(key_id, index), None)

    st.session_state[marker_key] = current


def _action_completion_states(task: dict, key_id: str) -> list[bool]:
    rows = _action_item_rows(task)
    states = []
    for index, row in enumerate(rows):
        checkbox_key = _action_checkbox_key(key_id, index)
        if checkbox_key not in st.session_state:
            st.session_state[checkbox_key] = bool(row.get("completed"))
        states.append(bool(st.session_state.get(checkbox_key)))
    return states


def _on_action_item_toggle(task: dict, key_id: str, action_index: int, status_key: str) -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("todo"):
        trace_action("workspace-callback-ignored", source="todo", callback="_on_action_item_toggle")
        return
    trace_action("todo-action-item-toggle", action_index=int(action_index))
    # Any new checkbox interaction invalidates a prior completion-block warning.
    # The warning is recomputed on Update from the current draft values.
    st.session_state.pop("todo_update_blocked_incomplete_uid", None)
    # Update only dialog drafts; persistence happens when Update is clicked.
    states = _action_completion_states(task, key_id)
    rows = _action_item_rows(task)
    active_states = [
        state for index, state in enumerate(states)
        if index < len(rows) and not bool(rows[index].get("cancelled"))
    ]
    base_status = _status(st.session_state.get(status_key) or task.get("status"))
    st.session_state[status_key] = _auto_status_for_action_progress(base_status, active_states)


def _render_action_items_panel(task: dict, key_id: str, status_key: str) -> None:
    rows = _action_item_rows(task)
    if not rows:
        return

    states = _action_completion_states(task, key_id)
    completed_count = sum(
        1 for index, state in enumerate(states)
        if state and not bool(rows[index].get("cancelled"))
    )
    total_count = sum(1 for row in rows if not bool(row.get("cancelled")))

    # Paused work is intentionally read-only at the action-item level.  Keep the
    # user's persisted completion progress frozen while the draft Status is On
    # Hold; changing the Status picker to an active state remounts this fragment
    # and immediately re-enables the checkboxes.  Cancelled remains locked too.
    action_items_locked = (
        _status(st.session_state.get(status_key) or task.get("status"))
        in {"Cancelled", "On Hold"}
    )

    action_deadline_values = {
        row.get("parsed_due").isoformat()
        for row in rows
        if row.get("parsed_due", datetime.max) != datetime.max
    }
    action_deadline_count = len(action_deadline_values)
    # Multiple action rows that inherit the exact same task/thread deadline are
    # one effective deadline. Only genuinely different date/times get the
    # per-action deadline columns and the multi-deadline UI.
    multiple_action_deadlines = action_deadline_count > 1
    no_task_deadline = (
        action_deadline_count == 0
        and _resolved_deadline(task)[0] == datetime.max
    )

    # The modal itself remains fixed. Action Items is the only primary scroll
    # region, with a little more room when per-action deadline metadata is shown.
    action_scroll_height = (
        TODO_ACTION_SCROLL_HEIGHT_WITH_DEADLINES
        if multiple_action_deadlines
        else TODO_ACTION_SCROLL_HEIGHT_DEFAULT
    )

    with st.container(key=f"todo_action_items_panel_{key_id}"):
        st.markdown(
            '<div class="todo-action-items-heading">'
            '<div class="todo-modal-label todo-modal-actions-label">Action items</div>'
            f'<div class="todo-action-items-counter">{completed_count}/{total_count} completed</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        with st.container(height=action_scroll_height, border=False, key=f"todo_action_items_scroll_{key_id}"):
            for index, row in enumerate(rows):
                checkbox_key = _action_checkbox_key(key_id, index)
                completed = bool(st.session_state.get(checkbox_key))
                cancelled = bool(row.get("cancelled"))
                row_class = " is-cancelled" if cancelled else (" is-completed" if completed else "")
                action = html.escape(str(row.get("action") or ""))
                action_due = row.get("parsed_due", datetime.max)

                with st.container(key=f"todo_action_item_row_{key_id}_{index}"):
                    if multiple_action_deadlines:
                        number_col, copy_col, deadline_col, check_col = st.columns(
                            [0.07, 0.49, 0.36, 0.08], gap="small", vertical_alignment="center"
                        )
                    elif no_task_deadline:
                        number_col, copy_col, empty_due_col, check_col = st.columns(
                            [0.07, 0.76, 0.09, 0.08], gap="small", vertical_alignment="center"
                        )
                    else:
                        number_col, copy_col, check_col = st.columns(
                            [0.07, 0.85, 0.08], gap="small", vertical_alignment="center"
                        )

                    with number_col:
                        st.markdown(
                            f'<div class="todo-action-item-number{row_class}">{index + 1}</div>',
                            unsafe_allow_html=True,
                        )

                    with copy_col:
                        cancelled_label = (
                            '<div class="todo-action-item-cancelled-label">Cancelled</div>'
                            if cancelled else ""
                        )
                        st.markdown(
                            f'<div class="todo-action-item-copy{row_class}">'
                            f'<p>{action}</p>{cancelled_label}</div>',
                            unsafe_allow_html=True,
                        )

                    if multiple_action_deadlines:
                        with deadline_col:
                            if action_due != datetime.max:
                                entry = {
                                    "parsed": action_due,
                                    "completed": completed,
                                    "cancelled": cancelled,
                                }
                                state_class, state_label = _deadline_state(entry)
                                if cancelled:
                                    state_class, state_label = "completed", "Cancelled"
                                st.markdown(
                                    '<div class="todo-action-item-deadline-inline">'
                                    f'<div class="todo-action-item-deadline-date"><span>▣</span>{html.escape(_format_deadline(action_due, str(row.get("due_date") or "")))}</div>'
                                    f'<span class="todo-action-item-deadline-state is-{state_class}">{html.escape(state_label)}</span>'
                                    '</div>',
                                    unsafe_allow_html=True,
                                )
                            else:
                                st.markdown(
                                    '<div class="todo-action-item-deadline-empty is-deadline-column">—</div>',
                                    unsafe_allow_html=True,
                                )
                    elif no_task_deadline:
                        with empty_due_col:
                            st.markdown(
                                '<div class="todo-action-item-deadline-empty">—</div>',
                                unsafe_allow_html=True,
                            )

                    with check_col:
                        st.checkbox(
                            f"Complete action item {index + 1}",
                            key=checkbox_key,
                            label_visibility="collapsed",
                            disabled=action_items_locked or cancelled,
                            on_change=_on_action_item_toggle,
                            args=(task, key_id, index, status_key),
                        )

        if multiple_action_deadlines:
            st.markdown(
                '<div class="todo-action-items-deadline-note">ⓘ Deadlines are shown with their related action items.</div>',
                unsafe_allow_html=True,
            )
        elif no_task_deadline:
            st.markdown(
                '<div class="todo-action-items-deadline-note">ⓘ No deadlines are set for the action items.</div>',
                unsafe_allow_html=True,
            )


def _manual_action_history_changes(rows: list[dict], before: list[bool], after: list[bool]) -> list[dict]:
    changes = []
    for index, row in enumerate(rows):
        if bool(row.get("cancelled")) or index >= len(before) or index >= len(after):
            continue
        old_value = bool(before[index])
        new_value = bool(after[index])
        if old_value == new_value:
            continue
        changes.append({
            "type": "action_completed" if new_value else "action_reopened",
            "action_id": str(row.get("action_id") or ""),
            "action": str(row.get("action") or "").strip(),
        })
    return changes


def _history_change_copy(change: dict) -> tuple[str, str]:
    kind = str(change.get("type") or "").strip().casefold()
    action = str(change.get("action") or "").strip()
    old_value = str(change.get("from") or "").strip()
    new_value = str(change.get("to") or "").strip()
    if kind == "status_changed":
        return "Status changed", f"{old_value or '—'} → {new_value or '—'}"
    if kind == "priority_changed":
        return "Priority changed", f"{old_value or '—'} → {new_value or '—'}"
    if kind == "deadline_changed":
        detail = f"{old_value or 'No deadline'} → {new_value or 'No deadline'}"
        return "Deadline updated", f"{detail}{f' · {action}' if action else ''}"
    if kind in {"deadline_removed", "task_deadline_removed"}:
        return "Deadline removed", action or old_value or "Explicit deadline removed"
    if kind == "action_completed":
        return "Action item completed", action or "Action item"
    if kind == "action_reopened":
        return "Action item reopened", action or "Action item"
    if kind == "action_added":
        return "Action item added", action or "New action item"
    if kind == "action_cancelled":
        return "Action item cancelled", action or "Action item"
    if kind == "action_reworded":
        return "Action item updated", f"{old_value} → {new_value}".strip(" →")
    if kind == "action_archived":
        return "Action item archived", action or "Action item"
    if kind == "title_changed":
        return "Task title updated", f"{old_value} → {new_value}".strip(" →")
    return "Task updated", action or new_value or old_value or "Task details changed"


def _history_source_label(entry: dict) -> str:
    # Keep ordinary/manual task history visually quiet. Only email-driven
    # synchronization needs provenance because the user did not perform that
    # change directly in To-Do. Use a complete explanatory sentence rather
    # than a badge-like source label.
    source = str(entry.get("source") or "").strip().casefold()
    if source in {"email_reply", "email_update", "thread_reply"}:
        return "This change was applied automatically based on a new email reply."
    if source == "user":
        return ""
    if str(entry.get("source_uid") or "").strip() or str(entry.get("message_id") or "").strip():
        # Backward-compatible attribution for reply history written before the
        # explicit source field was introduced.
        return "This change was applied automatically based on a new email reply."
    return ""

def _history_time_label(entry: dict) -> str:
    display = str(entry.get("date_display") or "").strip()
    if display:
        return display
    raw = str(entry.get("date") or "").strip()
    if not raw:
        return "Recently"
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
        return parsed.strftime("%b %d, %Y at %I:%M %p").replace(" 0", " ")
    except ValueError:
        return raw


def _is_task_history_entry(entry: dict) -> bool:
    # Keep both manual and reply-driven task changes in the To-Do audit trail.
    # Creation itself is intentionally not a history row; this view records
    # meaningful changes AFTER the task was created.
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("changes"), list)
        and any(isinstance(change, dict) for change in (entry.get("changes") or []))
    )

def _task_history_rows(task: dict) -> list[dict]:
    history = [
        entry for entry in (task.get("task_change_history") or [])
        if _is_task_history_entry(entry)
    ]

    rows: list[dict] = []
    for entry in reversed(history[-20:]):
        source = _history_source_label(entry)
        time_label = _history_time_label(entry)
        for change in reversed(entry.get("changes") or []):
            if not isinstance(change, dict):
                continue
            # Status is manual-only now. Suppress legacy automatic status rows
            # written by older email-thread logic, while keeping user-made
            # status changes visible in the audit trail.
            if (
                str(change.get("type") or "").strip().casefold() == "status_changed"
                and str(entry.get("source") or "").strip().casefold()
                in {"email_reply", "email_update", "thread_reply"}
            ):
                continue
            title, detail = _history_change_copy(change)
            rows.append({
                "title": title,
                "detail": detail,
                "time": time_label,
                "source": source,
            })
    return rows


def _render_task_history_rows(
    task: dict,
    key_id: str,
    *,
    key_prefix: str = "todo_history_dialog_list",
) -> None:
    rows = _task_history_rows(task)
    if not rows:
        st.markdown(
            '<div class="todo-history-empty">No task changes recorded yet.</div>',
            unsafe_allow_html=True,
        )
        return

    history_html = []
    for item in rows:
        source_html = (
            f'<div class="todo-history-source">{html.escape(item["source"])}</div>'
            if item["source"] else ""
        )
        history_html.append(
            '<div class="todo-history-row">'
            '<span class="todo-history-dot" aria-hidden="true"></span>'
            f'<div class="todo-history-time">{html.escape(item["time"])}</div>'
            '<div class="todo-history-copy">'
            f'<div class="todo-history-line"><strong>{html.escape(item["title"])}</strong>'
            f'<span>{html.escape(item["detail"])}</span></div>'
            f'{source_html}'
            '</div></div>'
        )

    with st.container(border=False, key=f"{key_prefix}_{key_id}"):
        st.markdown(
            '<div class="todo-history-scroll">' + ''.join(history_html) + '</div>',
            unsafe_allow_html=True,
        )


def publish_task_deadline_alerts() -> None:
    # Transition-based deadline events are background activity, so all three
    # stages are persistent Bell notifications only. Manual task edits still use
    # Toast feedback through _push_todo_toast().
    summaries = st.session_state.get("summaries", [])
    tasks = _task_records(summaries)
    today = date.today()
    tomorrow = today + timedelta(days=1)
    approaching = []
    due_today = []
    overdue = []
    for task in tasks:
        if _status(task.get("status")) not in ACTION_NEEDED_STATUSES:
            continue
        deadline = _parse_deadline(task)
        if deadline == datetime.max:
            continue
        uid = str(task.get("uid") or "").strip()
        if not uid:
            continue
        due_day = deadline.date()
        if due_day == tomorrow:
            marker = f"task-deadline:approaching:{uid}:{deadline.isoformat()}"
            if claim_notification_marker(marker):
                approaching.append(task)
        elif due_day == today:
            marker = f"task-deadline:due-today:{uid}:{deadline.isoformat()}"
            if claim_notification_marker(marker):
                due_today.append(task)
        elif due_day < today:
            marker = f"task-deadline:overdue:{uid}:{deadline.isoformat()}"
            if claim_notification_marker(marker):
                overdue.append(task)

    if approaching:
        count = len(approaching)
        noun = "task is" if count == 1 else "tasks are"
        record_notification(
            title="Deadline approaching" if count == 1 else "Deadlines approaching",
            message=f"{count} {noun} due tomorrow.",
            kind="warning",
            workspace="todo",
            details=[f"Task: {_display_task_title(task)}" for task in approaching[:5]],
            event_type="task-deadline-approaching",
            entity_id=str(approaching[0].get("uid") or "") if count == 1 else "",
        )

    if due_today:
        count = len(due_today)
        noun = "task is" if count == 1 else "tasks are"
        record_notification(
            title="Task due today" if count == 1 else "Tasks due today",
            message=f"{count} {noun} due today.",
            kind="warning",
            workspace="todo",
            details=[f"Task: {_display_task_title(task)}" for task in due_today[:5]],
            event_type="task-due-today",
            entity_id=str(due_today[0].get("uid") or "") if count == 1 else "",
        )
    if overdue:
        count = len(overdue)
        noun = "task is" if count == 1 else "tasks are"
        record_notification(
            title="Task overdue" if count == 1 else "Tasks overdue",
            message=f"{count} {noun} overdue.",
            kind="warning",
            workspace="todo",
            details=[f"Task: {_display_task_title(task)}" for task in overdue[:5]],
            event_type="task-overdue",
            entity_id=str(overdue[0].get("uid") or "") if count == 1 else "",
        )


def _queue_cancel_transition_confirmation(
    task: dict,
    requested_status: str,
    *,
    action_states: list[bool] | None = None,
    checkbox_key: str = "",
) -> None:
    # Arm this confirmation for the next To-Do render only. Pending state can
    # survive unrelated Streamlit reruns, so it must never be enough by itself
    # to reopen a status-confirmation dialog.
    st.session_state.pop("todo_pending_reopen_transition", None)
    st.session_state.todo_status_confirmation_armed = "cancel"
    st.session_state.todo_pending_cancel_transition = {
        "task": dict(task),
        "current_status": _status(task.get("status")),
        "requested_status": _status(requested_status),
        "action_states": list(action_states) if action_states is not None else None,
        "checkbox_key": str(checkbox_key or ""),
    }


def _queue_reopen_confirmation(
    task: dict,
    requested_status: str,
    *,
    action_states: list[bool] | None = None,
    checkbox_key: str = "",
) -> None:
    # Only one status confirmation should ever be active at a time. Arm it for
    # one render so stale Session State cannot reopen it later.
    st.session_state.pop("todo_pending_cancel_transition", None)
    st.session_state.todo_status_confirmation_armed = "reopen"
    st.session_state.todo_pending_reopen_transition = {
        "task": dict(task),
        "current_status": _status(task.get("status")),
        "requested_status": _status(requested_status),
        "action_states": list(action_states) if action_states is not None else None,
        "checkbox_key": str(checkbox_key or ""),
    }


def _status_change_toast(status: str, task: dict | None = None, previous_status: str = "") -> None:
    status = _status(status)
    transition = []
    if previous_status:
        transition.append(f"Status: {_status(previous_status)} → {status}")
    if status == "In Progress":
        _push_todo_toast("Task moved to In Progress.", "progress", task=task, details=transition, event_type="task-status")
    elif status == "Completed":
        _push_todo_toast("Task moved to Completed.", "complete", task=task, details=transition, event_type="task-completed")
    elif status == "On Hold":
        _push_todo_toast("Task moved to On Hold.", "info", task=task, details=transition, event_type="task-status")
    elif status == "Cancelled":
        _push_todo_toast("Task cancelled.", "info", task=task, details=transition, event_type="task-cancelled")
    else:
        _push_todo_toast("Task moved to Not Started.", "info", task=task, details=transition, event_type="task-status")


def _commit_status_change(
    task: dict,
    status: str,
    *,
    action_states: list[bool] | None = None,
) -> bool:
    # Persist a status change after any required confirmation has passed.
    requested_status = _status(status)
    current_status = _status(task.get("status"))
    if requested_status == current_status and action_states is None:
        return False

    store = st.session_state.get("summary_store")
    if store is None:
        _push_todo_toast(
            "Task status could not be saved because summary storage is not ready.",
            "error",
            task=task,
            event_type="task-error",
        )
        return False

    rows = _action_item_rows(task)
    original_action_states = [bool(row.get("completed")) for row in rows]
    history_changes = []
    if requested_status != current_status:
        history_changes.append({
            "type": "status_changed",
            "from": current_status,
            "to": requested_status,
        })
    if action_states is not None and rows:
        history_changes.extend(
            _manual_action_history_changes(rows, original_action_states, list(action_states))
        )
        if not _persist_all_action_items_completion(store, task, action_states):
            _push_todo_toast("Action items could not be saved.", "error", task=task, event_type="task-error")
            return False
    elif requested_status == "Completed" and rows:
        # Marking the task complete also persists every action item as complete.
        # Do NOT write to the action-item widget keys here: when this function is
        # called from the Task actions dialog, those checkbox widgets have already
        # been instantiated during the current Streamlit run and mutating their
        # session-state keys raises StreamlitAPIException. The dialog reruns/closes
        # after save; on the next open, _prepare_task_dialog_state() rebuilds the
        # checkbox state from these freshly persisted values.
        completed_states = [
            bool(row.get("completed")) if bool(row.get("cancelled")) else True
            for row in rows
        ]
        history_changes.extend(
            _manual_action_history_changes(rows, original_action_states, completed_states)
        )
        if not _persist_all_action_items_completion(
            store, task, completed_states
        ):
            _push_todo_toast("Action items could not be saved.", "error", task=task, event_type="task-error")
            return False

        # Never mutate checkbox widget keys here: these widgets may already
        # exist in the current run. Defer the visual sync to the next rerun.
        _queue_action_widget_sync(task, completed_states)

    if requested_status != current_status:
        _persist_status(store, task, requested_status)

    if history_changes:
        _append_task_change_history(store, task, history_changes, source="user")
        # A Reply Draft reflects task/action state at generation time. Any real
        # user state change makes that text stale, so remove it and require the
        # next Draft email click to generate against the newly persisted state.
        invalidate_reply_draft(str(task.get("uid") or ""))

    _reload_summaries()
    if requested_status != current_status:
        if current_status == "Completed" and requested_status in ACTIVE_TASK_STATUSES:
            _push_todo_toast(
                f"Task reopened as {requested_status}.",
                "progress",
                task=task,
                details=[f"Status: {current_status} → {requested_status}"],
                event_type="task-reopened",
            )
        else:
            _status_change_toast(requested_status, task, current_status)
    else:
        _push_todo_toast("Task updated.", "update", task=task, event_type="task-updated")
    return True


def _save_status(task: dict, status: str, *, checkbox_key: str = "") -> None:
    # Table status buttons are direct callbacks. Reject stale callbacks from a
    # previous workspace first, then collapse duplicate delivery of the exact
    # same task/status transition before any storage, history, toast, or rerun
    # side effect is allowed to happen.
    if not workspace_interaction_allowed():
        trace_action(
            "workspace-callback-ignored",
            source="todo",
            callback="_save_status",
            reason="session-transition",
        )
        return
    if not workspace_callback_allowed("todo"):
        trace_action(
            "workspace-callback-ignored",
            source="todo",
            callback="_save_status",
            reason="stale-workspace",
        )
        return

    requested_status = _status(status)
    current_status = _status(task.get("status"))
    uid = str(task.get("uid") or "").strip()
    transition_key = _safe_key(f"{uid}|{current_status}|{requested_status}")
    if not claim_foreground_interaction(
        f"todo-status-transition:{transition_key}",
        debounce_seconds=UI_DEBOUNCE_TODO_STATUS_SECONDS,
        settle_seconds=UI_FOREGROUND_SETTLE_SECONDS,
    ):
        trace_action(
            "todo-status-change",
            from_status=current_status,
            to_status=requested_status,
            outcome="duplicate-suppressed",
        )
        return

    trace_action("todo-status-change", from_status=current_status, to_status=requested_status)

    # Selecting the status the task already has is a true no-op.
    if requested_status == current_status:
        return

    if _requires_cancel_confirmation(current_status, requested_status):
        _queue_cancel_transition_confirmation(
            task, requested_status, checkbox_key=checkbox_key
        )
        return

    if _requires_reopen_confirmation(current_status, requested_status):
        _queue_reopen_confirmation(
            task, requested_status, checkbox_key=checkbox_key
        )
        return

    _commit_status_change(task, requested_status)


def _on_status_change(task: dict, select_key: str) -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("todo"):
        trace_action("workspace-callback-ignored", source="todo", callback="_on_status_change")
        return
    _save_status(task, str(st.session_state.get(select_key) or "Not Started"))


def _status_css_class(status: str) -> str:
    return f"status-{task_status_slug(status)}"


def _set_modal_status_draft(status_key: str, status: str) -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("todo"):
        trace_action("workspace-callback-ignored", source="todo", callback="_set_modal_status_draft")
        return
    selected_status = _status(status)
    trace_action("todo-dialog-status-select", status=selected_status)
    # A status change invalidates any prior completion-block warning; Update will
    # validate the new draft state again before persistence.
    st.session_state.pop("todo_update_blocked_incomplete_uid", None)
    # Update only the modal draft status; persistence still happens on Update.
    st.session_state[status_key] = selected_status


def _render_modal_status_picker(status_key: str, key_id: str, current_status: str) -> None:
    # Fast fragment-scoped status picker for the Task actions dialog.
    #
    # Keeping this selector in a fragment avoids a full-app rerun for every status
    # click, so the dialog stays open and the selected badge updates immediately.
    options = list(TASK_STATUSES)
    if st.session_state.get(status_key) not in options:
        st.session_state[status_key] = current_status

    selected_status = _status(st.session_state.get(status_key) or current_status)
    selected_slug = task_status_slug(selected_status)

    with st.container(key=f"todo_modal_status_field_status-{selected_slug}_{key_id}"):
        with st.popover(selected_status, use_container_width=False):
            st.markdown(
                '<div class="todo-modal-status-popover-marker"></div>',
                unsafe_allow_html=True,
            )
            for option in options:
                option_key = task_status_slug(option).replace("-", "_")
                st.button(
                    option,
                    key=f"todo_modal_status_choice_{key_id}_{option_key}",
                    use_container_width=True,
                    type="primary" if option == selected_status else "secondary",
                    on_click=_set_modal_status_draft,
                    args=(status_key, option),
                )


def _render_status_popover(task: dict, key_id: str, status: str) -> None:
    # Clickable table-status badge using the same picker UI as the task modal.
    #
    # Table changes save immediately because there is no separate Update action in
    # the list view. The normal Streamlit rerun after the button callback refreshes
    # counters and the row without an extra explicit rerun.
    selected_status = _status(status)
    selected_slug = task_status_slug(selected_status)
    with st.container(key=f"todo_table_status_field_status-{selected_slug}_{key_id}"):
        with st.popover(selected_status, use_container_width=False):
            st.markdown(
                '<div class="todo-modal-status-popover-marker"></div>',
                unsafe_allow_html=True,
            )
            for option in TASK_STATUSES:
                option_key = task_status_slug(option).replace("-", "_")
                st.button(
                    option,
                    key=f"todo_table_status_choice_{key_id}_{option_key}",
                    use_container_width=True,
                    type="primary" if option == selected_status else "secondary",
                    on_click=_save_status,
                    args=(task, option),
                )


def _deadline_state(entry: dict) -> tuple[str, str]:
    # Return CSS state + human label for one deadline row.
    if bool(entry.get("completed")):
        return "completed", "Completed"

    parsed = entry.get("parsed", datetime.max)
    if parsed == datetime.max:
        return "upcoming", "Upcoming"

    due_day = parsed.date()
    today = date.today()
    if due_day < today:
        return "overdue", "Past Due"
    if due_day == today:
        return "today", "Due today"
    return "upcoming", "Upcoming"


def _deadline_popover_html(task: dict) -> str:
    entries = _deadline_entries(task, include_completed=True)
    if not entries:
        return ""

    rows = []
    uses_action_items = any(entry.get("source") == "action" for entry in entries)
    for entry in entries:
        state_class, state_label = _deadline_state(entry)
        parsed = entry.get("parsed", datetime.max)
        action = str(entry.get("action") or "").strip()
        raw = str(entry.get("raw") or "").strip()
        date_label = _format_deadline(parsed, raw) if parsed != datetime.max else "No date"
        detail = action or raw or "Deadline from email"
        rows.append(
            '<div class="todo-deadline-popover-row">'
            f'<span class="todo-deadline-popover-dot is-{state_class}"></span>'
            f'<div class="todo-deadline-popover-date">{html.escape(date_label)}</div>'
            f'<div class="todo-deadline-popover-action">{html.escape(detail)}</div>'
            f'<span class="todo-deadline-popover-state is-{state_class}">{html.escape(state_label)}</span>'
            '</div>'
        )

    source_note = (
        "Showing deadlines from action items"
        if uses_action_items
        else "Showing deadlines from email"
    )
    return (
        '<div class="todo-deadline-popover-marker"></div>'
        f'<div class="todo-deadline-popover-title">All deadlines ({len(entries)})</div>'
        '<div class="todo-deadline-popover-list">'
        + ''.join(rows)
        + '</div>'
        f'<div class="todo-deadline-popover-footer">ⓘ {html.escape(source_note)}</div>'
    )


def _render_deadline_popover(task: dict, key_id: str, context: str) -> None:
    # Render a compact read-only list of all known deadlines.
    entries = _deadline_entries(task, include_completed=True)
    if len(entries) <= 1:
        return

    extra = len(entries) - 1
    trigger = f"+{extra} more" if context == "table" else f"+{extra} more deadline{'s' if extra != 1 else ''}"
    with st.container(key=f"todo_{context}_deadlines_popover_{key_id}"):
        with st.popover(trigger, use_container_width=False):
            st.markdown(_deadline_popover_html(task), unsafe_allow_html=True)


def _queue_row_completion_widget_sync(checkbox_key: str, value: bool) -> None:
    # Queue a table-row completion checkbox correction for the next full render.
    #
    # A row checkbox can already be instantiated when a confirmation dialog is
    # answered, so mutating its widget-backed key immediately is unsafe. Apply
    # the correction before the checkbox is recreated on the following rerun.
    key = str(checkbox_key or "").strip()
    if not key:
        return
    st.session_state.todo_pending_row_completion_widget_sync = {
        "checkbox_key": key,
        "value": bool(value),
    }


def _prepare_row_completion_widget_state(
    *,
    key_id: str,
    status: str,
    checkbox_key: str,
    expected_completed: bool,
) -> None:
    # Normalize stale row-checkbox state *before* the widget is instantiated.
    #
    # Row checkbox keys are status-specific. If a task later cycles back to a
    # status it has used before, Streamlit can restore the old widget value for
    # that key. Without this guard, a stale True/False can be mistaken for a new
    # user edit during a later/background rerun and trigger an unwanted status
    # transition. Track the last persisted status we rendered for each task and
    # reset the active widget key whenever that persisted status changes.
    marker_key = f"todo_row_completion_rendered_status_{key_id}"
    normalized_status = _status(status)
    previous_status = str(st.session_state.get(marker_key) or "")
    if previous_status != normalized_status:
        st.session_state[checkbox_key] = bool(expected_completed)
        st.session_state[marker_key] = normalized_status

    # Confirmation paths such as Keep Completed may need to restore the visual
    # checkbox while the persisted status intentionally stays unchanged. Apply
    # that queued correction here, before st.checkbox owns the key again.
    pending = st.session_state.get("todo_pending_row_completion_widget_sync")
    if isinstance(pending, dict) and str(pending.get("checkbox_key") or "") == checkbox_key:
        st.session_state[checkbox_key] = bool(pending.get("value"))
        st.session_state.pop("todo_pending_row_completion_widget_sync", None)


def _queue_action_widget_sync(task: dict, states: list[bool]) -> None:
    # Queue checkbox state for the *next* render, before widgets instantiate.
    #
    # Streamlit forbids changing a widget-backed session_state key after that
    # widget has been instantiated in the current run. Mark-as-Completed can be
    # triggered below the action-item checkboxes, so we persist to storage now
    # and defer widget-key synchronization until the rerun starts.
    st.session_state.todo_pending_action_widget_sync = {
        "uid": str(task.get("uid") or ""),
        "states": [bool(value) for value in states],
    }


def _apply_pending_action_widget_sync(task: dict, key_id: str) -> None:
    # Apply a queued checkbox sync before any action checkbox is rendered.
    pending = st.session_state.get("todo_pending_action_widget_sync")
    if not isinstance(pending, dict):
        return
    if str(pending.get("uid") or "") != str(task.get("uid") or ""):
        return

    states = [bool(value) for value in (pending.get("states") or [])]
    for index, value in enumerate(states):
        st.session_state[_action_checkbox_key(key_id, index)] = value
    st.session_state.pop("todo_pending_action_widget_sync", None)


def _prepare_task_dialog_state(task: dict) -> None:
    # Load persisted values into draft controls each time the dialog opens.
    uid = str(task.get("uid") or "")
    key_id = _safe_key(uid)
    st.session_state.pop("todo_update_blocked_incomplete_uid", None)
    st.session_state[f"todo_dialog_status_{key_id}"] = _status(task.get("status"))

    for index, row in enumerate(_action_item_rows(task)):
        st.session_state[_action_checkbox_key(key_id, index)] = bool(row.get("completed"))
    st.session_state[_action_widget_snapshot_key(key_id)] = _action_widget_snapshot(task)


def _apply_task_dialog_changes(
    task: dict,
    current_status: str,
    status_key: str,
) -> str:
    # Persist dialog drafts only when there is a real valid change.
    # Return an explicit outcome so the caller never closes Task Actions for
    # no-op/blocked/error attempts.
    store = st.session_state.get("summary_store")
    if store is None:
        _push_todo_toast(
            "Task could not be updated because summary storage is not ready.",
            "error",
            task=task,
            event_type="task-error",
        )
        return "error"

    key_id = _safe_key(str(task.get("uid") or ""))
    rows = _action_item_rows(task)
    action_states = _action_completion_states(task, key_id)
    original_action_states = [bool(row.get("completed")) for row in rows]

    # Action-item callbacks already keep this draft status synchronized while
    # the user checks/unchecks items. Do not re-run automation here because an
    # explicit reactivation such as Cancelled -> In Progress must win even if
    # old action items are still checked from the task's history.
    new_status = _status(st.session_state.get(status_key) or current_status)
    st.session_state[status_key] = new_status

    pending_action_states = (
        action_states if action_states != original_action_states else None
    )

    # A task cannot be explicitly completed while any active action item is
    # still unchecked. Do not silently auto-check remaining items from this
    # dialog: keep the user's draft intact and block persistence until resolved.
    active_incomplete_count = sum(
        1
        for index, row in enumerate(rows)
        if not bool(row.get("cancelled"))
        and index < len(action_states)
        and not bool(action_states[index])
    )
    if new_status == "Completed" and active_incomplete_count > 0:
        trace_action(
            "todo-update-blocked-incomplete",
            incomplete_count=int(active_incomplete_count),
        )
        return "blocked"

    # Clicking Update without changing status or action items is a true no-op.
    # Keep the modal open and avoid a meaningless save/rerun/toast.
    if new_status == current_status and pending_action_states is None:
        st.session_state.pop("todo_update_blocked_incomplete_uid", None)
        trace_action("todo-update-noop", outcome="no-changes")
        return "noop"

    st.session_state.pop("todo_update_blocked_incomplete_uid", None)

    if _requires_cancel_confirmation(current_status, new_status):
        # Nothing is persisted yet. Confirming applies both the draft action
        # checks and the requested status from the same confirmation action.
        _queue_cancel_transition_confirmation(
            task,
            new_status,
            action_states=pending_action_states,
        )
        return "confirmation"

    if _requires_reopen_confirmation(current_status, new_status):
        # A completed task may be reopened, but only after the user confirms the
        # meaning change. Preserve existing action-item completion unless the user
        # explicitly changed those draft checkboxes before clicking Update.
        _queue_reopen_confirmation(
            task,
            new_status,
            action_states=pending_action_states,
        )
        return "confirmation"

    changed = False
    history_changes = []
    if new_status != current_status:
        history_changes.append({
            "type": "status_changed",
            "from": current_status,
            "to": new_status,
        })
    if action_states != original_action_states:
        history_changes.extend(
            _manual_action_history_changes(rows, original_action_states, action_states)
        )
        if not _persist_all_action_items_completion(store, task, action_states):
            _push_todo_toast("Action items could not be saved.", "error", task=task, event_type="task-error")
            return "error"
        changed = True

    if new_status != current_status:
        _persist_status(store, task, new_status)
        changed = True

    if changed:
        if history_changes:
            _append_task_change_history(store, task, history_changes, source="user")
        # Task actions dialog is a separate persistence path from the compact
        # status callbacks above. Invalidate here too so changing Status or any
        # action checkbox through this modal cannot leave a stale Reply Draft.
        invalidate_reply_draft(str(task.get("uid") or ""))
        _reload_summaries()
        if new_status != current_status:
            _status_change_toast(new_status, task, current_status)
        else:
            changed_count = sum(a != b for a, b in zip(action_states, original_action_states))
            _push_todo_toast(
                "Task updated.",
                "update",
                task=task,
                details=[f"Action items changed: {changed_count}" if changed_count else "Task details updated"],
                event_type="task-updated",
            )
    return "saved" if changed else "noop"


def _close_todo_row_more_actions(version_key: str) -> None:
    """Remount the native row popover closed after one menu action."""
    current = int(st.session_state.get(version_key, 0) or 0)
    st.session_state[version_key] = current + 1


def _render_task_original_deleted_notice() -> None:
    # Reuse the same visual language as AI Summary when the provider confirms
    # that the source email/thread was deleted.
    st.markdown(
        """
        <section class="summary-original-deleted-note">
            <span class="summary-original-deleted-note-icon">i</span>
            <div class="summary-original-deleted-note-copy">
                <span class="summary-original-deleted-note-title">Original email deleted.</span>
                <span class="summary-original-deleted-note-text">This email is no longer available in your mailbox.</span>
            </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


@st.fragment
def _render_task_actions_body(task: dict) -> None:
    task_title = _display_task_title(task)
    actions = _clean_list(task.get("action_items"))
    all_deadlines = _deadline_entries(task, include_completed=True)
    subject = str(task.get("subject") or "No subject")
    uid = str(task.get("uid") or "")
    key_id = _safe_key(uid)
    original_deleted = is_original_email_deleted(uid, "INBOX")
    priority = task.get("priority") or "Medium"
    current_status = _status(task.get("status"))
    sender_name, sender_email = _sender_parts(task)
    parsed, due_source = _resolved_deadline(task)
    status_key = f"todo_dialog_status_{key_id}"

    _apply_pending_action_widget_sync(task, key_id)
    _sync_changed_action_widgets(task, key_id)

    draft_status = _status(st.session_state.get(status_key) or current_status)
    cancelled_task_class = " is-cancelled" if draft_status == "Cancelled" else ""
    deadline_count = len(all_deadlines)
    deadline_raw = next(
        (str(entry.get("raw") or "").strip() for entry in all_deadlines if entry.get("parsed") == parsed),
        "",
    )

    with st.container(border=False, key=f"todo_task_header_{key_id}"):
        st.markdown(
            f"""
            <div class="todo-modal-shell todo-task-actions-v2">
                <div class="todo-modal-task-card todo-modal-task-card-with-icon{cancelled_task_class}">
                    <span class="todo-modal-task-icon">✉</span>
                    <div class="todo-modal-task-copy">
                        <div class="todo-modal-task-title">{html.escape(task_title)}</div>
                        <div class="todo-modal-task-subject">{html.escape(subject)}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if original_deleted:
        _render_task_original_deleted_notice()

    with st.container(key=f"todo_modal_details_{key_id}"):
        sender_col, priority_col, deadline_col, status_col = st.columns(
            [0.34, 0.16, 0.30, 0.20], gap="medium", vertical_alignment="top"
        )

        with sender_col:
            st.markdown(
                '<div class="todo-modal-label todo-modal-field-label">Sender</div>',
                unsafe_allow_html=True,
            )
            email_line = (
                f'<div class="todo-modal-sender-email">{html.escape(sender_email)}</div>'
                if sender_email else ""
            )
            st.markdown(
                f'<div class="todo-modal-sender">'
                f'<span class="todo-sender-avatar hue-{_sender_hue(task)}">{html.escape(_sender_initials(task))}</span>'
                '<div class="todo-modal-sender-text">'
                f'<div class="todo-modal-sender-name">{html.escape(sender_name)}</div>'
                f'{email_line}</div></div>',
                unsafe_allow_html=True,
            )

        with priority_col:
            st.markdown(
                '<div class="todo-modal-label todo-modal-field-label">Priority</div>',
                unsafe_allow_html=True,
            )
            closed_priority_class = (
                " is-closed-priority"
                if draft_status in {"Completed", "Cancelled"}
                else ""
            )
            st.markdown(
                f'<div class="todo-modal-priority-wrap"><span class="todo-pill priority-{priority.casefold()}{closed_priority_class}">{html.escape(priority)}</span></div>',
                unsafe_allow_html=True,
            )

        with deadline_col:
            deadline_label = "Deadline (next)" if deadline_count > 1 else "Deadline"
            st.markdown(
                f'<div class="todo-modal-label todo-modal-field-label">{deadline_label}</div>',
                unsafe_allow_html=True,
            )
            if parsed != datetime.max:
                st.markdown(
                    f'<div class="todo-modal-deadline-summary"><span class="todo-modal-calendar">▣</span>'
                    f'<strong>{html.escape(_format_deadline(parsed, deadline_raw))}</strong></div>',
                    unsafe_allow_html=True,
                )
                if deadline_count > 1:
                    extra = deadline_count - 1
                    st.markdown(
                        f'<div class="todo-modal-deadline-helper">+{extra} more deadline{"s" if extra != 1 else ""}</div>',
                        unsafe_allow_html=True,
                    )
                elif due_source == "estimated":
                    st.markdown(
                        '<div class="todo-modal-deadline-helper">Estimated / planned deadline</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    '<div class="todo-modal-deadline-summary todo-modal-no-deadline">'
                    '<span class="todo-modal-calendar">▣</span><strong>No deadline</strong></div>'
                    '<div class="todo-modal-deadline-helper">No upcoming deadlines</div>',
                    unsafe_allow_html=True,
                )

        with status_col:
            st.markdown(
                '<div class="todo-modal-label todo-modal-field-label">Status</div>',
                unsafe_allow_html=True,
            )
            _render_modal_status_picker(status_key, key_id, current_status)

    if actions:
        _render_action_items_panel(task, key_id, status_key)

    close_col, spacer_col, update_col = st.columns([0.20, 0.55, 0.25], gap="small")
    with close_col:
        with st.container(key=f"todo_modal_close_{key_id}"):
            if st.button(
                "Close",
                key=f"todo_modal_close_button_{key_id}",
                use_container_width=True,
                type="secondary",
            ):
                st.session_state.todo_task_actions_close_requested = True
                st.session_state.pop("todo_update_blocked_incomplete_uid", None)
                st.session_state.pop("todo_dialog_uid", None)
                st.session_state.pop("todo_dialog_mode", None)
                _arm_foreground_navigation_guard()
                st.rerun(scope="app")

    with update_col:
        with st.container(key=f"todo_modal_update_{key_id}"):
            if st.button(
                "Update",
                key=f"todo_modal_update_button_{key_id}",
                use_container_width=True,
                type="primary",
            ):
                update_outcome = _apply_task_dialog_changes(
                    task,
                    current_status,
                    status_key,
                )
                if update_outcome in {"saved", "confirmation"}:
                    st.session_state.todo_task_actions_close_requested = True
                    st.session_state.pop("todo_update_blocked_incomplete_uid", None)
                    st.session_state.pop("todo_dialog_uid", None)
                    st.session_state.pop("todo_dialog_mode", None)
                    _arm_foreground_navigation_guard()
                    st.rerun(scope="app")
                elif update_outcome == "blocked":
                    rows_now = _action_item_rows(task)
                    states_now = _action_completion_states(task, key_id)
                    incomplete_count = sum(
                        1
                        for index, row in enumerate(rows_now)
                        if not bool(row.get("cancelled"))
                        and index < len(states_now)
                        and not bool(states_now[index])
                    )
                    item_word = "item remains" if incomplete_count == 1 else "items remain"
                    st.toast(
                        f"Cannot mark this task as Completed yet. {incomplete_count} action {item_word} incomplete. "
                        "Complete the remaining action items, or choose another status, then click Update again.",
                        icon="⚠️",
                        duration="long",
                    )
                elif update_outcome == "error":
                    # Keep Task Actions mounted. The storage layer already records
                    # the detailed error; show lightweight feedback without a
                    # second fragment/app rerun.
                    st.toast("Task could not be updated. Please try again.", icon="⚠️")
                # No-op intentionally does nothing: the modal remains open and
                # the current layout is left untouched.

@st.dialog(
    "Task actions",
    width="large",
    icon="📋",
    dismissible=False,
)
def _show_task_actions(task: dict) -> None:
    _render_task_actions_body(task)



@st.dialog(
    "Recent Activity",
    width="medium",
    icon=":material/history:",
    dismissible=False,
)
def _show_task_recent_activity(task: dict) -> None:
    """Show task history as the only active To-Do dialog."""
    uid = str(task.get("uid") or "").strip()
    if not uid:
        return

    key_id = _safe_key(uid)
    task_title = _display_task_title(task)
    subject = str(task.get("subject") or "No subject")

    # Marker scopes one canonical native-dialog CSS authority. No JS/component
    # bridge and no nested Task Actions overlay is involved.
    st.markdown(
        '<div class="todo-recent-activity-dialog-v2" aria-hidden="true"></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="todo-history-dialog-subtitle">Task change history</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="todo-history-dialog-task">'
        f'<div class="todo-history-dialog-task-title">{html.escape(task_title)}</div>'
        f'<div class="todo-history-dialog-task-subject">{html.escape(subject)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    with st.container(border=False, key=f"todo_recent_activity_list_{key_id}"):
        _render_task_history_rows(
            task,
            key_id,
            key_prefix="todo_recent_activity_rows",
        )

    with st.container(border=False, key=f"todo_recent_activity_footer_{key_id}"):
        close_col, spacer_col = st.columns([0.24, 0.76], gap="small")
        with close_col:
            if st.button(
                "Close",
                key=f"todo_recent_activity_close_{key_id}",
                type="secondary",
                use_container_width=True,
            ):
                trace_action("todo-recent-activity-close", uid=uid)
                st.session_state.pop("todo_dialog_uid", None)
                st.session_state.pop("todo_dialog_mode", None)
                _arm_foreground_navigation_guard()
                st.rerun(scope="app")


def render_task_actions_dialog() -> None:
    # Exactly one To-Do root dialog may be active. Row More Actions routes
    # directly to Task Actions or Recent Activity; Original Email is owned by
    # app.py and clears this To-Do dialog slot before it opens.
    tasks = _task_records(st.session_state.get("summaries", []))

    # Clean stale state from older builds that used nested history/original
    # overlays underneath Task Actions. Do not recreate those parent dialogs.
    st.session_state.pop("todo_history_overlay_uid", None)
    st.session_state.pop("todo_original_overlay_uid", None)

    legacy_history_uid = str(
        st.session_state.pop("todo_history_dialog_uid", "") or ""
    ).strip()
    legacy_return_uid = str(
        st.session_state.pop("todo_history_return_todo_uid", "") or ""
    ).strip()
    if legacy_history_uid and not str(
        st.session_state.get("todo_dialog_uid") or ""
    ).strip():
        st.session_state.todo_dialog_uid = legacy_history_uid
        st.session_state.todo_dialog_mode = "history"
    elif legacy_return_uid and not str(
        st.session_state.get("todo_dialog_uid") or ""
    ).strip():
        st.session_state.todo_dialog_uid = legacy_return_uid
        st.session_state.todo_dialog_mode = "actions"

    uid = str(st.session_state.get("todo_dialog_uid") or "").strip()
    if not uid:
        st.session_state.pop("todo_dialog_mode", None)
        return

    task = next(
        (item for item in tasks if str(item.get("uid") or "") == uid),
        None,
    )
    if task is None:
        st.session_state.pop("todo_dialog_uid", None)
        st.session_state.pop("todo_dialog_mode", None)
        return

    mode = str(
        st.session_state.get("todo_dialog_mode") or "actions"
    ).strip().casefold()
    if mode == "history":
        _show_task_recent_activity(task)
    else:
        st.session_state.todo_dialog_mode = "actions"
        _show_task_actions(task)


def _apply_dashboard_metric_filter(state_key: str, value) -> None:
    if not claim_foreground_interaction(
        "todo-dashboard-filter", debounce_seconds=UI_DEBOUNCE_FILTER_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("todo-dashboard-filter-detail", state_key=state_key, value=value)

    # Do not mutate Search/Filter widget-backed state from the callback prefix.
    # Under rapid clicks Streamlit can still deliver a second stale button event
    # before the first full rerun starts. Mutating mounted widget state here made
    # that extra rerun race the browser's cached widget tree. Queue one accepted
    # metric instead; render_todo_tab consumes it before any To-Do widgets mount.
    st.session_state.todo_dashboard_filter_pending = {
        "state_key": str(state_key or ""),
        "value": value,
    }


def _apply_pending_dashboard_metric_filter() -> None:
    pending = st.session_state.pop("todo_dashboard_filter_pending", None)
    if not isinstance(pending, dict):
        return

    state_key = str(pending.get("state_key") or "").strip()
    if state_key not in {
        "todo_status_filter",
        "todo_priority_filter",
        "todo_deadline_filter",
        "todo_action_needed_only",
    }:
        trace_action(
            "todo-dashboard-filter-apply",
            outcome="ignored-invalid-state-key",
            state_key=state_key,
        )
        return

    value = pending.get("value")
    trace_action("todo-dashboard-filter-apply", state_key=state_key, value=value)
    st.session_state.todo_status_filter = None
    st.session_state.todo_priority_filter = None
    st.session_state.todo_deadline_filter = None
    st.session_state.todo_action_needed_only = False
    st.session_state.todo_search_query = ""
    st.session_state[state_key] = value
    st.session_state.pop("todo_pending_page_direction", None)
    st.session_state.todo_offset = 0
    st.session_state.todo_list_scroll_reset_pending = True


def _dashboard_metric_button(
    count: int,
    label: str,
    *,
    key: str,
    state_key: str,
    value,
) -> None:
    # Render one compact dashboard card as a native Streamlit button.
    st.button(
        f"**{count:,}**\n{label}",
        key=key,
        type="secondary",
        use_container_width=True,
        on_click=_apply_dashboard_metric_filter,
        args=(state_key, value),
    )


def _render_header(tasks: list[dict]) -> None:
    counts = _metric_counts(tasks)

    # Keep the merge_15 dashboard proportions, but use native Streamlit
    # buttons for interaction so a metric click only changes session state.
    with st.container(key="todo_header_native"):
        st.markdown(
            '<div class="mailmind-workspace-header mailmind-workspace-header-todo"><div class="mailmind-workspace-title">To-Do List</div></div>',
            unsafe_allow_html=True,
        )

        with st.container(key="todo_dashboard_native"):
            status_col, priority_col, deadline_col = st.columns(
                [1.45, 1.0, 1.28],
                gap="small",
                vertical_alignment="top",
            )

            with status_col:
                with st.container(key="todo_metric_section_status"):
                    st.markdown(
                        '<div class="todo-native-metric-section-title">Status</div>',
                        unsafe_allow_html=True,
                    )
                    status_cells = st.columns(5, gap="small")
                    status_metrics = (
                        ("not_started", "Not Started", "Not Started"),
                        ("in_progress", "In Progress", "In Progress"),
                        ("on_hold", "On Hold", "On Hold"),
                        ("completed", "Completed", "Completed"),
                        ("cancelled", "Cancelled", "Cancelled"),
                    )
                    for cell, (metric_name, label, value) in zip(
                        status_cells, status_metrics
                    ):
                        with cell:
                            _dashboard_metric_button(
                                counts[metric_name],
                                label,
                                key=f"todo_metric_status_{metric_name}",
                                state_key="todo_status_filter",
                                value=value,
                            )

            with priority_col:
                with st.container(key="todo_metric_section_priority"):
                    st.markdown(
                        '<div class="todo-native-metric-section-title">Priority</div>',
                        unsafe_allow_html=True,
                    )
                    priority_cells = st.columns(4, gap="small")
                    priority_metrics = (
                        ("critical", "Critical", "Critical"),
                        ("high", "High", "High"),
                        ("medium", "Medium", "Medium"),
                        ("low", "Low", "Low"),
                    )
                    for cell, (metric_name, label, value) in zip(
                        priority_cells, priority_metrics
                    ):
                        with cell:
                            _dashboard_metric_button(
                                counts[metric_name],
                                label,
                                key=f"todo_metric_priority_{metric_name}",
                                state_key="todo_priority_filter",
                                value=value,
                            )

            with deadline_col:
                with st.container(key="todo_metric_section_deadline"):
                    st.markdown(
                        '<div class="todo-native-metric-section-title">Deadline</div>',
                        unsafe_allow_html=True,
                    )
                    deadline_cells = st.columns(4, gap="small")
                    deadline_metrics = (
                        ("due_today", "Due today", "due_today"),
                        ("this_week", "This week", "this_week"),
                        ("this_month", "This month", "this_month"),
                        ("overdue", "Overdue", "overdue"),
                    )
                    for cell, (metric_name, label, value) in zip(
                        deadline_cells, deadline_metrics
                    ):
                        with cell:
                            _dashboard_metric_button(
                                counts[metric_name],
                                label,
                                key=f"todo_metric_deadline_{metric_name}",
                                state_key="todo_deadline_filter",
                                value=value,
                            )


def _reset_todo_pagination() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("todo"):
        trace_action("workspace-callback-ignored", source="todo", callback="_reset_todo_pagination")
        return

    # A refresh clears the search widget on the server before the new To-Do DOM
    # is mounted. The browser can still deliver one late change event from the
    # old text-input node. Ignore that stale event during the short settle
    # window and keep the refresh result authoritative instead of scheduling a
    # second competing To-Do rerun.
    suppress_until = float(
        st.session_state.get("todo_refresh_search_suppress_until", 0.0) or 0.0
    )
    if suppress_until and time_module.monotonic() < suppress_until:
        st.session_state.todo_search_query = ""
        trace_action("todo-search-change", outcome="ignored-refresh-settle", query_len=0)
        return

    st.session_state.pop("todo_refresh_search_suppress_until", None)
    trace_action("todo-search-change", query_len=len(str(st.session_state.get("todo_search_query", "") or "")))
    _arm_foreground_navigation_guard()
    st.session_state.pop("todo_pending_page_direction", None)
    st.session_state.todo_offset = 0
    st.session_state.todo_list_scroll_reset_pending = True


def _refresh_todo_list() -> None:
    # Keep the button callback tiny. Mutating the search widget, filters and
    # summary payload directly inside this callback produced a second wave of
    # stale text-input events in the white/stale trace. Only queue the reset
    # here; render_todo_tab consumes it before any To-Do widgets are mounted.
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="_refresh_todo_list")
        return
    if not workspace_callback_allowed("todo"):
        trace_action("workspace-callback-ignored", source="todo", callback="_refresh_todo_list")
        return
    if not claim_foreground_interaction(
        "todo-refresh", debounce_seconds=UI_DEBOUNCE_REFRESH_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("todo-refresh-click")
    st.session_state.todo_refresh_reset_pending = True


def _apply_pending_todo_refresh() -> None:
    if not bool(st.session_state.pop("todo_refresh_reset_pending", False)):
        return

    trace_action("todo-refresh-apply")
    # Suppress old-DOM search callbacks long enough for the refreshed widget to
    # settle. This is deliberately shorter than the existing foreground guard.
    st.session_state.todo_refresh_search_suppress_until = time_module.monotonic() + 1.75
    st.session_state.todo_search_query = ""
    st.session_state.todo_status_filter = None
    st.session_state.todo_priority_filter = None
    st.session_state.todo_deadline_filter = None
    st.session_state.todo_action_needed_only = False
    st.session_state.pop("todo_pending_page_direction", None)
    st.session_state.todo_offset = 0
    _reload_summaries()
    st.session_state.todo_list_scroll_reset_pending = True


def _render_toolbar() -> None:
    # Keep the exact working toolbar structure from Email-Assistant_merge_1_old.
    with st.container(key="todo_toolbar"):
        with st.container(key="todo_search_row"):
            col_search, col_filter = st.columns([0.78, 0.22], gap="small")
            with col_search:
                st.text_input(
                    "Search tasks",
                    key="todo_search_query",
                    placeholder="Search tasks",
                    label_visibility="collapsed",
                    on_change=_reset_todo_pagination,
                )
            with col_filter:
                _render_todo_filter_menu()


def _render_empty_state(title: str, description: str) -> None:
    st.markdown(
        f"""
        <div class="todo-empty-state">
            <div class="todo-empty-icon">✓</div>
            <div class="todo-empty-title">{html.escape(title)}</div>
            <div class="todo-empty-description">{html.escape(description)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_list_header() -> None:
    # Match the Inbox visual rhythm: reserve a small gutter for the row checkbox,
    # while the visible table header aligns with the bordered task card itself.
    with st.container(border=False, key="todo_table_header_v2"):
        _checkbox_space, header_card = st.columns(
            [0.045, 0.955], gap="small", vertical_alignment="center"
        )
        with header_card:
            col_task, col_due, col_priority, col_status, col_actions = st.columns(
                [0.54, 0.19, 0.10, 0.13, 0.04],
                gap="small",
                vertical_alignment="center",
            )
            with col_task:
                st.markdown(
                    '<div class="todo-v2-header-label todo-v2-header-task">Task</div>',
                    unsafe_allow_html=True,
                )
            with col_due:
                st.markdown(
                    '<div class="todo-v2-header-label">Deadline</div>',
                    unsafe_allow_html=True,
                )
            with col_priority:
                st.markdown(
                    '<div class="todo-v2-header-label">Priority</div>',
                    unsafe_allow_html=True,
                )
            with col_status:
                st.markdown(
                    '<div class="todo-v2-header-label">Status</div>',
                    unsafe_allow_html=True,
                )
            with col_actions:
                st.markdown(
                    '<div class="todo-v2-header-label todo-v2-header-actions" aria-hidden="true"></div>',
                    unsafe_allow_html=True,
                )


def _render_due_cell(task: dict, uid: str, key_id: str) -> None:
    parsed, source = _resolved_deadline(task)
    all_deadlines = _deadline_entries(task, include_completed=True)
    deadline_raw = next(
        (str(entry.get("raw") or "").strip() for entry in all_deadlines if entry.get("parsed") == parsed),
        "",
    )

    if parsed == datetime.max:
        no_deadline_label = (
            "No deadline"
            if source == "none" and str(task.get("deadline_mode") or "").casefold() == "explicit_none"
            else "No upcoming deadline"
        )
        st.markdown(
            f'<div class="todo-due-stack"><div class="todo-no-upcoming-deadline">{html.escape(no_deadline_label)}</div></div>',
            unsafe_allow_html=True,
        )
        return

    st.markdown(
        '<div class="todo-due-stack">'
        f'<div class="todo-due-cell">{html.escape(_format_deadline(parsed, deadline_raw))}</div>'
        + (
            '<div class="todo-estimated-deadline-note">Estimated / planned deadline</div>'
            if source == "estimated"
            else ''
        )
        + '</div>',
        unsafe_allow_html=True,
    )

    if len(all_deadlines) > 1:
        _render_deadline_popover(task, key_id, "table")


def _mark_task_viewed(task: dict) -> None:
    # Task attention state is independent from Inbox unread and AI Summary
    # Unviewed. Opening the task acknowledges any unseen task attention.
    if (
        bool(task.get("task_is_read", True))
        and bool(task.get("task_update_is_read", True))
    ):
        return

    store = st.session_state.get("summary_store")
    if store is None:
        return

    parent_uid = str(task.get("_batch_parent_uid") or "").strip()
    source_uid = str(task.get("_batch_source_uid") or task.get("uid") or "").strip()
    source_index = task.get("_batch_source_index")
    persisted = False
    if parent_uid:
        mark_breakdown = getattr(store, "mark_breakdown_task_read", None)
        if callable(mark_breakdown):
            persisted = bool(
                mark_breakdown(
                    _FOLDER, parent_uid, source_uid, source_index=source_index
                )
            )
    else:
        mark_task = getattr(store, "mark_task_read", None)
        if callable(mark_task):
            persisted = bool(mark_task(_FOLDER, source_uid))

    # Keep the current Streamlit snapshot synchronized with storage so the
    # bold unseen-attention state clears on the same interaction.
    if (
        persisted
        or not bool(task.get("task_is_read", False))
        or not bool(task.get("task_update_is_read", True))
    ):
        task["task_is_read"] = True
        task["task_update_is_read"] = True
        for summary in st.session_state.get("summaries", []) or []:
            if not isinstance(summary, dict):
                continue
            if parent_uid and str(summary.get("uid") or "") == parent_uid:
                breakdowns = summary.get("email_breakdowns") or []
                for index, item in enumerate(breakdowns):
                    if not isinstance(item, dict):
                        continue
                    if source_uid and str(item.get("uid") or "") == source_uid:
                        item["task_is_read"] = True
                        item["task_update_is_read"] = True
                        break
                    if source_index is not None and index == source_index:
                        item["task_is_read"] = True
                        item["task_update_is_read"] = True
                        break
            elif not parent_uid and str(summary.get("uid") or "") == source_uid:
                summary["task_is_read"] = True
                summary["task_update_is_read"] = True
                break


def _open_task_from_card(task: dict) -> None:
    """Open the existing Task Actions dialog from the row card surface."""
    uid = str(task.get("uid") or "").strip()
    if not uid:
        return
    if not claim_foreground_interaction(
        f"todo-open:{uid}",
        debounce_seconds=UI_DEBOUNCE_FAST_SECONDS,
        settle_seconds=UI_FOREGROUND_SETTLE_SECONDS,
    ):
        return
    trace_action("todo-task-open", source="row-card")
    _mark_task_viewed(task)
    _prepare_task_dialog_state(task)
    st.session_state.todo_dialog_mode = "actions"
    st.session_state.todo_dialog_uid = uid


def _open_task_original_from_row_menu(task: dict, version_key: str) -> None:
    uid = str(task.get("uid") or "").strip()
    if not uid:
        return
    if not claim_foreground_interaction(
        f"todo-open-original:{uid}",
        debounce_seconds=UI_DEBOUNCE_FAST_SECONDS,
        settle_seconds=UI_FOREGROUND_SETTLE_SECONDS,
    ):
        return
    trace_action("todo-open-original-email", uid=uid, source="row-menu")
    _close_todo_row_more_actions(version_key)

    # Original Email is app-root owned. Clear the To-Do dialog slot first so
    # Task Actions cannot remain mounted underneath it. Close returns to the
    # To-Do workspace only; it does not reopen Task Actions.
    st.session_state.pop("todo_dialog_uid", None)
    st.session_state.pop("todo_dialog_mode", None)
    st.session_state.original_dialog_uid = uid
    st.session_state.original_dialog_return_workspace = "todo"
    st.session_state.pop("original_dialog_return_todo_uid", None)


def _open_task_recent_from_row_menu(task: dict, version_key: str) -> None:
    uid = str(task.get("uid") or "").strip()
    if not uid:
        return
    if not claim_foreground_interaction(
        f"todo-open-recent:{uid}",
        debounce_seconds=UI_DEBOUNCE_FAST_SECONDS,
        settle_seconds=UI_FOREGROUND_SETTLE_SECONDS,
    ):
        return
    trace_action("todo-view-recent-activity", uid=uid, source="row-menu")
    _close_todo_row_more_actions(version_key)

    # Recent Activity owns the To-Do root-dialog slot directly. Task Actions is
    # never mounted behind it.
    st.session_state.todo_dialog_mode = "history"
    st.session_state.todo_dialog_uid = uid


def _render_row_more_actions(task: dict, key_id: str) -> None:
    uid = str(task.get("uid") or "").strip()
    if not uid:
        return
    original_deleted = is_original_email_deleted(uid, "INBOX")
    version_key = f"todo_row_actions_popover_version_{key_id}"
    version = int(st.session_state.get(version_key, 0) or 0)

    with st.container(border=False, key=f"todo_row_more_actions_{key_id}"):
        with st.popover(
            "More actions",
            icon=":material/more_vert:",
            width="content",
            key=f"todo_row_actions_popover_{key_id}_v{version}",
        ):
            st.button(
                "View original email",
                icon=":material/open_in_new:",
                key=f"todo_row_original_{key_id}_v{version}",
                width="stretch",
                disabled=original_deleted,
                on_click=_open_task_original_from_row_menu,
                args=(task, version_key),
            )
            st.button(
                "View recent activity",
                icon=":material/history:",
                key=f"todo_row_recent_{key_id}_v{version}",
                width="stretch",
                on_click=_open_task_recent_from_row_menu,
                args=(task, version_key),
            )


def _render_task_row(task: dict) -> None:
    uid = str(task.get("uid") or "")
    key_id = _safe_key(uid)
    status = task["status"]
    priority = task["priority"]
    task_title = _display_task_title(task)
    subject = str(task.get("subject") or "No subject").strip()
    checkbox_key = f"todo_complete_{key_id}_{status.casefold().replace(' ', '_')}"

    # Inbox-style geometry: the completion checkbox sits in its own outside
    # gutter; the bordered/hoverable card begins with the task content.
    with st.container(key=f"todo_row_status-{task_status_slug(status)}_{key_id}"):
        col_checkbox, col_card = st.columns(
            [0.045, 0.955], gap="small", vertical_alignment="center"
        )
        with col_checkbox:
            expected_completed = status == "Completed"
            _prepare_row_completion_widget_state(
                key_id=key_id,
                status=status,
                checkbox_key=checkbox_key,
                expected_completed=expected_completed,
            )
            completed = bool(
                st.checkbox(
                    "Mark task complete",
                    value=expected_completed,
                    key=checkbox_key,
                    label_visibility="collapsed",
                )
            )

            pending_checkbox_keys = {
                str((st.session_state.get("todo_pending_cancel_transition") or {}).get("checkbox_key") or ""),
                str((st.session_state.get("todo_pending_reopen_transition") or {}).get("checkbox_key") or ""),
            }
            if completed != expected_completed and checkbox_key not in pending_checkbox_keys:
                trace_action(
                    "todo-row-complete-toggle",
                    completed=completed,
                    source="render-diff",
                )
                requested_status = "Completed" if completed else "In Progress"
                _save_status(task, requested_status, checkbox_key=checkbox_key)
                st.rerun()

        with col_card:
            selected_uid = str(st.session_state.get("todo_dialog_uid") or "").strip()
            original_uid = str(st.session_state.get("original_dialog_uid") or "").strip()
            original_returns_to_todo = (
                str(st.session_state.get("original_dialog_return_workspace") or "").strip().casefold()
                == "todo"
            )
            card_selected = uid == selected_uid or (original_returns_to_todo and uid == original_uid)
            card_key = f"todo_row_card_{key_id}{'__selected' if card_selected else ''}"
            with st.container(border=False, key=card_key):
                col_task, col_due, col_priority, col_status, col_actions = st.columns(
                    [0.54, 0.19, 0.10, 0.13, 0.04],
                    gap="small",
                    vertical_alignment="center",
                )
                with col_task:
                    activity_label = _task_activity_label(task)
                    activity_html = (
                        f'<span class="todo-row-task-activity">{html.escape(activity_label)}</span>'
                        if activity_label else ""
                    )
                    # Bold is the only row-level attention signal. The existing
                    # Created/Updated timestamp explains which kind of activity
                    # happened, so separate NEW/UPDATED badges are unnecessary.
                    has_unseen_attention = (
                        not bool(task.get("task_is_read", True))
                        or not bool(task.get("task_update_is_read", True))
                    )
                    attention_class = " has-unseen-attention" if has_unseen_attention else ""
                    st.markdown(
                        f'<div class="todo-row-task-copy{attention_class}">'
                        f'<div class="todo-row-task-title-line">'
                        f'<div class="todo-row-task-title">{html.escape(task_title)}</div>'
                        f'</div>'
                        f'<div class="todo-row-task-subject">'
                        f'<span class="todo-row-task-subject-text">{html.escape(subject)}</span>'
                        f'{activity_html}</div></div>',
                        unsafe_allow_html=True,
                    )
                with col_due:
                    with st.container(border=False, key=f"todo_due_cell_{key_id}"):
                        _render_due_cell(task, uid, key_id)
                with col_priority:
                    with st.container(border=False, key=f"todo_priority_cell_{key_id}"):
                        closed_priority_class = (
                            " is-closed-priority"
                            if status in {"Completed", "Cancelled"}
                            else ""
                        )
                        st.markdown(
                            f'<div class="todo-priority-cell"><span class="todo-pill priority-{priority.casefold()}{closed_priority_class}">{html.escape(priority)}</span></div>',
                            unsafe_allow_html=True,
                        )
                with col_status:
                    with st.container(border=False, key=f"todo_status_cell_{key_id}"):
                        _render_status_popover(task, key_id, status)
                with col_actions:
                    _render_row_more_actions(task, key_id)

                # Inbox/Summary-style invisible click surface. It sits below
                # the native Status/deadline/More-actions controls, so those
                # controls keep their own behavior while the rest of the card
                # opens the existing Task Actions dialog.
                with st.container(border=False, key=f"todo_row_open_target_{key_id}"):
                    st.button(
                        "Open task",
                        key=f"todo_row_open_button_{key_id}",
                        use_container_width=True,
                        on_click=_open_task_from_card,
                        args=(task,),
                    )


def _confirm_status_pill(status: str) -> str:
    # Render one compact status pill for confirmation dialogs.
    clean = _status(status)
    slug = task_status_slug(clean)
    return (
        f'<span class="todo-confirm-status-pill status-{html.escape(slug)}">'
        f'{html.escape(clean)}</span>'
    )


def _confirm_deadline_preview(task: dict, *, restore_closed: bool = False) -> datetime:
    # Return a truthful deadline preview without changing persisted data.
    if restore_closed:
        return _reopen_deadline_preview(task)
    return _parse_deadline(task)


def _confirm_deadline_line(
    deadline: datetime,
    *,
    action: str,
) -> tuple[str, str]:
    # Return copy + emphasis class for the deadline line in a confirmation.
    if deadline == datetime.max:
        if action == "cancel":
            return "No active deadline will need to be paused.", ""
        return "No deadline will be restored.", ""

    formatted = _format_deadline(deadline)
    if action == "cancel":
        return f"Deadline: {formatted} will be inactive while cancelled.", ""

    if deadline.date() < date.today():
        return f"Deadline: {formatted} will be restored and is already overdue.", " is-overdue"
    if deadline.date() == date.today():
        return f"Deadline: {formatted} will be restored as Due Today.", " is-due-today"
    return f"Deadline: {formatted} will be restored.", ""


def _render_status_confirmation_ui(
    *,
    variant: str,
    title: str,
    task_title: str,
    current_status: str,
    requested_status: str,
    description: str,
    info_primary: str,
    info_secondary: str,
    info_class: str = "",
) -> None:
    # Shared professional confirmation layout used by all task status gates.
    icon = {
        "reopen": "↻",
        "cancel": "!",
        "restore": "↻",
        "complete-cancelled": "✓",
    }.get(variant, "i")
    shell_class = f"todo-confirm-shell is-{variant}"
    st.markdown(
        f"""
        <div class="{shell_class}">
            <div class="todo-confirm-header">
                <div class="todo-confirm-icon" aria-hidden="true">{icon}</div>
                <div class="todo-confirm-heading-copy">
                    <div class="todo-confirm-title">{html.escape(title)}</div>
                    <div class="todo-confirm-subtitle">{html.escape(task_title)}</div>
                </div>
            </div>
            <div class="todo-confirm-transition">
                {_confirm_status_pill(current_status)}
                <span class="todo-confirm-arrow" aria-hidden="true">→</span>
                {_confirm_status_pill(requested_status)}
            </div>
            <div class="todo-confirm-description">{html.escape(description)}</div>
            <div class="todo-confirm-info{html.escape(info_class)}">
                <span class="todo-confirm-info-icon" aria-hidden="true">i</span>
                <div class="todo-confirm-info-copy">
                    <div>{html.escape(info_primary)}</div>
                    <div class="todo-confirm-deadline-line">{html.escape(info_secondary)}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _dismiss_cancel_transition_confirmation() -> None:
    # Clear stale pending state and restore the row checkbox to the persisted
    # status on the next render instead of mutating an instantiated widget key.
    pending = st.session_state.pop("todo_pending_cancel_transition", None) or {}
    checkbox_key = str(pending.get("checkbox_key") or "")
    if checkbox_key:
        current_status = _status(pending.get("current_status"))
        _queue_row_completion_widget_sync(
            checkbox_key, current_status == "Completed"
        )


def _dismiss_reopen_confirmation() -> None:
    # Keep Completed means persisted status remains Completed. Restore the row
    # checkbox on the next safe render so it cannot stay visually unchecked or
    # leak that stale value into a future lifecycle rerun.
    pending = st.session_state.pop("todo_pending_reopen_transition", None) or {}
    checkbox_key = str(pending.get("checkbox_key") or "")
    if checkbox_key:
        _queue_row_completion_widget_sync(checkbox_key, True)


@st.dialog(
    "Task status confirmation",
    width="medium",
    dismissible=False,
)
def _show_cancel_transition_confirmation() -> None:
    pending = st.session_state.get("todo_pending_cancel_transition") or {}
    task = pending.get("task")
    if not isinstance(task, dict):
        st.session_state.pop("todo_pending_cancel_transition", None)
        return

    current_status = _status(pending.get("current_status") or task.get("status"))
    requested_status = _status(pending.get("requested_status"))
    task_title = _display_task_title(task)

    if requested_status == "Cancelled":
        variant = "cancel"
        title = "Cancel completed task?" if current_status == "Completed" else "Cancel task?"
        if current_status == "Completed":
            description = (
                "The task will remain in task history but will no longer be treated as completed."
            )
            deadline = _confirm_deadline_preview(task, restore_closed=True)
            info_primary = "Completed action items will remain completed."
        else:
            description = (
                "Cancelling this task will remove it from active task tracking while keeping it in history."
            )
            deadline = _confirm_deadline_preview(task)
            info_primary = "Existing action-item progress will be preserved."
        info_secondary, info_class = _confirm_deadline_line(deadline, action="cancel")
        keep_label = f"Keep {current_status}"
        confirm_label = "Cancel Task"
    elif current_status == "Cancelled" and requested_status == "Completed":
        variant = "complete-cancelled"
        title = "Complete cancelled task?"
        description = (
            "This task is currently cancelled. Marking it completed will move it back to completed history."
        )
        deadline = _confirm_deadline_preview(task, restore_closed=True)
        info_primary = "All action items will be marked completed."
        if deadline == datetime.max:
            info_secondary, info_class = "No deadline will be reactivated.", ""
        else:
            info_secondary, info_class = (
                f"Deadline: {_format_deadline(deadline)} remains historical after completion.",
                "",
            )
        keep_label = "Keep Cancelled"
        confirm_label = "Mark Completed"
    else:
        variant = "restore"
        title = "Restore cancelled task?"
        description = "Restoring this task will return it to active task tracking."
        deadline = _confirm_deadline_preview(task, restore_closed=True)
        info_primary = "Completed action items will remain completed."
        info_secondary, info_class = _confirm_deadline_line(deadline, action="restore")
        keep_label = "Keep Cancelled"
        confirm_label = "Restore Task"

    _render_status_confirmation_ui(
        variant=variant,
        title=title,
        task_title=task_title,
        current_status=current_status,
        requested_status=requested_status,
        description=description,
        info_primary=info_primary,
        info_secondary=info_secondary,
        info_class=info_class,
    )

    keep_col, confirm_col = st.columns(2, gap="small")
    with keep_col:
        if st.button(
            keep_label,
            key="todo_cancel_transition_keep",
            use_container_width=True,
        ):
            checkbox_key = str(pending.get("checkbox_key") or "")
            if checkbox_key:
                _queue_row_completion_widget_sync(
                    checkbox_key, current_status == "Completed"
                )
            st.session_state.pop("todo_pending_cancel_transition", None)
            _arm_foreground_navigation_guard()
            st.rerun()

    with confirm_col:
        if st.button(
            confirm_label,
            key="todo_cancel_transition_confirm",
            type="primary",
            use_container_width=True,
        ):
            action_states = pending.get("action_states")
            st.session_state.pop("todo_pending_cancel_transition", None)
            _commit_status_change(
                task,
                requested_status,
                action_states=(
                    action_states if isinstance(action_states, list) else None
                ),
            )
            _arm_foreground_navigation_guard()
            st.rerun()


@st.dialog(
    "Task status confirmation",
    width="medium",
    dismissible=False,
)
def _show_reopen_confirmation() -> None:
    pending = st.session_state.get("todo_pending_reopen_transition") or {}
    task = pending.get("task")
    if not isinstance(task, dict):
        st.session_state.pop("todo_pending_reopen_transition", None)
        return

    current_status = _status(pending.get("current_status") or task.get("status"))
    requested_status = _status(pending.get("requested_status"))
    action_states = pending.get("action_states")
    preview_states = action_states if isinstance(action_states, list) else None
    deadline = _reopen_deadline_preview(task, preview_states)
    task_title = _display_task_title(task)
    info_secondary, info_class = _confirm_deadline_line(deadline, action="restore")

    _render_status_confirmation_ui(
        variant="reopen",
        title="Reopen completed task?",
        task_title=task_title,
        current_status=current_status,
        requested_status=requested_status,
        description="Reopening this task will restore it to active task tracking.",
        info_primary="Completed action items will remain completed.",
        info_secondary=info_secondary,
        info_class=info_class,
    )

    keep_col, confirm_col = st.columns(2, gap="small")
    with keep_col:
        if st.button(
            "Keep Completed",
            key="todo_reopen_transition_keep",
            use_container_width=True,
        ):
            checkbox_key = str(pending.get("checkbox_key") or "")
            if checkbox_key:
                _queue_row_completion_widget_sync(checkbox_key, True)
            st.session_state.pop("todo_pending_reopen_transition", None)
            _arm_foreground_navigation_guard()
            st.rerun()

    with confirm_col:
        if st.button(
            "Reopen Task",
            key="todo_reopen_transition_confirm",
            type="primary",
            use_container_width=True,
        ):
            st.session_state.pop("todo_pending_reopen_transition", None)
            _commit_status_change(
                task,
                requested_status,
                action_states=(
                    action_states if isinstance(action_states, list) else None
                ),
            )
            _arm_foreground_navigation_guard()
            st.rerun()


def _change_todo_page(direction: str) -> None:
    """Queue To-Do pagination; do not rebuild the table from a callback."""
    direction = str(direction or "").casefold()
    if direction not in {"prev", "next"}:
        return
    if not claim_foreground_interaction(
        "todo-pagination", debounce_seconds=UI_DEBOUNCE_PAGINATION_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("todo-pagination-click", direction=direction)
    st.session_state.todo_pending_page_direction = direction


def _apply_pending_todo_pagination() -> None:
    direction = str(
        st.session_state.pop("todo_pending_page_direction", "") or ""
    ).casefold()
    if direction not in {"prev", "next"}:
        return
    trace_action("todo-pagination-apply", direction=direction)
    page_size = int(
        st.session_state.get("todo_page_size", TODO_PAGE_SIZE) or TODO_PAGE_SIZE
    )
    offset = max(0, int(st.session_state.get("todo_offset", 0) or 0))
    st.session_state.todo_offset = (
        offset + page_size if direction == "next" else max(0, offset - page_size)
    )
    st.session_state.todo_list_scroll_reset_pending = True


def render_todo_tab() -> None:
    # Apply queued foreground state before Search/Filter widgets exist in this
    # run. Refresh clears everything; a later accepted dashboard metric then
    # becomes the authoritative filter without callback-time widget mutation.
    _apply_pending_todo_refresh()
    _apply_pending_dashboard_metric_filter()
    summaries = st.session_state.get("summaries", [])
    tasks = _task_records(summaries)

    st.session_state.setdefault("todo_search_query", "")
    st.session_state.setdefault("todo_status_filter", None)
    st.session_state.setdefault("todo_priority_filter", None)
    st.session_state.setdefault("todo_deadline_filter", None)
    st.session_state.setdefault("todo_action_needed_only", False)
    st.session_state.setdefault("todo_sort_by", "latest_activity")
    st.session_state.setdefault("todo_offset", 0)
    st.session_state.setdefault("todo_page_size", TODO_PAGE_SIZE)
    _ensure_todo_filter_state()
    _apply_pending_todo_pagination()
    scroll_reset_requested = bool(
        st.session_state.pop("todo_list_scroll_reset_pending", False)
    )

    confirmation_kind = str(
        st.session_state.pop("todo_status_confirmation_armed", "") or ""
    )
    if (
        confirmation_kind == "cancel"
        and st.session_state.get("todo_pending_cancel_transition")
    ):
        _show_cancel_transition_confirmation()
    elif (
        confirmation_kind == "reopen"
        and st.session_state.get("todo_pending_reopen_transition")
    ):
        _show_reopen_confirmation()
    else:
        # A pending transition without a fresh arm is stale state left by an
        # unrelated rerun/tab switch. Clear it instead of opening a modal.
        if st.session_state.get("todo_pending_cancel_transition"):
            _dismiss_cancel_transition_confirmation()
        if st.session_state.get("todo_pending_reopen_transition"):
            _dismiss_reopen_confirmation()

    # Restore the old working keyed structure. Its CSS already handles the
    # viewport, fixed table shell, bottom border, and rows-only scrollbar.
    with st.container(border=False, key="todo_workspace"):
        _render_header(tasks)

        st.session_state.pop("todo_notice", None)

        if not tasks:
            _render_empty_state(
                "No extracted tasks yet",
                "Generate an AI summary from an email containing a real action item. It will appear here automatically.",
            )
            if scroll_reset_requested:
                emit_scroll_reset_marker("todo")
            return

        _render_toolbar()
        visible_tasks = _apply_filters(tasks)
        total_visible = len(visible_tasks)

        page_size = TODO_PAGE_SIZE
        st.session_state.todo_page_size = page_size
        offset = max(0, int(st.session_state.get("todo_offset", 0)))
        if total_visible == 0:
            offset = 0
        elif offset >= total_visible:
            offset = ((total_visible - 1) // page_size) * page_size
        st.session_state.todo_offset = offset

        page_tasks = visible_tasks[offset: offset + page_size]
        start = offset + 1 if page_tasks else 0
        end = offset + len(page_tasks)
        can_prev = offset > 0
        can_next = offset + page_size < total_visible

        # Keep the stable pagination shell, adding the same compact refresh
        # control used by the other list workspaces.
        with st.container(key="todo_pagination_row"):
            col_range, col_refresh, col_prev, col_next, _col_spacer = st.columns(
                [2.8, 0.55, 0.55, 0.55, 11.45], gap="small"
            )
            with col_range:
                st.markdown(
                    f'<div class="todo-results-label">'
                    f'Showing {start}–{end} of {total_visible:,} tasks</div>',
                    unsafe_allow_html=True,
                )
            with col_refresh:
                st.button(
                    "↻",
                    key="refresh_todo_icon",
                    use_container_width=False,
                    on_click=_refresh_todo_list,
                )
            with col_prev:
                st.button(
                    "‹",
                    key="todo_prev_page",
                    use_container_width=False,
                    disabled=not can_prev,
                    on_click=_change_todo_page,
                    args=("prev",),
                )
            with col_next:
                st.button(
                    "›",
                    key="todo_next_page",
                    use_container_width=False,
                    disabled=not can_next,
                    on_click=_change_todo_page,
                    args=("next",),
                )

        # Keep the large task table mounted with one stable identity. Re-keying
        # the whole table during dashboard/filter/page clicks was a DOM teardown
        # race. Browser-side scroll reset keeps PaginationTop without remounting.
        scroll_epoch = int(st.session_state.get("todo_list_scroll_epoch", 0) or 0)
        task_list_key = f"todo_task_list_{scroll_epoch}"

        # Keep the exact list-shell geometry, but give the rows and empty state
        # different keyed subtree identities. Reusing the same task-list key for
        # both modes let Streamlit retain row children when a dashboard filter
        # suddenly returned zero results, producing rows + empty state together.
        # The key changes ONLY on rows <-> empty transitions, not on ordinary
        # pagination/filter changes with rows, so the stable-list white/stale
        # protection remains intact.
        with st.container(key="todo_list_shell"):
            if not page_tasks:
                with st.container(key=f"{task_list_key}_empty"):
                    _render_empty_state(
                        "No tasks match these filters",
                        "Change the search or active filters to see other extracted tasks.",
                    )
                if scroll_reset_requested:
                    emit_scroll_reset_marker("todo")
                return

            _render_list_header()
            with st.container(key=f"{task_list_key}_rows"):
                for task in page_tasks:
                    _render_task_row(task)

        if scroll_reset_requested:
            emit_scroll_reset_marker("todo")
