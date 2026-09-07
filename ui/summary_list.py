# Filterable and paginated AI Summary list with an Inbox-style UI.
import html as html_lib

from datetime import datetime
from email.utils import parsedate_to_datetime

import streamlit as st

from config import (
    SUMMARY_LIST_HEIGHT,
    SUMMARY_PAGE_SIZE,
    UI_DEBOUNCE_FILTER_SECONDS,
    UI_DEBOUNCE_PAGINATION_SECONDS,
    UI_DEBOUNCE_REFRESH_SECONDS,
    UI_FOREGROUND_SETTLE_SECONDS,
)

from services.ui_interaction_service import (
    arm_foreground_interaction,
    claim_foreground_interaction,
    workspace_callback_allowed,
    workspace_interaction_allowed,
)
from services.white_stale_trace_service import trace_action

from storage.summary_store import SUMMARY_FOLDER
from ui.inbox import _display_sender, _inbox_time_label, _sender_avatar
from ui.summary_metrics import is_task_ready
from ui.scripts import emit_scroll_reset_marker
from services.task_status import normalize_task_status, task_status_filter_key, task_status_slug



def _matches_search(item: dict, query: str) -> bool:
    text = " ".join([
        str(item.get("subject", "") or ""),
        str(item.get("from", "") or ""),
        str(item.get("summary", "") or ""),
        str(item.get("priority", "") or ""),
        str(item.get("status", "") or ""),
    ]).casefold()
    return not query or query.casefold() in text


def _status_label_and_class(status: str) -> tuple[str, str]:
    label = normalize_task_status(status)
    return label.upper(), f"status-{task_status_slug(label)}"


def _normalized_status(status: str) -> str:
    return task_status_filter_key(status)


def _priority_rank(priority: str) -> int:
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return ranks.get(str(priority or "medium").strip().casefold(), 4)


def _summary_type_key(item: dict) -> str:
    # Return the user-facing summary type used by cards and filters.
    is_batch = (
        str(item.get("record_type") or "").strip().casefold() == "batch"
        or str(item.get("generation_mode") or "").strip().casefold() == "batch"
    )
    return "batch" if is_batch else "individual"


def _timestamp_value(raw) -> float:
    if isinstance(raw, datetime):
        value = raw
    else:
        text = str(raw or "").strip()
        if not text:
            return 0.0
        try:
            value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            try:
                value = parsedate_to_datetime(text)
            except (TypeError, ValueError, OverflowError):
                return 0.0
    try:
        return value.timestamp()
    except (OSError, OverflowError, ValueError):
        return 0.0


def _summary_date_timestamp(item: dict, basis: str = "activity") -> float:
    # Summary-list time is based on summary activity by default. Creation time
    # stays immutable, while email date remains available as an explicit sort.
    basis = str(basis or "activity").strip().casefold()
    if basis == "created":
        raw = item.get("summary_created_at") or item.get("generated_at")
    elif basis == "email_date":
        raw = item.get("date") or item.get("date_display")
    else:
        raw = (
            item.get("summary_activity_at")
            or item.get("summary_created_at")
            or item.get("generated_at")
            or item.get("date")
            or item.get("date_display")
        )
    return _timestamp_value(raw)


def _summary_card_time_label(item: dict) -> str:
    # Cards always show the latest summary-content activity time, regardless of
    # which optional arrange mode the user selected.
    activity = (
        item.get("summary_activity_at")
        or item.get("summary_created_at")
        or item.get("generated_at")
    )
    if activity:
        return _inbox_time_label({"date": activity})
    return _inbox_time_label(item)


def _ensure_summary_filter_state() -> None:
    # Initialize the new independent AI Summary filter state.
    #
    # The legacy ``summary_filter`` value is migrated once so an existing hot
    # Streamlit session keeps its active choice after this update.
    legacy = str(st.session_state.get("summary_filter") or "all").strip().casefold()

    if "summary_task_filter" not in st.session_state:
        st.session_state.summary_task_filter = (
            "with_task" if legacy == "with_task"
            else "summary_only" if legacy == "summary_only"
            else None
        )
    if "summary_unread_only" not in st.session_state:
        st.session_state.summary_unread_only = legacy == "unread"
    if "summary_type_filter" not in st.session_state:
        st.session_state.summary_type_filter = None
    if "summary_status_filter" not in st.session_state:
        status_map = {
            "status_pending": "not_started",
            "status_not_started": "not_started",
            "status_in_progress": "in_progress",
            "status_on_hold": "on_hold",
            "status_complete": "completed",
            "status_completed": "completed",
            "status_cancelled": "cancelled",
            "status_canceled": "cancelled",
        }
        st.session_state.summary_status_filter = status_map.get(legacy)
    if "summary_priority_filter" not in st.session_state:
        priority_map = {
            "critical": "critical",
            "high": "high",
            "priority_critical": "critical",
            "priority_high": "high",
            "priority_medium": "medium",
            "priority_low": "low",
        }
        st.session_state.summary_priority_filter = priority_map.get(legacy)

    arrange_by = str(st.session_state.get("summary_arrange_by") or "activity").casefold()
    sort_order = str(st.session_state.get("summary_sort_order") or "newest").casefold()
    legacy_sort_map = {"desc": "newest", "asc": "oldest"}
    sort_order = legacy_sort_map.get(sort_order, sort_order)

    # Latest Activity/Newest is the new default. Hot Streamlit sessions can keep
    # the former Email Date/legacy sort after code reload, which makes an updated
    # thread look as if it did not move. Migrate once, then respect any explicit
    # Arrange By / Sort choice made by the user.
    policy_version = int(st.session_state.get("summary_activity_sort_policy_version") or 0)
    user_selected_sort = bool(st.session_state.get("summary_sort_user_selected", False))
    if policy_version < 2 and not user_selected_sort:
        arrange_by = "activity"
        sort_order = "newest"

    # Legacy "date" meant the old chronological source-email view.
    if arrange_by == "date":
        arrange_by = "activity"
    st.session_state.summary_arrange_by = (
        arrange_by
        if arrange_by in {"activity", "created", "email_date", "priority"}
        else "activity"
    )
    st.session_state.summary_sort_order = (
        sort_order if sort_order in {"newest", "oldest"} else "newest"
    )
    st.session_state.summary_activity_sort_policy_version = 2
    st.session_state.summary_filter = "all"


def _active_summary_filter_count() -> int:
    # Return the number of active AI Summary filters.
    #
    # Arrange By and Sort are view-order controls, so they intentionally do not
    # contribute to the filter count, matching the To-Do List behavior.
    return sum(
        (
            bool(st.session_state.get("summary_task_filter")),
            bool(st.session_state.get("summary_unread_only", False)),
            bool(st.session_state.get("summary_type_filter")),
            bool(st.session_state.get("summary_status_filter")),
            bool(st.session_state.get("summary_priority_filter")),
        )
    )


def _summary_filters_are_clear() -> bool:
    return _active_summary_filter_count() == 0


def _handle_summary_search_change():
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("summary"):
        trace_action("workspace-callback-ignored", source="summary", callback="_handle_summary_search_change")
        return
    trace_action("summary-search-change", query_len=len(str(st.session_state.get("summary_search_query", "") or "")))
    arm_foreground_interaction()
    st.session_state.pop("summary_pending_page_direction", None)
    st.session_state.summary_offset = 0
    st.session_state.selected_summary_uid = None
    st.session_state.summary_list_scroll_reset_pending = True


def _process_summary_search_value_without_callback(query: str) -> None:
    """Handle Summary search changes in the normal render rerun.

    The search box intentionally has no ``on_change`` callback. Streamlit can
    fire callbacks for a widget while its old workspace tree is being removed;
    processing the already-updated Session State here avoids that synthetic
    cross-workspace callback path.
    """
    current = str(query or "")
    tracker_key = "_summary_search_processed_value"
    if tracker_key not in st.session_state:
        st.session_state[tracker_key] = current
        return

    previous = str(st.session_state.get(tracker_key, "") or "")
    if current == previous:
        return

    if not workspace_interaction_allowed():
        st.session_state[tracker_key] = current
        return

    st.session_state[tracker_key] = current
    trace_action("summary-search-change", query_len=len(current))
    arm_foreground_interaction()
    st.session_state.pop("summary_pending_page_direction", None)
    st.session_state.summary_offset = 0
    st.session_state.selected_summary_uid = None
    st.session_state.summary_list_scroll_reset_pending = True


def _finish_summary_filter_change() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="workspace", callback="session-transition")
        return
    if not workspace_callback_allowed("summary"):
        trace_action("workspace-callback-ignored", source="summary", callback="_finish_summary_filter_change")
        return
    arm_foreground_interaction()
    st.session_state.summary_filter = "all"
    st.session_state.pop("summary_pending_page_direction", None)
    st.session_state.summary_offset = 0
    st.session_state.selected_summary_uid = None
    st.session_state.summary_list_scroll_reset_pending = True


def _reset_summary_filters() -> None:
    st.session_state.summary_task_filter = None
    st.session_state.summary_unread_only = False
    st.session_state.summary_type_filter = None
    st.session_state.summary_status_filter = None
    st.session_state.summary_priority_filter = None
    st.session_state.summary_arrange_by = "activity"
    st.session_state.summary_sort_order = "newest"
    st.session_state.summary_sort_user_selected = False
    _finish_summary_filter_change()


def _set_summary_menu_value(state_key: str, value) -> None:
    if not claim_foreground_interaction(
        "summary-filter", debounce_seconds=UI_DEBOUNCE_FILTER_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("summary-filter-detail", state_key=state_key, value=value)
    if state_key == "summary_reset_filters":
        _reset_summary_filters()
        return

    if state_key == "summary_unread_only":
        st.session_state.summary_unread_only = not bool(
            st.session_state.get("summary_unread_only", False)
        )
    elif state_key in {"summary_arrange_by", "summary_sort_order"}:
        # Arrange and Sort always keep exactly one selected option. Preserve the
        # explicit choice instead of reapplying the default on later reruns.
        st.session_state[state_key] = value
        st.session_state.summary_sort_user_selected = True
    else:
        # Task presence, Summary Type, Status, and Priority each allow at most one selection.
        current_value = st.session_state.get(state_key)
        st.session_state[state_key] = None if current_value == value else value

    _finish_summary_filter_change()


def _menu_button(
    label: str,
    key: str,
    state_key: str,
    value,
    *,
    active: bool | None = None,
) -> None:
    if active is None:
        if state_key == "summary_unread_only":
            active = bool(st.session_state.get(state_key, False))
        else:
            active = st.session_state.get(state_key) == value

    # Keep every item secondary. The `_selected` key suffix is the stable CSS
    # hook for the original light-blue selected state across Streamlit versions.
    visual_key = f"{key}_selected" if active else f"{key}_normal"
    st.button(
        label,
        key=visual_key,
        type="secondary",
        use_container_width=True,
        on_click=_set_summary_menu_value,
        args=(state_key, value),
    )


def _menu_section(title: str) -> None:
    st.markdown(
        '<div class="inbox-filter-menu-divider"></div>'
        f'<div class="inbox-filter-menu-title">{title}</div>'
        '<div class="inbox-filter-menu-spacer"></div>',
        unsafe_allow_html=True,
    )


def _render_summary_filter_menu():
    _ensure_summary_filter_state()
    filter_count = _active_summary_filter_count()
    with st.container(key="summary_filter_popover"):
        label = f"Filter ({filter_count})" if filter_count else "Filter"
        with st.popover(
            label,
            key="summary_filter_menu",
            icon=":material/filter_alt:",
            use_container_width=True,
        ):
            st.markdown(
                '<div class="summary-filter-menu-marker" aria-hidden="true"></div>'
                '<div class="inbox-filter-menu-title">FILTER</div>'
                '<div class="inbox-filter-menu-spacer"></div>',
                unsafe_allow_html=True,
            )
            _menu_button(
                "All Summaries",
                "summary_filter_item_all",
                "summary_reset_filters",
                "all",
                active=_summary_filters_are_clear(),
            )
            _menu_button(
                "With Task",
                "summary_filter_item_with_task",
                "summary_task_filter",
                "with_task",
            )
            _menu_button(
                "Summary Only",
                "summary_filter_item_summary_only",
                "summary_task_filter",
                "summary_only",
            )
            _menu_button(
                "Unread",
                "summary_filter_item_unread",
                "summary_unread_only",
                True,
            )

            _menu_section("SUMMARY TYPE")
            _menu_button(
                "Individual",
                "summary_filter_item_type_individual",
                "summary_type_filter",
                "individual",
            )
            _menu_button(
                "Batch",
                "summary_filter_item_type_batch",
                "summary_type_filter",
                "batch",
            )

            _menu_section("STATUS")
            for value, label in (
                ("not_started", "Not Started"),
                ("in_progress", "In Progress"),
                ("on_hold", "On Hold"),
                ("completed", "Completed"),
                ("cancelled", "Cancelled"),
            ):
                _menu_button(
                    label,
                    f"summary_filter_item_status_{value}",
                    "summary_status_filter",
                    value,
                )

            _menu_section("PRIORITY")
            for value, label in [
                ("critical", "Critical"),
                ("high", "High"),
                ("medium", "Medium"),
                ("low", "Low"),
            ]:
                _menu_button(
                    label,
                    f"summary_filter_item_priority_{value}",
                    "summary_priority_filter",
                    value,
                )

            _menu_section("ARRANGE BY")
            _menu_button(
                "Latest Activity",
                "summary_filter_item_arrange_activity",
                "summary_arrange_by",
                "activity",
            )
            _menu_button(
                "Created Date",
                "summary_filter_item_arrange_created",
                "summary_arrange_by",
                "created",
            )
            _menu_button(
                "Email Date",
                "summary_filter_item_arrange_email_date",
                "summary_arrange_by",
                "email_date",
            )
            _menu_button(
                "Priority",
                "summary_filter_item_arrange_priority",
                "summary_arrange_by",
                "priority",
            )

            _menu_section("SORT")
            _menu_button(
                "Newest First",
                "summary_filter_item_sort_newest",
                "summary_sort_order",
                "newest",
            )
            _menu_button(
                "Oldest First",
                "summary_filter_item_sort_oldest",
                "summary_sort_order",
                "oldest",
            )


def _apply_summary_view_options(
    summaries: list[dict], filter_key: str | None, query: str
) -> list[dict]:
    # Apply independent type, unread, status, and priority filters.
    #
    # ``filter_key`` is retained for compatibility with older callers; all active
    # choices now live in dedicated session-state keys.
    del filter_key
    _ensure_summary_filter_state()
    visible = [item for item in summaries if _matches_search(item, query)]

    task_filter = st.session_state.get("summary_task_filter")
    if task_filter == "with_task":
        visible = [item for item in visible if is_task_ready(item)]
    elif task_filter == "summary_only":
        visible = [item for item in visible if not is_task_ready(item)]

    summary_type_filter = st.session_state.get("summary_type_filter")
    if summary_type_filter in {"individual", "batch"}:
        visible = [
            item for item in visible
            if _summary_type_key(item) == summary_type_filter
        ]

    if bool(st.session_state.get("summary_unread_only", False)):
        # Opening an Unviewed summary marks it viewed immediately, but the
        # currently selected card must stay in place until the user chooses
        # another summary or leaves the Unviewed filter. Keep only that selected
        # read item; every other viewed summary remains filtered out.
        selected_uid = str(st.session_state.get("selected_summary_uid") or "")
        visible = [
            item for item in visible
            if (not item.get("is_read", False))
            or (selected_uid and str(item.get("uid") or "") == selected_uid)
        ]

    status_filter = st.session_state.get("summary_status_filter")
    if status_filter:
        visible = [
            item for item in visible
            if is_task_ready(item)
            and _normalized_status(item.get("status", "Not Started")) == status_filter
        ]

    priority_filter = st.session_state.get("summary_priority_filter")
    if priority_filter:
        visible = [
            item for item in visible
            if str(item.get("priority") or "Medium").strip().casefold()
            == priority_filter
        ]

    arrange_by = st.session_state.get("summary_arrange_by", "activity")
    sort_order = st.session_state.get("summary_sort_order", "newest")
    newest_first = sort_order == "newest"

    if arrange_by == "priority":
        # Keep Critical → High → Medium → Low as the main grouping. Latest
        # summary-content activity orders cards inside each priority group.
        visible.sort(
            key=lambda item: _summary_date_timestamp(item, "activity"),
            reverse=newest_first,
        )
        visible.sort(key=lambda item: _priority_rank(item.get("priority")))
    else:
        basis = arrange_by if arrange_by in {"activity", "created", "email_date"} else "activity"
        visible.sort(
            key=lambda item: _summary_date_timestamp(item, basis),
            reverse=newest_first,
        )

    return visible


def _reload_summaries():
    store = st.session_state.get("summary_store")
    if store is None:
        return

    refreshed = store.load_all(SUMMARY_FOLDER)
    st.session_state.summaries = refreshed
    st.session_state.summary_offset = 0

    selected_uid = str(st.session_state.get("selected_summary_uid") or "")
    valid_uids = {str(item.get("uid", "")) for item in refreshed}
    if selected_uid not in valid_uids:
        st.session_state.selected_summary_uid = None



def _change_summary_page(direction: str) -> None:
    """Queue Summary pagination; do not re-key UI from the callback."""
    direction = str(direction or "").casefold()
    if direction not in {"prev", "next"}:
        return
    if not claim_foreground_interaction(
        "summary-pagination", debounce_seconds=UI_DEBOUNCE_PAGINATION_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("summary-pagination-click", direction=direction)
    st.session_state.summary_pending_page_direction = direction


def _apply_pending_summary_pagination() -> None:
    direction = str(
        st.session_state.pop("summary_pending_page_direction", "") or ""
    ).casefold()
    if direction not in {"prev", "next"}:
        return
    trace_action("summary-pagination-apply", direction=direction)
    page_size = int(
        st.session_state.get("summary_page_size", SUMMARY_PAGE_SIZE)
        or SUMMARY_PAGE_SIZE
    )
    offset = max(0, int(st.session_state.get("summary_offset", 0) or 0))
    st.session_state.summary_offset = (
        offset + page_size if direction == "next" else max(0, offset - page_size)
    )
    st.session_state.summary_list_scroll_reset_pending = True


def _refresh_summary_list() -> None:
    if not claim_foreground_interaction(
        "summary-refresh", debounce_seconds=UI_DEBOUNCE_REFRESH_SECONDS, settle_seconds=UI_FOREGROUND_SETTLE_SECONDS
    ):
        return
    trace_action("summary-refresh-click")
    st.session_state.summary_refresh_reset_pending = True
    _reload_summaries()
    st.session_state.summary_list_scroll_reset_pending = True


def render_summary_list(summaries: list[dict], on_open=None):
    # Consume page intent only after the stable root render reaches this tab.
    _apply_pending_summary_pagination()
    # Keep one stable Summary list DOM across page/filter/search reruns.
    # The browser-side interaction guard scrolls the existing list to top.
    scroll_reset_requested = bool(
        st.session_state.pop("summary_list_scroll_reset_pending", False)
    )
    scroll_epoch = int(st.session_state.get("summary_list_scroll_epoch", 0) or 0)
    scroll_key = f"summary_list_scroll_{scroll_epoch}"
    with st.container(key="summary_toolbar"):
        with st.container(key="summary_search_row"):
            col_query, col_filter = st.columns([0.80, 0.20], gap="small")
            with col_query:
                query = st.text_input(
                    "Search summaries",
                    key="summary_search_query",
                    placeholder="Search summaries",
                    label_visibility="collapsed",
                ).strip()
                _process_summary_search_value_without_callback(query)
            with col_filter:
                _render_summary_filter_menu()

        filter_key = str(
            st.session_state.get("summary_filter") or "all"
        ).strip().casefold()
        st.session_state.summary_filter = filter_key
        visible_summaries = _apply_summary_view_options(summaries, filter_key, query)
        total_visible = len(visible_summaries)

        page_size = SUMMARY_PAGE_SIZE
        st.session_state.summary_page_size = page_size
        offset = max(0, int(st.session_state.get("summary_offset", 0)))
        if total_visible == 0:
            offset = 0
        elif offset >= total_visible:
            offset = ((total_visible - 1) // page_size) * page_size
        st.session_state.summary_offset = offset

        page_items = visible_summaries[offset: offset + page_size]
        start = offset + 1 if page_items else 0
        end = offset + len(page_items)
        can_prev = offset > 0
        can_next = offset + page_size < total_visible

        with st.container(key="summary_pagination_row"):
            col_range, col_refresh, col_prev, col_next = st.columns(
                [0.64, 0.12, 0.12, 0.12], gap=None
            )
            with col_range:
                st.markdown(
                    f'<div class="item-meta inbox-range-label pagination-results-label">'
                    f'Showing {start}–{end} of {total_visible:,} summaries</div>',
                    unsafe_allow_html=True,
                )
            with col_refresh:
                st.button(
                    "↻",
                    key="refresh_summary_icon",
                    use_container_width=True,
                    on_click=_refresh_summary_list,
                )
            with col_prev:
                st.button(
                    "‹",
                    key="summary_prev_page",
                    use_container_width=True,
                    disabled=not can_prev,
                    on_click=_change_summary_page,
                    args=("prev",),
                )
            with col_next:
                st.button(
                    "›",
                    key="summary_next_page",
                    use_container_width=True,
                    disabled=not can_next,
                    on_click=_change_summary_page,
                    args=("next",),
                )

    if not page_items:
        message = (
            "No saved summaries match the current search or filter."
            if summaries
            else "Generate a summary from selected Inbox emails to see it here."
        )
        with st.container(
            height=SUMMARY_LIST_HEIGHT, border=False, key=scroll_key
        ):
            st.markdown(
                f'<div class="empty-state inbox-empty-state">{message}</div>',
                unsafe_allow_html=True,
            )
        if scroll_reset_requested:
            emit_scroll_reset_marker("summary")
        return None

    with st.container(
        height=SUMMARY_LIST_HEIGHT, border=False, key=scroll_key
    ):
        for item in page_items:
            uid = str(item.get("uid", ""))
            selected = str(st.session_state.get("selected_summary_uid") or "") == uid
            unread = not item.get("is_read", False)
            priority = str(item.get("priority") or "Medium").strip()
            priority_key = priority.casefold()
            if priority_key not in {"critical", "high", "medium", "low"}:
                priority_key = "medium"
            status_label, status_class = _status_label_and_class(
                item.get("status", "Not Started")
            )
            # Closed tasks are not active workload. Use a dedicated priority
            # variant instead of stacking it with priority-low/high/etc.; this
            # prevents existing priority color rules from winning in the CSS
            # cascade. Reopened tasks automatically return to their real
            # priority variant on the next render.
            priority_variant = (
                "priority-closed"
                if status_label in {"COMPLETED", "CANCELLED"}
                else f"priority-{priority_key}"
            )
            sender = item.get("from", "")
            sender_text = _display_sender(sender)

            # Card UI only shows the summary type. Manual/automatic generation
            # is processing metadata and does not need to occupy card space.
            is_batch = _summary_type_key(item) == "batch"
            # Status/Priority belong to an actionable individual summary, not to
            # the parent Batch container. Summary-only individual records also
            # stay badge-free.
            has_task_data = (not is_batch) and is_task_ready(item)
            summary_type = "BATCH" if is_batch else "INDIVIDUAL"
            if is_batch:
                secondary_text = "Multiple emails"
                avatar_source = "Multiple emails"
            else:
                secondary_text = sender_text
                avatar_source = sender

            avatar_initial, avatar_class = _sender_avatar(avatar_source)
            subject = item.get("subject") or "(No Subject)"
            time_label = _summary_card_time_label(item)
            selected_class = " is-selected" if selected else ""
            unread_class = " is-summary-unread" if unread else ""
            # Keep the badge wrapper structurally stable for every card. Empty
            # placeholder pills preserve the clickable-card DOM/layout without
            # showing parent Batch or Summary-Only task metadata.
            if has_task_data:
                badge_markup = (
                    '<div class="summary-list-badge-stack">'
                    f'<span class="summary-list-status-pill {status_class}">{html_lib.escape(status_label)}</span>'
                    f'<span class="summary-list-priority-pill {priority_variant}">{html_lib.escape(priority.upper())}</span>'
                    '</div>'
                )
            else:
                badge_markup = (
                    '<div class="summary-list-badge-stack is-empty" aria-hidden="true">'
                    '<span class="summary-list-status-pill status-placeholder"></span>'
                    '<span class="summary-list-priority-pill priority-placeholder"></span>'
                    '</div>'
                )

            with st.container(key=f"summary_card_{uid}"):
                st.markdown(
                    f"""
                    <div class="summary-row-shell">
                        <span class="summary-static-checkbox" aria-hidden="true"></span>
                        <div class="mail-row-card summary-mail-row{selected_class}{unread_class}">
                            <div class="mail-row-avatar {avatar_class}">
                                {html_lib.escape(avatar_initial)}
                            </div>
                            <div class="mail-row-copy">
                                <div class="mail-row-subject">{html_lib.escape(subject)}</div>
                                <div class="mail-row-sender summary-source-line">
                                    <span class="summary-generation-pill summary-type-pill">{html_lib.escape(summary_type)}</span>
                                    <span>{html_lib.escape(secondary_text)}</span>
                                </div>
                            </div>
                            <div class="mail-row-time">{html_lib.escape(time_label)}</div>
                            {badge_markup}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if callable(on_open):
                    st.button(
                        "Open summary",
                        key=f"summary_item_{uid}",
                        use_container_width=True,
                        on_click=on_open,
                        args=(uid,),
                    )
                else:
                    clicked = st.button(
                        "Open summary",
                        key=f"summary_item_{uid}",
                        use_container_width=True,
                    )
                    if clicked:
                        arm_foreground_interaction()
                        return uid

            # Use a real Streamlit element for the gap. Margin on the keyed
            # card wrapper can be swallowed by Streamlit's layout wrappers.
            st.markdown(
                '<div class="summary-card-gap" aria-hidden="true"></div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            '<div class="inbox-list-bottom-spacer" aria-hidden="true"></div>',
            unsafe_allow_html=True,
        )
    if scroll_reset_requested:
        emit_scroll_reset_marker("summary")
    return None
