# Persistent MailMind notification history and global top-right bell.
from __future__ import annotations

import hashlib
import html
from datetime import datetime

import streamlit as st

from config import NOTIFICATION_CENTER_MAX_VISIBLE, NOTIFICATION_CENTER_PREVIEW_VISIBLE

from services.white_stale_trace_service import trace_action
from services.ui_interaction_service import workspace_interaction_allowed

from storage.notification_store import NotificationStore


def _account_key() -> str:
    return str(st.session_state.get("email_address") or "").strip().casefold()


def _get_store() -> NotificationStore | None:
    # Return one account-bound store for the current Streamlit session.
    account = _account_key()
    if not account:
        return None

    store = st.session_state.get("notification_store")
    if isinstance(store, NotificationStore) and store.account_email == account:
        return store

    if isinstance(store, NotificationStore):
        store.close()
    store = NotificationStore(account)
    st.session_state.notification_store = store
    return store


def _current_history() -> list[dict]:
    store = _get_store()
    return store.load_all(NOTIFICATION_CENTER_MAX_VISIBLE) if store is not None else []


def _notification_id(title: str, message: str, event_type: str, entity_id: str) -> str:
    raw = (
        f"{event_type}|{entity_id}|{title}|{message}|"
        f"{datetime.now().isoformat(timespec='microseconds')}"
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]


def record_notification(
    *,
    title: str,
    message: str,
    kind: str = "info",
    workspace: str = "",
    details: list[str] | tuple[str, ...] | None = None,
    event_type: str = "",
    entity_id: str = "",
) -> None:
    # Persist one detailed notification for the signed-in account.
    #
    # The toast stays concise. The notification center receives the richer
    # context and persists it in SQLite, so refresh/logout do not erase history.
    # Immediate semantic duplicates caused by Streamlit reruns are ignored by the
    # store.
    clean_title = str(title or "Notification").strip() or "Notification"
    clean_message = str(message or "").strip()
    if not clean_message:
        return

    clean_details = [
        str(value or "").strip()
        for value in (details or [])
        if str(value or "").strip()
    ]
    clean_kind = str(kind or "info").strip().casefold()
    clean_workspace = str(workspace or "").strip().casefold()
    clean_event_type = str(event_type or "").strip().casefold()
    clean_entity_id = str(entity_id or "").strip()
    created_at = datetime.now().isoformat(timespec="seconds")

    store = _get_store()
    if store is None:
        return
    store.add(
        notification_id=_notification_id(
            clean_title, clean_message, clean_event_type, clean_entity_id
        ),
        title=clean_title,
        message=clean_message,
        kind=clean_kind,
        workspace=clean_workspace,
        details=clean_details,
        event_type=clean_event_type,
        entity_id=clean_entity_id,
        created_at=created_at,
    )


def _relative_time(value: str) -> str:
    try:
        created = datetime.fromisoformat(str(value or ""))
    except ValueError:
        return "Recently"
    seconds = max(0, int((datetime.now() - created).total_seconds()))
    if seconds < 45:
        return "Just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hr ago" if hours == 1 else f"{hours} hrs ago"
    days = hours // 24
    if days < 7:
        return f"{days} day ago" if days == 1 else f"{days} days ago"
    return created.strftime("%b %d, %Y · %I:%M %p").replace(" 0", " ")


def _event_icon(item: dict) -> tuple[str, str]:
    event_type = str(item.get("event_type") or "").casefold()
    kind = str(item.get("kind") or "info").casefold()
    workspace = str(item.get("workspace") or "").casefold()
    if event_type in {"new-mail", "email-received"}:
        return "✉", "mail"
    if event_type.startswith("security-"):
        return "!", "warning"
    if event_type in {"task-due-today", "task-overdue"}:
        return "!", "warning"
    if event_type in {"deleted", "email-deleted"}:
        return "⌫", "deleted"
    if event_type in {"restored", "email-restored", "email-restored-to-inbox"}:
        return "↶", "mail"
    if event_type == "email-moved-to-spam":
        return "✉", "mail"
    if event_type in {"reply-sent", "sent-reply"}:
        return "➤", "reply"
    if event_type.startswith("task") or workspace == "todo":
        return ("!", "warning") if kind in {"error", "warning"} else ("✓", "task")
    if workspace == "summary":
        return ("!", "warning") if kind in {"error", "warning"} else ("✦", "summary")
    if kind in {"error", "warning"}:
        return "!", "warning"
    return "i", "info"


def _render_item(item: dict, *, expanded: bool = False) -> str:
    details = list(item.get("details") or [])
    # Keep the v58 content model: render the available detail rows and let the
    # list state control presentation. Preview uses single-line ellipsis;
    # View all allows wrapping without changing the data rendered.
    visible_details = details[:6]
    detail_rows = "".join(
        f'<div class="notification-center-detail">{html.escape(line)}</div>'
        for line in visible_details
    )
    details_html = (
        f'<div class="notification-center-details">{detail_rows}</div>'
        if detail_rows
        else ""
    )
    unread_class = " is-unread" if not bool(item.get("read")) else ""
    expanded_class = " is-expanded" if expanded else ""
    icon, icon_class = _event_icon(item)
    unread_dot = (
        '<span class="notification-center-unread-dot" aria-label="Unread"></span>'
        if not bool(item.get("read"))
        else ""
    )
    return (
        f'<div class="notification-center-item{unread_class}{expanded_class}">'
        f'<div class="notification-center-item-icon is-{icon_class}" aria-hidden="true">'
        f'{html.escape(icon)}</div>'
        '<div class="notification-center-item-copy">'
        '<div class="notification-center-item-topline">'
        f'<span class="notification-center-item-title">{html.escape(str(item.get("title") or "Notification"))}</span>'
        '<span class="notification-center-item-meta">'
        f'<span class="notification-center-item-time">{html.escape(_relative_time(str(item.get("created_at") or "")))}</span>'
        f'{unread_dot}'
        '</span>'
        '</div>'
        f'<div class="notification-center-item-message">{html.escape(str(item.get("message") or ""))}</div>'
        f'{details_html}'
        '</div>'
        '</div>'
    )


def claim_notification_marker(marker_key: str) -> bool:
    # Durable one-time marker used by transition-based alerts such as Due Today.
    store = _get_store()
    return bool(store.claim_marker(marker_key)) if store is not None else False


def mark_all_notifications_read() -> None:
    store = _get_store()
    if store is not None:
        store.mark_all_read()


def close_notification_store() -> None:
    store = st.session_state.get("notification_store")
    if isinstance(store, NotificationStore):
        store.close()
    st.session_state.pop("notification_store", None)
    st.session_state.notification_center_open = False
    st.session_state.notification_center_expanded = False
    st.session_state.notification_center_root_reconcile = False
    st.session_state.pop("notification_center_workspace", None)


def _open_notification_center() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="notifications", callback="_open_notification_center")
        return
    # Streamlit can replay the same native button callback while a fragment is
    # reconciling its previous DOM tree. Opening must therefore be idempotent:
    # duplicate bell callbacks may keep the panel open, but can never toggle it
    # closed again a few milliseconds after the user's click.
    was_open = bool(st.session_state.get("notification_center_open", False))
    trace_action("notification-center-open", already_open=was_open)
    st.session_state.notification_center_open = True
    st.session_state.notification_center_workspace = str(
        st.session_state.get("active_workspace") or "inbox"
    )
    if not was_open:
        st.session_state.notification_center_expanded = False


def _close_notification_center() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="notifications", callback="_close_notification_center")
        return
    trace_action("notification-center-close")
    st.session_state.notification_center_open = False
    st.session_state.notification_center_expanded = False
    st.session_state.pop("notification_center_workspace", None)


def _mark_all_read_callback() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="notifications", callback="_mark_all_read_callback")
        return
    trace_action("notification-mark-all-read")
    mark_all_notifications_read()
    # Read-state changes alter membership in the Unread view. Fragment-only
    # reconciliation can leave the previous keyed cards mounted in the browser
    # even after the server has correctly filtered them out. Queue one root
    # reconciliation so the next fragment pass replaces the stale DOM tree.
    st.session_state.notification_center_root_reconcile = True


def _mark_notification_read(notification_id: str) -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="notifications", callback="_mark_notification_read")
        return
    trace_action("notification-mark-read")
    store = _get_store()
    if store is not None:
        store.mark_read(notification_id)
        st.session_state.notification_center_root_reconcile = True


def _expand_notification_list() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="notifications", callback="_expand_notification_list")
        return
    trace_action("notification-expand")
    st.session_state.notification_center_expanded = True


def _collapse_notification_list() -> None:
    if not workspace_interaction_allowed():
        trace_action("workspace-callback-ignored", source="notifications", callback="_collapse_notification_list")
        return
    trace_action("notification-collapse")
    st.session_state.notification_center_expanded = False


@st.fragment
def render_notification_center() -> None:
    # Render the notification bell and a stable, self-contained activity panel.
    # A read/filter transition can require a one-time root rerun. This is kept
    # outside widget callbacks because Streamlit already owns callback reruns;
    # the fragment observes the flag first and promotes only that reconciliation
    # to an app rerun. It prevents the impossible mixed frame seen in Unread:
    # "You're all caught up" together with stale cards from the previous view.
    if bool(st.session_state.pop("notification_center_root_reconcile", False)):
        trace_action("notification-center-root-reconcile")
        st.rerun(scope="app")

    store = _get_store()
    unread_count = store.count_unread() if store is not None else 0

    # Keep bell + count positioning identical to the current known-good layout.
    with st.container(key="global_notification_center"):
        st.button(
            " ",
            icon=":material/notifications_none:",
            key="notification_bell_button",
            type="tertiary",
            use_container_width=True,
            on_click=_open_notification_center,
        )
        badge = "99+" if unread_count > 99 else str(unread_count)
        badge_class = "notification-bell-badge is-visible" if unread_count else "notification-bell-badge"
        st.markdown(
            f'<span class="{badge_class}" aria-hidden="true">{html.escape(badge)}</span>',
            unsafe_allow_html=True,
        )

    if not bool(st.session_state.get("notification_center_open", False)):
        return

    # The notification flyout belongs to the workspace where the bell was
    # opened. A full workspace navigation must dismiss it instead of carrying
    # the old overlay into the newly mounted tab. Keep this local to the
    # notification UI state so sidebar/navigation behavior itself is untouched.
    opened_workspace = str(st.session_state.get("notification_center_workspace") or "")
    active_workspace = str(st.session_state.get("active_workspace") or "inbox")
    if opened_workspace and opened_workspace != active_workspace:
        st.session_state.notification_center_open = False
        st.session_state.notification_center_expanded = False
        st.session_state.pop("notification_center_workspace", None)
        return
    if not opened_workspace:
        st.session_state.notification_center_workspace = active_workspace

    # A native full-screen button sits behind the panel while it is open.
    # It has two jobs: light-dismiss the panel on any outside click and absorb
    # that click so controls behind the notification panel can never fire.
    # Because this renderer is a fragment, the dismiss reruns only this overlay
    # instead of blanking/rebuilding the active workspace.
    with st.container(key="notification_center_backdrop"):
        st.button(
            "Close notifications",
            key="notification_center_backdrop_button",
            type="tertiary",
            use_container_width=True,
            on_click=_close_notification_center,
        )

    # Load notification history only when the panel is actually open.
    # This keeps the bell click path light while avoiding fragment DOM reuse.
    items = store.load_all(NOTIFICATION_CENTER_MAX_VISIBLE) if store is not None else []

    with st.container(key="notification_center_panel"):
        # Header stays in normal flow. No absolute close control and no card
        # overlay is allowed outside the list area.
        with st.container(key="notification_center_header"):
            header_copy, header_close = st.columns(
                [1, 0.24], gap="small", vertical_alignment="center"
            )
            with header_copy:
                st.markdown(
                    '<div class="notification-center-title">Notifications</div>'
                    '<div class="notification-center-subtitle">Important updates and alerts</div>',
                    unsafe_allow_html=True,
                )
            with header_close:
                st.button(
                    "Close",
                    key="notification_center_close",
                    type="tertiary",
                    use_container_width=True,
                    on_click=_close_notification_center,
                )

        # Keep the filter callback-free. The widget still reruns this fragment
        # naturally when the user changes All/Unread, but removing on_change
        # prevents an old radio node from firing a lifecycle callback while the
        # whole app is being torn down during logout.
        filter_value = st.radio(
            "Notification filter",
            ["All", "Unread"],
            horizontal=True,
            label_visibility="collapsed",
            key="notification_center_filter",
        )
        previous_filter = str(
            st.session_state.get("notification_center_last_filter") or ""
        )
        if previous_filter != filter_value:
            if previous_filter:
                trace_action(
                    "notification-filter-change",
                    previous=previous_filter,
                    current=filter_value,
                )
            st.session_state.notification_center_expanded = False
            st.session_state.notification_center_last_filter = filter_value
            # A radio change reruns only this fragment. On Streamlit 1.60+, the
            # browser can retain keyed cards from the previous filter while also
            # mounting the new empty state. Promote real filter changes to one
            # full-app reconciliation after persisting the selected filter. The
            # following run keeps the radio value and renders exactly one list
            # state, so All -> Unread cannot show stale All cards.
            if previous_filter:
                st.rerun(scope="app")

        filtered = (
            items
            if filter_value == "All"
            else [item for item in items if not bool(item.get("read"))]
        )
        expanded = bool(st.session_state.get("notification_center_expanded", False))
        visible_items = filtered if expanded else filtered[:NOTIFICATION_CENTER_PREVIEW_VISIBLE]

        # Own the complete list subtree with one replaceable placeholder. A
        # fragment can otherwise preserve keyed children from the previous All
        # view when Unread becomes empty, producing an impossible mixed frame
        # (empty state + old cards). st.empty() explicitly replaces that subtree
        # without requesting another rerun.
        list_state = "is-expanded" if expanded else "is-preview"
        with st.container(key="notification_center_list"):
            notification_list_slot = st.empty()
            with notification_list_slot.container():
                st.markdown(
                    f'<div class="notification-center-list-state {list_state}"></div>',
                    unsafe_allow_html=True,
                )
                if visible_items:
                    # Keep each keyed notification card directly in the replaceable
                    # list subtree. This matches the stable reference geometry: the
                    # keyed card owns the approved side inset, while CSS applies the
                    # row gap on the Streamlit vertical block that actually contains
                    # these card containers.
                    for item in visible_items:
                        item_id = str(item.get("id") or "").strip()
                        safe_key = "".join(ch for ch in item_id if ch.isalnum()) or "item"
                        with st.container(key=f"notification_item_{safe_key}"):
                            st.markdown(_render_item(item, expanded=expanded), unsafe_allow_html=True)
                            # Exactly one native button per card. The key stays tied
                            # to the notification itself across All/Unread and
                            # Preview/Expanded so Streamlit can update one DOM node.
                            st.button(
                                "Read notification",
                                key=f"notification_read_{safe_key}",
                                type="tertiary",
                                on_click=_mark_notification_read,
                                args=(item_id,),
                            )
                else:
                    empty_copy = (
                        "You're all caught up."
                        if filter_value == "Unread"
                        else "No notifications yet."
                    )
                    st.markdown(
                        '<div class="notification-center-empty">'
                        '<div class="notification-center-empty-icon">✓</div>'
                        f'<div>{html.escape(empty_copy)}</div>'
                        '</div>',
                        unsafe_allow_html=True,
                    )

        # Footer gets the same explicit replaceable ownership. When Unread has
        # no rows, the old All-view "View all" footer must be removed instead of
        # surviving below the empty state.
        has_list_action = len(filtered) > NOTIFICATION_CENTER_PREVIEW_VISIBLE
        notification_footer_slot = st.empty()
        if unread_count or has_list_action:
            footer_alignment = "distribute" if (unread_count and has_list_action) else (
                "left" if unread_count else "right"
            )
            with notification_footer_slot.container():
                with st.container(
                    key="notification_center_footer",
                    horizontal=True,
                    horizontal_alignment=footer_alignment,
                    vertical_alignment="center",
                    gap="small",
                ):
                    if unread_count:
                        st.button(
                            "Mark all as read",
                            icon=":material/check_circle:",
                            key="notification_mark_all_read",
                            type="tertiary",
                            on_click=_mark_all_read_callback,
                        )

                    if has_list_action:
                        if expanded:
                            st.button(
                                "Show less  ↑",
                                key="notification_show_less",
                                type="tertiary",
                                on_click=_collapse_notification_list,
                            )
                        else:
                            st.button(
                                f"View all {len(filtered)} notifications  ↓",
                                key="notification_view_all",
                                type="tertiary",
                                on_click=_expand_notification_list,
                            )
        else:
            notification_footer_slot.empty()
