# Reader UI for one structured AI email summary.
import html
import streamlit as st

from config import (
    SUMMARY_ACTION_ITEMS_PREVIEW_LIMIT,
    SUMMARY_DEADLINES_PREVIEW_LIMIT,
    SUMMARY_KEY_POINTS_PREVIEW_LIMIT,
    SUMMARY_READER_CONTENT_HEIGHT,
    SUMMARY_READER_EMPTY_HEIGHT,
    UI_FOREGROUND_SETTLE_SECONDS,
)

from services.task_status import normalize_task_status, task_status_slug
from services.summary_trace_service import trace_summary_pipeline
from services.todo_service import _format_deadline, _resolved_deadline
from services.ui_interaction_service import arm_foreground_interaction
from storage.summary_store import SUMMARY_FOLDER
from storage.session_store import (
    get_reply_draft, get_reply_draft_state_fingerprint, save_reply_draft,
)
from controllers.draft_controller import start_draft_generation
from services.ai_service import reply_draft_block_reason
from controllers.summary_deletion_controller import delete_summary_record
from ui.reader import _collapsible_cc_html, _collapsible_to_html, _content_email_header_html
from ui.summary_metrics import is_task_ready
from ui.draft_state import invalidate_reply_draft
from services.reply_draft_state_service import reply_draft_state_fingerprint


EMPTY_MARKERS = {"", "none identified.", "none", "n/a", "na", "null", "[]", "{}"}



def _foreground_rerun(*, scope: str | None = None) -> None:
    arm_foreground_interaction(settle_seconds=UI_FOREGROUND_SETTLE_SECONDS)
    if scope is None:
        st.rerun()
        return
    st.rerun(scope=scope)


def _clean_text(value, fallback: str = "") -> str:
    text = str(value or "").strip()
    if not text or text.casefold() in EMPTY_MARKERS:
        return fallback
    return text


def _clean_list(values) -> list[str]:
    cleaned = []
    for value in values or []:
        text = str(value or "").strip()
        if not text or text.casefold() in EMPTY_MARKERS:
            continue
        cleaned.append(text)
    return cleaned


def _current_thread_display(summary: dict) -> tuple[str, list[str]]:
    # The durable summary record is the CURRENT-STATE snapshot. Incremental
    # history exists only for Recent Activity / change highlighting; it must not
    # replace the current whole-thread summary with the latest delta.
    overview = _clean_text(summary.get("summary"), "No summary text is available for this email.")
    key_points = _clean_list(summary.get("key_points"))
    return overview, key_points


def _priority_badge(priority: str, extra_class: str = "") -> str:
    text = _clean_text(priority, "Medium")
    key = text.casefold()
    if key == "critical":
        variant = "priority-critical"
    elif key == "high":
        variant = "priority-high"
    elif key == "low":
        variant = "priority-low"
    else:
        variant = "priority-medium"
    extra = f" {extra_class}" if extra_class else ""
    return (
        f'<span class="summary-priority-badge {variant}{extra}">'
        f'{html.escape(text)}</span>'
    )


def _status_badge(status: str) -> str:
    label = normalize_task_status(status)
    variant = f"status-{task_status_slug(label)}"
    return (
        '<span class="summary-status-control">'
        '<span class="summary-status-label">Status:</span>'
        f'<span class="summary-status-badge {variant}">{html.escape(label)}</span>'
        '</span>'
    )



def _individual_list_html(
    items: list[str],
    variant: str = "check",
    *,
    start_index: int = 1,
    highlighted_values: set[str] | None = None,
) -> str:
    icon_class = "is-check" if variant == "check" else "is-action"
    highlighted = {
        str(value or "").strip().casefold()
        for value in (highlighted_values or set())
        if str(value or "").strip()
    }
    rows = "".join(
        '<li' + (' class="is-thread-update"' if str(item).strip().casefold() in highlighted else '') + '>'
        f'<span class="individual-summary-list-icon {icon_class}">'
        f'{"✓" if variant == "check" else start_index + offset}'
        '</span>'
        f'<span class="individual-summary-list-text">{html.escape(item)}</span>'
        '</li>'
        for offset, item in enumerate(items)
    )
    return f'<ul class="individual-summary-list {icon_class}">{rows}</ul>'




def _action_item_deadlines(summary: dict) -> list[str]:
    # Keep the Summary deadline card aligned with the To-Do source of truth.
    # Per-action due dates are authoritative when present; the email-level
    # deadline list is only a fallback for older summaries without detail dates.
    values = []
    seen = set()
    for detail in summary.get("action_item_details") or []:
        if not isinstance(detail, dict):
            continue
        if bool(detail.get("completed")) or bool(detail.get("cancelled")):
            continue
        due = _clean_text(detail.get("due_date") or detail.get("deadline"))
        key = due.casefold()
        if due and key not in seen:
            seen.add(key)
            values.append(due)
    return values


def _summary_task_deadlines(summary: dict, action_items: list[str], saved_deadlines) -> list[str]:
    # Summary-only emails do not own task deadlines. Preserve the existing
    # extracted/per-action dates exactly as saved by the Summary pipeline. Only
    # when no extracted date exists do we reuse To-Do's single deadline resolver
    # for the standard planned +14-day fallback. This keeps date parsing and
    # relative-date resolution in one source of truth.
    if not action_items:
        return []

    detail_deadlines = _action_item_deadlines(summary)
    if detail_deadlines:
        return detail_deadlines

    legacy_deadlines = _clean_list(saved_deadlines)
    if legacy_deadlines:
        return legacy_deadlines

    parsed, source = _resolved_deadline(summary)
    if source == "estimated":
        return [f"{_format_deadline(parsed)} — Estimated / planned deadline"]
    return []


def _individual_deadline_list_html(
    items: list[str],
    *,
    highlighted_values: set[str] | None = None,
) -> str:
    highlighted = {str(value or "").strip().casefold() for value in (highlighted_values or set()) if str(value or "").strip()}
    rows = "".join(
        '<li' + (' class="is-thread-update"' if str(item).strip().casefold() in highlighted else '') + '>'
        '<span class="individual-summary-deadline-icon">&#128197;</span>'
        f'<span>{html.escape(item)}</span>'
        '</li>'
        for item in items
    )
    return f'<ul class="individual-summary-deadline-list">{rows}</ul>'


def _individual_preview_html(
    items: list[str],
    *,
    limit: int,
    variant: str,
    singular_label: str,
    plural_label: str,
    highlighted_values: set[str] | None = None,
) -> str:
    # Render a compact preview with native HTML expand/collapse and no rerun.
    visible = items[:limit]
    hidden = items[limit:]

    if variant == "deadline":
        preview_html = _individual_deadline_list_html(visible, highlighted_values=highlighted_values)
        hidden_html = _individual_deadline_list_html(hidden, highlighted_values=highlighted_values)
    else:
        preview_html = _individual_list_html(
            visible,
            variant,
            start_index=1,
            highlighted_values=highlighted_values,
        )
        hidden_html = _individual_list_html(
            hidden,
            variant,
            start_index=len(visible) + 1,
            highlighted_values=highlighted_values,
        )

    preview_modifier = f" is-{html.escape(variant)}"
    if hidden:
        preview_modifier += " has-more"
    preview_block = (
        f'<div class="individual-summary-preview-body{preview_modifier}">'
        f'{preview_html}'
        '</div>'
    )

    if not hidden:
        return preview_block

    label = singular_label if len(items) == 1 else plural_label
    return (
        f'{preview_block}'
        '<details class="individual-summary-more">'
        '<summary>'
        f'<span class="individual-summary-more-closed">View all {len(items)} {html.escape(label)} '
        '<span aria-hidden="true">&#8595;</span></span>'
        '<span class="individual-summary-more-open">Show less '
        '<span aria-hidden="true">&#8593;</span></span>'
        '</summary>'
        '<div class="individual-summary-more-content">'
        f'{hidden_html}'
        '</div>'
        '</details>'
    )


def _list_html(items: list[str], variant: str = "check") -> str:
    icon = "✓" if variant == "check" else "→"
    icon_class = "is-check" if variant == "check" else "is-action"
    rows = "".join(
        f'<li><span class="summary-list-icon {icon_class}">{icon}</span>'
        f'<span>{html.escape(item)}</span></li>'
        for item in items
    )
    return f'<ul class="summary-clean-list">{rows}</ul>'



def _lookup_original_email(uid: str) -> dict | None:
    # Read the cached source even after the provider marks it unavailable.
    store = st.session_state.get("email_store")
    if not store or not uid:
        return None

    for folder in (SUMMARY_FOLDER, "INBOX", "SPAM", "JUNK"):
        try:
            email = store.get_email(folder, uid, include_unavailable=True)
        except TypeError:
            email = store.get_email(folder, uid)
        except Exception:
            email = None
        if email:
            return email
    return None


def _is_original_email_deleted(summary: dict) -> bool:
    # External mailbox deletion changes source availability only. The saved AI
    # summary and linked task remain available in MailMind.
    uid = str(summary.get("uid") or "").strip()
    original = _lookup_original_email(uid)
    if not original:
        return False

    remote_available = original.get("remote_available")
    if remote_available is None:
        return bool(original.get("remote_unavailable_at"))
    try:
        return int(remote_available or 0) != 1
    except (TypeError, ValueError):
        return bool(original.get("remote_unavailable_at"))


def _is_original_email_in_spam(summary: dict) -> bool:
    # A provider Spam/Junk move does not delete the source. Keep the summary and
    # actions available, but surface the source's current mailbox location.
    uid = str(summary.get("uid") or "").strip()
    original = _lookup_original_email(uid)
    if not original:
        return False
    try:
        remote_available = int(original.get("remote_available", 1) or 0) == 1
    except (TypeError, ValueError):
        remote_available = not bool(original.get("remote_unavailable_at"))
    return remote_available and bool(int(original.get("provider_spam") or 0))


def _render_original_spam_notice() -> None:
    st.markdown(
        """
        <section class="summary-original-deleted-note summary-original-spam-note">
            <span class="summary-original-deleted-note-icon">i</span>
            <div class="summary-original-deleted-note-copy">
                <span class="summary-original-deleted-note-title">Original email is currently in Spam/Junk.</span>
                <span class="summary-original-deleted-note-text">The saved summary is kept. Move the email back to Inbox to return it to the normal Inbox flow.</span>
            </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def _render_original_deleted_notice() -> None:
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


def _render_thread_updated_notice(summary: dict) -> None:
    # Show this notice only after a Summary that already existed has received a
    # genuinely NEW safe reply. Fresh-DB reconstruction may replay historical
    # provider turns through the same incremental merge engine, but those turns
    # predate the newly-created Summary and must not be presented as a new reply.
    updates = [
        item for item in (summary.get("incremental_updates") or [])
        if isinstance(item, dict)
    ]
    if not updates:
        return
    if all(bool(item.get("historical_reconstruction")) for item in updates):
        return
    st.markdown(
        """
        <section class="summary-original-deleted-note summary-thread-updated-note">
            <span class="summary-original-deleted-note-icon">i</span>
            <div class="summary-original-deleted-note-copy">
                <span class="summary-original-deleted-note-title">Summary updated from a new reply.</span>
                <span class="summary-original-deleted-note-text">Review the changes below. Linked To-Do details may also be updated when applicable.</span>
            </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

def _is_thread_summary(summary: dict) -> bool:
    # A canonical id alone is not enough because providers also assign one to a
    # single message. Show Recent Activity only once this summary represents a
    # real multi-message thread (or has durable incremental update history).
    if any(isinstance(item, dict) for item in (summary.get("incremental_updates") or [])):
        return True
    source_uids = {str(value or "").strip() for value in (summary.get("source_uids") or []) if str(value or "").strip()}
    try:
        thread_count = int(summary.get("thread_count") or 0)
    except (TypeError, ValueError):
        thread_count = 0
    return thread_count > 1 or len(source_uids) > 1


def _thread_history_entries(summary: dict) -> list[dict]:
    return [
        dict(entry) for entry in (summary.get("task_change_history") or [])
        if isinstance(entry, dict) and isinstance(entry.get("changes"), list)
    ]


def _thread_history_change_copy(change: dict) -> tuple[str, str]:
    kind = str(change.get("type") or "").strip().casefold()
    action = str(change.get("action") or "").strip()
    old_value = str(change.get("from") or "").strip()
    new_value = str(change.get("to") or "").strip()
    if kind == "priority_changed":
        return "Priority changed", f"{old_value or '—'} → {new_value or '—'}"
    if kind == "deadline_changed":
        return "Deadline updated", f"{old_value or 'No deadline'} → {new_value or 'No deadline'}"
    if kind in {"deadline_removed", "task_deadline_removed"}:
        return "Deadline removed", action or old_value or "Explicit deadline removed"
    if kind == "action_added":
        return "Action item added", action or "New action item"
    if kind == "action_cancelled":
        return "Action item cancelled", action or "Action item"
    if kind == "action_reopened":
        return "Action item reopened", action or "Action item"
    if kind == "action_completed":
        return "Action item completed", action or "Action item"
    if kind == "action_reworded":
        return "Action item updated", f"{old_value} → {new_value}".strip(" →")
    if kind == "action_archived":
        return "Action item archived", action or "Action item"
    if kind == "title_changed":
        return "Task title updated", f"{old_value} → {new_value}".strip(" →")
    if kind == "status_changed":
        # Legacy history can contain old automatic transitions; keep the history
        # readable even though v63+ no longer lets email updates change Status.
        return "Status changed", f"{old_value or '—'} → {new_value or '—'}"
    return "Task details updated", action or new_value or old_value or "Task details changed"


def _history_for_incremental_update(summary: dict, update: dict) -> list[dict]:
    # New records carry one exact source_uid for the reply that produced this
    # delta. Prefer it over source_uids, because source_uids may contain every
    # unseen/full-thread turn and previously caused old changes to be attached
    # to the newest update (breaking blue highlighting and Recent Activity).
    exact_uid = str(update.get("source_uid") or "").strip()
    update_uids = {
        str(value or "").strip()
        for value in (update.get("source_uids") or [])
        if str(value or "").strip()
    }
    update_date = str(update.get("date_display") or "").strip()
    entries = _thread_history_entries(summary)

    if exact_uid:
        exact = [
            entry for entry in entries
            if str(entry.get("source_uid") or "").strip() == exact_uid
        ]
        if exact:
            return exact
        # Do not broaden a new exact-turn record to the entire thread. If a
        # partially migrated record lacks matching history, showing no task
        # delta is safer than attributing an older change to the latest reply.
        return []

    matches = []
    for entry in entries:
        source_uid = str(entry.get("source_uid") or "").strip()
        if update_uids and source_uid in update_uids:
            matches.append(entry)
            continue
        if not update_uids and update_date and str(entry.get("date_display") or "").strip() == update_date:
            matches.append(entry)
    return matches


def _material_updated_deadlines(summary: dict) -> set[str]:
    # Highlight the current deadline only when history proves that the thread
    # update materially changed/introduced it. This prevents the same date from
    # appearing twice simply because the latest reply repeated the deadline.
    highlighted: set[str] = set()
    details_by_id = {
        str(item.get("action_id") or ""): item
        for item in (summary.get("action_item_details") or [])
        if isinstance(item, dict) and str(item.get("action_id") or "")
    }
    for entry in _thread_history_entries(summary):
        if not (str(entry.get("source_uid") or "").strip() or str(entry.get("message_id") or "").strip()):
            continue
        for change in entry.get("changes") or []:
            if not isinstance(change, dict):
                continue
            kind = str(change.get("type") or "").strip().casefold()
            if kind == "deadline_changed":
                value = str(change.get("to") or "").strip()
                if value:
                    highlighted.add(value.casefold())
            elif kind == "action_added":
                detail = details_by_id.get(str(change.get("action_id") or "")) or {}
                value = str(detail.get("due_date") or detail.get("deadline") or "").strip()
                if value:
                    highlighted.add(value.casefold())
    return highlighted


def _latest_incremental_update(summary: dict) -> dict:
    updates = [
        dict(item)
        for item in (summary.get("incremental_updates") or [])
        if isinstance(item, dict) and not bool(item.get("historical_reconstruction"))
    ]
    return updates[-1] if updates else {}


def _latest_thread_history_changes(summary: dict) -> list[dict]:
    latest = _latest_incremental_update(summary)
    if latest:
        matches = _history_for_incremental_update(summary, latest)
        if matches:
            return [
                dict(change)
                for entry in matches
                for change in (entry.get("changes") or [])
                if isinstance(change, dict)
            ]
        # A newest informational reply can legitimately have no task-history
        # changes. Do not fall back to an older reply and keep stale fields blue.
        return []
    # If the record contains only historical-reconstruction updates, there is
    # no post-creation "latest reply" to highlight. Do not fall back to the last
    # historical change and paint the initial Summary blue.
    if any(isinstance(item, dict) for item in (summary.get("incremental_updates") or [])):
        return []
    entries = _thread_history_entries(summary)
    return [dict(change) for change in (entries[-1].get("changes") or []) if isinstance(change, dict)] if entries else []


def _latest_modified_key_points(summary: dict) -> set[str]:
    latest = _latest_incremental_update(summary)
    if not isinstance(latest, dict):
        return set()
    # v66 writes changed_key_points explicitly. Older v64/v65 records only have
    # the latest key-point delta, which is still a safe compatibility highlight.
    values = latest.get("changed_key_points")
    if values is None:
        values = latest.get("key_points") or []
    return {str(value or "").strip().casefold() for value in values if str(value or "").strip()}


def _latest_modified_action_values(summary: dict) -> set[str]:
    changed_ids: set[str] = set()
    changed_text: set[str] = set()
    for change in _latest_thread_history_changes(summary):
        kind = str(change.get("type") or "").strip().casefold()
        if kind not in {"action_added", "action_reworded", "action_reopened"}:
            continue
        action_id = str(change.get("action_id") or "").strip()
        if action_id:
            changed_ids.add(action_id)
        value = str(change.get("to") or change.get("action") or "").strip()
        if value:
            changed_text.add(value.casefold())
    for detail in summary.get("action_item_details") or []:
        if not isinstance(detail, dict):
            continue
        if str(detail.get("action_id") or "").strip() in changed_ids:
            value = str(detail.get("action") or "").strip()
            if value:
                changed_text.add(value.casefold())
    return changed_text


def _latest_modified_deadlines(summary: dict) -> set[str]:
    changed: set[str] = set()
    detail_by_id = {
        str(item.get("action_id") or "").strip(): item
        for item in (summary.get("action_item_details") or [])
        if isinstance(item, dict) and str(item.get("action_id") or "").strip()
    }
    for change in _latest_thread_history_changes(summary):
        kind = str(change.get("type") or "").strip().casefold()
        if kind == "deadline_changed":
            value = str(change.get("to") or "").strip()
            if value:
                changed.add(value.casefold())
        elif kind == "action_added":
            detail = detail_by_id.get(str(change.get("action_id") or "").strip()) or {}
            value = str(detail.get("due_date") or detail.get("deadline") or "").strip()
            if value:
                changed.add(value.casefold())
    return changed


def _summary_recent_activity_rows(summary: dict) -> list[dict]:
    rows: list[dict] = []
    updates = [dict(item) for item in (summary.get("incremental_updates") or []) if isinstance(item, dict)]
    for update in reversed(updates[-20:]):
        time_label = _clean_text(update.get("date_display"), "Recently")
        update_rows: list[tuple[str, str]] = []
        summary_text = _clean_text(update.get("summary"))
        summary_changed = update.get("summary_changed")
        if summary_text and (summary_changed is None or bool(summary_changed)):
            update_rows.append(("Summary updated", summary_text))
        # New records always persist key_point_changes, including an explicit
        # empty list when the reply did not change any key point. Only legacy
        # updates that predate this field may fall back to treating key_points
        # as additions. This avoids false "Key point added" rows for a reply
        # that merely updates an action item.
        has_key_point_change_field = "key_point_changes" in update
        key_point_changes = [
            dict(change) for change in (update.get("key_point_changes") or [])
            if isinstance(change, dict)
        ]
        if key_point_changes:
            for change in key_point_changes:
                kind = str(change.get("type") or "").strip().casefold()
                old_value = _clean_text(change.get("from"))
                new_value = _clean_text(change.get("to"))
                if kind == "key_point_updated":
                    update_rows.append(("Key point updated", f"{old_value} → {new_value}".strip(" →")))
                elif new_value:
                    update_rows.append(("Key point added", new_value))
        elif not has_key_point_change_field:
            for value in _clean_list(update.get("key_points")):
                update_rows.append(("Key point added", value))

        matched_history = _history_for_incremental_update(summary, update)
        if matched_history:
            for entry in matched_history:
                for change in entry.get("changes") or []:
                    if not isinstance(change, dict):
                        continue
                    # Workflow Status is manual-only. Do not surface historical
                    # email-driven status transitions in Summary Recent Activity.
                    if (
                        str(change.get("type") or "").strip().casefold() == "status_changed"
                        and str(entry.get("source") or "").strip().casefold()
                        in {"email_reply", "email_update", "thread_reply"}
                    ):
                        continue
                    update_rows.append(_thread_history_change_copy(change))
        else:
            # Compatibility fallback for older saved updates that predate task
            # change history. Do not fabricate a status transition.
            for task_update in update.get("task_updates") or []:
                if not isinstance(task_update, dict):
                    continue
                state = str(task_update.get("state") or "").strip().casefold()
                action = str(task_update.get("action") or "").strip()
                if state == "new" and action:
                    update_rows.append(("Action item added", action))
                elif state in {"updated", "reopened"} and action:
                    update_rows.append(("Action item updated", action))
            for value in _clean_list(update.get("deadlines")):
                update_rows.append(("Deadline updated", value))

        seen = set()
        for title, detail in update_rows:
            key = (title.casefold(), detail.casefold())
            if key in seen:
                continue
            seen.add(key)
            rows.append({"time": time_label, "title": title, "detail": detail})
    return rows


def _render_summary_recent_activity_rows(summary: dict) -> None:
    rows = _summary_recent_activity_rows(summary)
    if not rows:
        st.markdown(
            '<div class="todo-history-empty">No summary updates recorded yet.</div>',
            unsafe_allow_html=True,
        )
        return
    history_html = []
    for item in rows:
        history_html.append(
            '<div class="todo-history-row">'
            '<span class="todo-history-dot" aria-hidden="true"></span>'
            f'<div class="todo-history-time">{html.escape(item["time"])}</div>'
            '<div class="todo-history-copy">'
            f'<div class="todo-history-line"><strong>{html.escape(item["title"])}</strong>'
            f'<span>{html.escape(item["detail"])}</span></div>'
            '<div class="todo-history-source">Updated from new reply</div>'
            '</div></div>'
        )
    st.markdown(
        '<div class="todo-history-scroll">' + ''.join(history_html) + '</div>',
        unsafe_allow_html=True,
    )


def _dismiss_summary_recent_activity() -> None:
    st.session_state.pop("summary_recent_activity_record", None)


@st.dialog("Recent Activity", width="medium", dismissible=False)
def _show_summary_recent_activity() -> None:
    summary = st.session_state.get("summary_recent_activity_record")
    if not isinstance(summary, dict):
        _dismiss_summary_recent_activity()
        _foreground_rerun(scope="app")

    # Marker used by one canonical CSS block. The dialog itself stays fixed;
    # only the activity list becomes scrollable when history grows.
    st.markdown('<div class="summary-recent-activity-v2"></div>', unsafe_allow_html=True)

    task_title = _clean_text(summary.get("task_title"), _clean_text(summary.get("subject"), "Email thread"))
    subject = _clean_text(summary.get("subject"), "(No Subject)")
    st.markdown(
        '<div class="summary-history-dialog-subtitle">Summary update history</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="todo-history-dialog-task">'
        f'<div class="todo-history-dialog-task-title">{html.escape(task_title)}</div>'
        f'<div class="todo-history-dialog-task-subject">{html.escape(subject)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    with st.container(border=False, key="summary_recent_activity_list"):
        _render_summary_recent_activity_rows(summary)
    with st.container(border=False, key="summary_recent_activity_footer"):
        close_col, _ = st.columns([0.24, 0.76], gap="small")
        with close_col:
            if st.button("Close", key="summary_recent_activity_close", type="secondary", use_container_width=True):
                _dismiss_summary_recent_activity()
                _foreground_rerun(scope="app")


def _handle_recent_activity_action(
    summary: dict,
    *,
    action_key: str,
    popover_version_key: str,
) -> None:
    if not _is_thread_summary(summary):
        return
    if st.button(
        "View recent activity",
        icon=":material/history:",
        key=f"summary_view_recent_activity_{action_key}",
        width="stretch",
    ):
        st.session_state.summary_recent_activity_record = dict(summary)
        _close_more_actions(popover_version_key)
        _foreground_rerun(scope="app")



def _existing_draft(summary: dict, uid: str) -> tuple[str, str]:
    # Resolve a saved draft only when it was generated for the current task state.
    # This is a second line of defense beyond explicit invalidation callbacks: a
    # status/action completion change can never silently reuse an older response.
    session_token = str(st.session_state.get("session_token") or "")
    prepared_draft = get_reply_draft(session_token, uid)
    saved_fingerprint = get_reply_draft_state_fingerprint(session_token, uid)
    current_fingerprint = reply_draft_state_fingerprint(summary)
    if prepared_draft.strip() and saved_fingerprint != current_fingerprint:
        invalidate_reply_draft(uid)
        prepared_draft = ""

    cached_draft = str(
        st.session_state.get(f"standalone_reply_backup_{uid}")
        or st.session_state.get(f"standalone_reply_draft_{uid}")
        or ""
    )
    # Unversioned UI-only caches are stale by definition after this change. Only
    # a fingerprinted durable draft can promote a cached editor copy.
    existing_draft = prepared_draft if prepared_draft.strip() else ""
    return prepared_draft, existing_draft


def _close_more_actions(version_key: str) -> None:
    # Give the popover a fresh Streamlit identity on the next rerun. This closes
    # it after a menu selection without JavaScript and keeps click-outside
    # dismissal fully native to st.popover.
    current = int(st.session_state.get(version_key, 0) or 0)
    st.session_state[version_key] = current + 1


def _handle_draft_action(
    summary: dict,
    uid: str,
    *,
    action_key: str,
    popover_version_key: str,
) -> None:
    # Open a saved draft, or generate a new one, from the More actions menu.
    # Check the existing reply rules before rendering the action so expected
    # restrictions (such as a no-reply sender) read as a quiet disabled state
    # instead of an error card after the user clicks.
    session_token = str(st.session_state.get("session_token") or "")
    prepared_draft, existing_draft = _existing_draft(summary, uid)
    has_saved_draft = bool(existing_draft.strip())
    label = "View / Edit draft" if has_saved_draft else "Draft email"
    draft_state = "saved" if has_saved_draft else "new"
    original = _lookup_original_email(uid)
    block_reason = "" if has_saved_draft else reply_draft_block_reason(summary, original)
    draft_disabled = bool(block_reason)

    clicked = st.button(
        label,
        icon=":material/edit_square:",
        key=f"summary_prepare_draft_{draft_state}_{action_key}",
        width="stretch",
        disabled=draft_disabled,
    )

    if draft_disabled:
        reason_key = block_reason.casefold()
        if "no-reply" in reason_key:
            helper = "Unavailable for no-reply senders."
        elif "unsafe" in reason_key or "suspicious" in reason_key:
            helper = "Unavailable for unsafe or suspicious emails."
        else:
            helper = "Reply is unavailable for this email."
        st.markdown(
            f'<div class="summary-draft-disabled-help">{html.escape(helper)}</div>',
            unsafe_allow_html=True,
        )
        # Clear any stale error left by the previous click-to-discover behavior.
        if str(st.session_state.get("draft_prepare_error_uid") or "") == uid:
            st.session_state.pop("draft_prepare_error_uid", None)
            st.session_state.pop("draft_prepare_error", None)
        return

    if clicked:
        st.session_state.pop("original_dialog_uid", None)
        _close_more_actions(popover_version_key)

        if existing_draft.strip():
            if not prepared_draft.strip():
                save_reply_draft(
                    session_token, uid, existing_draft, reply_draft_state_fingerprint(summary)
                )

            instance_key = f"standalone_reply_editor_instance_{uid}"
            st.session_state[instance_key] = int(st.session_state.get(instance_key, 0) or 0) + 1
            st.session_state.draft_dialog_uid = uid
            _foreground_rerun()

        if start_draft_generation(summary, original):
            _foreground_rerun()

        # Even if draft generation could not start, close the selected menu.
        _foreground_rerun()


def _handle_original_action(
    uid: str,
    *,
    action_key: str,
    popover_version_key: str,
    disabled: bool = False,
) -> None:
    # Open the source only while it still exists in the provider mailbox.
    clicked = st.button(
        "Open original email",
        icon=":material/open_in_new:",
        key=f"summary_open_original_{action_key}",
        width="stretch",
        disabled=disabled,
    )
    if disabled:
        return
    if clicked:
        st.session_state.pop("draft_dialog_uid", None)
        st.session_state.original_dialog_uid = uid
        _close_more_actions(popover_version_key)
        _foreground_rerun()


def _render_delete_preview_action(
    label: str,
    *,
    summary: dict,
    action_key: str,
    popover_version_key: str,
    original_deleted: bool,
    batch_parent_uid: str = "",
    batch_item_count: int = 0,
) -> None:
    # Queue a one-shot confirmation. The destructive operation itself runs only
    # after the user explicitly confirms in the native Streamlit dialog.
    if st.button(
        label,
        icon=":material/delete_outline:",
        key=f"summary_delete_preview_{action_key}",
        width="stretch",
    ):
        st.session_state.summary_pending_delete = {
            "summary": dict(summary),
            "summary_uid": str(summary.get("uid") or ""),
            "batch_parent_uid": str(batch_parent_uid or ""),
            "batch_item_count": max(0, int(batch_item_count or 0)),
            "original_deleted": bool(original_deleted),
        }
        _close_more_actions(popover_version_key)
        _foreground_rerun(scope="app")


def _render_source_more_actions(
    summary: dict,
    *,
    scope: str,
    compact_trigger: bool = False,
    delete_label: str = "Delete summary",
    original_deleted: bool | None = None,
    batch_parent_uid: str = "",
    batch_item_count: int = 0,
) -> None:
    # Secondary source-email actions stay in one compact Streamlit popover.
    uid = str(summary.get("uid") or "").strip()
    if not uid:
        return

    if original_deleted is None:
        original_deleted = _is_original_email_deleted(summary)
    trigger_label = "More actions"
    container_key = f"summary_more_actions_{scope}"
    version_key = f"summary_actions_popover_version_{scope}_{uid}"
    version = int(st.session_state.get(version_key, 0) or 0)

    with st.container(border=False, key=container_key):
        with st.popover(
            trigger_label,
            icon=":material/more_vert:",
            width="content" if compact_trigger else "stretch",
            key=f"summary_actions_popover_{scope}_{uid}_v{version}",
        ):
            _handle_draft_action(
                summary,
                uid,
                action_key=f"{scope}_{uid}",
                popover_version_key=version_key,
            )
            _handle_original_action(
                uid,
                action_key=f"{scope}_{uid}",
                popover_version_key=version_key,
                disabled=original_deleted,
            )
            _handle_recent_activity_action(
                summary,
                action_key=f"{scope}_{uid}",
                popover_version_key=version_key,
            )
            _render_delete_preview_action(
                delete_label,
                summary=summary,
                action_key=f"{scope}_{uid}",
                popover_version_key=version_key,
                original_deleted=bool(original_deleted),
                batch_parent_uid=batch_parent_uid,
                batch_item_count=batch_item_count,
            )




def _dismiss_summary_delete_confirmation() -> None:
    st.session_state.pop("summary_pending_delete", None)


@st.dialog(
    "Delete summary",
    width="medium",
    dismissible=False,
)
def _show_summary_delete_confirmation() -> None:
    pending = st.session_state.get("summary_pending_delete") or {}
    summary = pending.get("summary")
    if not isinstance(summary, dict):
        _dismiss_summary_delete_confirmation()
        _foreground_rerun(scope="app")

    subject = _clean_text(summary.get("subject"), "(No Subject)")
    has_task = is_task_ready(summary)
    status = normalize_task_status(summary.get("status") or "Not Started")
    active_task = has_task and status in {"Not Started", "In Progress", "On Hold"}
    original_deleted = bool(pending.get("original_deleted"))
    batch_parent_uid = str(pending.get("batch_parent_uid") or "")
    batch_item_count = int(pending.get("batch_item_count") or 0)
    last_batch_item = bool(batch_parent_uid and batch_item_count == 1)

    if active_task:
        title = "Delete summary with unfinished task?"
        description = (
            "This summary still has an unfinished task. Deleting it will also "
            "remove the linked task from your To-Do List."
        )
    elif has_task:
        title = "Delete summary and task history?"
        description = (
            "Deleting this summary will also remove its linked "
            f"{status.casefold()} task record from your To-Do List."
        )
    else:
        title = "Delete this summary?"
        description = "This AI summary will be permanently removed from MailMind."

    info_lines = []
    if original_deleted:
        info_lines.append("The original email is already unavailable in your mailbox.")
    else:
        info_lines.append("The original email will remain in your mailbox.")
    if has_task:
        info_lines.append("Summary and To-Do stay synchronized, so the linked task will be removed too.")
    if last_batch_item:
        info_lines.append("This is the last summary in the batch; the empty Batch Summary will also be removed.")

    source_label = "Summary + Task" if has_task else "AI Summary"
    st.markdown(
        f"""
        <div class="todo-confirm-shell is-summary-delete summary-delete-confirm-shell">
            <div class="todo-confirm-header">
                <div class="todo-confirm-icon summary-delete-confirm-icon" aria-hidden="true">!</div>
                <div class="todo-confirm-heading-copy">
                    <div class="todo-confirm-title">{html.escape(title)}</div>
                    <div class="todo-confirm-subtitle">{html.escape(subject)}</div>
                </div>
            </div>
            <div class="todo-confirm-transition summary-delete-transition">
                <span class="todo-confirm-status-pill summary-delete-pill-current">{html.escape(source_label)}</span>
                <span class="todo-confirm-arrow" aria-hidden="true">→</span>
                <span class="todo-confirm-status-pill summary-delete-pill-target">Deleted</span>
            </div>
            <div class="todo-confirm-description">{html.escape(description)}</div>
            <div class="todo-confirm-info summary-delete-confirm-info">
                <span class="todo-confirm-info-icon" aria-hidden="true">i</span>
                <div class="todo-confirm-info-copy">
                    {''.join(f'<div>{html.escape(line)}</div>' for line in info_lines)}
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cancel_col, delete_col = st.columns(2, gap="small")
    with cancel_col:
        if st.button(
            "Cancel",
            icon=":material/block:",
            key="summary_delete_cancel",
            use_container_width=True,
        ):
            _dismiss_summary_delete_confirmation()
            _foreground_rerun(scope="app")

    with delete_col:
        if st.button(
            "Delete",
            icon=":material/delete_outline:",
            key="summary_delete_confirm",
            use_container_width=True,
        ):
            success = delete_summary_record(
                summary_uid=str(pending.get("summary_uid") or summary.get("uid") or ""),
                batch_parent_uid=batch_parent_uid,
            )
            _dismiss_summary_delete_confirmation()
            if not success:
                st.toast("Summary could not be deleted. Please try again.", icon=":material/error:")
            _foreground_rerun(scope="app")


def _render_header(summary, *, show_subject: bool = True):
    sender = _clean_text(summary.get("from"))
    recipient = _clean_text(summary.get("to"))
    cc_value = _clean_text(summary.get("cc"))
    subject = _clean_text(summary.get("subject"), "(No Subject)")
    date_display = _clean_text(summary.get("date_display"), "Unknown")

    st.markdown(
        _content_email_header_html(
            subject=subject,
            sender=sender,
            recipient=recipient,
            cc_value=cc_value,
            date_display=date_display,
            show_subject=show_subject,
        ),
        unsafe_allow_html=True,
    )

def _batch_values(summary: dict, field: str) -> list[str]:
    # Use one canonical per-email dataset for every batch view and count.
    return [
        value
        for email_item in (summary.get("email_breakdowns") or [])
        for value in _clean_list(email_item.get(field))
    ]


def _render_individual_summary_sections(
    summary: dict,
    *,
    original_deleted: bool | None = None,
) -> None:
    # Render the same summary content used by the standalone Individual viewer.
    #
    # Batch Summary reuses this renderer inside each source-email expander so the
    # two modes stay visually and behaviorally aligned instead of maintaining a
    # second set of Summary/Key Points/Action Items tabs.
    if original_deleted is None:
        original_deleted = _is_original_email_deleted(summary)
    if original_deleted:
        _render_original_deleted_notice()
    elif _is_original_email_in_spam(summary):
        _render_original_spam_notice()
    _render_thread_updated_notice(summary)

    overview, key_points = _current_thread_display(summary)
    has_thread_update = bool(_latest_incremental_update(summary))
    modified_key_points = _latest_modified_key_points(summary)
    modified_actions = _latest_modified_action_values(summary)
    modified_deadlines = _latest_modified_deadlines(summary)
    # Action Items already contain the reconciled current task state. Render
    # that snapshot directly; old/reworded values remain available in Recent
    # Activity instead of being duplicated in the live card.
    current_action_items = _clean_list(summary.get("action_items"))
    action_items = current_action_items
    has_actions = bool(current_action_items)
    task_is_cancelled = (
        has_actions
        and normalize_task_status(summary.get("status") or "Not Started") == "Cancelled"
    )
    # Deadlines are task metadata. Keep the AI Summary aligned with To-Do:
    # per-action due dates are authoritative when available, while the saved
    # email-level list remains a compatibility fallback. Summary-only records
    # never show a task deadline even if a legacy record contains a stray date.
    deadlines = _summary_task_deadlines(summary, current_action_items, summary.get("deadlines"))
    trace_summary_pipeline(
        "UI_RENDER",
        summary=summary,
        payload={
            "display_summary": overview,
            "display_key_points": key_points,
            "display_action_items": action_items,
            "display_deadlines": deadlines,
            "saved_deadlines": summary.get("deadlines"),
            "detail_deadlines": _action_item_deadlines(summary),
        },
    )
    has_deadlines = bool(deadlines)
    st.markdown(
        f'''
        <section class="individual-summary-section individual-summary-overview-section">
            <div class="individual-summary-section-heading">
                <span class="individual-summary-section-icon is-blue">&#8801;</span>
                <span>Summary</span>
            </div>
            <div class="individual-summary-overview-text{' is-thread-update' if has_thread_update else ''}">{html.escape(overview)}</div>
        </section>
        ''',
        unsafe_allow_html=True,
    )
    # Keep grounded Key Points visible when present. An empty list is valid and
    # uses the same compact informational empty-state pattern as No Action.
    if key_points:
        key_points_body = (
            _individual_preview_html(
                key_points,
                limit=SUMMARY_KEY_POINTS_PREVIEW_LIMIT,
                variant="check",
                singular_label="key point",
                plural_label="key points",
                highlighted_values=modified_key_points,
            )
            if key_points
            else ""
        )
        st.markdown(
            f'''
            <section class="individual-summary-section individual-summary-collapsible-card is-key-points-card">
                <div class="individual-summary-section-heading">
                    <span class="individual-summary-section-icon is-green">&#10003;</span>
                    <span>Key Points</span>
                </div>
                {key_points_body}
            </section>
            ''',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '''
            <section class="individual-summary-no-action individual-summary-no-key-points">
                <span class="individual-summary-no-action-icon">i</span>
                <div>
                    <div class="individual-summary-no-action-title">No key points</div>
                    <div class="individual-summary-no-action-text">This email has no key information to highlight.</div>
                </div>
            </section>
            ''',
            unsafe_allow_html=True,
        )
    if has_deadlines or has_actions:
        show_deadline_panel = bool(has_deadlines)
        show_action_panel = bool(has_actions)
        detail_class = "" if show_deadline_panel and show_action_panel else " is-single"
        deadline_panel = ""
        action_panel = ""

        if show_deadline_panel:
            deadline_title = "Important Deadline" if len(deadlines) == 1 else "Important Deadlines"
            deadline_body = _individual_preview_html(
                deadlines,
                limit=SUMMARY_DEADLINES_PREVIEW_LIMIT,
                variant="deadline",
                singular_label="deadline",
                plural_label="deadlines",
                highlighted_values=modified_deadlines,
            )
            deadline_panel = (
                '<section class="individual-summary-section individual-summary-detail-card individual-summary-collapsible-card is-deadline-card">'
                '<div class="individual-summary-section-heading">'
                '<span class="individual-summary-section-icon is-blue">&#9635;</span>'
                f'<span>{deadline_title}</span>'
                '</div>'
                f'{deadline_body}'
                '</section>'
            )

        if show_action_panel:
            action_body = _individual_preview_html(
                action_items,
                limit=SUMMARY_ACTION_ITEMS_PREVIEW_LIMIT,
                variant="action",
                singular_label="action item",
                plural_label="action items",
                highlighted_values=modified_actions,
            )
            cancelled_class = " is-cancelled-task" if task_is_cancelled else ""
            cancelled_note = (
                '<div class="individual-summary-cancelled-note">'
                '<span class="individual-summary-cancelled-note-icon">i</span>'
                '<span>Task cancelled. No action is currently required.</span>'
                '</div>'
                if task_is_cancelled
                else ""
            )
            action_panel = (
                '<section class="individual-summary-section individual-summary-detail-card individual-summary-collapsible-card is-action-card'
                f'{cancelled_class}">'
                '<div class="individual-summary-section-heading">'
                '<span class="individual-summary-section-icon is-amber">&#8594;</span>'
                '<span>Action Items</span>'
                '</div>'
                f'{action_body}'
                f'{cancelled_note}'
                '</section>'
            )

        st.markdown(
            f'<div class="individual-summary-detail-grid{detail_class}">'
            f'{deadline_panel}{action_panel}'
            '</div>',
            unsafe_allow_html=True,
        )

    if not has_actions:
        st.markdown(
            '''
            <section class="individual-summary-no-action">
                <span class="individual-summary-no-action-icon">i</span>
                <div>
                    <div class="individual-summary-no-action-title">No action required</div>
                    <div class="individual-summary-no-action-text">This email is for your information only.</div>
                </div>
            </section>
            ''',
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="individual-summary-bottom-spacer"></div>',
        unsafe_allow_html=True,
    )

def _batch_expander_badges_markdown(email_item: dict) -> str:
    # Keep source-level update state visible in a collapsed Batch row so the
    # user does not have to open every source email to find the changed thread.
    # Reuse the same durable, non-historical incremental-update signal as the
    # expanded "Summary updated from a new reply" notice.
    badges: list[str] = []
    if _latest_incremental_update(email_item):
        badges.append("  :blue-badge[UPDATED]")

    # Informational source emails have no task status/priority metadata. An
    # UPDATED badge can still appear by itself when that thread received a new
    # reply, while actionable rows keep their normal status + priority badges.
    if not is_task_ready(email_item):
        return "".join(badges)

    status = normalize_task_status(email_item.get("status") or "Not Started")
    status_color = {
        "Completed": "green",
        "In Progress": "blue",
        "On Hold": "yellow",
        "Cancelled": "gray",
        "Not Started": "orange",
    }.get(status, "orange")

    priority = _clean_text(email_item.get("priority"), "Medium").title()
    if priority not in {"Critical", "High", "Medium", "Low"}:
        priority = "Medium"
    priority_color = (
        "gray"
        if status in {"Completed", "Cancelled"}
        else {
            "Critical": "red",
            "High": "red",
            "Medium": "orange",
            "Low": "green",
        }[priority]
    )

    badges.extend((
        f"  :{status_color}-badge[{status.upper()}]",
        f"  :{priority_color}-badge[{priority.upper()}]",
    ))
    return "".join(badges)


def _batch_expander_label(index: int, email_item: dict) -> str:
    # Source-email title with task badges in the expander header itself.
    subject = _clean_text(email_item.get("subject"), "(No Subject)")

    # Escape Markdown-sensitive subject characters while preserving the native
    # badge directives that are appended after the subject. Sender details remain
    # available in the expanded Individual-style header.
    escaped = str(subject).replace("\\", "\\\\")
    for marker in ("*", "_", "`", "[", "]", "<", ">", "#"):
        escaped = escaped.replace(marker, f"\\{marker}")

    return f"**{index}**  {escaped}{_batch_expander_badges_markdown(email_item)}"

def _render_batch_email_sources(summary: dict) -> None:
    # Render Batch sources as numbered collapsible Individual Summary cards.
    breakdowns = [
        item for item in (summary.get("email_breakdowns") or [])
        if isinstance(item, dict)
    ]
    if not breakdowns:
        st.caption("No source emails are available for this Batch Summary.")
        return

    for index, email_item in enumerate(breakdowns, 1):
        # Availability belongs to this source email only. One deleted message in
        # a Batch must not disable actions or add notices to its sibling items.
        original_deleted = _is_original_email_deleted(email_item)

        with st.container(border=False, key=f"batch_email_group_{index}"):
            with st.expander(_batch_expander_label(index, email_item), expanded=False):
                # The expanded body keeps only the Individual summary content.
                # Source actions stay attached to the collapsible header.
                _render_header(email_item, show_subject=False)
                _render_individual_summary_sections(
                    email_item,
                    original_deleted=original_deleted,
                )

            _render_source_more_actions(
                email_item,
                scope=f"batch_source_{index}",
                compact_trigger=True,
                delete_label="Delete this summary",
                original_deleted=original_deleted,
                batch_parent_uid=str(summary.get("uid") or ""),
                batch_item_count=len(breakdowns),
            )

def _render_batch_header(summary: dict) -> None:
    # Render the fixed Batch title/meta area outside the source-email scroller.
    breakdowns = [
        item for item in (summary.get("email_breakdowns") or [])
        if isinstance(item, dict)
    ]
    count = len(breakdowns) or int(summary.get("email_count") or 0)
    actions = _batch_values(summary, "action_items")
    deadlines = _batch_values(summary, "deadlines")
    topic = _clean_text(summary.get("subject"), "Selected Email Highlights")
    mail_icon = """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 6.5h17v11h-17z"/><path d="m4 7 8 6 8-6"/></svg>"""
    task_icon = """<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4.5h10a2 2 0 0 1 2 2v13H5v-13a2 2 0 0 1 2-2z"/><path d="M9 3h6v3H9z"/><path d="m8.5 12 2 2 5-5"/></svg>"""
    deadline_icon = """<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="5.5" width="16" height="14" rx="1.5"/><path d="M8 3.5v4M16 3.5v4M4 9h16"/><path d="M9 13h6v4H9z"/></svg>"""

    st.markdown(
        f'''
        <div class="batch-summary-heading batch-summary-heading-compact">
            <div class="batch-summary-title">{html.escape(topic)}</div>
            <div class="batch-summary-counts" aria-label="Batch summary totals">
                <span class="batch-summary-count-item"><i>{mail_icon}</i><strong>{count}</strong> email{'s' if count != 1 else ''}</span>
                <span class="batch-summary-count-divider" aria-hidden="true"></span>
                <span class="batch-summary-count-item"><i>{task_icon}</i><strong>{len(actions)}</strong> action item{'s' if len(actions) != 1 else ''}</span>
                <span class="batch-summary-count-divider" aria-hidden="true"></span>
                <span class="batch-summary-count-item"><i>{deadline_icon}</i><strong>{len(deadlines)}</strong> deadline{'s' if len(deadlines) != 1 else ''}</span>
            </div>
        </div>
        ''',
        unsafe_allow_html=True,
    )


def _render_batch_reader(summary: dict) -> None:
    # Render only the scrollable source-email cards for a Batch Summary.
    _render_batch_email_sources(summary)

def render_summary_reader(summary):
    if st.session_state.get("summary_recent_activity_record"):
        _show_summary_recent_activity()
    if st.session_state.get("summary_pending_delete"):
        _show_summary_delete_confirmation()

    if not summary:
        with st.container(height=SUMMARY_READER_EMPTY_HEIGHT, border=False, key="summary_reader_empty_scroll"):
            st.markdown(
                """
                <div class="summary-empty-state">
                    <div class="summary-empty-inner">
                        <div class="summary-empty-icon" aria-hidden="true">
                            <svg viewBox="0 0 64 64" role="img">
                                <path d="M32 10l3.8 10.2L46 24l-10.2 3.8L32 38l-3.8-10.2L18 24l10.2-3.8L32 10Z" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linejoin="round"/>
                                <path d="M48 35l2.1 5.9L56 43l-5.9 2.1L48 51l-2.1-5.9L40 43l5.9-2.1L48 35Z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
                                <path d="M16 34l1.6 4.4L22 40l-4.4 1.6L16 46l-1.6-4.4L10 40l4.4-1.6L16 34Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                            </svg>
                        </div>
                        <div class="summary-empty-title">Select a summary to review its details.</div>
                        <div class="summary-empty-copy">MailMind will show the AI summary, key points, action items, and deadlines here.</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        return

    if summary.get("record_type") == "batch":
        # Match the Individual reader structure: keep the Batch title/meta fixed
        # above the dedicated scroll surface so only Included emails scroll.
        with st.container(border=False, key="batch_summary_header"):
            _render_batch_header(summary)

        with st.container(height=SUMMARY_READER_CONTENT_HEIGHT, border=False, key="batch_summary_reader_scroll"):
            _render_batch_reader(summary)
        return


    original_deleted = _is_original_email_deleted(summary)

    with st.container(border=False, key="individual_summary_header"):
        _render_header(summary)
        _render_source_more_actions(
            summary,
            scope="individual",
            delete_label="Delete summary",
            original_deleted=original_deleted,
        )

    with st.container(height=SUMMARY_READER_CONTENT_HEIGHT, border=False, key="individual_summary_reader_scroll"):
        _render_individual_summary_sections(
            summary,
            original_deleted=original_deleted,
        )
