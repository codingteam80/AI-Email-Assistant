# Summary deletion workflow for Individual and per-source Batch summaries.
import streamlit as st

from storage.summary_store import SUMMARY_FOLDER
from ui.inbox_notifications import push_summary_toast
from ui.summary_metrics import is_task_ready


def _live_summary(uid: str) -> dict | None:
    uid = str(uid or "").strip()
    for item in st.session_state.get("summaries", []) or []:
        if str(item.get("uid") or "").strip() == uid:
            return dict(item)
    return None


def _live_batch_source(batch_uid: str, source_uid: str) -> tuple[dict | None, dict | None]:
    parent = _live_summary(batch_uid)
    if not parent or str(parent.get("record_type") or "").casefold() != "batch":
        return None, None
    source_uid = str(source_uid or "").strip()
    source = next(
        (
            dict(item) for item in (parent.get("email_breakdowns") or [])
            if isinstance(item, dict) and str(item.get("uid") or "").strip() == source_uid
        ),
        None,
    )
    return parent, source


def delete_summary_record(
    *,
    summary_uid: str,
    batch_parent_uid: str = "",
    folder: str = SUMMARY_FOLDER,
) -> bool:
    # Delete the visible AI summary and therefore its derived To-Do record. A
    # tiny thread checkpoint survives so a future reply can start a fresh
    # summary without resurrecting old completed/cancelled work.
    store = st.session_state.get("summary_store")
    if store is None:
        return False

    summary_uid = str(summary_uid or "").strip()
    batch_parent_uid = str(batch_parent_uid or "").strip()
    if not summary_uid:
        return False

    if batch_parent_uid:
        parent, target = _live_batch_source(batch_parent_uid, summary_uid)
        if not parent or not target:
            st.session_state.summaries = store.load_all(folder)
            parent, target = _live_batch_source(batch_parent_uid, summary_uid)
        if not parent or not target:
            return False

        store.record_deletion_checkpoint(folder, target)
        result = store.delete_batch_source(folder, batch_parent_uid, summary_uid)
        if not result.get("deleted"):
            return False

        st.session_state.summaries = store.load_all(folder)
        if result.get("deleted_parent"):
            if str(st.session_state.get("selected_summary_uid") or "") == batch_parent_uid:
                st.session_state.selected_summary_uid = None
        else:
            st.session_state.selected_summary_uid = batch_parent_uid

        task_removed = is_task_ready(target)
        subject = str(target.get("subject") or "(No Subject)").strip()
        details = [f"Summary: {subject}"]
        if task_removed:
            details.append("Linked To-Do task removed")
        if result.get("deleted_parent"):
            details.append("Empty Batch Summary removed")

        message = (
            "Summary and linked task deleted successfully."
            if task_removed
            else "Summary deleted successfully."
        )
        push_summary_toast(
            message,
            "success",
            title="Summary deleted",
            details=details,
            event_type="summary-deleted",
            entity_id=summary_uid,
        )
        return True

    target = _live_summary(summary_uid)
    if target is None:
        st.session_state.summaries = store.load_all(folder)
        target = _live_summary(summary_uid)
    if target is None:
        return False

    store.record_deletion_checkpoint(folder, target)
    if not store.delete_summary(folder, summary_uid):
        return False

    st.session_state.summaries = store.load_all(folder)
    if str(st.session_state.get("selected_summary_uid") or "") == summary_uid:
        st.session_state.selected_summary_uid = None

    task_removed = is_task_ready(target)
    subject = str(target.get("subject") or "(No Subject)").strip()
    details = [f"Summary: {subject}"]
    if task_removed:
        details.append("Linked To-Do task removed")

    push_summary_toast(
        (
            "Summary and linked task deleted successfully."
            if task_removed
            else "Summary deleted successfully."
        ),
        "success",
        title="Summary deleted",
        details=details,
        event_type="summary-deleted",
        entity_id=summary_uid,
    )
    return True
