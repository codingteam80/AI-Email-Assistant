def promote_pending_draft_dialog(state) -> bool:
    # Promote a completed draft into the root-owned dialog only on a full-app run.
    # A background fragment may queue the UID, but it must not directly open
    # dialog state because that can leave an orphaned blank Streamlit portal.
    pending_uid = str(state.get("draft_dialog_pending_uid") or "").strip()
    if not pending_uid:
        return False

    active_dialog = any(
        str(state.get(key) or "").strip()
        for key in ("draft_dialog_uid", "original_dialog_uid", "spam_email_dialog_uid")
    )
    if active_dialog:
        return False

    state["draft_dialog_uid"] = pending_uid
    state.pop("draft_dialog_pending_uid", None)
    state.pop("original_dialog_uid", None)
    return True
