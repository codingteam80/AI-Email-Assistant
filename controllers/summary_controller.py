# Background-safe coordination for AI summary generation and reading.
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Event, Lock
import time

import streamlit as st

from config import (
    AUTO_SUMMARY_MONITOR_FRAGMENT_SECONDS,
    AUTO_SUMMARY_SECURITY_WAIT_SECONDS,
    SUMMARY_GENERATION_FRAGMENT_SECONDS,
)

from services.white_stale_trace_service import trace_action

from storage.summary_store import SUMMARY_FOLDER
from services.restoration_service import same_message_identity
from email_handler.thread_identity import canonical_thread_id
from email_handler.display_time import parse_timestamp
from services.summary_eligibility_service import evaluate_summary_eligibility
from services.ui_interaction_service import foreground_interaction_is_settling
from services.email_service import get_full_email
from services.generation_trace_service import (
    begin_generation_trace, finish_generation_trace, new_generation_job_id,
    trace_event, trace_external, trace_launch,
)

from ui.loading import (
    clear_app_loading_state,
    render_summary_live_progress,
    set_app_loading_state,
    update_app_loading_state,
)
from services.summary_service import (
    create_batch_summary, create_single_email_batch_summary, create_summary, create_incremental_summary,
    merge_incremental_summary, merge_unseen_thread_updates, reconstruct_thread_summary,
    update_batch_breakdown,
)
from services.ai_service import get_ollama_status
from services.ollama_runtime_service import user_facing_ai_error
from services.streamlit_latency_profiler_service import (
    mark_commit_done,
    mark_future_done,
    mark_job_launch,
)
from services.thread_service import (
    build_incremental_thread_email, build_thread_email, filter_thread_email_for_summary,
    freeze_thread_email_for_summary_snapshot,
)
from ui.inbox_notifications import push_summary_toast, queue_summary_confirmation
from ui.notification_center import record_notification
from ui.draft_state import invalidate_updated_summary_drafts


class SummaryProgress:
    # Thread-safe, UI-readable progress snapshot for one summary job.

    def __init__(self, total: int):
        self.total = total
        self.processed = 0
        self._lock = Lock()

    def advance(self):
        with self._lock:
            self.processed += 1

    def snapshot(self):
        with self._lock:
            return self.processed, self.total


class SummaryCancellation:
    # Cooperative cancellation token shared by the Streamlit UI and worker.

    def __init__(self):
        self._event = Event()

    def request(self) -> None:
        self._event.set()

    def requested(self) -> bool:
        return self._event.is_set()


def _cancelled_summary_result(
    summaries: list[dict],
    working_batches: dict[str, dict],
    failures: list[tuple[str, str]],
    security_skips: list[tuple[str, str]],
    mode: str,
    progress: SummaryProgress,
) -> dict:
    # Individual mode keeps work completed before cancellation. Batch output is
    # atomic, so an unfinished manual/auto batch is never persisted partially.
    retained = [] if mode in {"batch", "auto_batch"} else list(summaries) + list(working_batches.values())
    processed, total = progress.snapshot()
    return {
        "summaries": retained,
        "failures": failures,
        "security_skips": security_skips,
        "mode": mode,
        "cancelled": True,
        "cancelled_processed": processed,
        "requested_count": total,
    }


def _summarize_batch(client, email_store, headers: list[dict], folder: str,
                     progress: SummaryProgress, mode: str = "manual",
                     existing_summaries: list[dict] | None = None,
                     deletion_checkpoints: dict[str, dict] | None = None,
                     origin: str = "manual",
                     cancel_token: SummaryCancellation | None = None,
                     recipient_identity: str = "",
                     trace_job_id: str = "",
                     thread_snapshot: dict[str, dict] | None = None) -> dict:
    # Summarize selected reply threads and optionally combine them into one card.
    begin_generation_trace(
        "SUMMARY", trace_job_id, origin=str(origin or "manual"), mode=mode, items=len(headers)
    )
    summaries, failures = [], []
    existing_by_thread = {
        str(item.get("canonical_thread_id") or ""): dict(item)
        for item in (existing_summaries or [])
        if str(item.get("canonical_thread_id") or "")
        and str(item.get("record_type") or "manual") != "batch"
    }
    batch_owners, working_batches = {}, {}
    for item in (existing_summaries or []):
        if str(item.get("record_type") or "manual") != "batch":
            continue
        batch_uid = str(item.get("uid") or "")
        for index, breakdown in enumerate(item.get("email_breakdowns") or []):
            canonical_id = str(breakdown.get("canonical_thread_id") or "").strip()
            if canonical_id:
                batch_owners[canonical_id] = (batch_uid, index, item)
    checkpoints = {
        str(key or "").strip(): dict(value)
        for key, value in (deletion_checkpoints or {}).items()
        if str(key or "").strip() and isinstance(value, dict)
    }
    processed_thread_uids = set()
    security_skips = []
    up_to_date_threads = []

    def cancellation_requested() -> bool:
        return bool(cancel_token is not None and cancel_token.requested())

    def cancelled_result() -> dict:
        finish_generation_trace(
            "cancelled", summaries=len(summaries) + len(working_batches),
            failures=len(failures), security_skips=len(security_skips),
        )
        return _cancelled_summary_result(
            summaries, working_batches, failures, security_skips, mode, progress
        )

    def selected_incremental_fallback(current_header: dict, thread_email: dict, known_uids, existing_record: dict):
        # A Security-finalized selected reply can arrive before the provider's
        # conversation expansion reflects it. If it is genuinely newer than the
        # saved card, summarize that selected turn rather than silently no-op.
        selected_uid = str(current_header.get("uid") or "").strip()
        known = {str(value or "").strip() for value in (known_uids or []) if str(value or "").strip()}
        if not selected_uid or selected_uid in known or same_message_identity(current_header, existing_record):
            return None
        full_result = get_full_email(client, selected_uid, folder=folder, store=email_store)
        if not full_result.get("success"):
            return None
        selected_full = dict(full_result.get("email") or {})
        if not selected_full:
            return None
        selected_thread = {
            **selected_full,
            "thread_messages": [selected_full],
            "source_uids": [selected_uid],
            "thread_count": 1,
            "canonical_thread_id": str(thread_email.get("canonical_thread_id") or ""),
            "thread_subject": str(thread_email.get("thread_subject") or ""),
        }
        return build_incremental_thread_email(selected_thread, known)

    def promote_fallback_turn(thread_email: dict, incremental_email: dict) -> dict:
        # Keep the persisted card's latest-message metadata/source set aligned
        # with a fallback turn that was absent from the provider expansion.
        current_sources = [str(value) for value in (thread_email.get("source_uids") or []) if str(value)]
        incremental_sources = [str(value) for value in (incremental_email.get("source_uids") or []) if str(value)]
        missing = [value for value in incremental_sources if value not in current_sources]
        if not missing:
            return thread_email
        promoted = dict(thread_email)
        for key in ("uid", "from", "to", "cc", "subject", "date", "date_display", "snippet", "message_id"):
            value = incremental_email.get(key)
            if value not in (None, ""):
                promoted[key] = value
        promoted["source_uids"] = list(dict.fromkeys(current_sources + incremental_sources))
        promoted["thread_count"] = len(promoted["source_uids"])
        return promoted

    for item_index, header in enumerate(headers, 1):
        if cancellation_requested():
            return cancelled_result()

        uid = str(header["uid"])
        lifecycle_state = str(header.get("_mailmind_lifecycle") or "EXISTING")

        # RESTORED/provider-moved messages are never Auto Summary arrivals. The
        # mailbox controller removes them before queueing, and this worker-level
        # guard is the final defense against stale queues from an older session.
        # Manual summarization remains available when current Security/location
        # eligibility allows it.
        if str(origin or "manual") == "auto" and lifecycle_state in {
            "RESTORED",
            "MOVED_SPAM_TO_INBOX",
        }:
            security_skips.append((
                header.get("subject") or uid,
                "Restored email is not treated as new and does not trigger Auto Summary.",
            ))
            progress.advance()
            continue

        try:
            # Final provider-neutral gate for BOTH Auto and Manual generation.
            # An email may move Inbox <-> Spam/Junk after selection/queueing but
            # before its worker reaches it, so always re-read the current stored
            # location + final Security verdict immediately before any LLM work.
            current = email_store.get_email(folder, uid)
            if current is None or int(current.get("security_input_version") or 0) < 2:
                security_skips.append((
                    header.get("subject") or uid,
                    "The email is no longer available as a Security-finalized Inbox message.",
                ))
                progress.advance()
                continue
            eligibility = evaluate_summary_eligibility(
                current, lifecycle_state=lifecycle_state, already_summarized=False
            )
            if not eligibility.can_generate:
                security_skips.append((
                    current.get("subject") or header.get("subject") or uid,
                    eligibility.reason,
                ))
                progress.advance()
                continue
            header = current

            if cancellation_requested():
                return cancelled_result()

            thread_started = time.perf_counter()
            thread_email = build_thread_email(client, email_store, header, folder)
            prefilter_canonical_id = str(thread_email.get("canonical_thread_id") or "").strip()
            if str(origin or "manual") == "auto" and thread_snapshot:
                snapshot_key = (
                    prefilter_canonical_id
                    or str(canonical_thread_id(header) or "").strip()
                    or f"uid:{uid}"
                )
                snapshot = dict(thread_snapshot.get(snapshot_key) or {})
                if snapshot:
                    thread_email = freeze_thread_email_for_summary_snapshot(
                        thread_email,
                        boundary_date=str(snapshot.get("boundary_date") or ""),
                        known_uids=snapshot.get("known_uids") or [],
                    )
                    prefilter_canonical_id = str(
                        thread_email.get("canonical_thread_id") or prefilter_canonical_id
                    ).strip()
            first_thread_summary = bool(
                prefilter_canonical_id
                and prefilter_canonical_id not in existing_by_thread
                and prefilter_canonical_id not in batch_owners
                and prefilter_canonical_id not in checkpoints
            )
            if first_thread_summary:
                thread_email = filter_thread_email_for_summary(
                    thread_email, email_store, folder,
                    allow_historical_provider_safe=True,
                )
            else:
                # Preserve the established 3-argument call path for existing
                # summaries/checkpoints and for tests/plugins that wrap this
                # helper with the legacy signature.
                thread_email = filter_thread_email_for_summary(
                    thread_email, email_store, folder
                )
            trace_event(
                "thread_ready",
                elapsed=time.perf_counter() - thread_started,
                item=item_index,
                items=int(thread_email.get("thread_count") or 1),
                security_excluded=len(thread_email.get("excluded_summary_uids") or []),
            )
            if recipient_identity:
                thread_email["_mailmind_recipient_identity"] = recipient_identity
            if cancellation_requested():
                return cancelled_result()

            source_uids = set(thread_email.get("source_uids") or [uid])
            if source_uids & processed_thread_uids:
                progress.advance()
                continue
            canonical_id = str(thread_email.get("canonical_thread_id") or "")
            existing = existing_by_thread.get(canonical_id)
            if existing:
                known_uids = existing.get("source_uids") or [existing.get("uid")]
                merged_existing, applied_turns = merge_unseen_thread_updates(
                    existing, thread_email, known_uids
                )
                if applied_turns:
                    if cancellation_requested():
                        return cancelled_result()
                    summaries.append(merged_existing)
                else:
                    incremental_email = selected_incremental_fallback(
                        header, thread_email, known_uids, existing
                    )
                    if incremental_email is not None:
                        thread_email = promote_fallback_turn(thread_email, incremental_email)
                    if incremental_email is not None and recipient_identity:
                        incremental_email["_mailmind_recipient_identity"] = recipient_identity
                    if incremental_email is None:
                        up_to_date_threads.append(header.get("subject") or uid)
                        progress.advance()
                        continue
                    generated = create_incremental_summary(incremental_email, existing)
                    if cancellation_requested():
                        return cancelled_result()
                    summaries.append(merge_incremental_summary(existing, generated, thread_email))
            elif canonical_id in batch_owners:
                batch_uid, index, saved_batch = batch_owners[canonical_id]
                current_batch = working_batches.get(batch_uid) or deepcopy(saved_batch)
                existing_breakdown = (current_batch.get("email_breakdowns") or [])[index]
                known_uids = existing_breakdown.get("source_uids") or [existing_breakdown.get("uid")]
                merged_breakdown, applied_turns = merge_unseen_thread_updates(
                    existing_breakdown, thread_email, known_uids
                )
                if not applied_turns:
                    incremental_email = selected_incremental_fallback(
                        header, thread_email, known_uids, existing_breakdown
                    )
                    if incremental_email is not None:
                        thread_email = promote_fallback_turn(thread_email, incremental_email)
                    if incremental_email is not None and recipient_identity:
                        incremental_email["_mailmind_recipient_identity"] = recipient_identity
                    if incremental_email is None:
                        up_to_date_threads.append(header.get("subject") or uid)
                        progress.advance()
                        continue
                    generated = create_incremental_summary(incremental_email, existing_breakdown)
                    if cancellation_requested():
                        return cancelled_result()
                    merged_breakdown = merge_incremental_summary(
                        existing_breakdown, generated, thread_email
                    )
                if cancellation_requested():
                    return cancelled_result()
                working_batches[batch_uid] = update_batch_breakdown(
                    current_batch, merged_breakdown
                )
            else:
                checkpoint = checkpoints.get(canonical_id) if canonical_id else None
                if checkpoint:
                    known_uids = checkpoint.get("source_uids") or []
                    incremental_email = build_incremental_thread_email(thread_email, known_uids)
                    if incremental_email is not None and recipient_identity:
                        incremental_email["_mailmind_recipient_identity"] = recipient_identity
                    if incremental_email is None:
                        # Manual regeneration is an explicit user request, so an
                        # unchanged deleted thread may be summarized again. Auto
                        # Summary never recreates a deleted summary without a
                        # genuinely new conversation turn.
                        if (
                            str(origin or "manual") == "auto"
                            and lifecycle_state != "MOVED_SPAM_TO_INBOX"
                        ):
                            progress.advance()
                            processed_thread_uids.update(source_uids)
                            continue
                        # Case 7: moving a Safe email back to Inbox is an
                        # explicit new eligibility event. If its old summary was
                        # intentionally deleted, allow one fresh summary instead
                        # of treating the deletion checkpoint as a duplicate.
                        fresh = reconstruct_thread_summary(thread_email)
                    else:
                        # Only unseen turns feed the LLM, but persist the full set
                        # of already-processed UIDs. Future replies then remain
                        # incremental and old deleted work cannot reappear.
                        fresh = create_summary(incremental_email)
                        if cancellation_requested():
                            return cancelled_result()
                        fresh["source_uids"] = list(dict.fromkeys(
                            [str(value) for value in (known_uids or []) if str(value)]
                            + [str(value) for value in (thread_email.get("source_uids") or []) if str(value)]
                        ))
                        fresh["thread_count"] = int(
                            thread_email.get("thread_count")
                            or len(fresh["source_uids"])
                            or 1
                        )
                        fresh["canonical_thread_id"] = canonical_id
                    if cancellation_requested():
                        return cancelled_result()
                    summaries.append(fresh)
                else:
                    fresh = reconstruct_thread_summary(thread_email)
                    if cancellation_requested():
                        return cancelled_result()
                    summaries.append(fresh)
            processed_thread_uids.update(source_uids)
        except RuntimeError as error:
            trace_event("item_error", item=item_index, status=type(error).__name__)
            failures.append((header.get("subject") or uid, str(error)))
        progress.advance()

    if cancellation_requested():
        return cancelled_result()

    summaries.extend(working_batches.values())
    loose_summaries = [
        item for item in summaries if str(item.get("record_type") or "manual") != "batch"
    ]
    batch_updates = [
        item for item in summaries if str(item.get("record_type") or "manual") == "batch"
    ]
    if mode in {"batch", "auto_batch"} and len(loose_summaries) >= 2:
        try:
            batch_summary = create_batch_summary(loose_summaries)
            if cancellation_requested():
                return _cancelled_summary_result(
                    [], {}, failures, security_skips, mode, progress
                )
            summaries = batch_updates + [batch_summary]
        except RuntimeError as error:
            failures.append(("Selected email batch", str(error)))
            summaries = batch_updates
    elif mode == "auto_batch" and len(loose_summaries) == 1:
        # Auto Batch is a user-selected output mode, not a minimum-size rule.
        # A single new email is therefore persisted as a one-email Batch record
        # so the AI Summary tab uses the Batch card/reader UI consistently.
        # This wrapper reuses the already-generated individual analysis and does
        # not make a second LLM call.
        if cancellation_requested():
            return _cancelled_summary_result(
                [], {}, failures, security_skips, mode, progress
            )
        summaries = batch_updates + [create_single_email_batch_summary(loose_summaries[0])]
    # Manual Batch remains graceful after duplicate/thread de-duplication: if
    # only one distinct email remains after a valid 2+ selection, keep its
    # individual summary instead of failing the manual request.

    finish_generation_trace(
        "ok", summaries=len(summaries), failures=len(failures),
        security_skips=len(security_skips),
    )
    return {
        "summaries": summaries,
        "failures": failures,
        "security_skips": security_skips,
        "up_to_date_threads": up_to_date_threads,
        "mode": mode,
        "cancelled": False,
        "requested_count": len(headers),
    }


def _selected_headers(
    list_source, folder: str, selected_uids_override=None
) -> list[dict]:
    # Resolve the click-time UID snapshot from storage, including selections on
    # other pages.  Callers without a snapshot retain the established behavior.
    selected_uids = set(
        selected_uids_override
        if selected_uids_override is not None
        else st.session_state.checked_uids
    )
    fallback = {str(item.get("uid")): item for item in list_source}
    headers = []
    for uid in selected_uids:
        header = st.session_state.email_store.get_email(folder, uid)
        if header is not None:
            headers.append(header)
        elif uid in fallback:
            headers.append(fallback[uid])
    return headers


def _normalize_uid(value) -> str:
    # Normalize identifiers before comparing Inbox mail with saved summaries.
    return str(value or "").strip()


def _header_notification_details(headers, *, limit: int = 5) -> tuple[list[str], str]:
    rows = [item for item in (headers or []) if isinstance(item, dict)]
    details = []
    for item in rows[:limit]:
        subject = str(item.get("subject") or "(No Subject)").strip()
        sender = str(item.get("from") or "Unknown sender").strip()
        details.append(f"{subject} — From {sender}")
    if len(rows) > limit:
        details.append(f"+{len(rows) - limit} more email{'s' if len(rows) - limit != 1 else ''}")
    entity_id = _normalize_uid(rows[0].get("uid")) if len(rows) == 1 else ""
    return details, entity_id


def _summary_notification_details(summaries, *, limit: int = 5) -> tuple[list[str], str]:
    rows = [item for item in (summaries or []) if isinstance(item, dict)]
    details = []
    for item in rows[:limit]:
        if str(item.get("record_type") or "").casefold() == "batch":
            count = int(item.get("email_count") or len(item.get("email_breakdowns") or []) or 1)
            title = str(item.get("subject") or item.get("batch_title") or "Batch Summary").strip()
            details.append(f"{title} — {count} emails")
        else:
            subject = str(item.get("subject") or "(No Subject)").strip()
            sender = str(item.get("from") or "Unknown sender").strip()
            details.append(f"{subject} — From {sender}")
    if len(rows) > limit:
        details.append(f"+{len(rows) - limit} more summaries")
    entity_id = _normalize_uid(rows[0].get("uid")) if len(rows) == 1 else ""
    return details, entity_id


def _legacy_identity_matches(header: dict, summary: dict) -> bool:
    # Keep the established duplicate-check API while sharing the same physical
    # message identity rule used by mailbox RESTORED-vs-NEW classification.
    return same_message_identity(header, summary)


def _existing_summary_records(folder: str) -> list[dict]:
    # Read duplicate metadata from storage plus any currently loaded summaries.
    records = list(st.session_state.summary_store.get_duplicate_records(folder))
    known_uids = {_normalize_uid(item.get("uid")) for item in records}
    for item in st.session_state.get("summaries", []):
        uid = _normalize_uid(item.get("uid"))
        if uid and uid not in known_uids:
            records.append(dict(item))
            known_uids.add(uid)
    return records


def _summary_loading_copy(headers: list[dict], folder: str) -> tuple[str, str]:
    # Make reply-driven incremental work obvious before the LLM starts. A new
    # message in a thread that already owns a visible Individual/Batch summary
    # updates that existing card instead of creating a duplicate card.
    records = _existing_summary_records(folder)
    summarized_threads = {
        canonical_thread_id(item)
        for item in records
        if canonical_thread_id(item)
    }
    update_flags = [
        bool(canonical_thread_id(header) in summarized_threads)
        for header in headers
    ]
    count = len(headers)

    if count == 1 and update_flags and update_flags[0]:
        return (
            "Updating thread summary",
            "Analyzing new reply and updating the existing summary...",
        )
    if count > 1 and update_flags and all(update_flags):
        return (
            "Updating thread summaries",
            "Analyzing new replies and updating existing summaries...",
        )
    if count > 1 and any(update_flags):
        return (
            "Generating and updating summaries",
            "Analyzing selected emails and new thread replies...",
        )
    if count == 1:
        return "Generating summary", "Analyzing selected email..."
    return "Generating summaries", "Analyzing selected emails..."


def _partition_summary_candidates(headers: list[dict], folder: str):
    # Split manually selected mail into pending and already summarized messages.
    # Both Manual Individual and Manual Batch use the same provider-neutral
    # physical-message identity rule as RESTORED classification, so restoring a
    # summarized email never creates a duplicate summary. A restored email that
    # truly never had a summary remains eligible when the user explicitly asks.
    records = _existing_summary_records(folder)
    exact_uids = {
        uid
        for item in records
        for uid in (
            [_normalize_uid(item.get("uid"))]
            + [_normalize_uid(value) for value in (item.get("source_uids") or [])]
        )
        if uid
    }
    claimed_legacy_uids = set()
    pending_headers = []
    relinks = []

    for header in headers:
        current_uid = _normalize_uid(header.get("uid"))
        if current_uid in exact_uids:
            continue

        legacy_match = next(
            (
                item for item in records
                if _normalize_uid(item.get("uid")) not in claimed_legacy_uids
                and _legacy_identity_matches(header, item)
            ),
            None,
        )
        if legacy_match is None:
            pending_headers.append(header)
            continue

        old_uid = _normalize_uid(legacy_match.get("uid"))
        claimed_legacy_uids.add(old_uid)
        if old_uid and current_uid and old_uid != current_uid:
            relinks.append((old_uid, current_uid))

    return pending_headers, relinks


def _prepare_manual_security_eligible_headers(
    headers: list[dict], folder: str
) -> tuple[list[dict], list[tuple[dict, object]]]:
    # Manual Individual and Manual Batch share the exact same Security gate as
    # Auto Summary. Full-message Security must finish first; Safe + current
    # provider Inbox is eligible, while Spam/Junk or any unsafe verdict is
    # excluded. Duplicate detection remains a separate step afterward.
    client = st.session_state.get("imap_client")
    store = st.session_state.get("email_store")
    if store is None:
        return [], [(dict(item), None) for item in headers]

    eligible = []
    blocked = []
    for original in headers:
        uid = _normalize_uid(original.get("uid"))
        header = store.get_email(folder, uid) or dict(original)
        if int(header.get("security_input_version") or 0) < 2 and client is not None and uid:
            full_result = get_full_email(
                client, uid, folder=folder, store=store, force_remote=True
            )
            if full_result.get("success"):
                header = store.get_email(folder, uid) or header

        if int(header.get("security_input_version") or 0) < 2:
            blocked.append((header, None))
            continue

        result = evaluate_summary_eligibility(
            header, lifecycle_state="EXISTING", already_summarized=False
        )
        if result.can_generate:
            eligible.append(header)
        else:
            blocked.append((header, result))
    return eligible, blocked


def _notify_manual_security_exclusions(blocked, *, mode: str) -> None:
    if not blocked:
        return
    details = []
    for header, result in blocked[:5]:
        subject = str((header or {}).get("subject") or "(No Subject)").strip()
        if result is None:
            reason = "Security analysis could not be finalized yet."
        else:
            reason = str(result.reason or "Not eligible for summarization.")
        details.append(f"{subject} — {reason}")
    if len(blocked) > 5:
        details.append(f"+{len(blocked) - 5} more excluded emails")

    count = len(blocked)
    noun = "email" if count == 1 else "emails"
    message = (
        f"{count} selected {noun} excluded by Security."
        if mode == "batch" or count > 1
        else "This email is not eligible for summarization."
    )
    push_summary_toast(
        message,
        "info",
        details=details,
        event_type="summary-security-blocked",
        entity_id=_normalize_uid((blocked[0][0] or {}).get("uid")) if count == 1 else "",
    )


def _build_auto_summary_thread_snapshot(
    pending_headers: list[dict], folder: str
) -> dict[str, dict]:
    """Capture the conversation boundary owned by one automatic summary job."""
    store = st.session_state.get("email_store")
    snapshot: dict[str, dict] = {}

    for raw in pending_headers or []:
        header = dict(raw or {})
        uid = _normalize_uid(header.get("uid"))
        thread_id = str(canonical_thread_id(header) or "").strip() or f"uid:{uid}"
        entry = snapshot.setdefault(
            thread_id, {"known_uids": set(), "boundary_date": "", "_boundary_ts": None}
        )
        if uid:
            entry["known_uids"].add(uid)
        parsed = parse_timestamp(header.get("date"))
        current = entry.get("_boundary_ts")
        if parsed is not None and (current is None or parsed > current):
            entry["_boundary_ts"] = parsed
            entry["boundary_date"] = parsed.isoformat()

    get_members = getattr(store, "get_thread_members", None) if store is not None else None
    if callable(get_members):
        for thread_id, entry in snapshot.items():
            if thread_id.startswith("uid:"):
                continue
            try:
                members = list(get_members(folder, thread_id) or [])
            except Exception:
                members = []
            for member in members:
                uid = _normalize_uid(member.get("uid"))
                if uid:
                    entry["known_uids"].add(uid)

    frozen: dict[str, dict] = {}
    for thread_id, entry in snapshot.items():
        frozen[thread_id] = {
            "known_uids": sorted(entry.get("known_uids") or set()),
            "boundary_date": str(entry.get("boundary_date") or ""),
        }
    return frozen


def _auto_summary_commit_conflicts_with_draft(folder: str) -> bool:
    """Defer only same-thread Auto Summary commit while a reply draft is active."""
    active_uids = {
        _normalize_uid(st.session_state.get("draft_processing_uid")),
        _normalize_uid(st.session_state.get("draft_dialog_pending_uid")),
        _normalize_uid(st.session_state.get("draft_dialog_uid")),
    }
    active_uids.discard("")
    if not active_uids:
        return False

    job_uids = {
        _normalize_uid(value) for value in (st.session_state.get("summary_job_uids", []) or [])
        if _normalize_uid(value)
    }
    if active_uids & job_uids:
        return True

    job_threads = {
        str(value or "").strip()
        for value in (st.session_state.get("summary_job_thread_ids", []) or [])
        if str(value or "").strip()
    }
    if not job_threads:
        return False

    store = st.session_state.get("email_store")
    if store is None:
        return False
    for uid in active_uids:
        try:
            email = store.get_email(folder, uid)
        except Exception:
            email = None
        if not email:
            continue
        thread_id = str(canonical_thread_id(email) or "").strip()
        if thread_id and thread_id in job_threads:
            return True
    return False


def _clear_summary_job_state() -> None:
    # Remove stale summary/loading state without touching Inbox selections.
    cancel_token = st.session_state.pop("summary_cancel_token", None)
    if cancel_token is not None:
        cancel_token.request()

    future = st.session_state.pop("summary_future", None)
    if future is not None and not future.done():
        future.cancel()

    executor = st.session_state.pop("summary_executor", None)
    if executor is not None:
        executor.shutdown(wait=False, cancel_futures=True)

    st.session_state.summary_processing = False
    st.session_state.summary_cancel_requested = False
    st.session_state.summary_deferred_ready = False
    st.session_state.pop("deferred_summary_request", None)
    st.session_state.pop("summary_pending_confirmation", None)
    st.session_state.pop("active_inbox_toast_on_dismiss", None)
    st.session_state.pop("summary_progress", None)
    st.session_state.pop("summary_job_uids", None)
    st.session_state.pop("summary_job_context", None)
    st.session_state.pop("summary_job_thread_ids", None)
    st.session_state.summary_job_origin = "manual"
    st.session_state.pop("summary_trace_job_id", None)
    clear_app_loading_state()


def _launch_summary_job(
    pending_headers: list[dict],
    selected_uids: set[str] | list[str],
    folder: str,
    mode: str = "manual",
    origin: str = "manual",
) -> None:
    # Start the worker and blocking overlay after any notice is closed.
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="email-summary")
    progress = SummaryProgress(len(pending_headers))
    cancel_token = SummaryCancellation()
    st.session_state.summary_executor = executor
    st.session_state.summary_cancel_token = cancel_token
    st.session_state.summary_cancel_requested = False
    account_email = str(st.session_state.get("active_store_account") or "").strip()
    display_name = str(st.session_state.get("profile_display_name") or "").strip()
    recipient_identity = (
        f"{display_name} <{account_email}>" if display_name and account_email
        else account_email or display_name
    )
    normalized_origin = str(origin or "manual")
    thread_snapshot = (
        _build_auto_summary_thread_snapshot(pending_headers, folder)
        if normalized_origin == "auto"
        else {}
    )
    trace_job_id = new_generation_job_id("summary")
    trace_launch(
        "SUMMARY", trace_job_id, origin=normalized_origin, mode=mode, items=len(pending_headers)
    )
    st.session_state.summary_future = executor.submit(
        _summarize_batch,
        st.session_state.imap_client,
        st.session_state.email_store,
        pending_headers,
        folder,
        progress,
        mode,
        list(st.session_state.get("summaries", [])),
        st.session_state.summary_store.get_deletion_checkpoints(folder),
        normalized_origin,
        cancel_token,
        recipient_identity,
        trace_job_id,
        thread_snapshot,
    )
    st.session_state.summary_progress = progress
    st.session_state.summary_job_uids = list(selected_uids)
    st.session_state.summary_job_context = [
        {
            "uid": _normalize_uid(item.get("uid")),
            "subject": str(item.get("subject") or "(No Subject)"),
            "from": str(item.get("from") or "Unknown sender"),
        }
        for item in pending_headers
    ]
    st.session_state.summary_job_thread_ids = sorted({
        str(canonical_thread_id(item) or "").strip()
        for item in pending_headers
        if str(canonical_thread_id(item) or "").strip()
    })
    st.session_state.summary_job_origin = normalized_origin
    st.session_state.summary_trace_job_id = trace_job_id
    mark_job_launch(origin=normalized_origin)
    st.session_state.summary_processing = True

    # Manual Summary is an explicit foreground action, so retain the blocking
    # progress modal + Cancel control. Auto Summary is background automation:
    # never cover the user's current workspace or steal clicks while they are
    # reading mail, reviewing notifications, or editing task state. Inbox already
    # exposes a compact non-blocking "Summarizing…" chip for Auto jobs.
    if normalized_origin != "auto":
        summary_count = len(pending_headers)
        loading_title, loading_message = _summary_loading_copy(pending_headers, folder)
        set_app_loading_state(
            loading_title,
            loading_message,
            f"0 of {summary_count}",
        )
    else:
        clear_app_loading_state()


def resume_deferred_summary_generation() -> bool:
    # Start a mixed-selection job after its notification is dismissed.
    if not st.session_state.get("summary_deferred_ready"):
        return False

    st.session_state.summary_deferred_ready = False
    request = st.session_state.pop("deferred_summary_request", None)
    if not request or st.session_state.get("summary_processing"):
        return False

    pending_headers = list(request.get("headers") or [])
    if not pending_headers:
        return False

    _launch_summary_job(
        pending_headers,
        request.get("selected_uids") or [],
        str(request.get("folder") or SUMMARY_FOLDER),
        str(request.get("mode") or "manual"),
    )
    return True


def start_summary_generation(
    list_source, folder: str = SUMMARY_FOLDER, selected_uids_override=None
) -> bool:
    # Handle a summary request and signal when the app should rerun.
    if st.session_state.summary_processing:
        return False

    selected_source = (
        selected_uids_override
        if selected_uids_override is not None
        else st.session_state.checked_uids
    )
    selected_uids = {
        _normalize_uid(uid) for uid in selected_source
        if _normalize_uid(uid)
    }
    headers = _selected_headers(
        list_source, folder, selected_uids_override=selected_uids
    )
    if not headers:
        return False

    mode = str(st.session_state.get("summary_mode") or "manual")
    if mode == "batch" and len(headers) < 2:
        # The Generate Summary control is already disabled in Batch mode until
        # at least two emails are selected, with helper text beside the control.
        return False

    eligible_headers, security_blocked = _prepare_manual_security_eligible_headers(
        headers, folder
    )
    if security_blocked:
        _notify_manual_security_exclusions(security_blocked, mode=mode)

    # Manual Batch requires at least two Security-eligible emails. Unsafe or
    # provider-Spam selections are excluded individually rather than weakening
    # the gate for the whole batch.
    if mode == "batch" and len(eligible_headers) < 2:
        if eligible_headers:
            remaining_details, remaining_entity = _header_notification_details(eligible_headers)
            push_summary_toast(
                "Batch Summary needs at least 2 Security-eligible emails.",
                "info",
                details=remaining_details,
                event_type="summary-security-blocked",
                entity_id=remaining_entity,
            )
        return bool(security_blocked)
    if not eligible_headers:
        return bool(security_blocked)
    headers = eligible_headers

    # Duplicate detection must finish before creating the worker or showing the
    # blocking overlay. This keeps an all-duplicate selection notification-only.
    pending_headers, relinks = _partition_summary_candidates(headers, folder)
    skipped = len(headers) - len(pending_headers)

    # Persist the current provider UID once a legacy same-message match is proven.
    # Future duplicate checks then use the fast exact-ID path. This is mainly
    # needed for Outlook Graph ID migration, but the duplicate decision itself
    # is provider-neutral and also protects Gmail thread replies.
    if relinks:
        selected_summary_uid = _normalize_uid(
            st.session_state.get("selected_summary_uid")
        )
        relink_map = dict(relinks)
        for old_uid, new_uid in relinks:
            st.session_state.summary_store.relink_uid(folder, old_uid, new_uid)
        st.session_state.summaries = st.session_state.summary_store.load_all(folder)
        if selected_summary_uid in relink_map:
            st.session_state.selected_summary_uid = relink_map[selected_summary_uid]

    if not pending_headers:
        duplicate_details, duplicate_entity = _header_notification_details(headers)
        _clear_summary_job_state()
        if mode == "batch":
            push_summary_toast(
                "All selected emails are already summarized.",
                "info",
                details=duplicate_details,
                event_type="summary-skipped",
                entity_id=duplicate_entity,
            )
        else:
            push_summary_toast(
                "Already summarized",
                "info",
                details=duplicate_details,
                event_type="summary-skipped",
                entity_id=duplicate_entity,
            )
        return True

    # In Batch mode the 2-email minimum applies to the original selection,
    # not to the remaining work after duplicate detection. If only one email
    # still needs a summary, let the normal mixed-selection confirmation show
    # "Generate 1 email" and process that remaining email after confirmation.
    if skipped:
        # Mixed selection is intentionally two-step: show the explanation first
        # and launch the blocking worker only after the user closes the popup.
        st.session_state.deferred_summary_request = {
            "headers": pending_headers,
            "selected_uids": list(selected_uids),
            "folder": folder,
            "mode": mode,
        }
        st.session_state.summary_deferred_ready = False
        clear_app_loading_state()
        queue_summary_confirmation(
            selected_count=len(headers),
            ready_count=len(pending_headers),
            skipped_count=skipped,
        )
        return True

    _launch_summary_job(pending_headers, selected_uids, folder, mode)
    return True


def _clear_auto_batch_window() -> None:
    # Reset collection-window timestamps after an Auto Summary queue is consumed.
    st.session_state.auto_summary_batch_started_at = 0.0
    st.session_state.auto_summary_batch_deadline = 0.0


def process_pending_auto_summary(folder: str = SUMMARY_FOLDER) -> bool:
    # Launch a timer-approved Auto Summary queue without touching selection.
    if not st.session_state.pop("auto_summary_start_requested", False):
        return False

    pending_uids = {
        _normalize_uid(uid)
        for uid in st.session_state.get("pending_auto_summary_uids", set())
        if _normalize_uid(uid)
    }
    if not pending_uids:
        return False

    if not st.session_state.get("auto_summary_enabled"):
        st.session_state.pending_auto_summary_uids = set()
        st.session_state.pending_auto_summary_lifecycle = {}
        st.session_state.auto_summary_not_before = 0.0
        st.session_state.auto_summary_retry_after = 0.0
        _clear_auto_batch_window()
        return False

    if st.session_state.get("summary_processing"):
        return False

    if not get_ollama_status().get("model_ready"):
        st.session_state.auto_summary_retry_after = time.time() + 30.0
        return False

    auto_type = str(st.session_state.get("auto_summary_type_choice") or "Individual")
    lifecycle_by_uid = dict(st.session_state.get("pending_auto_summary_lifecycle", {}) or {})
    candidate_uids = set(pending_uids)

    headers = []
    for uid in candidate_uids:
        header = st.session_state.email_store.get_email(folder, uid)
        if header is not None:
            headers.append(header)

    if not headers:
        st.session_state.pending_auto_summary_uids = set()
        st.session_state.pending_auto_summary_lifecycle = {}
        st.session_state.auto_summary_not_before = 0.0
        _clear_auto_batch_window()
        return False

    pending_headers, relinks = _partition_summary_candidates(headers, folder)

    if relinks:
        selected_summary_uid = _normalize_uid(st.session_state.get("selected_summary_uid"))
        relink_map = dict(relinks)
        for old_uid, new_uid in relinks:
            st.session_state.summary_store.relink_uid(folder, old_uid, new_uid)
        st.session_state.summaries = st.session_state.summary_store.load_all(folder)
        if selected_summary_uid in relink_map:
            st.session_state.selected_summary_uid = relink_map[selected_summary_uid]

    # Case 8 + shared Auto Individual/Batch rule: every queued UID is checked
    # again immediately before worker launch. Header-only entries are hydrated;
    # current provider Spam/Junk or unsafe verdicts are removed from the queue.
    eligible_headers = []
    waiting_uids = set()
    for header in pending_headers:
        uid = _normalize_uid(header.get("uid"))
        lifecycle = str(lifecycle_by_uid.get(uid) or "NEW")

        if int(header.get("security_input_version") or 0) < 2 and uid:
            client = st.session_state.get("imap_client")
            store = st.session_state.get("email_store")
            if client is None or store is None:
                waiting_uids.add(uid)
                continue
            full_result = get_full_email(
                client, uid, folder=folder, store=store, force_remote=True
            )
            if not full_result.get("success"):
                waiting_uids.add(uid)
                continue
            refreshed = store.get_email(folder, uid)
            if refreshed is None or int(refreshed.get("security_input_version") or 0) < 2:
                waiting_uids.add(uid)
                continue
            header = refreshed

        result = evaluate_summary_eligibility(
            header,
            lifecycle_state=lifecycle,
            already_summarized=False,
        )
        if result.can_generate:
            prepared = dict(header)
            prepared["_mailmind_lifecycle"] = lifecycle
            eligible_headers.append(prepared)
        elif result.waiting_for_security and uid:
            waiting_uids.add(uid)

    pending_headers = eligible_headers
    candidate_uids = {_normalize_uid(item.get("uid")) for item in pending_headers}

    st.session_state.pending_auto_summary_uids = set(waiting_uids)
    st.session_state.pending_auto_summary_lifecycle = {
        uid: str(lifecycle_by_uid.get(uid) or "NEW") for uid in waiting_uids
    }
    st.session_state.auto_summary_not_before = (time.time() + AUTO_SUMMARY_SECURITY_WAIT_SECONDS) if waiting_uids else 0.0
    st.session_state.auto_summary_retry_after = 0.0
    _clear_auto_batch_window()
    if not pending_headers:
        return False

    mode = "auto_batch" if auto_type == "Batch" else "manual"
    _launch_summary_job(
        pending_headers,
        candidate_uids,
        folder,
        mode=mode,
        origin="auto",
    )
    return True


@st.fragment(run_every=AUTO_SUMMARY_MONITOR_FRAGMENT_SECONDS)
def monitor_auto_summary_queue(folder: str = SUMMARY_FOLDER) -> None:
    if st.session_state.get("root_render_in_progress", False):
        return
    if foreground_interaction_is_settling():
        return
    # Start queued Auto Summary only after a quiet debounce window.
    # Like the mailbox monitor, skip the inline invocation caused by a normal
    # full-app rerun. This keeps user clicks completely separate from the
    # automatic summary scheduler.
    generation = int(st.session_state.get("app_run_generation", 0) or 0)
    seen_generation = int(
        st.session_state.get("auto_summary_monitor_seen_generation", -1) or -1
    )
    if seen_generation != generation:
        st.session_state.auto_summary_monitor_seen_generation = generation
        return

    if not st.session_state.get("logged_in"):
        return
    pending = {
        _normalize_uid(uid)
        for uid in st.session_state.get("pending_auto_summary_uids", set())
        if _normalize_uid(uid)
    }
    if not pending:
        return
    if not st.session_state.get("auto_summary_enabled"):
        st.session_state.pending_auto_summary_uids = set()
        st.session_state.auto_summary_not_before = 0.0
        _clear_auto_batch_window()
        return
    if st.session_state.get("summary_processing"):
        return
    if st.session_state.get("auto_summary_start_requested"):
        # Individual Auto Summary can request its handoff immediately at the
        # Security-publish boundary. If the publication rerun was temporarily
        # maintenance-paused (for example by a foreground settle guard), wake a
        # fresh app run once this timer is allowed to run so the queued request
        # cannot remain stuck indefinitely.
        st.rerun(scope="app")
        return

    now = time.time()
    not_before = float(st.session_state.get("auto_summary_not_before", 0.0) or 0.0)
    retry_after = float(st.session_state.get("auto_summary_retry_after", 0.0) or 0.0)
    if now < max(not_before, retry_after):
        return

    st.session_state.auto_summary_start_requested = True
    st.rerun(scope="app")


def request_summary_cancellation() -> bool:
    trace_action("summary-cancel-request")
    # Request cooperative cancellation without mutating worker-owned state.
    if not st.session_state.get("summary_processing"):
        return False
    if st.session_state.get("summary_cancel_requested"):
        return True

    token = st.session_state.get("summary_cancel_token")
    if token is None:
        return False

    token.request()
    st.session_state.summary_cancel_requested = True
    progress = st.session_state.get("summary_progress")
    detail = ""
    if progress is not None:
        processed, total = progress.snapshot()
        detail = f"{processed} of {total}"
    update_app_loading_state(
        title="Cancelling summary...",
        subtitle="Finishing the current step safely...",
        detail=detail,
    )
    return True


def render_summary_cancel_control() -> None:
    # Keep Summary Cancel on the stable app root for MANUAL generation only.
    # Auto Summary is intentionally background/non-blocking and therefore must
    # not mount the fixed Cancel control without its foreground loader.
    if not st.session_state.get("summary_processing"):
        return
    if str(st.session_state.get("summary_job_origin") or "manual") == "auto":
        return

    cancel_requested = bool(st.session_state.get("summary_cancel_requested"))
    if cancel_requested:
        # The loading card already switches to "Cancelling summary...". Do not
        # remount the just-clicked Streamlit button as disabled under the same key:
        # browsers can retain its transient busy spinner and visually corrupt the
        # compact overlay. Removing the control gives one stable cancellation card.
        return

    with st.container(key="summary_cancel_overlay"):
        st.button(
            "Cancel",
            key="summary_cancel_button",
            type="secondary",
            use_container_width=True,
            on_click=request_summary_cancellation,
        )


@st.fragment(run_every=SUMMARY_GENERATION_FRAGMENT_SECONDS)
def monitor_summary_generation(activity_slot=None, folder: str = SUMMARY_FOLDER):
    if st.session_state.get("root_render_in_progress", False):
        return
    if foreground_interaction_is_settling():
        return
    # Poll the worker without repainting the root loading card/spinner. Only the
    # changing count/progress bar is refreshed by this small fragment.
    if not st.session_state.get("summary_processing"):
        return

    progress = st.session_state.get("summary_progress")
    detail = ""
    if progress is not None:
        processed, total = progress.snapshot()
        detail = f"{processed} of {total}"

    # Auto Summary never activates/re-activates the global loading overlay.
    # The Inbox header chip is the only in-progress UI for background automation.
    origin = str(st.session_state.get("summary_job_origin") or "manual")
    if origin != "auto":
        update_app_loading_state(detail=detail)
        render_summary_live_progress(detail)

    if poll_summary_generation(folder=folder):
        st.rerun(scope="app")


def _should_navigate_to_summary_after_generation(
    origin: str,
    cancelled: bool,
    summaries: list[dict] | None,
) -> bool:
    """Keep Automatic completion in the user's current workspace.

    Manual generation remains an explicit foreground action and keeps its
    existing handoff to AI Summary. Automatic Individual/Batch completion is
    background-only: a toast plus the existing Unviewed count is sufficient.
    """
    if bool(cancelled) or not summaries:
        return False
    return str(origin or "manual") != "auto"


def poll_summary_generation(folder: str = SUMMARY_FOLDER) -> bool:
    # Commit a completed background job on the UI thread and report completion.
    future = st.session_state.get("summary_future")
    if not st.session_state.get("summary_processing") or future is None:
        return False
    if not future.done():
        return False

    origin = str(st.session_state.get("summary_job_origin") or "manual")
    # A reply draft may be generated while Auto Summary runs in the background.
    # If both touch the same thread, let the foreground draft finish/open/send
    # first and commit the already-finished summary afterward. Unrelated work is
    # never blocked by this guard.
    if origin == "auto" and _auto_summary_commit_conflicts_with_draft(folder):
        return False

    trace_job_id = str(st.session_state.get("summary_trace_job_id") or "")
    trace_external("SUMMARY", trace_job_id, "future_ready", origin=origin)
    cancel_requested = bool(st.session_state.get("summary_cancel_requested"))
    job_context = list(st.session_state.get("summary_job_context", []) or [])
    mark_future_done(origin=origin)
    st.session_state.summary_processing = False
    # Only a manual Summary owns the foreground loader. An Auto Summary may
    # finish while the user has started another foreground action (for example
    # Draft or manual Refresh), so it must never clear that action's loader.
    if origin != "auto":
        clear_app_loading_state()
    try:
        result = future.result()
    except Exception as error:
        st.session_state.pop("summary_job_context", None)
        st.session_state.pop("summary_job_uids", None)
        st.session_state.pop("summary_job_thread_ids", None)
        st.session_state.summary_job_origin = "manual"
        failure_details, failure_entity = _header_notification_details(job_context)
        safe_error = user_facing_ai_error(error, action="summary")
        print(f"[summary] Generation failed: {error}", flush=True)
        if cancel_requested:
            push_summary_toast(
                "Auto Summary stopped." if origin == "auto" else "Summarization cancelled.",
                "info",
                details=failure_details,
                event_type="auto-summary-cancelled" if origin == "auto" else "summary-cancelled",
                entity_id=failure_entity,
            )
        elif origin == "auto":
            record_notification(
                title="Auto Summary failed",
                message="Auto Summary stopped before it could finish.",
                kind="error",
                workspace="summary",
                details=failure_details + [f"Reason: {safe_error}"],
                event_type="auto-summary-error",
                entity_id=failure_entity,
            )
        else:
            push_summary_toast(
                safe_error,
                "error",
                details=failure_details,
                event_type="summary-error",
                entity_id=failure_entity,
            )
        return True
    finally:
        executor = st.session_state.pop("summary_executor", None)
        if executor is not None:
            executor.shutdown(wait=False)
        st.session_state.pop("summary_future", None)
        st.session_state.pop("summary_progress", None)
        st.session_state.pop("summary_cancel_token", None)
        st.session_state.summary_cancel_requested = False

    # A click that arrives after the worker finished but before the UI commit is
    # still a valid cancellation. Nothing has been persisted yet, so discard the
    # late result instead of surprising the user with a summary after Cancel.
    worker_cancelled = bool(result.get("cancelled"))
    if cancel_requested and not worker_cancelled:
        result = dict(result)
        result["summaries"] = []
        result["cancelled"] = True
        result["late_cancel"] = True

    cancelled = bool(result.get("cancelled"))
    summaries = list(result.get("summaries") or [])
    navigate_to_summary = _should_navigate_to_summary_after_generation(
        origin, cancelled, summaries
    )
    if summaries:
        summaries = st.session_state.summary_store.rebase_live_task_state(folder, summaries)
        updated_summary_count = sum(
            1 for item in summaries if bool(item.get("_thread_summary_updated"))
        )
        new_summary_count = max(0, len(summaries) - updated_summary_count)
        generation_source = "auto" if origin == "auto" else "manual"
        todo_notices = []
        for summary in summaries:
            is_batch_card = str(summary.get("record_type") or "manual") == "batch"
            summary["generation_source"] = generation_source
            summary["generation_mode"] = "batch" if is_batch_card else "individual"

            if isinstance(summary.get("todo_update_notice"), dict):
                todo_notices.append(summary.get("todo_update_notice"))
            todo_notices.extend(
                notice for notice in (summary.get("todo_update_notices") or [])
                if isinstance(notice, dict)
            )
        # Any legitimate thread/source update changes the Reply Draft source of
        # truth. Discard a previously prepared draft before saving the new
        # current state so the next Draft email action is generated fresh.
        for summary in summaries:
            invalidate_updated_summary_drafts(summary)
        st.session_state.summary_store.append_all(folder, summaries)
        active_thread_ids = {
            str(item.get("canonical_thread_id") or "").strip()
            for summary in summaries
            for item in (
                [summary]
                + [entry for entry in (summary.get("email_breakdowns") or []) if isinstance(entry, dict)]
            )
            if str(item.get("canonical_thread_id") or "").strip()
        }
        st.session_state.summary_store.clear_deletion_checkpoints(folder, active_thread_ids)
        if todo_notices:
            if len(todo_notices) == 1:
                notice = todo_notices[0]
                notice_title = str(notice.get("title") or "Task updated from new reply")
                notice_message = str(notice.get("message") or "The existing To-Do was updated.")
                notice_details = list(notice.get("details") or [])
                notice_entity = str(notice.get("entity_id") or "")
            else:
                notice_title = "Tasks updated from new replies"
                notice_message = f"{len(todo_notices)} existing To-Do tasks were synchronized with new replies."
                notice_entity = ""
                notice_details = []
                for notice in todo_notices[:5]:
                    details = [str(value) for value in (notice.get("details") or []) if str(value).strip()]
                    notice_details.extend(details[:2])
                if len(todo_notices) > 5:
                    notice_details.append(f"+{len(todo_notices) - 5} more task updates")

            record_notification(
                title=notice_title,
                message=notice_message,
                kind="update",
                workspace="todo",
                details=notice_details,
                event_type="task-email-update",
                entity_id=notice_entity,
            )
            # Background reply-driven task changes are Bell-only. The user did
            # not initiate this update, so do not interrupt the active workspace.
        st.session_state.summaries = st.session_state.summary_store.load_all(folder)
        # Manual generation keeps its explicit handoff to AI Summary. Automatic
        # Individual/Batch completion never steals the user's current workspace.
        if navigate_to_summary:
            st.session_state.selected_summary_uid = None
            # Set both the canonical workspace and the one-shot handoff. The
            # canonical value keeps the sidebar selected correctly on the first
            # rerun; switch_to_summary keeps the existing app.py navigation path
            # durable across reruns.
            st.session_state.active_workspace = "summary"
            st.session_state.switch_to_summary = True

        completed_uids = st.session_state.pop("summary_job_uids", [])
        st.session_state.pop("summary_job_context", None)
        st.session_state.pop("summary_job_thread_ids", None)
        summary_details, summary_entity = _summary_notification_details(summaries)
        if cancelled:
            count = len(summaries)
            noun = "summary" if count == 1 else "summaries"
            if origin == "auto":
                message = f"Auto Summary stopped. {count} completed {noun} saved."
                event_type = "auto-summary-cancelled"
                toast_title = None
            else:
                requested_count = max(0, int(result.get("requested_count") or 0))
                if str(result.get("mode") or "manual") == "batch":
                    # Manual Batch is atomic: an interrupted batch is never
                    # persisted as a partial batch card.
                    message = "Batch summarization cancelled. No batch summary was saved."
                elif requested_count > 0:
                    if count == 0:
                        email_word = "email" if requested_count == 1 else "emails"
                        message = (
                            f"Summarization cancelled. No summaries were generated from "
                            f"the {requested_count} selected {email_word}."
                        )
                    elif count == 1:
                        message = (
                            f"Summarization cancelled. 1 of {requested_count} summaries "
                            "was generated and saved."
                        )
                    else:
                        message = (
                            f"Summarization cancelled. {count} of {requested_count} summaries "
                            "were generated and saved."
                        )
                else:
                    message = f"Summarization cancelled. {count} completed {noun} saved."
                event_type = "summary-cancelled"
                toast_title = "Summary cancelled"
            push_summary_toast(
                message,
                "info",
                title=toast_title,
                details=summary_details,
                event_type=event_type,
                entity_id=summary_entity,
            )
        elif origin == "auto":
            # Successful Auto Summary completion uses a transient toast only.
            # Incoming-mail and Security events remain Bell notifications, but
            # generating/updating a Summary is not persisted in Notification
            # Center. Automatic completion stays in the current workspace; the
            # existing Unviewed count remains the persistent attention signal.
            count = len(summaries)
            if updated_summary_count and not new_summary_count:
                if updated_summary_count == 1:
                    title = "Auto Summary updated"
                    message = "Auto Summary updated the existing thread summary with the new reply."
                else:
                    title = "Auto Summaries updated"
                    message = f"Auto Summary updated {updated_summary_count} existing thread summaries with new replies."
                event_type = "auto-summary-updated"
            elif updated_summary_count and new_summary_count:
                title = "Auto Summary completed"
                message = (
                    f"Auto Summary created {new_summary_count} new and updated "
                    f"{updated_summary_count} existing summar{'y' if updated_summary_count == 1 else 'ies'}."
                )
                event_type = "auto-summary-created-updated"
            elif result.get("mode") == "auto_batch" and count == 1 and summaries[0].get("record_type") == "batch":
                email_count = int(summaries[0].get("email_count") or 1)
                email_word = "email" if email_count == 1 else "emails"
                title = "Auto Summary created"
                message = f"Auto Summary created 1 batch summary from {email_count} {email_word}."
                event_type = "auto-summary-created"
            elif result.get("mode") == "auto_batch" and count == 1:
                title = "Auto Summary created"
                message = "Auto Summary created 1 individual summary for the new email."
                event_type = "auto-summary-created"
            else:
                noun = "summary" if count == 1 else "summaries"
                title = "Auto Summary created"
                message = f"Auto Summary created {count} {noun} for new emails."
                event_type = "auto-summary-created"
            push_summary_toast(
                message,
                "success",
                title=title,
                details=summary_details,
                event_type=event_type,
                entity_id=summary_entity,
                notify_bell=False,
            )
        else:
            st.session_state.clear_checked_after_summary = completed_uids
            # Manual Individual and Manual Batch retain the existing explicit
            # completion handoff to AI Summary.
            if not navigate_to_summary:
                raise RuntimeError("Manual summary completion navigation invariant failed.")
            if updated_summary_count and not new_summary_count:
                if updated_summary_count == 1:
                    push_summary_toast(
                        "Updated the existing AI Summary with the new reply.",
                        "success",
                        title="Thread summary updated",
                        details=summary_details,
                        event_type="summary-updated",
                        entity_id=summary_entity,
                    )
                else:
                    push_summary_toast(
                        f"Updated {updated_summary_count} existing thread summaries with new replies.",
                        "success",
                        title="Thread summaries updated",
                        details=summary_details,
                        event_type="summaries-updated",
                        entity_id=summary_entity,
                    )
            elif updated_summary_count and new_summary_count:
                push_summary_toast(
                    f"Generated {new_summary_count} new and updated {updated_summary_count} existing AI summar{'y' if updated_summary_count == 1 else 'ies'}.",
                    "success",
                    title="Summaries generated and updated",
                    details=summary_details,
                    event_type="summaries-created-updated",
                    entity_id=summary_entity,
                )
            elif (
                result.get("mode") == "batch"
                and len(summaries) == 1
                and str(summaries[0].get("record_type") or "manual") == "batch"
            ):
                push_summary_toast(
                    "Generated one batch summary for the selected emails.",
                    "success",
                    details=summary_details,
                    event_type="batch-summary-created",
                    entity_id=summary_entity,
                )
            elif result.get("mode") == "batch" and len(summaries) == 1:
                push_summary_toast(
                    "Generated 1 AI summary for the remaining email.",
                    "success",
                    details=summary_details,
                    event_type="summary-created",
                    entity_id=summary_entity,
                )
            else:
                push_summary_toast(
                    f"Generated {len(summaries)} AI summar{'y' if len(summaries) == 1 else 'ies'}.",
                    "success",
                    details=summary_details,
                    event_type="summary-created",
                    entity_id=summary_entity,
                )
    else:
        st.session_state.pop("summary_job_uids", None)
        st.session_state.pop("summary_job_context", None)
        st.session_state.pop("summary_job_thread_ids", None)
        up_to_date_threads = list(result.get("up_to_date_threads") or [])
        if not cancelled and origin != "auto" and up_to_date_threads:
            details = [str(value) for value in up_to_date_threads[:5] if str(value).strip()]
            if len(up_to_date_threads) > 5:
                details.append(f"+{len(up_to_date_threads) - 5} more threads")
            push_summary_toast(
                "Thread summary is already up to date."
                if len(up_to_date_threads) == 1
                else f"{len(up_to_date_threads)} thread summaries are already up to date.",
                "info",
                title="Summary up to date",
                details=details,
                event_type="summary-up-to-date",
            )
        if cancelled:
            cancel_details, cancel_entity = _header_notification_details(job_context)
            if origin == "auto":
                cancel_message = "Auto Summary stopped."
                cancel_title = None
            else:
                requested_count = max(0, int(result.get("requested_count") or 0))
                if str(result.get("mode") or "manual") == "batch":
                    cancel_message = "Batch summarization cancelled. No batch summary was saved."
                elif requested_count > 0:
                    email_word = "email" if requested_count == 1 else "emails"
                    cancel_message = (
                        f"Summarization cancelled. No summaries were generated from "
                        f"the {requested_count} selected {email_word}."
                    )
                else:
                    cancel_message = "Summarization cancelled. No summaries were generated."
                cancel_title = "Summary cancelled"
            push_summary_toast(
                cancel_message,
                "info",
                title=cancel_title,
                details=cancel_details,
                event_type="auto-summary-cancelled" if origin == "auto" else "summary-cancelled",
                entity_id=cancel_entity,
            )

    security_skips = list(result.get("security_skips") or [])
    if security_skips and origin != "auto" and not cancelled:
        count = len(security_skips)
        noun = "email was" if count == 1 else "emails were"
        details = [
            f"{subject} — {reason}"
            for subject, reason in security_skips[:5]
        ]
        if count > 5:
            details.append(f"+{count - 5} more skipped emails")
        push_summary_toast(
            f"{count} selected {noun} skipped because Security or provider location changed.",
            "info",
            details=details,
            event_type="summary-security-blocked",
        )

    mark_commit_done(origin=origin, summary_count=len(summaries))
    trace_external(
        "SUMMARY", trace_job_id, "commit_done", origin=origin,
        summaries=len(summaries), status="cancelled" if cancelled else "ok",
    )
    st.session_state.pop("summary_trace_job_id", None)
    st.session_state.summary_job_origin = "manual"
    if not cancelled:
        failures = list(result["failures"] or [])
        if origin == "auto" and failures:
            failure_details = [
                f"{subject} — {user_facing_ai_error(error, action='summary')}"
                for subject, error in failures[:5]
            ]
            if len(failures) > 5:
                failure_details.append(f"+{len(failures) - 5} more failed summaries")
            count = len(failures)
            noun = "email" if count == 1 else "emails"
            record_notification(
                title="Auto Summary failed",
                message=f"Auto Summary could not summarize {count} {noun}.",
                kind="warning",
                workspace="summary",
                details=failure_details,
                event_type="auto-summary-failed",
            )
        elif origin != "auto":
            for subject, error in failures:
                safe_error = user_facing_ai_error(error, action="summary")
                print(f"[summary] Could not summarize {subject!r}: {error}", flush=True)
                failure_details = [f"Subject: {subject}", f"Reason: {safe_error}"]
                push_summary_toast(
                    f"Could not summarize '{subject}'. {safe_error}",
                    "warning",
                    details=failure_details,
                    event_type="summary-failed",
                )
    return True


def open_summary(uid: str, folder: str = SUMMARY_FOLDER):
    # Select a summary and persist its read status.
    st.session_state.summary_store.mark_read(folder, uid)
    st.session_state.summaries = st.session_state.summary_store.load_all(folder)
    st.session_state.selected_summary_uid = str(uid)
