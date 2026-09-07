# Persistent, account-isolated SQLite storage for generated AI summaries.
import json
import os
import sqlite3
import re
from datetime import datetime, timezone
from collections import Counter
from email.utils import parseaddr

from services.task_status import aggregate_task_status, normalize_task_status
from services.summary_trace_service import trace_summary_pipeline


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "summaries.db")
SUMMARY_FOLDER = "ALL_MAIL"
LEGACY_SUMMARY_FOLDER = "INBOX"


def _summary_timestamp_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _batch_title_from_breakdowns(breakdowns: list[dict]) -> str:
    # Rebuild a Batch title from the remaining source subjects only. This mirrors
    # the deterministic title used at Batch creation and never calls the LLM.
    topics = []
    seen = set()
    for item in breakdowns or []:
        subject = re.sub(r"\s+", " ", str(item.get("subject") or "")).strip()
        subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject, flags=re.IGNORECASE).strip()
        words = (subject or "Email Topic").split()
        topic = " ".join(words[:5]).strip(" -–—,:;")
        if len(topic) > 32:
            clipped = topic[:32].rsplit(" ", 1)[0].strip(" -–—,:;")
            topic = clipped or topic[:32].strip()
        key = topic.casefold()
        if topic and key not in seen:
            topics.append(topic)
            seen.add(key)

    if not topics:
        return "Selected Email Topics"
    if len(topics) == 1:
        return topics[0]
    if len(topics) == 2:
        title = f"{topics[0]} & {topics[1]}"
    elif len(topics) == 3:
        title = f"{topics[0]}, {topics[1]} & {topics[2]}"
    else:
        title = f"{topics[0]}, {topics[1]} & {len(topics) - 2} More Topics"

    if len(title) <= 70:
        return title

    def _shorter(value: str, max_chars: int) -> str:
        words = value.split()[:3]
        label = " ".join(words).strip(" -–—,:;")
        if len(label) <= max_chars:
            return label
        clipped = label[:max_chars].rsplit(" ", 1)[0].strip(" -–—,:;")
        return clipped or label[:max_chars].strip()

    if len(topics) > 2:
        return f"{_shorter(topics[0], 24)}, {_shorter(topics[1], 24)} & {len(topics) - 2} More Topics"
    return f"{_shorter(topics[0], 30)} & {_shorter(topics[1], 30)}"


class SummaryStore:
    # Store the current generated summary set for one signed-in account.

    def __init__(self, account_email: str, db_path: str = DB_PATH):
        self.account_email = (account_email or "").strip().casefold()
        if not self.account_email:
            raise ValueError("A signed-in email address is required for SummaryStore.")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        self._migrate_legacy_folder()

    def _migrate_legacy_folder(self):
        # Move existing Inbox summaries into the unified received-mail view.
        with self.conn:
            self.conn.execute(
                """DELETE FROM summaries WHERE account_email=? AND folder=? AND uid IN (
                       SELECT uid FROM summaries WHERE account_email=? AND folder=?
                   )""",
                (self.account_email, LEGACY_SUMMARY_FOLDER, self.account_email, SUMMARY_FOLDER),
            )
            self.conn.execute(
                "UPDATE summaries SET folder=? WHERE account_email=? AND folder=?",
                (SUMMARY_FOLDER, self.account_email, LEGACY_SUMMARY_FOLDER),
            )

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS summaries (
                account_email TEXT NOT NULL,
                folder TEXT NOT NULL,
                uid TEXT NOT NULL,
                sender TEXT,
                recipient TEXT,
                cc TEXT NOT NULL DEFAULT '',
                subject TEXT,
                date_value TEXT,
                date_display TEXT,
                snippet TEXT,
                summary TEXT NOT NULL,
                key_points TEXT NOT NULL,
                deadlines TEXT NOT NULL,
                action_items TEXT NOT NULL,
                action_item_details TEXT NOT NULL DEFAULT '[]',
                task_title TEXT NOT NULL DEFAULT '',
                task_title_source TEXT NOT NULL DEFAULT 'generated',
                priority TEXT NOT NULL DEFAULT 'Medium',
                status TEXT NOT NULL DEFAULT 'Not Started',
                status_source TEXT NOT NULL DEFAULT 'email',
                task_due_date TEXT NOT NULL DEFAULT '',
                deadline_mode TEXT NOT NULL DEFAULT 'auto',
                task_change_history TEXT NOT NULL DEFAULT '[]',
                task_revision INTEGER NOT NULL DEFAULT 0,
                is_read INTEGER NOT NULL DEFAULT 0,
                task_is_read INTEGER NOT NULL DEFAULT 0,
                task_update_is_read INTEGER NOT NULL DEFAULT 1,
                record_type TEXT NOT NULL DEFAULT 'manual',
                email_count INTEGER NOT NULL DEFAULT 1,
                top_senders TEXT NOT NULL DEFAULT '[]',
                attachments TEXT NOT NULL DEFAULT '[]',
                email_breakdowns TEXT NOT NULL DEFAULT '[]',
                incremental_updates TEXT NOT NULL DEFAULT '[]',
                source_uids TEXT NOT NULL DEFAULT '[]',
                thread_count INTEGER NOT NULL DEFAULT 1,
                canonical_thread_id TEXT NOT NULL DEFAULT '',
                message_id TEXT NOT NULL DEFAULT '',
                generation_source TEXT NOT NULL DEFAULT 'manual',
                generation_mode TEXT NOT NULL DEFAULT 'individual',
                generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                summary_created_at TEXT NOT NULL DEFAULT '',
                summary_activity_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (account_email, folder, uid)
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS summary_deletion_checkpoints (
                account_email TEXT NOT NULL,
                folder TEXT NOT NULL,
                canonical_thread_id TEXT NOT NULL,
                source_uids TEXT NOT NULL DEFAULT '[]',
                message_id TEXT NOT NULL DEFAULT '',
                deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (account_email, folder, canonical_thread_id)
            )
        """)
        columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(summaries)")
        }
        had_status_source = "status_source" in columns
        had_task_is_read = "task_is_read" in columns
        had_task_update_is_read = "task_update_is_read" in columns
        additions = {
            "cc": "TEXT NOT NULL DEFAULT ''",
            "action_item_details": "TEXT NOT NULL DEFAULT '[]'",
            "task_title": "TEXT NOT NULL DEFAULT ''",
            "task_title_source": "TEXT NOT NULL DEFAULT 'generated'",
            "priority": "TEXT NOT NULL DEFAULT 'Medium'",
            "status": "TEXT NOT NULL DEFAULT 'Not Started'",
            "status_source": "TEXT NOT NULL DEFAULT 'email'",
            "task_due_date": "TEXT NOT NULL DEFAULT ''",
            "deadline_mode": "TEXT NOT NULL DEFAULT 'auto'",
            "task_change_history": "TEXT NOT NULL DEFAULT '[]'",
            "task_revision": "INTEGER NOT NULL DEFAULT 0",
            "is_read": "INTEGER NOT NULL DEFAULT 0",
            "task_is_read": "INTEGER NOT NULL DEFAULT 0",
            "task_update_is_read": "INTEGER NOT NULL DEFAULT 1",
            "record_type": "TEXT NOT NULL DEFAULT 'manual'",
            "email_count": "INTEGER NOT NULL DEFAULT 1",
            "top_senders": "TEXT NOT NULL DEFAULT '[]'",
            "attachments": "TEXT NOT NULL DEFAULT '[]'",
            "email_breakdowns": "TEXT NOT NULL DEFAULT '[]'",
            "incremental_updates": "TEXT NOT NULL DEFAULT '[]'",
            "source_uids": "TEXT NOT NULL DEFAULT '[]'",
            "thread_count": "INTEGER NOT NULL DEFAULT 1",
            "canonical_thread_id": "TEXT NOT NULL DEFAULT ''",
            "message_id": "TEXT NOT NULL DEFAULT ''",
            "generation_source": "TEXT NOT NULL DEFAULT 'manual'",
            "generation_mode": "TEXT NOT NULL DEFAULT 'individual'",
            "summary_created_at": "TEXT NOT NULL DEFAULT ''",
            "summary_activity_at": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in additions.items():
            if name not in columns:
                self.conn.execute(f"ALTER TABLE summaries ADD COLUMN {name} {definition}")
        if not had_task_is_read:
            # Existing tasks were already visible before this attention-state
            # feature existed. Mark legacy rows viewed so upgrading does not make
            # the entire historical To-Do list look newly created.
            self.conn.execute("UPDATE summaries SET task_is_read=1")
        if not had_task_update_is_read:
            # Existing history must not suddenly appear as UPDATED after upgrade.
            # Only a future email-driven task delta can create this attention state.
            self.conn.execute("UPDATE summaries SET task_update_is_read=1")
        # Existing summaries predate explicit creation/activity timestamps. Their
        # historical generated_at value is the safest baseline for both fields.
        self.conn.execute(
            "UPDATE summaries SET summary_created_at=generated_at "
            "WHERE COALESCE(summary_created_at, '')=''"
        )
        self.conn.execute(
            "UPDATE summaries SET summary_activity_at=generated_at "
            "WHERE COALESCE(summary_activity_at, '')=''"
        )
        if not had_status_source:
            # Legacy rows cannot tell whether a closed/paused status came from AI
            # or a user confirmation. Preserve progress conservatively on upgrade.
            self.conn.execute(
                "UPDATE summaries SET status_source='user' "
                "WHERE status IN ('Completed', 'Cancelled', 'On Hold')"
            )
        self.conn.commit()

    @staticmethod
    def _loads_list(value):
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        return loaded if isinstance(loaded, list) else []

    @classmethod
    def _loads_breakdowns(cls, value):
        breakdowns = cls._loads_list(value)
        for item in breakdowns:
            if isinstance(item, dict):
                item["status"] = normalize_task_status(item.get("status"))
                if not str(item.get("status_source") or "").strip():
                    item["status_source"] = (
                        "user" if item["status"] in {"Completed", "Cancelled", "On Hold"} else "email"
                    )
                else:
                    item["status_source"] = str(item.get("status_source"))
                item["deadline_mode"] = str(item.get("deadline_mode") or "auto")
                item["task_title_source"] = str(item.get("task_title_source") or "generated")
                item["task_revision"] = int(item.get("task_revision") or 0)
                item["task_change_history"] = list(item.get("task_change_history") or [])
                # Missing means legacy data from before task-level attention
                # tracking, so treat it as already viewed. New persisted
                # breakdowns always write this field explicitly.
                item["task_is_read"] = bool(item.get("task_is_read", True))
                item["task_update_is_read"] = bool(item.get("task_update_is_read", True))
        return breakdowns

    @staticmethod
    def _persistable_breakdowns(item: dict) -> list[dict]:
        # New nested tasks start unread at the To-Do level. Existing breakdowns
        # carry their preserved task_is_read state through rebase_live_task_state.
        persisted = []
        for value in (item.get("email_breakdowns") or []):
            if not isinstance(value, dict):
                continue
            row = dict(value)
            row["task_is_read"] = bool(row.get("task_is_read", False))
            row["task_update_is_read"] = bool(row.get("task_update_is_read", True))
            # Private one-run reconciliation markers must never become durable data.
            row.pop("_thread_task_updated", None)
            persisted.append(row)
        return persisted

    def append_all(self, folder: str, summaries: list[dict]):
        # Save new summaries without removing earlier summaries in the folder.
        persisted_at = _summary_timestamp_now()
        for item in summaries or []:
            if isinstance(item, dict):
                trace_summary_pipeline("STORE_BEFORE_WRITE", summary=item, payload={"folder": folder})
        with self.conn:
            incoming_uids = [str(item.get("uid") or "") for item in summaries if str(item.get("uid") or "")]
            self.conn.executemany(
                "DELETE FROM summaries WHERE account_email=? AND folder=? AND uid=?",
                [(self.account_email, folder, uid) for uid in incoming_uids],
            )
            # A later message can expand an already summarized provider thread.
            # Replace the older conversation card while leaving unrelated cards
            # and Project 2's task metadata schema intact.
            canonical_ids = {
                canonical_id for item in summaries
                for canonical_id in ([str(item.get("canonical_thread_id") or "").strip()] + [str(value or "").strip() for value in (item.get("absorbed_canonical_thread_ids") or [])])
                if canonical_id
            }
            for canonical_id in canonical_ids:
                self.conn.execute(
                    "DELETE FROM summaries WHERE account_email=? AND folder=? "
                    "AND canonical_thread_id=?",
                    (self.account_email, folder, canonical_id),
                )
            self.conn.executemany("""
                INSERT INTO summaries (
                    account_email, folder, uid, sender, recipient, cc, subject,
                    date_value, date_display, snippet, summary, key_points,
                    deadlines, action_items, action_item_details, task_title, task_title_source, priority, status, record_type,
                    status_source, task_due_date, deadline_mode, task_change_history, task_revision, is_read, task_is_read, task_update_is_read,
                    email_count, top_senders, attachments, email_breakdowns,
                    incremental_updates, source_uids, thread_count, canonical_thread_id,
                    message_id, generation_source, generation_mode,
                    summary_created_at, summary_activity_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    self.account_email, folder, str(item.get("uid", "")),
                    item.get("from", ""), item.get("to", ""), item.get("cc", ""),
                    item.get("subject", ""), item.get("date", ""),
                    item.get("date_display", ""), item.get("snippet", ""),
                    item.get("summary", ""), json.dumps(item.get("key_points", [])),
                    json.dumps(item.get("deadlines", [])),
                    json.dumps(item.get("action_items", [])),
                    json.dumps(item.get("action_item_details", [])),
                    str(item.get("task_title") or "").strip(),
                    str(item.get("task_title_source") or "generated"),
                    item.get("priority", "Medium"),
                    normalize_task_status(item.get("status")),
                    item.get("record_type", "manual"),
                    str(item.get("status_source") or "email"),
                    str(item.get("task_due_date") or "").strip(),
                    str(item.get("deadline_mode") or "auto"),
                    json.dumps(item.get("task_change_history", [])),
                    int(item.get("task_revision") or 0),
                    0,  # Every new/updated summary is intentionally Unviewed.
                    int(bool(item.get("task_is_read", False))),
                    int(bool(item.get("task_update_is_read", True))),
                    int(item.get("email_count") or 1),
                    json.dumps(item.get("top_senders", [])),
                    json.dumps(item.get("attachments", [])),
                    json.dumps(self._persistable_breakdowns(item)),
                    json.dumps(item.get("incremental_updates", [])),
                    json.dumps(item.get("source_uids", [str(item.get("uid", ""))])),
                    int(item.get("thread_count") or 1),
                    str(item.get("canonical_thread_id") or ""),
                    str(item.get("message_id") or ""),
                    item.get("generation_source", "manual"),
                    item.get("generation_mode", "individual"),
                    str(item.get("summary_created_at") or item.get("generated_at") or persisted_at),
                    str(item.get("summary_activity_at") or item.get("generated_at") or persisted_at),
                ) for item in summaries
            ])

    @staticmethod
    def _normalized_action(value) -> str:
        return " ".join(str(value or "").casefold().split()).rstrip(".")

    @staticmethod
    def _task_history_identity(entry: dict) -> str:
        # Stable identity used when a background thread update and a foreground
        # user edit both extend Recent Activity from the same saved snapshot.
        # Never drop either source: de-duplicate only byte-equivalent audit rows.
        if not isinstance(entry, dict):
            return ""
        payload = {
            "source": str(entry.get("source") or "").strip().casefold(),
            "source_uid": str(entry.get("source_uid") or "").strip(),
            "message_id": str(entry.get("message_id") or "").strip(),
            "date": str(entry.get("date") or "").strip(),
            "changes": [dict(item) for item in (entry.get("changes") or []) if isinstance(item, dict)],
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _task_history_timestamp(entry: dict) -> float:
        raw = str((entry or {}).get("date") or "").strip()
        if not raw:
            return 0.0
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.timestamp()
            return parsed.timestamp()
        except (TypeError, ValueError, OSError):
            return 0.0

    @classmethod
    def _merge_task_change_history(cls, incoming_history, live_history) -> list[dict]:
        # Incoming history contains the newest email-driven delta while live
        # history can contain user edits made during generation. Merge the two
        # audit streams instead of allowing rebase to overwrite one with the
        # other, then keep chronological order for the Recent Activity dialog.
        merged = []
        seen = set()
        for order, raw in enumerate(list(incoming_history or []) + list(live_history or [])):
            if not isinstance(raw, dict):
                continue
            entry = dict(raw)
            identity = cls._task_history_identity(entry)
            if identity and identity in seen:
                continue
            if identity:
                seen.add(identity)
            merged.append((cls._task_history_timestamp(entry), order, entry))
        merged.sort(key=lambda item: (item[0], item[1]))
        return [entry for _, _, entry in merged[-100:]]

    @classmethod
    def _rebase_task_item(cls, incoming: dict, live: dict) -> dict:
        # The worker starts from a snapshot. If the user changed the To-Do while
        # the worker was running, preserve that newer local state before save.
        incoming_revision = int(incoming.get("task_revision") or 0)
        live_revision = int(live.get("task_revision") or 0)
        live_had_task = bool(live.get("action_items"))
        # Workflow Status is manual-only. Rebase always preserves the live
        # user-owned status and source for an existing task, regardless of what
        # an AI/thread worker inferred while processing a new email.
        live_status = normalize_task_status(live.get("status"))
        live_status_source = str(live.get("status_source") or "manual").strip() or "manual"
        if live_revision <= incoming_revision:
            rebased = dict(incoming)
            # Task attention is user-owned view state even when there were no
            # task edits to rebase. Preserve it across thread-summary refreshes.
            if live_had_task:
                rebased["task_is_read"] = bool(live.get("task_is_read", True))
                live_update_read = bool(live.get("task_update_is_read", True))
                if bool(incoming.get("_thread_task_updated")) and bool(live.get("task_is_read", True)):
                    rebased["task_update_is_read"] = False
                else:
                    rebased["task_update_is_read"] = live_update_read
            else:
                rebased["task_update_is_read"] = True
            # Status ownership is independent of whether the summary currently
            # has action rows. Preserve it for every existing live record.
            rebased["status"] = live_status
            rebased["status_source"] = live_status_source
            rebased.pop("_thread_status_override", None)
            rebased.pop("_thread_terminal_status_override", None)
            return rebased

        rebased = dict(incoming)
        rebased.pop("_thread_status_override", None)
        rebased.pop("_thread_terminal_status_override", None)
        rebased["status"] = live_status
        rebased["status_source"] = live_status_source
        if str(live.get("task_title_source") or "generated").strip().casefold() == "user":
            rebased["task_title"] = str(live.get("task_title") or "").strip()
            rebased["task_title_source"] = "user"
        incoming_details = [dict(item) for item in (incoming.get("action_item_details") or []) if isinstance(item, dict)]
        live_details = [dict(item) for item in (live.get("action_item_details") or []) if isinstance(item, dict)]
        live_by_id = {
            str(item.get("action_id") or ""): item
            for item in live_details if str(item.get("action_id") or "")
        }
        live_by_action = {
            cls._normalized_action(item.get("action")): item
            for item in live_details if str(item.get("action") or "").strip()
        }
        live_ids = set(live_by_id)

        for index, detail in enumerate(incoming_details):
            action_id = str(detail.get("action_id") or "")
            matched = live_by_id.get(action_id) if action_id else None
            if matched is None:
                matched = live_by_action.get(cls._normalized_action(detail.get("action")))
            if matched is None and index < len(live_details):
                candidate = live_details[index]
                if not action_id or not candidate.get("action_id"):
                    matched = candidate
            if matched is None:
                continue
            # Preserve live user completion for unchanged work. If the new
            # email materially changed this action and intentionally reactivated
            # it, do not overwrite the incoming open state with the older user's
            # completion flag from the pre-update wording.
            if (
                str(matched.get("completion_source") or "").casefold() == "user"
                and not bool(detail.get("reactivated_by_update"))
            ):
                detail["completed"] = bool(matched.get("completed"))
                detail["completion_source"] = "user"
            if str(matched.get("cancellation_source") or "").casefold() == "user":
                detail["cancelled"] = bool(matched.get("cancelled"))
                detail["cancellation_source"] = "user"

        rebased["action_item_details"] = incoming_details
        rebased["task_due_date"] = str(live.get("task_due_date") or "")
        # Recent Activity is a unified audit trail. The incoming summary carries
        # the new email-reply changes while the live row may carry manual edits
        # made while generation was running. Preserve BOTH and de-duplicate.
        rebased["task_change_history"] = cls._merge_task_change_history(
            incoming.get("task_change_history"),
            live.get("task_change_history"),
        )
        rebased["task_revision"] = live_revision
        if live_had_task:
            rebased["task_is_read"] = bool(live.get("task_is_read", True))
            live_update_read = bool(live.get("task_update_is_read", True))
            if bool(incoming.get("_thread_task_updated")) and bool(live.get("task_is_read", True)):
                rebased["task_update_is_read"] = False
            else:
                rebased["task_update_is_read"] = live_update_read
        else:
            rebased["task_update_is_read"] = True

        open_rows = [
            item for item in incoming_details
            if not bool(item.get("completed")) and not bool(item.get("cancelled"))
        ]
        if incoming_details and not open_rows and normalize_task_status(rebased.get("status")) == "Completed":
            rebased["priority"] = "Low"
        return rebased

    def rebase_live_task_state(self, folder: str, summaries: list[dict]) -> list[dict]:
        # Rebase is intentionally done on the main thread immediately before the
        # delete/insert save, closing the race with To-Do checkbox/status edits.
        live_records = self.load_all(folder)
        live_by_uid = {str(item.get("uid") or ""): item for item in live_records}
        live_by_thread = {
            str(item.get("canonical_thread_id") or ""): item
            for item in live_records
            if str(item.get("canonical_thread_id") or "")
            and str(item.get("record_type") or "manual") != "batch"
        }
        rebased_records = []
        for incoming in summaries:
            item = dict(incoming)
            if str(item.get("record_type") or "manual") == "batch":
                live_batch = live_by_uid.get(str(item.get("uid") or ""))
                if live_batch is not None:
                    live_breakdowns = [entry for entry in (live_batch.get("email_breakdowns") or []) if isinstance(entry, dict)]
                    live_breakdown_by_thread = {
                        str(entry.get("canonical_thread_id") or ""): entry
                        for entry in live_breakdowns if str(entry.get("canonical_thread_id") or "")
                    }
                    rebased_breakdowns = []
                    for incoming_breakdown in item.get("email_breakdowns") or []:
                        if not isinstance(incoming_breakdown, dict):
                            continue
                        canonical = str(incoming_breakdown.get("canonical_thread_id") or "")
                        live_breakdown = live_breakdown_by_thread.get(canonical)
                        rebased_breakdowns.append(
                            self._rebase_task_item(incoming_breakdown, live_breakdown)
                            if live_breakdown is not None else dict(incoming_breakdown)
                        )
                    item["email_breakdowns"] = rebased_breakdowns
                    item["status"] = aggregate_task_status(entry.get("status") for entry in rebased_breakdowns)
                    priority_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                    item["priority"] = max(
                        (str(entry.get("priority") or "Low").title() for entry in rebased_breakdowns),
                        key=lambda value: priority_rank.get(value.casefold(), 0),
                        default="Low",
                    )
            else:
                canonical = str(item.get("canonical_thread_id") or "")
                live = live_by_thread.get(canonical) or live_by_uid.get(str(item.get("uid") or ""))
                if live is not None:
                    item = self._rebase_task_item(item, live)
            rebased_records.append(item)
        return rebased_records

    def get_uids(self, folder: str) -> set[str]:
        # Return saved card IDs.
        rows = self.conn.execute(
            "SELECT uid FROM summaries WHERE account_email=? AND folder=?",
            (self.account_email, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows}

    def get_summarized_source_uids(self, folder: str) -> set[str]:
        # Return every mailbox email already represented by any summary card.
        rows = self.conn.execute(
            "SELECT uid, source_uids, email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=?",
            (self.account_email, folder),
        ).fetchall()
        used = set()
        for row in rows:
            values = self._loads_list(row["source_uids"])
            breakdowns = self._loads_list(row["email_breakdowns"])
            if not values:
                values = [
                    str(item.get("uid", ""))
                    for item in breakdowns if isinstance(item, dict)
                ] or [str(row["uid"])]
            used.update(str(value) for value in values if str(value))
        return used

    def get_duplicate_records(self, folder: str) -> list[dict]:
        # Return metadata used by the base app's stable duplicate detector.
        #
        # Batch cards are expanded into their source-email breakdowns so exact UID
        # checks and the legacy Outlook ID migration continue to work.
        rows = self.conn.execute(
            """
            SELECT uid, sender, recipient, subject, date_value, snippet,
                   record_type, source_uids, email_breakdowns,
                   thread_count, canonical_thread_id, message_id
            FROM summaries
            WHERE account_email=? AND folder=?
            ORDER BY generated_at DESC, rowid DESC
            """,
            (self.account_email, folder),
        ).fetchall()
        records = []
        for row in rows:
            base = {
                "uid": str(row["uid"]),
                "sender": row["sender"],
                "recipient": row["recipient"],
                "subject": row["subject"],
                "date_value": row["date_value"],
                "snippet": row["snippet"],
                "source_uids": self._loads_list(row["source_uids"]),
                "thread_count": int(row["thread_count"] or 1),
                "canonical_thread_id": row["canonical_thread_id"] or "",
                "message_id": row["message_id"] or "",
            }
            breakdowns = self._loads_list(row["email_breakdowns"])
            if str(row["record_type"] or "manual") == "batch" and breakdowns:
                for item in breakdowns:
                    if not isinstance(item, dict):
                        continue
                    records.append({
                        "uid": str(item.get("uid", "")),
                        "sender": item.get("from", ""),
                        "recipient": item.get("to", ""),
                        "subject": item.get("subject", ""),
                        "date_value": item.get("date", ""),
                        "snippet": item.get("snippet", ""),
                        "source_uids": list(item.get("source_uids") or [str(item.get("uid", ""))]),
                        "thread_count": int(item.get("thread_count") or len(item.get("source_uids") or []) or 1),
                        "canonical_thread_id": str(item.get("canonical_thread_id") or ""),
                        "message_id": str(item.get("message_id") or ""),
                    })
            else:
                records.append(base)
        return records

    def relink_uid(self, folder: str, old_uid: str, new_uid: str) -> None:
        # Relink a legacy mailbox identifier without breaking batch card IDs.
        old_uid = str(old_uid or "").strip()
        new_uid = str(new_uid or "").strip()
        if not old_uid or not new_uid or old_uid == new_uid:
            return

        with self.conn:
            direct = self.conn.execute(
                """SELECT record_type FROM summaries
                   WHERE account_email=? AND folder=? AND uid=?""",
                (self.account_email, folder, old_uid),
            ).fetchone()
            if direct and str(direct["record_type"] or "manual") != "batch":
                already_linked = self.conn.execute(
                    """SELECT 1 FROM summaries
                       WHERE account_email=? AND folder=? AND uid=?""",
                    (self.account_email, folder, new_uid),
                ).fetchone()
                if already_linked:
                    self.conn.execute(
                        "DELETE FROM summaries WHERE account_email=? AND folder=? AND uid=?",
                        (self.account_email, folder, old_uid),
                    )
                else:
                    self.conn.execute(
                        "UPDATE summaries SET uid=? WHERE account_email=? AND folder=? AND uid=?",
                        (new_uid, self.account_email, folder, old_uid),
                    )

            rows = self.conn.execute(
                """SELECT uid, source_uids, email_breakdowns FROM summaries
                   WHERE account_email=? AND folder=?""",
                (self.account_email, folder),
            ).fetchall()
            for row in rows:
                source_uids = [str(value) for value in self._loads_list(row["source_uids"])]
                breakdowns = self._loads_list(row["email_breakdowns"])
                changed = False
                if old_uid in source_uids:
                    source_uids = [new_uid if value == old_uid else value for value in source_uids]
                    source_uids = list(dict.fromkeys(source_uids))
                    changed = True
                for item in breakdowns:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("uid", "")) == old_uid:
                        item["uid"] = new_uid
                        changed = True
                    item_sources = [str(value) for value in (item.get("source_uids") or [])]
                    if old_uid in item_sources:
                        item["source_uids"] = [
                            new_uid if value == old_uid else value for value in item_sources
                        ]
                        changed = True
                if changed:
                    self.conn.execute(
                        """UPDATE summaries SET source_uids=?, email_breakdowns=?
                           WHERE account_email=? AND folder=? AND uid=?""",
                        (
                            json.dumps(source_uids), json.dumps(breakdowns),
                            self.account_email, folder, str(row["uid"]),
                        ),
                    )

    def mark_task_read(self, folder: str, uid: str) -> bool:
        # To-Do attention state is independent from AI Summary Unviewed.
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE summaries SET task_is_read=1, task_update_is_read=1 "
                "WHERE account_email=? AND folder=? AND uid=? "
                "AND (task_is_read=0 OR task_update_is_read=0)",
                (self.account_email, folder, str(uid)),
            )
        return bool(cursor.rowcount)

    def mark_breakdown_task_read(
        self, folder: str, batch_uid: str, source_uid: str, source_index=None
    ) -> bool:
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False
        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        if (
            bool(breakdowns[index].get("task_is_read", True))
            and bool(breakdowns[index].get("task_update_is_read", True))
        ):
            return False
        breakdowns[index]["task_is_read"] = True
        breakdowns[index]["task_update_is_read"] = True
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(breakdowns), self.account_email, folder, str(batch_uid)),
            )
        return True

    def update_status(self, folder: str, uid: str, status: str):
        value = normalize_task_status(status)
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET status=?, status_source='user', task_revision=task_revision+1 "
                "WHERE account_email=? AND folder=? AND uid=?",
                (value, self.account_email, folder, str(uid)),
            )

    def update_task_due_date(self, folder: str, uid: str, due_date: str):
        value = str(due_date or "").strip()
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET task_due_date=?, task_revision=task_revision+1 "
                "WHERE account_email=? AND folder=? AND uid=?",
                (value, self.account_email, folder, str(uid)),
            )

    def update_task_title(self, folder: str, uid: str, task_title: str):
        # Persist the To-Do-only generated title for an individual summary task.
        value = str(task_title or "").strip()
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET task_title=?, task_title_source='user', task_revision=task_revision+1 "
                "WHERE account_email=? AND folder=? AND uid=?",
                (value, self.account_email, folder, str(uid)),
            )

    @staticmethod
    def _task_history_entry(changes, *, source: str = "user") -> dict:
        # Use the same history envelope as automatic new-reply synchronization.
        now = datetime.now()
        return {
            "source": str(source or "user").strip().casefold() or "user",
            "source_uid": "",
            "message_id": "",
            "date": now.isoformat(timespec="seconds"),
            "date_display": now.strftime("%b %d, %Y at %I:%M %p").replace(" 0", " "),
            "changes": [dict(item) for item in (changes or []) if isinstance(item, dict)],
        }

    def append_task_change_history(
        self, folder: str, uid: str, changes, *, source: str = "user"
    ) -> bool:
        # Append one meaningful user/system task-change group for an individual task.
        clean_changes = [dict(item) for item in (changes or []) if isinstance(item, dict)]
        if not clean_changes:
            return False
        row = self.conn.execute(
            "SELECT task_change_history FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(uid)),
        ).fetchone()
        if row is None:
            return False
        history = self._loads_list(row["task_change_history"])[-99:]
        history.append(self._task_history_entry(clean_changes, source=source))
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET task_change_history=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(history), self.account_email, folder, str(uid)),
            )
        return True

    @staticmethod
    def _merge_action_completion(action_items, action_item_details, completed_flags):
        # Merge checkbox state into the CURRENT visible action list without
        # discarding durable closed-history rows. Partial thread reconciliation
        # may omit closed work from ``action_items``; a whole-task cancellation
        # intentionally keeps the final action snapshot visible while marking the
        # task Cancelled. Keep visible rows first so existing action-index callers
        # remain stable, then append unmatched historical detail rows.
        actions = [str(value or "").strip() for value in (action_items or []) if str(value or "").strip()]
        details = [dict(item) for item in (action_item_details or []) if isinstance(item, dict)]
        flags = [bool(value) for value in (completed_flags or [])]

        detail_indexes_by_action = {}
        for detail_index, item in enumerate(details):
            key = str(item.get("action") or "").strip().casefold()
            if key and key not in detail_indexes_by_action:
                detail_indexes_by_action[key] = detail_index

        used_detail_indexes = set()
        merged = []
        for index, action in enumerate(actions):
            detail_index = detail_indexes_by_action.get(action.casefold())
            detail = {}
            if detail_index is not None:
                detail = dict(details[detail_index])
                used_detail_indexes.add(detail_index)
            elif index < len(details):
                candidate = details[index]
                candidate_action = str(candidate.get("action") or "").strip()
                if not candidate_action or candidate_action.casefold() == action.casefold():
                    detail = dict(candidate)
                    used_detail_indexes.add(index)
            detail["action"] = action
            if "due_date" not in detail and detail.get("deadline"):
                detail["due_date"] = detail.get("deadline")
            if index < len(flags):
                detail["completed"] = flags[index]
            else:
                detail["completed"] = bool(detail.get("completed"))
            merged.append(detail)

        for detail_index, item in enumerate(details):
            if detail_index in used_detail_indexes:
                continue
            action = str(item.get("action") or "").strip()
            if not action:
                continue
            merged.append(dict(item))
        return merged

    def update_action_item_completion(self, folder: str, uid: str, action_index: int, completed: bool):
        # Persist one action-item checkbox for an individual summary task.
        row = self.conn.execute(
            "SELECT action_items, action_item_details FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(uid)),
        ).fetchone()
        if row is None:
            return False
        actions = self._loads_list(row["action_items"])
        details = self._loads_list(row["action_item_details"])
        try:
            index = int(action_index)
        except (TypeError, ValueError):
            return False
        if index < 0 or index >= len(actions):
            return False
        merged_current = self._merge_action_completion(actions, details, [])
        merged = [dict(item) for item in merged_current]
        merged[index]["completed"] = bool(completed)
        merged[index]["completion_source"] = "user"
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET action_item_details=?, task_revision=task_revision+1 "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(merged), self.account_email, folder, str(uid)),
            )
        return True

    def update_action_items_completion(self, folder: str, uid: str, completed_flags):
        # Persist all action-item checkbox states for an individual summary task.
        row = self.conn.execute(
            "SELECT action_items, action_item_details FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(uid)),
        ).fetchone()
        if row is None:
            return False
        actions = self._loads_list(row["action_items"])
        details = self._loads_list(row["action_item_details"])
        flags = [bool(value) for value in (completed_flags or [])]
        merged = self._merge_action_completion(actions, details, [])
        for index, flag in enumerate(flags[:len(merged)]):
            if bool(merged[index].get("completed")) != flag:
                merged[index]["completed"] = flag
                merged[index]["completion_source"] = "user"
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET action_item_details=?, task_revision=task_revision+1 "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(merged), self.account_email, folder, str(uid)),
            )
        return True

    @staticmethod
    def _normalized_status_value(status: str) -> str:
        return normalize_task_status(status)

    @staticmethod
    def _find_breakdown_index(breakdowns, source_uid: str, source_index=None):
        source_uid = str(source_uid or "").strip()
        if source_uid:
            for index, item in enumerate(breakdowns):
                if not isinstance(item, dict):
                    continue
                if str(item.get("uid") or "").strip() == source_uid:
                    return index
                item_sources = [
                    str(value or "").strip()
                    for value in (item.get("source_uids") or [])
                ]
                if source_uid in item_sources:
                    return index
        try:
            index = int(source_index)
        except (TypeError, ValueError):
            return None
        return index if 0 <= index < len(breakdowns) else None

    def append_breakdown_task_change_history(
        self, folder: str, batch_uid: str, source_uid: str, changes, *,
        source_index=None, source: str = "user"
    ) -> bool:
        # Append task history to the source-email task nested inside a Batch summary.
        clean_changes = [dict(item) for item in (changes or []) if isinstance(item, dict)]
        if not clean_changes:
            return False
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False
        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        item = breakdowns[index]
        history = list(item.get("task_change_history") or [])[-99:]
        history.append(self._task_history_entry(clean_changes, source=source))
        item["task_change_history"] = history
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(breakdowns), self.account_email, folder, str(batch_uid)),
            )
        return True

    def update_breakdown_status(
        self, folder: str, batch_uid: str, source_uid: str, status: str, source_index=None
    ):
        # Persist the status of one source email inside a batch summary.
        value = self._normalized_status_value(status)
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False

        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        breakdowns[index]["status"] = value
        breakdowns[index]["status_source"] = "user"
        breakdowns[index]["task_revision"] = int(breakdowns[index].get("task_revision") or 0) + 1

        statuses = [
            self._normalized_status_value(item.get("status"))
            for item in breakdowns if isinstance(item, dict)
        ]
        aggregate_status = aggregate_task_status(statuses)
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=?, status=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (
                    json.dumps(breakdowns), aggregate_status, self.account_email,
                    folder, str(batch_uid),
                ),
            )
        return True

    def update_breakdown_task_due_date(
        self, folder: str, batch_uid: str, source_uid: str, due_date: str, source_index=None
    ):
        # Persist a manual due date for one source email inside a batch summary.
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False

        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        breakdowns[index]["task_due_date"] = str(due_date or "").strip()
        breakdowns[index]["task_revision"] = int(breakdowns[index].get("task_revision") or 0) + 1
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(breakdowns), self.account_email, folder, str(batch_uid)),
            )
        return True

    def update_breakdown_task_title(
        self, folder: str, batch_uid: str, source_uid: str, task_title: str, source_index=None
    ):
        # Persist the To-Do-only title for one source email inside a batch summary.
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False

        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        breakdowns[index]["task_title"] = str(task_title or "").strip()
        breakdowns[index]["task_title_source"] = "user"
        breakdowns[index]["task_revision"] = int(breakdowns[index].get("task_revision") or 0) + 1
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(breakdowns), self.account_email, folder, str(batch_uid)),
            )
        return True

    def update_breakdown_action_item_completion(
        self, folder: str, batch_uid: str, source_uid: str, action_index: int, completed: bool, source_index=None
    ):
        # Persist one action-item checkbox inside one source email of a batch summary.
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False
        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        item = breakdowns[index]
        actions = item.get("action_items") or []
        details = item.get("action_item_details") or []
        try:
            action_idx = int(action_index)
        except (TypeError, ValueError):
            return False
        if action_idx < 0 or action_idx >= len(actions):
            return False
        current = self._merge_action_completion(actions, details, [])
        merged = [dict(detail) for detail in current]
        merged[action_idx]["completed"] = bool(completed)
        merged[action_idx]["completion_source"] = "user"
        item["action_item_details"] = merged
        item["task_revision"] = int(item.get("task_revision") or 0) + 1
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(breakdowns), self.account_email, folder, str(batch_uid)),
            )
        return True

    def update_breakdown_action_items_completion(
        self, folder: str, batch_uid: str, source_uid: str, completed_flags, source_index=None
    ):
        # Persist all action-item checkbox states inside one batch source email.
        row = self.conn.execute(
            "SELECT email_breakdowns FROM summaries "
            "WHERE account_email=? AND folder=? AND uid=?",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if row is None:
            return False
        breakdowns = self._loads_list(row["email_breakdowns"])
        index = self._find_breakdown_index(breakdowns, source_uid, source_index)
        if index is None or not isinstance(breakdowns[index], dict):
            return False
        item = breakdowns[index]
        actions = item.get("action_items") or []
        details = item.get("action_item_details") or []
        flags = [bool(value) for value in (completed_flags or [])]
        merged = self._merge_action_completion(actions, details, [])
        for action_index, flag in enumerate(flags[:len(merged)]):
            if bool(merged[action_index].get("completed")) != flag:
                merged[action_index]["completed"] = flag
                merged[action_index]["completion_source"] = "user"
        item["action_item_details"] = merged
        item["task_revision"] = int(item.get("task_revision") or 0) + 1
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET email_breakdowns=? "
                "WHERE account_email=? AND folder=? AND uid=?",
                (json.dumps(breakdowns), self.account_email, folder, str(batch_uid)),
            )
        return True

    def record_deletion_checkpoint(self, folder: str, summary: dict) -> bool:
        # Preserve only thread progress after a visible summary is deleted. This
        # prevents old completed/cancelled work from being resurrected when a
        # later reply arrives in the same provider thread.
        canonical_id = str(summary.get("canonical_thread_id") or "").strip()
        if not canonical_id:
            return False

        source_uids = [
            str(value).strip()
            for value in (summary.get("source_uids") or [summary.get("uid")])
            if str(value or "").strip()
        ]
        message_id = str(summary.get("message_id") or "").strip()
        existing = self.conn.execute(
            """SELECT source_uids, message_id FROM summary_deletion_checkpoints
               WHERE account_email=? AND folder=? AND canonical_thread_id=?""",
            (self.account_email, folder, canonical_id),
        ).fetchone()
        if existing:
            source_uids = list(dict.fromkeys(
                [str(value) for value in self._loads_list(existing["source_uids"])]
                + source_uids
            ))
            if not message_id:
                message_id = str(existing["message_id"] or "")

        with self.conn:
            self.conn.execute(
                """INSERT INTO summary_deletion_checkpoints (
                       account_email, folder, canonical_thread_id, source_uids,
                       message_id, deleted_at
                   ) VALUES (?, ?, ?, ?, ?, datetime('now'))
                   ON CONFLICT(account_email, folder, canonical_thread_id) DO UPDATE SET
                       source_uids=excluded.source_uids,
                       message_id=CASE WHEN excluded.message_id<>'' THEN excluded.message_id ELSE summary_deletion_checkpoints.message_id END,
                       deleted_at=datetime('now')""",
                (
                    self.account_email, folder, canonical_id,
                    json.dumps(source_uids), message_id,
                ),
            )
        return True

    def get_deletion_checkpoints(self, folder: str) -> dict[str, dict]:
        rows = self.conn.execute(
            """SELECT canonical_thread_id, source_uids, message_id, deleted_at
               FROM summary_deletion_checkpoints
               WHERE account_email=? AND folder=?""",
            (self.account_email, folder),
        ).fetchall()
        return {
            str(row["canonical_thread_id"]): {
                "canonical_thread_id": str(row["canonical_thread_id"]),
                "source_uids": self._loads_list(row["source_uids"]),
                "message_id": str(row["message_id"] or ""),
                "deleted_at": str(row["deleted_at"] or ""),
            }
            for row in rows
            if str(row["canonical_thread_id"] or "").strip()
        }

    def clear_deletion_checkpoints(self, folder: str, canonical_ids) -> int:
        values = sorted({str(value or "").strip() for value in canonical_ids if str(value or "").strip()})
        if not values:
            return 0
        placeholders = ",".join("?" for _ in values)
        with self.conn:
            cursor = self.conn.execute(
                f"DELETE FROM summary_deletion_checkpoints WHERE account_email=? AND folder=? AND canonical_thread_id IN ({placeholders})",
                (self.account_email, folder, *values),
            )
        return int(cursor.rowcount or 0)

    def delete_summary(self, folder: str, uid: str) -> bool:
        with self.conn:
            cursor = self.conn.execute(
                "DELETE FROM summaries WHERE account_email=? AND folder=? AND uid=?",
                (self.account_email, folder, str(uid)),
            )
        return int(cursor.rowcount or 0) > 0

    def delete_batch_source(self, folder: str, batch_uid: str, source_uid: str) -> dict:
        # Remove one source summary from a Batch card and refresh every derived
        # aggregate used by AI Summary and To-Do. If it was the last source, the
        # now-empty Batch container is removed automatically.
        row = self.conn.execute(
            """SELECT email_breakdowns FROM summaries
               WHERE account_email=? AND folder=? AND uid=? AND record_type='batch'""",
            (self.account_email, folder, str(batch_uid)),
        ).fetchone()
        if not row:
            return {"deleted": False, "deleted_parent": False, "remaining_count": 0}

        breakdowns = [dict(item) for item in self._loads_breakdowns(row["email_breakdowns"]) if isinstance(item, dict)]
        source_uid = str(source_uid or "").strip()
        remaining = [item for item in breakdowns if str(item.get("uid") or "").strip() != source_uid]
        if len(remaining) == len(breakdowns):
            return {"deleted": False, "deleted_parent": False, "remaining_count": len(breakdowns)}

        if not remaining:
            deleted = self.delete_summary(folder, batch_uid)
            return {"deleted": deleted, "deleted_parent": deleted, "remaining_count": 0}

        sender_counts = Counter()
        attachments = []
        for item in remaining:
            name, address = parseaddr(str(item.get("from") or ""))
            sender_counts[name or address or "Unknown sender"] += 1
            attachments.extend(
                {**attachment, "subject": item.get("subject", "")}
                for attachment in (item.get("attachments") or [])
                if isinstance(attachment, dict)
            )
        action_items = [
            str(value).strip() for item in remaining
            for value in (item.get("action_items") or []) if str(value or "").strip()
        ]
        deadlines = [
            str(value).strip() for item in remaining
            for value in (item.get("deadlines") or []) if str(value or "").strip()
        ]
        source_uids = sorted({
            str(value).strip() for item in remaining
            for value in (item.get("source_uids") or [item.get("uid")])
            if str(value or "").strip()
        })
        priority_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        priority = max(
            (str(item.get("priority") or "Low").strip().title() for item in remaining),
            key=lambda value: priority_rank.get(value.casefold(), 0),
            default="Low",
        )
        status = aggregate_task_status(item.get("status") for item in remaining)
        latest = max(remaining, key=lambda item: str(item.get("date") or ""), default={})
        batch_title = _batch_title_from_breakdowns(remaining)

        with self.conn:
            self.conn.execute(
                """UPDATE summaries SET
                       subject=?, email_breakdowns=?, email_count=?, action_items=?, deadlines=?,
                       priority=?, status=?, top_senders=?, attachments=?, source_uids=?,
                       date_value=?, date_display=?
                   WHERE account_email=? AND folder=? AND uid=?""",
                (
                    batch_title, json.dumps(remaining), len(remaining), json.dumps(action_items),
                    json.dumps(deadlines), priority, status,
                    json.dumps([
                        {"sender": sender, "count": count}
                        for sender, count in sender_counts.most_common()
                    ]),
                    json.dumps(attachments), json.dumps(source_uids),
                    str(latest.get("date") or ""),
                    str(latest.get("date_display") or "Unknown"),
                    self.account_email, folder, str(batch_uid),
                ),
            )
        return {"deleted": True, "deleted_parent": False, "remaining_count": len(remaining)}

    def mark_read(self, folder: str, uid: str):
        with self.conn:
            self.conn.execute(
                "UPDATE summaries SET is_read=1 WHERE account_email=? AND folder=? AND uid=?",
                (self.account_email, folder, str(uid)),
            )

    def mark_unread_many(self, folder: str, uids) -> int:
        """Restore MailMind Unviewed state for existing saved summaries only."""
        normalized = sorted({str(uid) for uid in (uids or []) if str(uid)})
        if not normalized:
            return 0
        changed = 0
        with self.conn:
            for start in range(0, len(normalized), 400):
                batch = normalized[start:start + 400]
                placeholders = ",".join("?" for _ in batch)
                before = self.conn.total_changes
                self.conn.execute(
                    f"UPDATE summaries SET is_read=0 "
                    f"WHERE account_email=? AND folder=? AND uid IN ({placeholders})",
                    [self.account_email, folder, *batch],
                )
                changed += self.conn.total_changes - before
        return changed

    def load_all(self, folder: str) -> list[dict]:
        rows = self.conn.execute("""
            SELECT uid, sender, recipient, cc, subject, date_value, date_display,
                   snippet, summary, key_points, deadlines, action_items, action_item_details, task_title, task_title_source,
                   priority, status, status_source, task_due_date, deadline_mode,
                   task_change_history, task_revision, is_read, task_is_read, task_update_is_read, record_type,
                   email_count, top_senders, attachments, email_breakdowns, incremental_updates,
                   source_uids, thread_count, canonical_thread_id, message_id,
                   generation_source, generation_mode, generated_at,
                   summary_created_at, summary_activity_at
            FROM summaries
            WHERE account_email=? AND folder=?
            ORDER BY COALESCE(NULLIF(summary_activity_at, ''), generated_at) DESC, rowid DESC
        """, (self.account_email, folder)).fetchall()
        loaded = [{
            "uid": row["uid"], "from": row["sender"], "to": row["recipient"], "cc": row["cc"] or "",
            "subject": row["subject"], "date": row["date_value"],
            "date_display": row["date_display"], "snippet": row["snippet"],
            "summary": row["summary"], "task_title": row["task_title"] or "",
            "task_title_source": row["task_title_source"] or "generated",
            "priority": row["priority"],
            "status": normalize_task_status(row["status"]),
            "status_source": row["status_source"] or "email",
            "task_due_date": row["task_due_date"] or "",
            "deadline_mode": row["deadline_mode"] or "auto",
            "task_change_history": self._loads_list(row["task_change_history"]),
            "task_revision": int(row["task_revision"] or 0),
            "is_read": bool(row["is_read"]),
            "task_is_read": bool(row["task_is_read"]),
            "task_update_is_read": bool(row["task_update_is_read"]),
            "record_type": row["record_type"] or "manual",
            "email_count": int(row["email_count"] or 1),
            "top_senders": self._loads_list(row["top_senders"]),
            "attachments": self._loads_list(row["attachments"]),
            "email_breakdowns": self._loads_breakdowns(row["email_breakdowns"]),
            "incremental_updates": self._loads_list(row["incremental_updates"]),
            "source_uids": self._loads_list(row["source_uids"]),
            "thread_count": int(row["thread_count"] or 1),
            "canonical_thread_id": row["canonical_thread_id"] or "",
            "message_id": row["message_id"] or "",
            "generation_source": row["generation_source"] or "manual",
            "generation_mode": row["generation_mode"] or "individual",
            "generated_at": row["generated_at"],
            "summary_created_at": row["summary_created_at"] or row["generated_at"],
            "summary_activity_at": row["summary_activity_at"] or row["generated_at"],
            "key_points": self._loads_list(row["key_points"]),
            "deadlines": self._loads_list(row["deadlines"]),
            "action_items": self._loads_list(row["action_items"]),
            "action_item_details": self._loads_list(row["action_item_details"]),
        } for row in rows]
        for item in loaded:
            trace_summary_pipeline("STORE_AFTER_READ", summary=item, payload={"folder": folder})
        return loaded

    def close(self):
        self.conn.close()
