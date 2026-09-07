# Persistent, account-isolated notification history for MailMind.
from __future__ import annotations

import hashlib
import json
import os
import sqlite3

from config import NOTIFICATION_DEDUPE_WINDOW_SECONDS, NOTIFICATION_HISTORY_LIMIT
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notifications.db")

# Legacy event types that are immediate feedback rather than review-worthy alerts.
# Remove them from the persistent Bell so upgrades immediately get the curated policy.
_NON_PERSISTENT_EVENT_TYPES = {
    "summary-skipped",
    "summary-created",
    "batch-summary-created",
    "summary-security-blocked",
    "summary-cancelled",
    "summary-error",
    "summary-failed",
    "summary-deleted",
    "reply-draft-cancelled",
    "reply-sent",
    "batch-selection-warning",
    "auto-batch-queued",
    "auto-summary-cancelled",
    "task-status",
    "task-completed",
    "task-cancelled",
    "task-reopened",
    "task-updated",
    "task-error",
}


class NotificationStore:
    # Persist notification-center history for one signed-in account.

    def __init__(self, account_email: str, db_path: str = DB_PATH):
        self.account_email = str(account_email or "").strip().casefold()
        if not self.account_email:
            raise ValueError("A signed-in email address is required for NotificationStore.")
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._init_db()

    def _init_db(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                account_email TEXT NOT NULL,
                id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'info',
                workspace TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '[]',
                event_type TEXT NOT NULL DEFAULT '',
                entity_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (account_email, id)
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_account_created "
            "ON notifications(account_email, created_at DESC)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_fingerprint "
            "ON notifications(account_email, fingerprint, created_at DESC)"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_markers (
                account_email TEXT NOT NULL,
                marker_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (account_email, marker_key)
            )
            """
        )
        if _NON_PERSISTENT_EVENT_TYPES:
            placeholders = ",".join("?" for _ in _NON_PERSISTENT_EVENT_TYPES)
            self.conn.execute(
                f"DELETE FROM notifications WHERE account_email=? AND event_type IN ({placeholders})",
                (self.account_email, *sorted(_NON_PERSISTENT_EVENT_TYPES)),
            )
        self.conn.commit()

    @staticmethod
    def _loads_details(value: str) -> list[str]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        return [str(item) for item in loaded] if isinstance(loaded, list) else []

    @staticmethod
    def build_fingerprint(
        *,
        title: str,
        message: str,
        event_type: str,
        entity_id: str,
        details: list[str],
    ) -> str:
        # Return a stable semantic fingerprint used only for short-window dedupe.
        raw = "|".join(
            [
                str(event_type or "").strip().casefold(),
                str(entity_id or "").strip(),
                str(title or "").strip(),
                str(message or "").strip(),
                "\x1f".join(str(item or "").strip() for item in details),
            ]
        )
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def add(
        self,
        *,
        notification_id: str,
        title: str,
        message: str,
        kind: str,
        workspace: str,
        details: list[str],
        event_type: str,
        entity_id: str,
        created_at: str,
    ) -> bool:
        # Insert one event, ignoring immediate rerun duplicates.
        #
        # Streamlit reruns can re-enter the same event handler more than once. A
        # semantic fingerprint plus a short time window prevents those duplicate
        # rows while still allowing a real repeated action later.
        fingerprint = self.build_fingerprint(
            title=title,
            message=message,
            event_type=event_type,
            entity_id=entity_id,
            details=details,
        )
        now = datetime.fromisoformat(created_at)
        recent = self.conn.execute(
            """
            SELECT created_at
            FROM notifications
            WHERE account_email=? AND fingerprint=?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (self.account_email, fingerprint),
        ).fetchone()
        if recent is not None:
            try:
                previous = datetime.fromisoformat(str(recent["created_at"] or ""))
                if abs((now - previous).total_seconds()) <= NOTIFICATION_DEDUPE_WINDOW_SECONDS:
                    return False
            except ValueError:
                pass

        with self.conn:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO notifications (
                    account_email, id, fingerprint, title, message, kind,
                    workspace, details, event_type, entity_id, created_at, is_read
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    self.account_email,
                    notification_id,
                    fingerprint,
                    title,
                    message,
                    kind,
                    workspace,
                    json.dumps(details, ensure_ascii=False),
                    event_type,
                    entity_id,
                    created_at,
                ),
            )
            # Keep the persistent history bounded per account.
            self.conn.execute(
                """
                DELETE FROM notifications
                WHERE account_email=? AND id NOT IN (
                    SELECT id FROM notifications
                    WHERE account_email=?
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                )
                """,
                (self.account_email, self.account_email, NOTIFICATION_HISTORY_LIMIT),
            )
        return True

    def claim_marker(self, marker_key: str) -> bool:
        # Atomically claim a durable one-time event marker for this account.
        clean_key = str(marker_key or "").strip()
        if not clean_key:
            return False
        created_at = datetime.now().isoformat(timespec="seconds")
        with self.conn:
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO notification_markers "
                "(account_email, marker_key, created_at) VALUES (?, ?, ?)",
                (self.account_email, clean_key, created_at),
            )
        return bool(cursor.rowcount)

    def load_all(self, limit: int = NOTIFICATION_HISTORY_LIMIT) -> list[dict]:
        rows = self.conn.execute(
            """
            SELECT id, title, message, kind, workspace, details,
                   event_type, entity_id, created_at, is_read
            FROM notifications
            WHERE account_email=?
            ORDER BY created_at DESC, rowid DESC
            LIMIT ?
            """,
            (self.account_email, int(limit)),
        ).fetchall()
        return [
            {
                "id": str(row["id"]),
                "title": str(row["title"] or "Notification"),
                "message": str(row["message"] or ""),
                "kind": str(row["kind"] or "info"),
                "workspace": str(row["workspace"] or ""),
                "details": self._loads_details(row["details"]),
                "event_type": str(row["event_type"] or ""),
                "entity_id": str(row["entity_id"] or ""),
                "created_at": str(row["created_at"] or ""),
                "read": bool(row["is_read"]),
            }
            for row in rows
        ]

    def count_unread(self) -> int:
        # Return unread notification count without loading notification bodies.
        row = self.conn.execute(
            "SELECT COUNT(*) AS count FROM notifications "
            "WHERE account_email=? AND is_read=0",
            (self.account_email,),
        ).fetchone()
        return int(row["count"] or 0) if row is not None else 0

    def mark_read(self, notification_id: str) -> None:
        # Mark one notification as read for this account.
        clean_id = str(notification_id or "").strip()
        if not clean_id:
            return
        with self.conn:
            self.conn.execute(
                "UPDATE notifications SET is_read=1 WHERE account_email=? AND id=?",
                (self.account_email, clean_id),
            )

    def mark_all_read(self) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE notifications SET is_read=1 WHERE account_email=?",
                (self.account_email,),
            )

    def clear(self) -> None:
        with self.conn:
            self.conn.execute(
                "DELETE FROM notifications WHERE account_email=?",
                (self.account_email,),
            )

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass
