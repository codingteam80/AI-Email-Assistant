import json
import os
import re
import shutil
import sqlite3
from email_handler.display_time import format_display_datetime, parse_timestamp
from email_handler.thread_identity import canonical_thread_id
from services.spam_detection_service import detect_spam
from services.security_trace_service import trace_security_detection
from services.security_input_service import (
    deserialize_security_links,
    normalize_security_input,
    serialize_security_links,
)
import unicodedata
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emails.db")

_NON_SECURITY_ROUTING_CATEGORIES = {"safe / misclassified", "promotional"}


def _category_routes_to_security_workspace(category: str) -> bool:
    return str(category or "").strip().casefold() not in _NON_SECURITY_ROUTING_CATEGORIES

_FILTER_RE = re.compile(r'(?i)(?:^|\s)(from|to|subject):(?:"([^"]*)"|(\S+))')


def _spam_message_rows(rows: List[Dict]) -> List[Dict]:
    """Return one Spam/Security card row per persisted unsafe email.

    Spam is intentionally message-scoped rather than thread-scoped. Two replies
    from the same provider/RFC conversation can carry different security
    classifications, evidence, review state, and timestamps, so every unsafe
    message must remain independently selectable and reviewable. Inbox, Summary,
    To-Do, and normal conversation reconstruction keep their existing thread
    behavior; this helper is used only by the Spam list projection.
    """
    items: List[Dict] = []
    for row in rows or []:
        item = dict(row)
        # The Spam list never advertises a conversation badge because the card
        # represents exactly this physical unsafe message, even when other unsafe
        # replies belong to the same provider thread.
        item["thread_count"] = 1
        items.append(item)
    return items

def normalize_account_email(email_address: str) -> str:
    # Normalize the email address used as the account key.
    return (email_address or "").strip().casefold()


def _normalize_unicode(value) -> str:
    # Normalize text for search matching.
    if value is None:
        return ""
    text = unicodedata.normalize("NFKD", str(value)).casefold()
    return "".join(ch for ch in text if not unicodedata.combining(ch))


def _search_tokens(value) -> List[str]:
    # Split normalized text into search words.
    return re.findall(r"[a-z0-9]+", _normalize_unicode(value))


def _query_units(query) -> List[Tuple[str, str]]:
    # Build flexible search units without joining unrelated words.
    tokens = _search_tokens(query)
    units: List[Tuple[str, str]] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if len(token) == 1 and i + 1 < len(tokens):
            units.append(("compact", token + tokens[i + 1]))
            i += 2
        else:
            units.append(("word", token))
            i += 1
    return units


# Match compact search text against saved words.
def _compact_unit_matches(field_tokens: List[str], compact: str) -> bool:
    if not compact:
        return False

    if any(compact in token for token in field_tokens):
        return True

    for left, right in zip(field_tokens, field_tokens[1:]):
        if len(left) == 1 or len(right) == 1:
            if compact in (left + right):
                return True
    return False


# Check whether the query matches the selected fields.
def _search_matches_fields(query, values) -> int:
    field_token_lists = [_search_tokens(value) for value in values]
    all_tokens = [token for tokens in field_token_lists for token in tokens]
    units = _query_units(query)
    if not units:
        return 0

    for kind, value in units:
        if kind == "word":
            if any(value in token for token in all_tokens):
                continue
            if any(_compact_unit_matches(tokens, value) for tokens in field_token_lists):
                continue
            return 0

        if not any(_compact_unit_matches(tokens, value) for tokens in field_token_lists):
            return 0

    return 1


# Expose single-field matching to SQLite.
def _search_matches(value, query) -> int:
    return _search_matches_fields(query, [value])


# Expose full email matching to SQLite.
def _search_matches_email(subject, sender, recipient, snippet, body_text, query) -> int:
    return _search_matches_fields(
        query, [subject, sender, recipient, snippet, body_text]
    )


def _email_sort_timestamp(value) -> float:
    """Return one timezone-normalized timestamp for Inbox ordering.

    Provider messages can contain different UTC offsets even when they are shown
    together in the same local Inbox. Comparing the persisted ISO text directly
    sorts the local clock text, not the real instant. Reuse MailMind's timestamp
    parser so list ordering and the displayed time are based on the same value.
    """
    parsed = parse_timestamp(value)
    return float(parsed.timestamp()) if parsed is not None else 0.0


# Store email data in one database while keeping accounts isolated.
class EmailStore:
    # Open the database for one signed-in account.
    def __init__(self, account_email: str, db_path: str = DB_PATH):
        self.account_email = normalize_account_email(account_email)
        if not self.account_email or "@" not in self.account_email:
            raise ValueError("A valid signed-in email address is required for EmailStore.")

        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._backup_legacy_mixed_database_if_needed()

        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.create_function(
            "SEARCH_MATCH", 2, _search_matches, deterministic=True
        )
        self.conn.create_function(
            "SEARCH_MATCH_EMAIL", 6, _search_matches_email, deterministic=True
        )
        self.conn.create_function(
            "MAILMIND_TS", 1, _email_sort_timestamp, deterministic=True
        )
        self.cache_identifier_migrated = False
        self._init_db()
        self.account_id = self._get_or_create_account_id()
        self._reclassify_cached_spam_if_needed()
        self._split_cached_promotional_spam_if_needed()
        self._repair_cached_promotional_routing_if_needed()
        self._repair_promotional_provider_inbox_routing_if_needed()
        self._normalize_provider_location_metadata_if_needed()
        # IMPORTANT: do not run mailbox-wide Python backfills during login.
        # Thread identity and display time are derived lazily for the rows that
        # are actually shown/opened, while newly synced rows are persisted in
        # the current format. This keeps sign-in time independent of mailbox
        # size (for example 30k+ cached messages).


    def _split_cached_promotional_spam_if_needed(self) -> None:
        # One-time compatibility repair for the old rule where ordinary marketing
        # vocabulary (discount/promotion/limited-time/etc.) directly produced a
        # Spam verdict. Touch only cached non-user Spam rows whose stored reasons
        # contain promotional wording and no separate spam/security reason. This
        # avoids rescanning the mailbox or disturbing established threat verdicts.
        meta_key = f"security_promotional_split_v1_account_{self.account_id}"
        if self.conn.execute(
            "SELECT 1 FROM app_meta WHERE key=? AND value='complete'",
            (meta_key,),
        ).fetchone():
            return

        rows = self.conn.execute(
            """
            SELECT folder, uid, spam_reason, security_source, provider_spam
            FROM emails
            WHERE account_id=? AND remote_available=1 AND spam_override=0
              AND security_category='Spam'
              AND LOWER(COALESCE(security_source, '')) <> 'user'
              AND LOWER(COALESCE(spam_reason, '')) LIKE '%promotional/deceptive wording:%'
            """,
            (self.account_id,),
        ).fetchall()

        updates = []
        provider_only = "the email provider placed it in spam/junk"
        old_prefix = "promotional/deceptive wording:"
        for row in rows:
            parts = [
                " ".join(part.strip().split())
                for part in str(row["spam_reason"] or "").split(";")
                if part.strip()
            ]
            normalized = [part.casefold() for part in parts]
            if not normalized:
                continue
            if any(
                not (value.startswith(old_prefix) or value == provider_only)
                for value in normalized
            ):
                continue
            rewritten = [
                "Promotional wording:" + part.split(":", 1)[1]
                if part.casefold().startswith(old_prefix) and ":" in part
                else part
                for part in parts
            ]
            updates.append((
                1 if int(row["provider_spam"] or 0) else 0,
                0,
                "; ".join(rewritten),
                "Promotional",
                self.account_id,
                row["folder"],
                row["uid"],
            ))

        if updates:
            self.conn.executemany(
                "UPDATE emails SET is_spam=?, spam_score=?, spam_reason=?, "
                "security_category=? WHERE account_id=? AND folder=? AND uid=?",
                updates,
            )

        self.conn.execute(
            "INSERT INTO app_meta(key, value) VALUES (?, 'complete') "
            "ON CONFLICT(key) DO UPDATE SET value='complete'",
            (meta_key,),
        )
        self.conn.commit()

    def _repair_cached_promotional_routing_if_needed(self) -> None:
        # One-time targeted repair for the first Promotional split. Re-evaluate
        # only rows currently labeled Promotional: ordinary provider-Inbox
        # promotions leave the Security workspace, provider-Junk promotions stay
        # there because of location, and stronger spam/threat evidence is allowed
        # to restore the appropriate security category.
        meta_key = f"security_promotional_routing_v2_account_{self.account_id}"
        if self.conn.execute(
            "SELECT 1 FROM app_meta WHERE key=? AND value='complete'",
            (meta_key,),
        ).fetchone():
            return

        rows = self.conn.execute(
            """
            SELECT folder, uid, subject, sender, recipient, cc, reply_to,
                   spam_evidence, security_links_json, snippet, body_text,
                   has_attachment, provider_spam, spam_override,
                   security_category, security_confidence, security_source,
                   spam_score, spam_reason
            FROM emails
            WHERE account_id=? AND remote_available=1 AND spam_override=0
              AND LOWER(COALESCE(security_source, '')) <> 'user'
              AND security_category='Promotional'
            """,
            (self.account_id,),
        ).fetchall()

        sender_scores = self._learned_sender_scores(row["sender"] for row in rows)
        updates = []
        for row in rows:
            item = dict(row)
            item["from"] = item.pop("sender", "")
            item["to"] = item.pop("recipient", "")
            item["links"] = deserialize_security_links(item.get("security_links_json"))
            item = normalize_security_input(
                item, provider_spam=bool(item.get("provider_spam"))
            )
            item["learned_spam_score"] = sender_scores.get(str(item["from"] or ""), 0)
            verdict = detect_spam(item)
            new_category = str(verdict.get("category") or "Promotional")
            provider_spam = bool(row["provider_spam"] or 0)

            if new_category == "Promotional":
                new_is_spam = 1 if provider_spam else 0
                new_score = int(row["spam_score"] or 0)
                new_reason = str(row["spam_reason"] or verdict.get("reason") or "")
                new_confidence = int(row["security_confidence"] or verdict.get("confidence") or 0)
                new_source = str(row["security_source"] or verdict.get("source") or "Security signals")
            else:
                new_is_spam = 1 if (provider_spam or _category_routes_to_security_workspace(new_category)) else 0
                new_score = int(verdict.get("score") or 0)
                new_reason = str(verdict.get("reason") or row["spam_reason"] or "")
                new_confidence = int(verdict.get("confidence") or 0)
                new_source = str(verdict.get("source") or "Security signals")

            updates.append((
                new_is_spam, new_score, new_reason, new_category,
                new_confidence, new_source, self.account_id,
                row["folder"], row["uid"],
            ))

        if updates:
            self.conn.executemany(
                "UPDATE emails SET is_spam=?, spam_score=?, spam_reason=?, "
                "security_category=?, security_confidence=?, security_source=? "
                "WHERE account_id=? AND folder=? AND uid=?",
                updates,
            )

        self.conn.execute(
            "INSERT INTO app_meta(key, value) VALUES (?, 'complete') "
            "ON CONFLICT(key) DO UPDATE SET value='complete'",
            (meta_key,),
        )
        self.conn.commit()

    def _repair_promotional_provider_inbox_routing_if_needed(self) -> None:
        # Targeted compatibility repair for builds where a Promotional message
        # could move from provider Spam/Junk to Inbox but keep is_spam=1. The
        # current provider location is authoritative; do not reclassify content
        # and do not touch any security category other than Promotional.
        meta_key = f"promotional_provider_inbox_routing_v1_account_{self.account_id}"
        if self.conn.execute(
            "SELECT 1 FROM app_meta WHERE key=? AND value='complete'",
            (meta_key,),
        ).fetchone():
            return

        self.conn.execute(
            """
            UPDATE emails
            SET is_spam=0, synced_at=datetime('now')
            WHERE account_id=? AND remote_available=1
              AND provider_spam=0 AND spam_override=0
              AND LOWER(COALESCE(security_category, ''))='promotional'
              AND is_spam<>0
            """,
            (self.account_id,),
        )
        self.conn.execute(
            "INSERT INTO app_meta(key, value) VALUES (?, 'complete') "
            "ON CONFLICT(key) DO UPDATE SET value='complete'",
            (meta_key,),
        )
        self.conn.commit()

    def _normalize_provider_location_metadata_if_needed(self) -> None:
        # One-time metadata repair for older builds that could leave a historical
        # provider-folder=spam marker after the message had already moved back to
        # Inbox. This never changes MailMind's security category/score; it only
        # makes stored provider evidence match the authoritative provider_spam flag.
        meta_key = f"provider_location_metadata_v1_account_{self.account_id}"
        if self.conn.execute(
            "SELECT 1 FROM app_meta WHERE key=? AND value='complete'", (meta_key,)
        ).fetchone():
            return

        rows = self.conn.execute(
            """
            SELECT folder, uid, provider_spam, spam_evidence, spam_reason
            FROM emails
            WHERE account_id=?
              AND (
                    LOWER(COALESCE(spam_evidence, '')) LIKE '%provider-folder=spam%'
                    OR LOWER(COALESCE(spam_evidence, '')) LIKE '%provider-folder=junk%'
                    OR LOWER(COALESCE(spam_reason, '')) LIKE '%provider placed it in spam/junk%'
                  )
            """,
            (self.account_id,),
        ).fetchall()

        updates = []
        provider_reason = "the email provider placed it in spam/junk"
        for row in rows:
            provider_spam = bool(row["provider_spam"] or 0)
            evidence_parts = [
                part.strip()
                for part in str(row["spam_evidence"] or "").split("|")
                if part.strip()
                and "provider-folder=spam" not in part.casefold()
                and "provider-folder=junk" not in part.casefold()
            ]
            if provider_spam:
                evidence_parts.insert(0, "X-MailMind-Provider-Folder=spam")
            evidence = " | ".join(dict.fromkeys(evidence_parts))

            reason_parts = [
                part.strip()
                for part in str(row["spam_reason"] or "").split(";")
                if part.strip()
            ]
            if not provider_spam:
                reason_parts = [
                    part for part in reason_parts
                    if part.casefold() != provider_reason
                ]
            reason = "; ".join(dict.fromkeys(reason_parts))

            if (
                evidence != str(row["spam_evidence"] or "")
                or reason != str(row["spam_reason"] or "")
            ):
                updates.append((evidence, reason, self.account_id, row["folder"], row["uid"]))

        if updates:
            self.conn.executemany(
                """
                UPDATE emails
                SET spam_evidence=?, spam_reason=?
                WHERE account_id=? AND folder=? AND uid=?
                """,
                updates,
            )
        self.conn.execute(
            "INSERT INTO app_meta(key, value) VALUES (?, 'complete') "
            "ON CONFLICT(key) DO UPDATE SET value='complete'",
            (meta_key,),
        )
        self.conn.commit()

    def _backfill_display_dates(self):
        # Reformat cached provider timestamps in the configured display zone.
        rows = self.conn.execute(
            "SELECT folder, uid, date, date_display FROM emails WHERE account_id=?",
            (self.account_id,),
        ).fetchall()
        updates = []
        for row in rows:
            converted = format_display_datetime(row["date"], row["date_display"] or "Unknown")
            if converted != str(row["date_display"] or ""):
                updates.append((converted, self.account_id, row["folder"], row["uid"]))
        if updates:
            self.conn.executemany(
                "UPDATE emails SET date_display=? "
                "WHERE account_id=? AND folder=? AND uid=?",
                updates,
            )
            self.conn.commit()

    def _backfill_canonical_thread_ids(self):
        # Populate the provider-neutral key for records saved by older releases.
        rows = self.conn.execute(
            """
            SELECT uid, folder, subject, sender, recipient, message_id,
                   in_reply_to, reference_ids, gmail_thread_id, conversation_id
            FROM emails
            WHERE account_id=? AND COALESCE(canonical_thread_id, '')=''
            """,
            (self.account_id,),
        ).fetchall()
        updates = []
        for row in rows:
            item = dict(row)
            item["from"] = item.pop("sender", "")
            item["to"] = item.pop("recipient", "")
            thread_id = canonical_thread_id(item)
            if thread_id:
                updates.append((thread_id, self.account_id, row["folder"], row["uid"]))
        if updates:
            self.conn.executemany(
                """
                UPDATE emails SET canonical_thread_id=?
                WHERE account_id=? AND folder=? AND uid=?
                """,
                updates,
            )
            self.conn.commit()

    def _backup_legacy_mixed_database_if_needed(self):
        # Back up an old database that has no account ownership.
        if not os.path.exists(self.db_path) or os.path.getsize(self.db_path) == 0:
            return

        probe = None
        try:
            probe = sqlite3.connect(self.db_path)
            tables = {
                row[0]
                for row in probe.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "emails" not in tables:
                return
            email_columns = {
                row[1] for row in probe.execute("PRAGMA table_info(emails)").fetchall()
            }
            if "account_id" in email_columns:
                return
        except sqlite3.DatabaseError:
            return
        finally:
            if probe is not None:
                probe.close()

        base_dir = os.path.dirname(os.path.abspath(self.db_path))
        base_name = os.path.join(base_dir, "emails_legacy_mixed_backup.db")
        backup_path = base_name
        if os.path.exists(backup_path):
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            backup_path = os.path.join(
                base_dir, f"emails_legacy_mixed_backup_{stamp}.db"
            )

        shutil.move(self.db_path, backup_path)
        print(
            "[email_store] Legacy mixed database moved to "
            f"'{backup_path}'. A clean account-aware database will be created.",
            flush=True,
        )

    # Create the account-aware database tables.
    def _init_db(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_address TEXT NOT NULL UNIQUE,
                created_at TEXT DEFAULT (datetime('now')),
                last_login_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS emails (
                account_id INTEGER NOT NULL,
                folder TEXT NOT NULL,
                uid TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                recipient TEXT,
                cc TEXT,
                reply_to TEXT,
                spam_evidence TEXT,
                security_links_json TEXT,
                security_input_version INTEGER NOT NULL DEFAULT 0,
                date TEXT,
                date_display TEXT,
                snippet TEXT,
                body_text TEXT,
                body_html TEXT,
                is_full INTEGER DEFAULT 0,
                has_attachment INTEGER NOT NULL DEFAULT 0,
                remote_available INTEGER NOT NULL DEFAULT 1,
                ui_visible INTEGER NOT NULL DEFAULT 1,
                mailmind_unread INTEGER NOT NULL DEFAULT 0,
                remote_unavailable_at TEXT,
                message_id TEXT,
                in_reply_to TEXT,
                reference_ids TEXT,
                gmail_thread_id TEXT,
                conversation_id TEXT,
                canonical_thread_id TEXT,
                provider_thread_count INTEGER NOT NULL DEFAULT 1,
                is_spam INTEGER NOT NULL DEFAULT 0,
                spam_score INTEGER NOT NULL DEFAULT 0,
                spam_reason TEXT,
                spam_override INTEGER NOT NULL DEFAULT 0,
                provider_spam INTEGER NOT NULL DEFAULT 0,
                security_category TEXT NOT NULL DEFAULT 'Unclassified',
                security_confidence INTEGER NOT NULL DEFAULT 0,
                security_source TEXT,
                security_reviewed INTEGER NOT NULL DEFAULT 1,
                synced_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (account_id, folder, uid),
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_emails_account_folder_date
                ON emails(account_id, folder, date DESC);
            CREATE INDEX IF NOT EXISTS idx_emails_account_folder_sender
                ON emails(account_id, folder, sender);
            CREATE INDEX IF NOT EXISTS idx_emails_account_folder_recipient
                ON emails(account_id, folder, recipient);
            CREATE INDEX IF NOT EXISTS idx_emails_account_folder_subject
                ON emails(account_id, folder, subject);

            CREATE TABLE IF NOT EXISTS attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                folder TEXT NOT NULL,
                uid TEXT NOT NULL,
                filename TEXT,
                content_type TEXT,
                size INTEGER,
                data BLOB,
                FOREIGN KEY (account_id, folder, uid)
                    REFERENCES emails(account_id, folder, uid)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_attachments_account_email
                ON attachments(account_id, folder, uid);

            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_preferences (
                account_id INTEGER NOT NULL,
                preference_key TEXT NOT NULL,
                preference_value TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (account_id, preference_key),
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                account_id INTEGER NOT NULL,
                folder TEXT NOT NULL,
                full_sync_complete INTEGER DEFAULT 0,
                remote_total INTEGER DEFAULT 0,
                synced_count INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (account_id, folder),
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS sender_reputation (
                account_id INTEGER NOT NULL,
                sender_key TEXT NOT NULL,
                spam_reports INTEGER NOT NULL DEFAULT 0,
                ham_reports INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT DEFAULT (datetime('now')),
                PRIMARY KEY (account_id, sender_key),
                FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
            );
        """)

        existing_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(emails)").fetchall()
        }
        if "cc" not in existing_columns:
            self.conn.execute("ALTER TABLE emails ADD COLUMN cc TEXT")
        for definition in (
            "reply_to TEXT",
            "spam_evidence TEXT",
            "security_links_json TEXT",
            "security_input_version INTEGER NOT NULL DEFAULT 0",
        ):
            name = definition.split()[0]
            if name not in existing_columns:
                self.conn.execute(f"ALTER TABLE emails ADD COLUMN {definition}")
        if "has_attachment" not in existing_columns:
            self.conn.execute(
                "ALTER TABLE emails ADD COLUMN has_attachment INTEGER NOT NULL DEFAULT 0"
            )
        if "remote_available" not in existing_columns:
            self.conn.execute(
                "ALTER TABLE emails ADD COLUMN remote_available INTEGER NOT NULL DEFAULT 1"
            )
        if "ui_visible" not in existing_columns:
            self.conn.execute(
                "ALTER TABLE emails ADD COLUMN ui_visible INTEGER NOT NULL DEFAULT 1"
            )
        if "mailmind_unread" not in existing_columns:
            self.conn.execute(
                "ALTER TABLE emails ADD COLUMN mailmind_unread INTEGER NOT NULL DEFAULT 0"
            )
        if "remote_unavailable_at" not in existing_columns:
            self.conn.execute(
                "ALTER TABLE emails ADD COLUMN remote_unavailable_at TEXT"
            )
        for name in (
            "message_id", "in_reply_to", "reference_ids", "gmail_thread_id",
            "conversation_id", "canonical_thread_id",
        ):
            if name not in existing_columns:
                self.conn.execute(f"ALTER TABLE emails ADD COLUMN {name} TEXT")
        if "provider_thread_count" not in existing_columns:
            self.conn.execute(
                "ALTER TABLE emails ADD COLUMN provider_thread_count INTEGER NOT NULL DEFAULT 1"
            )
        provider_spam_was_missing = "provider_spam" not in existing_columns
        for definition in (
            "is_spam INTEGER NOT NULL DEFAULT 0",
            "spam_score INTEGER NOT NULL DEFAULT 0",
            "spam_reason TEXT",
            "spam_override INTEGER NOT NULL DEFAULT 0",
            "provider_spam INTEGER NOT NULL DEFAULT 0",
            "security_category TEXT NOT NULL DEFAULT 'Unclassified'",
            "security_confidence INTEGER NOT NULL DEFAULT 0",
            "security_source TEXT",
            "security_reviewed INTEGER NOT NULL DEFAULT 1",
        ):
            name = definition.split()[0]
            if name not in existing_columns:
                self.conn.execute(f"ALTER TABLE emails ADD COLUMN {definition}")
        # Legacy migration ONLY: infer provider location from the old reason text
        # at the exact moment provider_spam is first introduced. Running this on
        # every login would incorrectly revive historical Spam/Junk locations for
        # messages that have already moved back to Inbox.
        if provider_spam_was_missing:
            self.conn.execute(
                "UPDATE emails SET provider_spam=1 "
                "WHERE provider_spam=0 AND LOWER(COALESCE(spam_reason, '')) "
                "LIKE '%provider placed it in spam/junk%'"
            )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_emails_gmail_thread "
            "ON emails(account_id, folder, gmail_thread_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_emails_conversation "
            "ON emails(account_id, folder, conversation_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_emails_canonical_thread "
            "ON emails(account_id, folder, canonical_thread_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_emails_mailmind_unread "
            "ON emails(account_id, folder, mailmind_unread, remote_available, ui_visible, is_spam)"
        )

        self.conn.execute("""
            UPDATE emails
            SET has_attachment=1
            WHERE EXISTS (
                SELECT 1 FROM attachments a
                WHERE a.account_id=emails.account_id
                  AND a.folder=emails.folder
                  AND a.uid=emails.uid
            )
        """)

        identifier_mode_row = self.conn.execute(
            "SELECT value FROM app_meta WHERE key='email_identifier_mode'"
        ).fetchone()
        identifier_mode = identifier_mode_row[0] if identifier_mode_row else None
        if identifier_mode != "imap_uid_v1":
            legacy_count = self.conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
            if legacy_count:
                # Older versions stored mutable IMAP sequence numbers. Rebuild
                # only the email cache so a deletion cannot point at another email.
                self.conn.execute("DELETE FROM attachments")
                self.conn.execute("DELETE FROM emails")
                self.conn.execute("DELETE FROM sync_state")
                self.cache_identifier_migrated = True
            self.conn.execute(
                """
                INSERT INTO app_meta (key, value)
                VALUES ('email_identifier_mode', 'imap_uid_v1')
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """
            )
        self.conn.commit()

    # Load or create the current account record.
    def _get_or_create_account_id(self) -> int:
        self.conn.execute(
            """
            INSERT INTO accounts (email_address, last_login_at)
            VALUES (?, datetime('now'))
            ON CONFLICT(email_address) DO UPDATE SET
                last_login_at=datetime('now')
            """,
            (self.account_email,),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM accounts WHERE email_address=?",
            (self.account_email,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Could not create or load the signed-in account record.")
        account_id = int(row["id"])
        self._request_attachment_metadata_rescan(account_id)
        return account_id

    def get_user_preference(self, key: str, default: str = "") -> str:
        # Load one account-scoped UI/application preference. Preferences live
        # in SQLite rather than Streamlit session state so logout, browser
        # refresh, and a later sign-in do not erase an explicit user choice.
        row = self.conn.execute(
            """
            SELECT preference_value
            FROM user_preferences
            WHERE account_id=? AND preference_key=?
            """,
            (self.account_id, str(key)),
        ).fetchone()
        return str(row["preference_value"]) if row else str(default)

    def set_user_preferences(self, preferences: Dict[str, str]) -> None:
        # Save a small set of account preferences atomically. This is used only
        # for explicit Settings changes; transient UI/session flags never enter
        # this table.
        rows = [
            (self.account_id, str(key), str(value))
            for key, value in dict(preferences or {}).items()
            if str(key).strip()
        ]
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO user_preferences (
                account_id, preference_key, preference_value, updated_at
            ) VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(account_id, preference_key) DO UPDATE SET
                preference_value=excluded.preference_value,
                updated_at=datetime('now')
            """,
            rows,
        )
        self.conn.commit()

    def _pending_new_mail_meta_key(self, folder: str) -> str:
        # Persist only the lifecycle hand-off for genuinely NEW mail. The actual
        # email/Security data already lives in the emails table; this tiny list
        # lets a replacement Streamlit session finish publication instead of
        # losing the in-memory NEW queue and leaving ui_visible=0 forever.
        normalized_folder = str(folder or "INBOX").strip().upper() or "INBOX"
        return f"pending_new_mail_v1:{self.account_id}:{normalized_folder}"

    def _security_catchup_notice_meta_key(self, folder: str = "INBOX") -> str:
        normalized_folder = str(folder or "INBOX").strip().upper() or "INBOX"
        return f"security_catchup_running_notice_v1:{self.account_id}:{normalized_folder}"

    def _initial_security_gate_meta_key(self, folder: str = "INBOX") -> str:
        # Persist the blocking first-login Security pass across browser/WebSocket
        # session replacement. A completed mailbox sync can already contain
        # header-only rows, so full_sync_complete alone is not enough to decide
        # that the Inbox is safe to expose after an interrupted Analyzing pass.
        normalized_folder = str(folder or "INBOX").strip().upper() or "INBOX"
        return f"initial_security_gate_v1:{self.account_id}:{normalized_folder}"

    def initial_security_gate_active(self, folder: str = "INBOX") -> bool:
        row = self.conn.execute(
            "SELECT value FROM app_meta WHERE key=?",
            (self._initial_security_gate_meta_key(folder),),
        ).fetchone()
        return bool(row and str(row["value"] or "").strip() == "active")

    def set_initial_security_gate_active(
        self, folder: str = "INBOX", *, active: bool
    ) -> None:
        key = self._initial_security_gate_meta_key(folder)
        if active:
            self.conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES (?, 'active')
                ON CONFLICT(key) DO UPDATE SET value='active'
                """,
                (key,),
            )
        else:
            self.conn.execute("DELETE FROM app_meta WHERE key=?", (key,))
        self.conn.commit()

    def security_catchup_notice_active(self, folder: str = "INBOX") -> bool:
        row = self.conn.execute(
            "SELECT value FROM app_meta WHERE key=?",
            (self._security_catchup_notice_meta_key(folder),),
        ).fetchone()
        return bool(row and str(row["value"] or "").strip() == "active")

    def set_security_catchup_notice_active(
        self, folder: str = "INBOX", *, active: bool
    ) -> None:
        key = self._security_catchup_notice_meta_key(folder)
        if active:
            self.conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES (?, 'active')
                ON CONFLICT(key) DO UPDATE SET value='active'
                """,
                (key,),
            )
        else:
            self.conn.execute("DELETE FROM app_meta WHERE key=?", (key,))
        self.conn.commit()

    def get_pending_new_mail_uids(self, folder: str = "INBOX") -> Set[str]:
        row = self.conn.execute(
            "SELECT value FROM app_meta WHERE key=?",
            (self._pending_new_mail_meta_key(folder),),
        ).fetchone()
        if not row:
            return set()
        try:
            values = json.loads(str(row["value"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return set()
        if not isinstance(values, list):
            return set()
        return {str(uid) for uid in values if str(uid)}

    def set_pending_new_mail_uids(self, folder: str, uids: Iterable[str]) -> None:
        normalized = sorted({str(uid) for uid in (uids or []) if str(uid)})
        key = self._pending_new_mail_meta_key(folder)
        if not normalized:
            self.conn.execute("DELETE FROM app_meta WHERE key=?", (key,))
        else:
            self.conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, json.dumps(normalized, ensure_ascii=False)),
            )
        self.conn.commit()

    def get_hidden_security_uids(self, folder: str = "INBOX") -> Set[str]:
        # Hidden rows are the Security publish gate. They are normally transient,
        # but may survive a browser/WebSocket session replacement after the DB
        # worker has already completed. Expose their UIDs for safe recovery.
        rows = self.conn.execute(
            """
            SELECT uid FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1 AND ui_visible=0
            """,
            (self.account_id, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows if str(row["uid"])}

    def _attachment_scan_meta_key(self, account_id: int) -> str:
        return f"attachment_metadata_scan_v2:{int(account_id)}"

    def _request_attachment_metadata_rescan(self, account_id: int) -> None:
        # Schedule one full header/BODYSTRUCTURE sync for older caches.
        #
        # Previous IMAP versions saved headers without attachment metadata, so
        # zero meant both "no attachment" and "not checked". Preserve cached
        # mail, but mark the account sync incomplete once so the normal startup
        # sync backfills has_attachment for every message.
        meta_key = self._attachment_scan_meta_key(account_id)
        row = self.conn.execute(
            "SELECT value FROM app_meta WHERE key=?", (meta_key,)
        ).fetchone()
        if row and row[0] == "complete":
            return

        # Opened messages may already have real attachment rows; expose those
        # immediately even before the one-time mailbox rescan finishes.
        self.conn.execute(
            """
            UPDATE emails
            SET has_attachment=1
            WHERE account_id=? AND EXISTS (
                SELECT 1 FROM attachments a
                WHERE a.account_id=emails.account_id
                  AND a.folder=emails.folder
                  AND a.uid=emails.uid
            )
            """,
            (account_id,),
        )
        self.conn.execute(
            """
            INSERT INTO sync_state (
                account_id, folder, full_sync_complete, remote_total,
                synced_count, last_error, updated_at
            ) VALUES (?, 'INBOX', 0, 0, 0, NULL, datetime('now'))
            ON CONFLICT(account_id, folder) DO UPDATE SET
                full_sync_complete=0,
                last_error=NULL,
                updated_at=datetime('now')
            """,
            (account_id,),
        )
        self.conn.execute(
            """
            INSERT INTO app_meta (key, value) VALUES (?, 'pending')
            ON CONFLICT(key) DO UPDATE SET value='pending'
            """,
            (meta_key,),
        )
        self.conn.commit()

    # Convert one database row to the UI format.
    @staticmethod
    def _row_to_email(row: sqlite3.Row) -> Dict:
        data = dict(row)
        data.pop("account_id", None)
        if "sender" in data:
            data["from"] = data.pop("sender")
        if "recipient" in data:
            data["to"] = data.pop("recipient")
        data["cc"] = data.get("cc") or ""
        data["reply_to"] = data.get("reply_to") or ""
        data["spam_evidence"] = data.get("spam_evidence") or ""
        data["links"] = deserialize_security_links(data.get("security_links_json"))
        # Normalize only the row being consumed instead of rewriting the whole
        # mailbox on every login. Ten visible inbox rows means ten cheap date
        # conversions, not tens of thousands.
        if data.get("date"):
            data["date_display"] = format_display_datetime(
                data.get("date"), data.get("date_display") or "Unknown"
            )
        if not str(data.get("canonical_thread_id") or "").strip():
            data["canonical_thread_id"] = canonical_thread_id(data)
        return data

    # Return the saved email count for this account.
    def get_count(self, folder: str = "INBOX") -> int:
        return self.conn.execute(
            """
            SELECT COUNT(*) FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1 AND ui_visible=1 AND is_spam=0
            """,
            (self.account_id, folder),
        ).fetchone()[0]

    def get_active_uids(self, folder: str = "INBOX") -> set[str]:
        # Return all locally cached UIDs that still exist remotely.
        rows = self.conn.execute(
            """
            SELECT uid FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1
            """,
            (self.account_id, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows if str(row["uid"])}

    def update_provider_thread_counts(self, folder: str,
                                      counts: Dict[str, int]) -> int:
        # Persist Outlook conversation counts collected during the same full
        # mailbox traversal. This avoids a separate Graph request per thread.
        rows = [
            (
                max(1, int(count or 1)),
                self.account_id,
                folder,
                str(conversation_id),
                max(1, int(count or 1)),
            )
            for conversation_id, count in (counts or {}).items()
            if str(conversation_id or "").strip()
        ]
        if not rows:
            return 0

        before_changes = self.conn.total_changes
        self.conn.executemany(
            """
            UPDATE emails
            SET provider_thread_count=?
            WHERE account_id=? AND folder=?
              AND conversation_id=?
              AND provider_thread_count IS NOT ?
            """,
            rows,
        )
        self.conn.commit()
        return self.conn.total_changes - before_changes

    # Write operations.

    # Save or update one page of email headers.
    def save_page(self, folder: str, parsed_emails: List[Dict], source: str = "page") -> int:
        if not parsed_emails:
            return 0

        # Header/snippet Security is a one-time stage for an existing physical
        # message. A normal login, refresh, RESTORED event, or provider-folder
        # move must not keep feeding the same cached message back through the
        # lightweight classifier. Only rows that have never been header checked
        # (security_input_version=0 / absent) receive a new deterministic header
        # verdict here. Completed/full-message results remain durable.
        incoming_uids = [
            str(item.get("uid") or "") for item in parsed_emails
            if str(item.get("uid") or "")
        ]
        existing_security = {}
        for start in range(0, len(incoming_uids), 400):
            batch = incoming_uids[start:start + 400]
            if not batch:
                continue
            placeholders = ",".join("?" for _ in batch)
            rows = self.conn.execute(
                f"""
                SELECT uid, security_input_version, is_spam, spam_score, spam_reason,
                       provider_spam, security_category, security_confidence,
                       security_source, spam_override
                FROM emails
                WHERE account_id=? AND folder=? AND uid IN ({placeholders})
                """,
                [self.account_id, folder, *batch],
            ).fetchall()
            existing_security.update({str(row["uid"]): dict(row) for row in rows})

        sender_scores = self._learned_sender_scores(
            email_item.get("from", "") for email_item in parsed_emails
        )
        verdicts = []
        normalized_emails = []
        for email_item in parsed_emails:
            enriched = normalize_security_input(email_item)
            uid = str(enriched.get("uid") or "")
            cached = existing_security.get(uid)
            if cached is not None and int(cached.get("security_input_version") or 0) >= 1:
                evidence = str(enriched.get("spam_evidence") or "").casefold()
                provider_flagged = (
                    "provider-folder=spam" in evidence
                    or "provider-folder=junk" in evidence
                )
                verdict = {
                    "is_spam": bool(cached.get("is_spam")),
                    "score": int(cached.get("spam_score") or 0),
                    "reason": str(cached.get("spam_reason") or ""),
                    "provider_flagged": provider_flagged,
                    "category": str(cached.get("security_category") or "Unclassified"),
                    "confidence": int(cached.get("security_confidence") or 0),
                    "source": str(cached.get("security_source") or "Security signals"),
                }
            else:
                enriched["learned_spam_score"] = sender_scores.get(
                    str(enriched.get("from", "")), 0
                )
                verdict = detect_spam(enriched)
            normalized_emails.append(enriched)
            verdicts.append(verdict)
        rows = [
            (
                self.account_id,
                folder,
                str(e["uid"]),
                e.get("subject", ""),
                e.get("from", ""),
                e.get("to", ""),
                e.get("cc", ""),
                e.get("reply_to", ""),
                e.get("spam_evidence", ""),
                serialize_security_links(e.get("links") or []),
                1,
                e.get("date", ""),
                e.get("date_display", ""),
                e.get("snippet", ""),
                1 if e.get("has_attachment") else 0,
                0 if str(source or "").strip().casefold() == "automatic_mailbox_monitor" else 1,
                e.get("message_id", ""),
                e.get("in_reply_to", ""),
                e.get("references", ""),
                e.get("gmail_thread_id", ""),
                e.get("conversation_id", ""),
                canonical_thread_id(e),
                max(1, int(e.get("provider_thread_count") or 1)),
                1 if verdict["is_spam"] else 0,
                int(verdict["score"]),
                verdict["reason"],
                1 if verdict.get("provider_flagged") else 0,
                str(verdict.get("category") or "Suspicious"),
                int(verdict.get("confidence") or 0),
                str(verdict.get("source") or "Security signals"),
            )
            for e, verdict in zip(normalized_emails, verdicts)
        ]
        before_changes = self.conn.total_changes
        self.conn.executemany("""
            INSERT INTO emails (
                account_id, folder, uid, subject, sender, recipient, cc,
                reply_to, spam_evidence, security_links_json, security_input_version,
                date, date_display, snippet, has_attachment, remote_available,
                ui_visible, remote_unavailable_at, message_id, in_reply_to, reference_ids,
                gmail_thread_id, conversation_id, canonical_thread_id,
                provider_thread_count, is_spam, spam_score, spam_reason,
                provider_spam, security_category, security_confidence,
                security_source, synced_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(account_id, folder, uid) DO UPDATE SET
                subject=excluded.subject,
                sender=excluded.sender,
                recipient=excluded.recipient,
                cc=excluded.cc,
                reply_to=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 2 THEN emails.reply_to
                    WHEN excluded.reply_to <> '' THEN excluded.reply_to ELSE emails.reply_to
                END,
                spam_evidence=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 2 THEN emails.spam_evidence
                    WHEN excluded.spam_evidence <> '' THEN excluded.spam_evidence ELSE emails.spam_evidence
                END,
                security_links_json=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 2 THEN emails.security_links_json
                    WHEN excluded.security_links_json <> '[]' THEN excluded.security_links_json ELSE emails.security_links_json
                END,
                security_input_version=MAX(COALESCE(emails.security_input_version, 0), excluded.security_input_version),
                date=excluded.date,
                date_display=excluded.date_display,
                snippet=CASE
                    WHEN excluded.snippet <> '' THEN excluded.snippet
                    ELSE emails.snippet
                END,
                has_attachment=MAX(emails.has_attachment, excluded.has_attachment),
                message_id=CASE WHEN excluded.message_id <> '' THEN excluded.message_id ELSE emails.message_id END,
                in_reply_to=CASE WHEN excluded.in_reply_to <> '' THEN excluded.in_reply_to ELSE emails.in_reply_to END,
                reference_ids=CASE WHEN excluded.reference_ids <> '' THEN excluded.reference_ids ELSE emails.reference_ids END,
                gmail_thread_id=CASE WHEN excluded.gmail_thread_id <> '' THEN excluded.gmail_thread_id ELSE emails.gmail_thread_id END,
                conversation_id=CASE WHEN excluded.conversation_id <> '' THEN excluded.conversation_id ELSE emails.conversation_id END,
                canonical_thread_id=CASE WHEN excluded.canonical_thread_id <> '' THEN excluded.canonical_thread_id ELSE emails.canonical_thread_id END,
                provider_thread_count=MAX(emails.provider_thread_count, excluded.provider_thread_count),
                is_spam=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 1 THEN
                        CASE
                            WHEN excluded.provider_spam=1 THEN 1
                            WHEN LOWER(COALESCE(emails.security_category, '')) IN ('safe / misclassified', 'promotional')
                            THEN 0
                            ELSE 1
                        END
                    ELSE excluded.is_spam
                END,
                spam_score=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 1
                    THEN emails.spam_score ELSE excluded.spam_score
                END,
                spam_reason=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 1
                    THEN emails.spam_reason ELSE excluded.spam_reason
                END,
                provider_spam=excluded.provider_spam,
                security_category=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 1
                    THEN emails.security_category ELSE excluded.security_category
                END,
                security_confidence=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 1
                    THEN emails.security_confidence ELSE excluded.security_confidence
                END,
                security_source=CASE
                    WHEN COALESCE(emails.security_input_version, 0) >= 1
                    THEN emails.security_source ELSE excluded.security_source
                END,
                remote_available=1,
                remote_unavailable_at=NULL,
                synced_at=excluded.synced_at
            WHERE
                emails.subject IS NOT excluded.subject OR
                emails.sender IS NOT excluded.sender OR
                emails.recipient IS NOT excluded.recipient OR
                emails.cc IS NOT excluded.cc OR
                (COALESCE(emails.security_input_version, 0) < 2
                 AND excluded.reply_to <> ''
                 AND COALESCE(emails.reply_to, '') IS NOT excluded.reply_to) OR
                (COALESCE(emails.security_input_version, 0) < 2
                 AND excluded.spam_evidence <> ''
                 AND COALESCE(emails.spam_evidence, '') IS NOT excluded.spam_evidence) OR
                (COALESCE(emails.security_input_version, 0) < 2
                 AND excluded.security_links_json <> '[]'
                 AND COALESCE(emails.security_links_json, '[]') IS NOT excluded.security_links_json) OR
                COALESCE(emails.security_input_version, 0) < excluded.security_input_version OR
                emails.date IS NOT excluded.date OR
                emails.date_display IS NOT excluded.date_display OR
                emails.has_attachment IS NOT excluded.has_attachment OR
                (excluded.message_id <> '' AND emails.message_id IS NOT excluded.message_id) OR
                (excluded.in_reply_to <> '' AND emails.in_reply_to IS NOT excluded.in_reply_to) OR
                (excluded.reference_ids <> '' AND emails.reference_ids IS NOT excluded.reference_ids) OR
                (excluded.gmail_thread_id <> '' AND emails.gmail_thread_id IS NOT excluded.gmail_thread_id) OR
                (excluded.conversation_id <> '' AND emails.conversation_id IS NOT excluded.conversation_id) OR
                (excluded.canonical_thread_id <> '' AND emails.canonical_thread_id IS NOT excluded.canonical_thread_id) OR
                emails.provider_thread_count IS NOT excluded.provider_thread_count OR
                (emails.spam_override=0
                 AND LOWER(COALESCE(emails.security_source, '')) NOT IN ('hybrid ai', 'user')
                 AND emails.is_spam IS NOT excluded.is_spam) OR
                emails.provider_spam IS NOT excluded.provider_spam OR
                (emails.spam_override=0
                 AND LOWER(COALESCE(emails.security_source, '')) NOT IN ('hybrid ai', 'user')
                 AND emails.security_category IS NOT excluded.security_category) OR
                (emails.spam_override=0
                 AND LOWER(COALESCE(emails.security_source, '')) NOT IN ('hybrid ai', 'user')
                 AND emails.security_confidence IS NOT excluded.security_confidence) OR
                (emails.spam_override=0
                 AND LOWER(COALESCE(emails.security_source, '')) NOT IN ('hybrid ai', 'user')
                 AND COALESCE(emails.security_source, '') IS NOT COALESCE(excluded.security_source, '')) OR
                emails.remote_available <> 1 OR
                (excluded.snippet <> '' AND emails.snippet IS NOT excluded.snippet)
        """, rows)
        self.conn.commit()
        changed_rows = self.conn.total_changes - before_changes
        return changed_rows

    def classify_and_store_security(self, folder: str, email_data: Dict) -> Dict:
        # Re-run the deterministic classifier through the same normalized
        # provider-neutral input contract after a full body/attachment fetch.
        enriched = normalize_security_input(email_data)
        enriched["learned_spam_score"] = self._learned_sender_score(
            enriched.get("from", "")
        )
        verdict = detect_spam(enriched)
        uid = str(enriched.get("uid") or "")
        if not uid:
            return verdict

        row = self.conn.execute(
            "SELECT spam_override, provider_spam, is_spam, spam_score, spam_reason, "
            "security_category, security_confidence, security_source FROM emails "
            "WHERE account_id=? AND folder=? AND uid=?",
            (self.account_id, folder, uid),
        ).fetchone()
        if not row:
            return verdict

        provider_spam = int(bool(verdict.get("provider_flagged")))
        if not provider_spam:
            provider_spam = int(row["provider_spam"] or 0)

        cached_source = str(row["security_source"] or "").strip()
        cached_source_key = cached_source.casefold()
        strong_flags = {str(value) for value in (verdict.get("strong_flags") or [])}
        dangerous_new_evidence = bool(
            "dangerous-attachment" in strong_flags
            or str(verdict.get("category") or "") == "Malware"
        )

        if int(row["spam_override"] or 0):
            is_spam = 0
            category = "Safe / Misclassified"
            confidence = 100
            source = "User"
            spam_score = int(row["spam_score"] or 0)
            spam_reason = str(row["spam_reason"] or "Marked as not spam by user")
        elif cached_source_key in {"hybrid ai", "user"} and not dangerous_new_evidence:
            # Opening a message or refreshing its full body must not downgrade a
            # durable contextual classification back to the lightweight header
            # baseline. Provider-folder membership may still change whether a
            # Safe/Misclassified message remains visible in the Spam workspace.
            category = str(row["security_category"] or "Suspicious")
            confidence = int(row["security_confidence"] or 0)
            source = cached_source or "Hybrid AI"
            spam_score = int(row["spam_score"] or 0)
            spam_reason = str(row["spam_reason"] or "")
            is_spam = int(
                provider_spam
                or _category_routes_to_security_workspace(category)
            )
        else:
            is_spam = 1 if verdict.get("is_spam") or provider_spam else 0
            category = str(verdict.get("category") or "Suspicious")
            confidence = int(verdict.get("confidence") or 0)
            source = str(verdict.get("source") or "Security signals")
            spam_score = int(verdict.get("score") or 0)
            spam_reason = str(verdict.get("reason") or "")

        self.conn.execute(
            "UPDATE emails SET is_spam=?, spam_score=?, spam_reason=?, "
            "provider_spam=?, security_category=?, security_confidence=?, "
            "security_source=? WHERE account_id=? AND folder=? AND uid=?",
            (
                is_spam, spam_score, spam_reason, provider_spam, category,
                confidence, source, self.account_id, folder, uid,
            ),
        )
        self.conn.commit()
        verdict.update({
            "is_spam": bool(is_spam),
            "score": spam_score,
            "reason": spam_reason,
            "provider_flagged": bool(provider_spam),
            "category": category,
            "confidence": confidence,
            "source": source,
        })
        return verdict

    def publish_security_ready(self, folder: str, uids: Iterable[str]) -> set[str]:
        # Publish staged NEW/provider-move rows only after full-message Security
        # input is complete. Existing rows default to visible=1, so this method
        # is a no-op for normal catch-up mail and cannot change classification.
        normalized = sorted({str(uid) for uid in (uids or []) if str(uid)})
        if not normalized:
            return set()

        published = set()
        for start in range(0, len(normalized), 400):
            batch = normalized[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            rows = self.conn.execute(
                f"SELECT uid FROM emails WHERE account_id=? AND folder=? "
                f"AND uid IN ({placeholders}) AND remote_available=1 "
                f"AND ui_visible=0 AND COALESCE(security_input_version, 0) >= 2",
                [self.account_id, folder, *batch],
            ).fetchall()
            ready = {str(row["uid"]) for row in rows if str(row["uid"])}
            if not ready:
                continue
            ready_placeholders = ",".join("?" for _ in ready)
            self.conn.execute(
                f"UPDATE emails SET ui_visible=1 WHERE account_id=? AND folder=? "
                f"AND uid IN ({ready_placeholders})",
                [self.account_id, folder, *sorted(ready)],
            )
            published.update(ready)
        self.conn.commit()
        return published

    def update_security_classification(
        self, folder: str, uid: str, classification: Dict
    ) -> Optional[Dict]:
        # Cache a contextual/AI classification. Provider Spam/Junk placement is
        # preserved even when the contextual result says the message itself is
        # legitimate, so Safe/Misclassified provider mail stays visible there.
        uid = str(uid or "")
        row = self.conn.execute(
            "SELECT provider_spam, spam_override, spam_score, spam_reason FROM emails "
            "WHERE account_id=? AND folder=? AND uid=?",
            (self.account_id, folder, uid),
        ).fetchone()
        if not row:
            return None

        trace_security_detection(
            "STORE_UPDATE_INPUT",
            email={"uid": uid},
            classification=classification,
            payload={"folder": folder},
        )
        category = str(classification.get("category") or "Suspicious")
        confidence = max(0, min(100, int(classification.get("confidence") or 0)))
        source = str(classification.get("source") or "Hybrid AI")
        reason = str(classification.get("reason") or row["spam_reason"] or "")
        provider_spam = bool(row["provider_spam"] or 0)
        overridden = bool(row["spam_override"] or 0)
        if overridden:
            category = "Safe / Misclassified"
            confidence = 100
            source = "User"
            is_spam = 0
        else:
            is_spam = int(provider_spam or _category_routes_to_security_workspace(category))

        self.conn.execute(
            "UPDATE emails SET is_spam=?, spam_reason=?, security_category=?, "
            "security_confidence=?, security_source=? "
            "WHERE account_id=? AND folder=? AND uid=?",
            (
                is_spam, reason, category, confidence, source,
                self.account_id, folder, uid,
            ),
        )
        self.conn.commit()
        stored = {
            "is_spam": bool(is_spam),
            "spam_score": int(row["spam_score"] or 0),
            "spam_reason": reason,
            "provider_spam": provider_spam,
            "security_category": category,
            "security_confidence": confidence,
            "security_source": source,
        }
        trace_security_detection(
            "STORE_UPDATE_FINAL",
            email={"uid": uid},
            classification=stored,
            payload={"folder": folder, "provider_spam": provider_spam, "overridden": overridden},
        )
        return stored

    def mark_not_spam(self, folder: str, uid: str) -> None:
        row = self.conn.execute("SELECT sender FROM emails WHERE account_id=? AND folder=? AND uid=?", (self.account_id, folder, str(uid))).fetchone()
        self.conn.execute("UPDATE emails SET is_spam=0, spam_override=1, spam_reason='Marked as not spam by user', security_category='Safe / Misclassified', security_confidence=100, security_source='User', security_reviewed=1 WHERE account_id=? AND folder=? AND uid=?", (self.account_id, folder, str(uid)))
        if row: self._record_sender_feedback(row["sender"], spam=False)
        self.conn.commit()

    def mark_spam(self, folder: str, uid: str) -> None:
        row = self.conn.execute("SELECT sender FROM emails WHERE account_id=? AND folder=? AND uid=?", (self.account_id, folder, str(uid))).fetchone()
        self.conn.execute("UPDATE emails SET is_spam=1, mailmind_unread=0, spam_override=0, spam_score=100, spam_reason='Reported as spam by user', security_category='Spam', security_confidence=100, security_source='User', security_reviewed=1 WHERE account_id=? AND folder=? AND uid=?", (self.account_id, folder, str(uid)))
        if row: self._record_sender_feedback(row["sender"], spam=True)
        self.conn.commit()

    @staticmethod
    def _sender_keys(sender: str) -> list[str]:
        from email.utils import parseaddr
        address = parseaddr(str(sender or ""))[1].casefold()
        domain = address.rpartition("@")[2]
        return [key for key in (address, "@" + domain if domain else "") if key]

    def _record_sender_feedback(self, sender: str, *, spam: bool) -> None:
        spam_increment, ham_increment = (1, 0) if spam else (0, 1)
        for key in self._sender_keys(sender):
            self.conn.execute("""INSERT INTO sender_reputation(account_id, sender_key, spam_reports, ham_reports, updated_at)
                VALUES (?, ?, ?, ?, datetime('now')) ON CONFLICT(account_id, sender_key) DO UPDATE SET
                spam_reports=spam_reports+excluded.spam_reports, ham_reports=ham_reports+excluded.ham_reports, updated_at=datetime('now')""",
                (self.account_id, key, spam_increment, ham_increment))

    def _learned_sender_score(self, sender: str) -> int:
        return self._learned_sender_scores([sender]).get(str(sender or ""), 0)

    def _learned_sender_scores(self, senders: Iterable[str]) -> Dict[str, int]:
        # Resolve sender/domain feedback in batches instead of one query per email.
        original_senders = list(dict.fromkeys(str(sender or "") for sender in senders))
        sender_keys = {sender: self._sender_keys(sender) for sender in original_senders}
        all_keys = sorted({key for keys in sender_keys.values() for key in keys})
        reputation = {}

        for start in range(0, len(all_keys), 400):
            batch = all_keys[start:start + 400]
            if not batch:
                continue
            placeholders = ",".join("?" for _ in batch)
            rows = self.conn.execute(
                f"SELECT sender_key, spam_reports, ham_reports "
                f"FROM sender_reputation WHERE account_id=? "
                f"AND sender_key IN ({placeholders})",
                [self.account_id, *batch],
            ).fetchall()
            for row in rows:
                reputation[str(row["sender_key"])] = (
                    int(row["spam_reports"] or 0),
                    int(row["ham_reports"] or 0),
                )

        scores = {}
        for sender, keys in sender_keys.items():
            spam = sum(reputation.get(key, (0, 0))[0] for key in keys)
            ham = sum(reputation.get(key, (0, 0))[1] for key in keys)
            scores[sender] = (
                min(60, spam * 30) if spam > ham else (-35 if ham > spam else 0)
            )
        return scores

    def _reclassify_cached_spam_if_needed(self) -> None:
        meta_key = f"security_engine_v8_account_{self.account_id}"
        if self.conn.execute(
            "SELECT 1 FROM app_meta WHERE key=? AND value='complete'",
            (meta_key,),
        ).fetchone():
            return

        # Reclassify only previously flagged rows during migration. New and
        # refreshed mail receives the new classifier in save_page(), while a
        # 30k-message healthy Inbox is never rescanned just because the security
        # category schema changed.
        cursor = self.conn.execute(
            """
            SELECT uid, folder, subject, sender, recipient, snippet, body_text,
                   spam_override, provider_spam, is_spam, spam_score, spam_reason,
                   security_category, security_confidence, security_source
            FROM emails
            WHERE account_id=? AND remote_available=1 AND spam_override=0
              AND LOWER(COALESCE(security_source, '')) <> 'user'
              AND (is_spam=1 OR provider_spam=1)
            """,
            (self.account_id,),
        )
        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break

            sender_scores = self._learned_sender_scores(
                row["sender"] for row in rows
            )
            updates = []
            for row in rows:
                item = dict(row)
                item["from"] = item.pop("sender", "")
                item["to"] = item.pop("recipient", "")
                item = normalize_security_input(
                    item, provider_spam=bool(item.get("provider_spam"))
                )
                item["learned_spam_score"] = sender_scores.get(
                    str(item["from"] or ""), 0
                )
                verdict = detect_spam(item)
                is_spam = 1 if verdict["is_spam"] else 0
                spam_score = int(verdict["score"] or 0)
                spam_reason = str(verdict["reason"] or "")
                security_category = str(verdict.get("category") or "Suspicious")
                security_confidence = int(verdict.get("confidence") or 0)
                security_source = str(verdict.get("source") or "Security signals")
                if (
                    int(row["is_spam"] or 0) == is_spam
                    and int(row["spam_score"] or 0) == spam_score
                    and str(row["spam_reason"] or "") == spam_reason
                    and str(row["security_category"] or "") == security_category
                    and int(row["security_confidence"] or 0) == security_confidence
                    and str(row["security_source"] or "") == security_source
                ):
                    continue
                updates.append(
                    (
                        is_spam, spam_score, spam_reason, security_category,
                        security_confidence, security_source, self.account_id,
                        row["folder"], row["uid"],
                    )
                )
            if updates:
                self.conn.executemany(
                    "UPDATE emails SET is_spam=?, spam_score=?, spam_reason=?, "
                    "security_category=?, security_confidence=?, security_source=? "
                    "WHERE account_id=? AND folder=? AND uid=?",
                    updates,
                )

        self.conn.execute(
            "INSERT INTO app_meta(key, value) VALUES (?, 'complete') "
            "ON CONFLICT(key) DO UPDATE SET value='complete'",
            (meta_key,),
        )
        self.conn.commit()

    def initialize_mailmind_unread_state(
        self, folder: str, legacy_uids: Iterable[str]
    ) -> bool:
        """Seed durable MailMind Unread once when upgrading from session-only state.

        Existing installs historically kept Inbox Unread only in Streamlit
        Session State. The first run after this migration may still have that
        legacy set (or its signed-session snapshot), so persist it exactly once.
        Afterward SQLite is authoritative and stale browser/session snapshots can
        never resurrect a message that the user already viewed.
        """
        normalized_folder = str(folder or "INBOX")
        meta_key = (
            f"mailmind_unread_state_v1_account_{self.account_id}_"
            f"{normalized_folder.casefold()}"
        )
        ready = self.conn.execute(
            "SELECT 1 FROM app_meta WHERE key=? AND value='complete'",
            (meta_key,),
        ).fetchone()
        if ready:
            return False

        self.mark_mailmind_unread(normalized_folder, legacy_uids)
        self.conn.execute(
            "INSERT INTO app_meta(key, value) VALUES (?, 'complete') "
            "ON CONFLICT(key) DO UPDATE SET value='complete'",
            (meta_key,),
        )
        self.conn.commit()
        return True

    def get_mailmind_unread_uids(self, folder: str = "INBOX") -> set[str]:
        """Return Inbox emails still unread inside MailMind.

        This is intentionally separate from the provider Seen/Unread flag so a
        browser refresh, Streamlit rerun, or app restart cannot consume MailMind
        attention state. Only a successful MailMind email view clears it.
        """
        rows = self.conn.execute(
            "SELECT uid FROM emails WHERE account_id=? AND folder=? "
            "AND remote_available=1 AND ui_visible=1 AND is_spam=0 "
            "AND COALESCE(mailmind_unread, 0)=1",
            (self.account_id, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows if str(row["uid"])}

    def mark_mailmind_unread(self, folder: str, uids: Iterable[str]) -> int:
        """Persist MailMind Inbox unread markers without changing provider state."""
        normalized = sorted({str(uid) for uid in (uids or []) if str(uid)})
        if not normalized:
            return 0
        changed = 0
        for start in range(0, len(normalized), 400):
            batch = normalized[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            before = self.conn.total_changes
            self.conn.execute(
                f"UPDATE emails SET mailmind_unread=1 WHERE account_id=? AND folder=? "
                f"AND remote_available=1 AND ui_visible=1 AND is_spam=0 "
                f"AND uid IN ({placeholders})",
                [self.account_id, folder, *batch],
            )
            changed += self.conn.total_changes - before
        self.conn.commit()
        return changed

    def mark_mailmind_read(self, folder: str, uids: Iterable[str]) -> int:
        """Clear MailMind unread markers after a successful view or routing change."""
        normalized = sorted({str(uid) for uid in (uids or []) if str(uid)})
        if not normalized:
            return 0
        changed = 0
        for start in range(0, len(normalized), 400):
            batch = normalized[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            before = self.conn.total_changes
            self.conn.execute(
                f"UPDATE emails SET mailmind_unread=0 WHERE account_id=? AND folder=? "
                f"AND uid IN ({placeholders})",
                [self.account_id, folder, *batch],
            )
            changed += self.conn.total_changes - before
        self.conn.commit()
        return changed

    def get_spam_count(self, folder: str = "INBOX") -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM emails WHERE account_id=? AND folder=? AND remote_available=1 AND ui_visible=1 AND is_spam=1", (self.account_id, folder)).fetchone()[0])

    def get_security_unreviewed_count(self, folder: str = "INBOX") -> int:
        # Count Security findings the user has not opened yet, whether found
        # during catch-up or while processing genuinely NEW mail. This is separate
        # from the provider/email read state.
        return int(self.conn.execute(
            "SELECT COUNT(*) FROM emails WHERE account_id=? AND folder=? "
            "AND remote_available=1 AND ui_visible=1 AND is_spam=1 AND COALESCE(security_reviewed, 1)=0",
            (self.account_id, folder),
        ).fetchone()[0])

    def get_security_unreviewed_uids(self, folder: str = "INBOX") -> set[str]:
        """Return the durable MailMind Detected/UI-review UID set."""
        rows = self.conn.execute(
            "SELECT uid FROM emails WHERE account_id=? AND folder=? "
            "AND remote_available=1 AND ui_visible=1 AND is_spam=1 "
            "AND COALESCE(security_reviewed, 1)=0",
            (self.account_id, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows if str(row["uid"])}

    def mark_security_unreviewed(self, folder: str, uids: Iterable[str]) -> int:
        # Mark newly discovered unsafe Security results for the Spam -> Detected UI.
        normalized = sorted({str(uid) for uid in (uids or []) if str(uid)})
        if not normalized:
            return 0
        changed = 0
        for start in range(0, len(normalized), 400):
            batch = normalized[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            before = self.conn.total_changes
            self.conn.execute(
                f"UPDATE emails SET security_reviewed=0 WHERE account_id=? AND folder=? "
                f"AND remote_available=1 AND is_spam=1 AND uid IN ({placeholders})",
                [self.account_id, folder, *batch],
            )
            changed += self.conn.total_changes - before
        self.conn.commit()
        return changed

    def mark_security_reviewed(self, folder: str, uid: str) -> bool:
        # Opening a Detected Spam/Security result consumes only the MailMind
        # security-review state; it never changes the email's read/unread flag.
        before = self.conn.total_changes
        self.conn.execute(
            "UPDATE emails SET security_reviewed=1 WHERE account_id=? AND folder=? AND uid=?",
            (self.account_id, folder, str(uid)),
        )
        self.conn.commit()
        return self.conn.total_changes > before

    def get_spam_category_counts(self, folder: str = "INBOX") -> Dict[str, int]:
        # Count the same complete Spam workspace used by the category filter.
        rows = self.conn.execute(
            """
            SELECT TRIM(COALESCE(security_category, '')) AS category, COUNT(*) AS count
            FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1 AND ui_visible=1 AND is_spam=1
            GROUP BY TRIM(COALESCE(security_category, ''))
            """,
            (self.account_id, folder),
        ).fetchall()
        counts = {str(row["category"] or ""): int(row["count"] or 0) for row in rows}
        counts["all"] = sum(counts.values())
        return counts

    def get_pending_security_classifications(
        self, folder: str = "INBOX", limit: int = 250
    ) -> List[Dict]:
        # Blocking login Security is only needed for header-only messages that
        # are STILL eligible to appear in the Inbox but already carry a local
        # risk signal. Rows already quarantined by MailMind (is_spam=1) are safe
        # to refine through the normal background catch-up after the workspace
        # opens; hydrating hundreds of already-quarantined Spam/Junk rows here
        # only delays login without improving Inbox safety.
        #
        # Once a message reaches full input version 2 it is durable and is never
        # returned here. The background catch-up query remains broader and still
        # processes every remaining header-only row, including quarantined mail.
        rows = self.conn.execute(
            """
            SELECT * FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1
              AND LOWER(COALESCE(security_source, '')) NOT IN ('hybrid ai', 'user')
              AND COALESCE(security_input_version, 0) < 2
              AND COALESCE(is_spam, 0)=0
              AND COALESCE(spam_score, 0) > 0
            ORDER BY date DESC, uid DESC
            LIMIT ?
            """,
            (self.account_id, folder, max(1, int(limit or 250))),
        ).fetchall()
        return [self._row_to_email(row) for row in rows]

    def count_security_catchup_pending(self, folder: str = "INBOX") -> int:
        # Persistent source of truth for old/existing messages that have only
        # received the one-time header/snippet pass. No separate progress row is
        # required: a full-message Security check promotes the email to input
        # version 2, so logout/login naturally resumes only the remainder.
        row = self.conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1
              AND COALESCE(security_input_version, 0) < 2
            """,
            (self.account_id, folder),
        ).fetchone()
        return int(row["count"] or 0) if row else 0

    def get_security_catchup_candidates(
        self, folder: str = "INBOX", limit: int = 3
    ) -> List[Dict]:
        # Catch-up is deliberately lifecycle-neutral. NEW/RESTORED/MOVED are
        # handled by mailbox orchestration; this query only asks which currently
        # available rows still lack complete full-message security inputs.
        rows = self.conn.execute(
            """
            SELECT * FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1
              AND COALESCE(security_input_version, 0) < 2
            ORDER BY date DESC, uid DESC
            LIMIT ?
            """,
            (self.account_id, folder, max(1, int(limit or 3))),
        ).fetchall()
        return [self._row_to_email(row) for row in rows]

    def copy_security_state(self, folder: str, old_uid: str, new_uid: str) -> bool:
        # Gmail/IMAP can change a folder-scoped UID when the SAME physical email
        # moves Inbox <-> Spam/Junk or is restored. Reuse the old security/body
        # cache instead of classifying the unchanged message again. The new
        # provider location remains authoritative and is intentionally NOT copied.
        old_uid = str(old_uid or "").strip()
        new_uid = str(new_uid or "").strip()
        if not old_uid or not new_uid or old_uid == new_uid:
            return False

        old = self.conn.execute(
            """
            SELECT reply_to, spam_evidence, security_links_json, security_input_version,
                   body_text, body_html, is_full, has_attachment, spam_override,
                   is_spam, spam_score, spam_reason, security_category,
                   security_confidence, security_source, security_reviewed
            FROM emails
            WHERE account_id=? AND folder=? AND uid=?
            """,
            (self.account_id, folder, old_uid),
        ).fetchone()
        current = self.conn.execute(
            """
            SELECT provider_spam FROM emails
            WHERE account_id=? AND folder=? AND uid=?
            """,
            (self.account_id, folder, new_uid),
        ).fetchone()
        if old is None or current is None:
            return False

        category = str(old["security_category"] or "Unclassified")
        provider_spam = int(current["provider_spam"] or 0)
        overridden = int(old["spam_override"] or 0)
        evidence_parts = [
            part.strip()
            for part in str(old["spam_evidence"] or "").split("|")
            if part.strip()
            and "provider-folder=spam" not in part.casefold()
            and "provider-folder=junk" not in part.casefold()
        ]
        if provider_spam:
            evidence_parts.insert(0, "X-MailMind-Provider-Folder=spam")
        copied_spam_evidence = " | ".join(evidence_parts)
        copied_reason_parts = [
            part.strip()
            for part in str(old["spam_reason"] or "").split(";")
            if part.strip()
        ]
        if not provider_spam:
            copied_reason_parts = [
                part for part in copied_reason_parts
                if part.casefold() != "the email provider placed it in spam/junk"
            ]
        copied_spam_reason = "; ".join(dict.fromkeys(copied_reason_parts))

        if provider_spam:
            new_is_spam = 1
        elif not _category_routes_to_security_workspace(category):
            # Safe/Misclassified and Promotional are the only categories allowed
            # back into MailMind Inbox when the provider location is Inbox.
            new_is_spam = 0
        else:
            # Never trust a stale old is_spam bit during a UID-changing restore or
            # folder move. The persisted Security category is the routing authority.
            new_is_spam = 1

        self.conn.execute(
            """
            UPDATE emails
            SET reply_to=?, spam_evidence=?, security_links_json=?,
                security_input_version=?, body_text=?, body_html=?, is_full=?,
                has_attachment=MAX(has_attachment, ?), spam_override=?,
                is_spam=?, spam_score=?, spam_reason=?, security_category=?,
                security_confidence=?, security_source=?, security_reviewed=?, synced_at=datetime('now')
            WHERE account_id=? AND folder=? AND uid=?
            """,
            (
                str(old["reply_to"] or ""),
                copied_spam_evidence,
                str(old["security_links_json"] or "[]"),
                int(old["security_input_version"] or 0),
                str(old["body_text"] or ""),
                str(old["body_html"] or ""),
                int(old["is_full"] or 0),
                int(old["has_attachment"] or 0),
                overridden,
                new_is_spam,
                int(old["spam_score"] or 0),
                copied_spam_reason,
                category,
                int(old["security_confidence"] or 0),
                str(old["security_source"] or ""),
                int(old["security_reviewed"] or 0),
                self.account_id, folder, new_uid,
            ),
        )

        # Reuse cached attachment metadata/data when the old row already had a
        # complete message. Viewing the moved/restored email therefore does not
        # force an unnecessary second full fetch just because its UID changed.
        if int(old["is_full"] or 0):
            self.conn.execute(
                "DELETE FROM attachments WHERE account_id=? AND folder=? AND uid=?",
                (self.account_id, folder, new_uid),
            )
            self.conn.execute(
                """
                INSERT INTO attachments (
                    account_id, folder, uid, filename, content_type, size, data
                )
                SELECT account_id, folder, ?, filename, content_type, size, data
                FROM attachments
                WHERE account_id=? AND folder=? AND uid=?
                """,
                (new_uid, self.account_id, folder, old_uid),
            )

        self.conn.commit()
        return True

    def exclude_spam_uids(self, folder: str, uids: Iterable[str]) -> set[str]:
        normalized = {str(uid) for uid in uids if str(uid)}
        spam = set()
        for start in range(0, len(normalized), 400):
            batch = sorted(normalized)[start:start + 400]
            if not batch: continue
            placeholders = ",".join("?" for _ in batch)
            spam.update(str(row["uid"]) for row in self.conn.execute(f"SELECT uid FROM emails WHERE account_id=? AND folder=? AND is_spam=1 AND uid IN ({placeholders})", [self.account_id, folder, *batch]).fetchall())
        return normalized.difference(spam)

    # Save the full body and attachments for one email.
    def save_full(self, folder: str, parsed_email: Dict):
        uid = str((parsed_email or {}).get("uid") or "")
        existing = self.conn.execute(
            "SELECT provider_spam FROM emails WHERE account_id=? AND folder=? AND uid=?",
            (self.account_id, folder, uid),
        ).fetchone()
        provider_spam = bool(existing["provider_spam"] or 0) if existing else False
        e = normalize_security_input(
            parsed_email, provider_spam=provider_spam, full_message=True
        )
        uid = str(e["uid"])
        self.conn.execute("""
            INSERT INTO emails (
                account_id, folder, uid, subject, sender, recipient, cc,
                reply_to, spam_evidence, security_links_json, security_input_version,
                date, date_display, snippet, body_text, body_html, is_full,
                has_attachment, remote_available, remote_unavailable_at,
                message_id, in_reply_to, reference_ids, conversation_id,
                gmail_thread_id, canonical_thread_id, synced_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, 1, ?, 1, NULL, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(account_id, folder, uid) DO UPDATE SET
                subject=excluded.subject,
                sender=excluded.sender,
                recipient=excluded.recipient,
                cc=excluded.cc,
                reply_to=excluded.reply_to,
                spam_evidence=excluded.spam_evidence,
                security_links_json=excluded.security_links_json,
                security_input_version=2,
                date=excluded.date,
                date_display=excluded.date_display,
                snippet=excluded.snippet,
                body_text=excluded.body_text,
                body_html=excluded.body_html,
                is_full=1,
                has_attachment=excluded.has_attachment,
                message_id=CASE WHEN excluded.message_id <> '' THEN excluded.message_id ELSE emails.message_id END,
                in_reply_to=CASE WHEN excluded.in_reply_to <> '' THEN excluded.in_reply_to ELSE emails.in_reply_to END,
                reference_ids=CASE WHEN excluded.reference_ids <> '' THEN excluded.reference_ids ELSE emails.reference_ids END,
                gmail_thread_id=CASE WHEN excluded.gmail_thread_id <> '' THEN excluded.gmail_thread_id ELSE emails.gmail_thread_id END,
                conversation_id=CASE WHEN excluded.conversation_id <> '' THEN excluded.conversation_id ELSE emails.conversation_id END,
                canonical_thread_id=CASE
                    WHEN emails.canonical_thread_id <> '' THEN emails.canonical_thread_id
                    ELSE excluded.canonical_thread_id
                END,
                remote_available=1,
                remote_unavailable_at=NULL,
                synced_at=excluded.synced_at
        """, (
            self.account_id,
            folder,
            uid,
            e.get("subject", ""),
            e.get("from", ""),
            e.get("to", ""),
            e.get("cc", ""),
            e.get("reply_to", ""),
            e.get("spam_evidence", ""),
            serialize_security_links(e.get("links") or []),
            e.get("date", ""),
            e.get("date_display", ""),
            e.get("snippet", ""),
            e.get("body_text", ""),
            e.get("body_html", ""),
            1 if e.get("attachments") or e.get("has_attachment") else 0,
            e.get("message_id", ""),
            e.get("in_reply_to", ""),
            e.get("references", ""),
            e.get("conversation_id", ""),
            e.get("gmail_thread_id", ""),
            canonical_thread_id(e),
        ))
        self.conn.commit()

        if e.get("attachments"):
            self.save_attachments(folder, uid, e["attachments"])

        self.classify_and_store_security(folder, e)

    # Replace the saved attachments for one email.
    def save_attachments(self, folder: str, uid: str, attachments: List[Dict]):
        uid = str(uid)
        self.conn.execute(
            """
            DELETE FROM attachments
            WHERE account_id=? AND folder=? AND uid=?
            """,
            (self.account_id, folder, uid),
        )
        rows = [
            (
                self.account_id,
                folder,
                uid,
                a.get("filename", ""),
                a.get("content_type", ""),
                a.get("size", 0),
                a.get("data"),
            )
            for a in attachments
        ]
        if rows:
            self.conn.executemany("""
                INSERT INTO attachments (
                    account_id, folder, uid, filename, content_type, size, data
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, rows)
        self.conn.commit()

    # Record that the first full sync has started.
    def mark_sync_started(self, folder: str = "INBOX"):
        self.conn.execute("""
            INSERT INTO sync_state (
                account_id, folder, full_sync_complete, remote_total,
                synced_count, last_error, updated_at
            ) VALUES (?, ?, 0, 0, 0, NULL, datetime('now'))
            ON CONFLICT(account_id, folder) DO UPDATE SET
                full_sync_complete=0,
                synced_count=0,
                last_error=NULL,
                updated_at=datetime('now')
        """, (self.account_id, folder))
        self.conn.commit()

    # Record a completed full mailbox sync.
    def mark_sync_complete(self, folder: str, remote_total: int, synced_count: int):
        self.conn.execute("""
            INSERT INTO sync_state (
                account_id, folder, full_sync_complete, remote_total,
                synced_count, last_error, updated_at
            ) VALUES (?, ?, 1, ?, ?, NULL, datetime('now'))
            ON CONFLICT(account_id, folder) DO UPDATE SET
                full_sync_complete=1,
                remote_total=excluded.remote_total,
                synced_count=excluded.synced_count,
                last_error=NULL,
                updated_at=datetime('now')
        """, (self.account_id, folder, remote_total or 0, synced_count or 0))
        if str(folder).upper() == "INBOX":
            self.conn.execute(
                """
                INSERT INTO app_meta (key, value) VALUES (?, 'complete')
                ON CONFLICT(key) DO UPDATE SET value='complete'
                """,
                (self._attachment_scan_meta_key(self.account_id),),
            )
        self.conn.commit()

    # Record a failed full mailbox sync.
    def mark_sync_failed(self, folder: str, error: str, synced_count: int = 0):
        self.conn.execute("""
            INSERT INTO sync_state (
                account_id, folder, full_sync_complete, synced_count,
                last_error, updated_at
            ) VALUES (?, ?, 0, ?, ?, datetime('now'))
            ON CONFLICT(account_id, folder) DO UPDATE SET
                full_sync_complete=0,
                synced_count=excluded.synced_count,
                last_error=excluded.last_error,
                updated_at=datetime('now')
        """, (self.account_id, folder, synced_count, error))
        self.conn.commit()

    # Update the latest remote mailbox count.
    def update_remote_total(self, folder: str, remote_total: int):
        self.conn.execute("""
            INSERT INTO sync_state (account_id, folder, remote_total, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(account_id, folder) DO UPDATE SET
                remote_total=excluded.remote_total,
                updated_at=datetime('now')
        """, (self.account_id, folder, remote_total or 0))
        self.conn.commit()

    # Read operations.

    def _get_spam_projection_page(
        self,
        where_sql: str,
        params: List[object],
        *,
        limit: int,
        offset: int,
        arrange_by: str,
        sort_order: str,
    ) -> Dict:
        """Return one independently reviewable Spam card per unsafe email.

        The regular Inbox SQL remains unchanged and continues to collapse real
        reply threads. Spam is different: security verdicts belong to individual
        messages, so linked unsafe replies must never be merged into one card.
        Active search/category/detected filters are applied first, then pagination
        operates on the resulting physical unsafe messages.
        """
        rows = self.conn.execute(
            f"""
            SELECT
                e.uid, e.subject, e.sender, e.recipient, e.date,
                e.date_display, e.snippet, e.is_full, e.message_id,
                e.in_reply_to, e.reference_ids, e.gmail_thread_id,
                e.conversation_id, e.canonical_thread_id,
                e.is_spam, e.spam_score, e.spam_reason, e.provider_spam,
                e.security_category, e.security_confidence, e.security_source,
                e.security_reviewed,
                CASE
                    WHEN COALESCE(e.has_attachment, 0)=1 OR EXISTS (
                        SELECT 1 FROM attachments a
                        WHERE a.account_id=e.account_id
                          AND a.folder=e.folder
                          AND a.uid=e.uid
                    ) THEN 1 ELSE 0
                END AS has_attachment
            FROM emails e
            WHERE {where_sql}
            """,
            params,
        ).fetchall()

        messages = _spam_message_rows([dict(row) for row in rows])

        # Match the established list ordering, but sort physical messages rather
        # than thread representatives. A reply never replaces an earlier unsafe
        # card simply because both belong to the same conversation.
        reverse_date = str(sort_order or "newest").casefold() != "oldest"
        messages.sort(
            key=lambda item: (
                _email_sort_timestamp(item.get("date")),
                str(item.get("uid") or ""),
            ),
            reverse=reverse_date,
        )
        if str(arrange_by or "date").casefold() == "from":
            messages.sort(
                key=lambda item: str(item.get("sender") or "").casefold()
            )

        total = len(messages)
        page_rows = messages[offset:offset + limit]
        return {
            "emails": [self._row_to_email(row) for row in page_rows],
            "total": total,
            "has_more": offset + len(page_rows) < total,
        }

    # Load one saved Inbox page for this account using the active view options.
    def get_page(
        self,
        folder: str,
        limit: int = 50,
        offset: int = 0,
        filter_key: str = "all",
        arrange_by: str = "date",
        sort_order: str = "newest",
        unread_uids=None,
        query: str = "",
        security_category: str = "all",
        security_detected_only: bool = False,
    ) -> Dict:
        filter_key = str(filter_key or "all").strip().casefold()
        arrange_by = str(arrange_by or "date").strip().casefold()
        sort_order = str(sort_order or "newest").strip().casefold()
        query = str(query or "").strip()
        security_category = str(security_category or "all").strip()
        conditions = ["e.account_id=?", "e.folder=?", "e.remote_available=1", "e.ui_visible=1"]
        params: List[object] = [self.account_id, folder]

        if filter_key == "spam":
            conditions.append("e.is_spam=1")
            spam_filter = security_category.casefold()
            # Backward compatibility: old sessions encoded Detected as a fake
            # category. New state keeps it independent so Detected + Category
            # can be applied together.
            if spam_filter == "newly_detected":
                security_detected_only = True
                spam_filter = "all"
            if security_detected_only:
                conditions.append("COALESCE(e.security_reviewed, 1)=0")
            if spam_filter != "all":
                conditions.append("LOWER(TRIM(COALESCE(e.security_category, ''))) = LOWER(?)")
                params.append(security_category)
        else:
            conditions.append("e.is_spam=0")

        unread_filter_active = filter_key in {"unread", "unread_with_attachment"}
        attachment_filter_active = filter_key in {"with_attachment", "unread_with_attachment"}
        if unread_filter_active:
            normalized_uids = sorted({str(uid) for uid in (unread_uids or set()) if str(uid)})
            if not normalized_uids:
                return {"emails": [], "total": 0, "has_more": False}
            placeholders = ",".join("?" for _ in normalized_uids)
            conditions.append(f"e.uid IN ({placeholders})")
            params.extend(normalized_uids)
        if attachment_filter_active:
            conditions.append("""
                (
                    COALESCE(e.has_attachment, 0)=1 OR
                    EXISTS (
                        SELECT 1 FROM attachments a
                        WHERE a.account_id=e.account_id
                          AND a.folder=e.folder
                          AND a.uid=e.uid
                    )
                )
            """)

        # Apply search conditions to the complete filtered inbox before LIMIT
        # and OFFSET. This guarantees that pagination is based on every matching
        # saved email, not just the ten rows currently visible in the UI.
        if query:
            field_filters, general_query = self._parse_search_query(query)
            if not field_filters and not _query_units(general_query):
                return {"emails": [], "total": 0, "has_more": False}

            field_map = {
                "from": "e.sender",
                "to": "e.recipient",
                "subject": "e.subject",
            }
            for field, value in field_filters:
                if _query_units(value):
                    conditions.append(
                        f"SEARCH_MATCH(COALESCE({field_map[field]}, ''), ?) = 1"
                    )
                    params.append(value)

            if general_query and _query_units(general_query):
                conditions.append("""
                    SEARCH_MATCH_EMAIL(
                        COALESCE(e.subject, ''),
                        COALESCE(e.sender, ''),
                        COALESCE(e.recipient, ''),
                        COALESCE(e.snippet, ''),
                        COALESCE(e.body_text, ''),
                        ?
                    ) = 1
                """)
                params.append(general_query)

        where_sql = " AND ".join(conditions)
        if filter_key == "spam":
            return self._get_spam_projection_page(
                where_sql,
                params,
                limit=limit,
                offset=offset,
                arrange_by=arrange_by,
                sort_order=sort_order,
            )

        thread_key_sql = (
            "COALESCE(NULLIF(e.canonical_thread_id, ''), "
            "CASE "
            "WHEN COALESCE(e.gmail_thread_id, '') <> '' "
            "THEN 'gmail:' || LOWER(TRIM(e.gmail_thread_id)) "
            "WHEN COALESCE(e.conversation_id, '') <> '' "
            "THEN 'outlook:' || LOWER(TRIM(e.conversation_id)) "
            "ELSE 'local:' || e.uid END)"
        )
        total = self.conn.execute(
            f"SELECT COUNT(DISTINCT {thread_key_sql}) "
            f"FROM emails e WHERE {where_sql}",
            params,
        ).fetchone()[0]

        date_direction = "ASC" if sort_order == "oldest" else "DESC"
        # One canonical timestamp drives both thread promotion and Inbox sorting.
        # This is the same timezone-aware parser used by MailMind's display-time
        # layer, so a new reply always promotes its thread according to the actual
        # received instant regardless of the sender/provider UTC offset.
        if arrange_by == "from":
            order_sql = (
                "LOWER(COALESCE(e.sender, '')) ASC, "
                f"MAILMIND_TS(e.date) {date_direction}, "
                f"e.uid {date_direction}"
            )
        else:
            order_sql = (
                f"MAILMIND_TS(e.date) {date_direction}, "
                f"e.uid {date_direction}"
            )

        rows = self.conn.execute(f"""
            WITH filtered AS (
                SELECT e.*, {thread_key_sql} AS thread_key
                FROM emails e
                WHERE {where_sql}
            ), ranked AS (
                SELECT filtered.*,
                       -- Card badges are scoped to the current MailMind view.
                       -- A provider-wide conversation count can include a reply
                       -- that now lives in Spam/Junk (or another mailbox area),
                       -- which would leave a misleading thread indicator behind
                       -- on the Inbox card. The provider thread identity/count is
                       -- still persisted for conversation reconstruction; the list
                       -- badge reflects only rows visible in this filtered view.
                       COUNT(*) OVER (PARTITION BY thread_key) AS thread_count,
                       ROW_NUMBER() OVER (
                           PARTITION BY thread_key
                           ORDER BY MAILMIND_TS(date) DESC, uid DESC
                       ) AS thread_rank
                FROM filtered
            )
            SELECT
                e.uid, e.subject, e.sender, e.recipient, e.date,
                e.date_display, e.snippet, e.is_full, e.message_id,
                e.in_reply_to, e.reference_ids, e.gmail_thread_id,
                e.conversation_id, e.canonical_thread_id, e.thread_count,
                e.is_spam, e.spam_score, e.spam_reason, e.provider_spam,
                e.security_category, e.security_confidence, e.security_source,
                e.security_reviewed,
                CASE
                    WHEN COALESCE(e.has_attachment, 0)=1 OR EXISTS (
                        SELECT 1 FROM attachments a
                        WHERE a.account_id=e.account_id
                          AND a.folder=e.folder
                          AND a.uid=e.uid
                    ) THEN 1 ELSE 0
                END AS has_attachment
            FROM ranked e
            WHERE e.thread_rank=1
            ORDER BY {order_sql}
            LIMIT ? OFFSET ?
        """, [*params, limit, offset]).fetchall()
        return {
            "emails": [self._row_to_email(r) for r in rows],
            "total": total,
            "has_more": offset + len(rows) < total,
        }

    # Split field filters from the search text.
    def _parse_search_query(self, query: str) -> Tuple[List[Tuple[str, str]], str]:
        filters: List[Tuple[str, str]] = []

        # Collect one field filter from the query.
        def capture(match):
            field = match.group(1).lower()
            value = match.group(2) if match.group(2) is not None else match.group(3)
            if value and value.strip():
                filters.append((field, value.strip()))
            return " "

        remaining = _FILTER_RE.sub(capture, query or "")
        return filters, " ".join(remaining.split())

    # Search saved emails for this account.
    def search_emails(self, folder: str, query: str, limit: int = 100) -> Dict:
        query = (query or "").strip()
        if not query:
            return {"emails": [], "total": 0}

        filters, general_query = self._parse_search_query(query)
        if not filters and not _query_units(general_query):
            return {"emails": [], "total": 0}

        conditions = ["e.account_id=?", "e.folder=?", "e.remote_available=1", "e.ui_visible=1"]
        params: List[object] = [self.account_id, folder]

        field_map = {
            "from": "e.sender",
            "to": "e.recipient",
            "subject": "e.subject",
        }
        for field, value in filters:
            if _query_units(value):
                conditions.append(
                    f"SEARCH_MATCH(COALESCE({field_map[field]}, ''), ?) = 1"
                )
                params.append(value)

        if general_query and _query_units(general_query):
            conditions.append("""
                SEARCH_MATCH_EMAIL(
                    COALESCE(e.subject, ''),
                    COALESCE(e.sender, ''),
                    COALESCE(e.recipient, ''),
                    COALESCE(e.snippet, ''),
                    COALESCE(e.body_text, ''),
                    ?
                ) = 1
            """)
            params.append(general_query)

        where_sql = " AND ".join(conditions)
        thread_key_sql = (
            "COALESCE(NULLIF(e.canonical_thread_id, ''), "
            "CASE "
            "WHEN COALESCE(e.gmail_thread_id, '') <> '' "
            "THEN 'gmail:' || LOWER(TRIM(e.gmail_thread_id)) "
            "WHEN COALESCE(e.conversation_id, '') <> '' "
            "THEN 'outlook:' || LOWER(TRIM(e.conversation_id)) "
            "ELSE 'local:' || e.uid END)"
        )
        total = self.conn.execute(
            f"SELECT COUNT(DISTINCT {thread_key_sql}) "
            f"FROM emails e WHERE {where_sql}",
            params,
        ).fetchone()[0]
        rows = self.conn.execute(f"""
            WITH filtered AS (
                SELECT e.*, {thread_key_sql} AS thread_key
                FROM emails e
                WHERE {where_sql}
            ), ranked AS (
                SELECT filtered.*,
                       -- Card badges are scoped to the current MailMind view.
                       -- A provider-wide conversation count can include a reply
                       -- that now lives in Spam/Junk (or another mailbox area),
                       -- which would leave a misleading thread indicator behind
                       -- on the Inbox card. The provider thread identity/count is
                       -- still persisted for conversation reconstruction; the list
                       -- badge reflects only rows visible in this filtered view.
                       COUNT(*) OVER (PARTITION BY thread_key) AS thread_count,
                       ROW_NUMBER() OVER (
                           PARTITION BY thread_key
                           ORDER BY MAILMIND_TS(date) DESC, uid DESC
                       ) AS thread_rank
                FROM filtered
            )
            SELECT
                e.uid, e.subject, e.sender, e.recipient, e.date,
                e.date_display, e.snippet, e.is_full, e.message_id,
                e.in_reply_to, e.reference_ids, e.gmail_thread_id,
                e.conversation_id, e.canonical_thread_id, e.thread_count,
                e.is_spam, e.spam_score, e.spam_reason, e.provider_spam,
                e.security_category, e.security_confidence, e.security_source,
                e.security_reviewed,
                CASE
                    WHEN COALESCE(e.has_attachment, 0)=1 OR EXISTS (
                        SELECT 1 FROM attachments a
                        WHERE a.account_id=e.account_id
                          AND a.folder=e.folder
                          AND a.uid=e.uid
                    ) THEN 1 ELSE 0
                END AS has_attachment
            FROM ranked e
            WHERE e.thread_rank=1
            ORDER BY MAILMIND_TS(e.date) DESC, e.uid DESC
            LIMIT ?
        """, [*params, limit]).fetchall()

        return {
            "emails": [self._row_to_email(r) for r in rows],
            "total": total,
        }

    # Load one saved email by folder and UID.
    def get_email(
        self, folder: str, uid: str, include_unavailable: bool = False
    ) -> Optional[Dict]:
        availability_sql = "" if include_unavailable else " AND remote_available=1"
        row = self.conn.execute(
            f"""
            SELECT * FROM emails
            WHERE account_id=? AND folder=? AND uid=?{availability_sql}
            """,
            (self.account_id, folder, str(uid)),
        ).fetchone()
        return self._row_to_email(row) if row else None

    def get_thread_members(self, folder: str, thread_id: str) -> List[Dict]:
        # Return one indexed thread without scanning the whole mailbox.
        #
        # Older caches may not yet have ``canonical_thread_id`` persisted. For
        # native Gmail/Outlook threads, match their already-indexed provider ID
        # directly so login never needs a mailbox-wide backfill first.
        thread_id = str(thread_id or "").strip()
        if not thread_id:
            return []

        conditions = ["canonical_thread_id=?"]
        params: List[object] = [self.account_id, folder, thread_id]
        folded = thread_id.casefold()
        if folded.startswith("gmail:"):
            provider_id = thread_id.split(":", 1)[1].strip()
            conditions.append("LOWER(TRIM(COALESCE(gmail_thread_id, '')))=?")
            params.append(provider_id.casefold())
        elif folded.startswith("outlook:"):
            provider_id = thread_id.split(":", 1)[1].strip()
            conditions.append("LOWER(TRIM(COALESCE(conversation_id, '')))=?")
            params.append(provider_id.casefold())

        where_thread = " OR ".join(f"({condition})" for condition in conditions)
        rows = self.conn.execute(
            f"""
            SELECT uid, subject, sender, recipient, date, date_display, snippet,
                   is_full, message_id, in_reply_to, reference_ids,
                   gmail_thread_id, conversation_id, canonical_thread_id,
                   is_spam, provider_spam, security_category, security_input_version,
                   remote_available
            FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1 AND ui_visible=1
              AND ({where_thread})
            ORDER BY date ASC, uid ASC
            """,
            params,
        ).fetchall()
        return [self._row_to_email(row) for row in rows]

    def get_thread_candidates(self, folder: str = "INBOX") -> List[Dict]:
        # Return lightweight metadata used to reconstruct reply chains.
        rows = self.conn.execute(
            """
            SELECT uid, subject, sender, recipient, date, date_display, snippet,
                   is_full, message_id, in_reply_to, reference_ids,
                   gmail_thread_id, conversation_id, canonical_thread_id,
                   is_spam, provider_spam, security_category,
                   security_input_version, security_reviewed, remote_available
            FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1 AND ui_visible=1
            ORDER BY date ASC, uid ASC
            """,
            (self.account_id, folder),
        ).fetchall()
        return [self._row_to_email(row) for row in rows]

    def get_active_uids(self, folder: str = "INBOX") -> Set[str]:
        # Return locally visible stable UIDs for one folder.
        rows = self.conn.execute(
            """
            SELECT uid FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1
            """,
            (self.account_id, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows}

    def get_provider_location_counts(self, folder: str = "INBOX") -> Dict[str, int]:
        # Return the locally persisted active Inbox vs Spam/Junk counts.
        # The mailbox monitor compares these counts with the provider's cheap
        # per-folder count signature so an external move can be detected even
        # when the combined Inbox+Spam total does not change.
        row = self.conn.execute(
            """
            SELECT
                SUM(CASE WHEN provider_spam=0 THEN 1 ELSE 0 END) AS inbox_count,
                SUM(CASE WHEN provider_spam=1 THEN 1 ELSE 0 END) AS spam_count
            FROM emails
            WHERE account_id=? AND folder=? AND remote_available=1
            """,
            (self.account_id, folder),
        ).fetchone()
        return {
            "inbox": int((row["inbox_count"] if row is not None else 0) or 0),
            "spam": int((row["spam_count"] if row is not None else 0) or 0),
        }

    def get_unavailable_uids(self, folder: str = "INBOX") -> Set[str]:
        # Return cached UIDs that were previously confirmed absent remotely.
        rows = self.conn.execute(
            """
            SELECT uid FROM emails
            WHERE account_id=? AND folder=? AND remote_available=0
            """,
            (self.account_id, folder),
        ).fetchall()
        return {str(row["uid"]) for row in rows if str(row["uid"])}

    def mark_remote_unavailable(
        self, folder: str, uids: Iterable[str]
    ) -> List[str]:
        # Hide cached emails confirmed absent from the remote folder.
        normalized = sorted({str(uid) for uid in uids if str(uid)})
        if not normalized:
            return []

        changed: List[str] = []
        for start in range(0, len(normalized), 400):
            batch = normalized[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            rows = self.conn.execute(
                f"""
                SELECT uid FROM emails
                WHERE account_id=? AND folder=? AND remote_available=1
                  AND uid IN ({placeholders})
                """,
                [self.account_id, folder, *batch],
            ).fetchall()
            changed.extend(str(row["uid"]) for row in rows)
            self.conn.execute(
                f"""
                UPDATE emails
                SET remote_available=0,
                    mailmind_unread=0,
                    remote_unavailable_at=datetime('now')
                WHERE account_id=? AND folder=? AND uid IN ({placeholders})
                """,
                [self.account_id, folder, *batch],
            )
        self.conn.commit()
        return changed

    def mark_remote_available(self, folder: str, uids: Iterable[str]) -> int:
        # Restore cached emails whose stable UIDs reappear remotely.
        normalized = sorted({str(uid) for uid in uids if str(uid)})
        if not normalized:
            return 0

        changed = 0
        for start in range(0, len(normalized), 400):
            batch = normalized[start:start + 400]
            placeholders = ",".join("?" for _ in batch)
            cursor = self.conn.execute(
                f"""
                UPDATE emails
                SET remote_available=1,
                    remote_unavailable_at=NULL
                WHERE account_id=? AND folder=?
                  AND remote_available=0
                  AND uid IN ({placeholders})
                """,
                [self.account_id, folder, *batch],
            )
            changed += cursor.rowcount
        self.conn.commit()
        return changed

    def reconcile_remote_uids(
        self, folder: str, remote_uids: Iterable[str]
    ) -> List[str]:
        # Persist availability by comparing cached and remote stable UIDs.
        remote = {str(uid) for uid in remote_uids if str(uid)}
        rows = self.conn.execute(
            """
            SELECT uid, remote_available FROM emails
            WHERE account_id=? AND folder=?
            """,
            (self.account_id, folder),
        ).fetchall()
        active = {
            str(row["uid"])
            for row in rows
            if int(row["remote_available"] or 0) == 1
        }
        inactive = {str(row["uid"]) for row in rows}.difference(active)
        changed_missing = self.mark_remote_unavailable(
            folder, active.difference(remote)
        )
        self.mark_remote_available(folder, inactive.intersection(remote))
        return changed_missing

    def update_provider_locations(
        self, folder: str, location_by_uid: Dict[str, str]
    ) -> Dict[str, Set[str]]:
        # Refresh the provider Inbox/Junk location without changing MailMind's
        # security verdict. This is especially important for Outlook immutable
        # IDs, where moving Junk -> Inbox keeps the same message UID.
        locations = {
            str(uid): str(location or "").strip().casefold()
            for uid, location in dict(location_by_uid or {}).items()
            if str(uid) and str(location or "").strip().casefold() in {"inbox", "spam", "junk"}
        }
        moved_to_inbox: Set[str] = set()
        moved_to_spam: Set[str] = set()
        if not locations:
            return {"moved_to_inbox": moved_to_inbox, "moved_to_spam": moved_to_spam}

        for start in range(0, len(locations), 400):
            batch_uids = list(locations)[start:start + 400]
            placeholders = ",".join("?" for _ in batch_uids)
            rows = self.conn.execute(
                f"""
                SELECT uid, provider_spam, security_category, spam_override, spam_evidence, spam_reason
                FROM emails
                WHERE account_id=? AND folder=? AND uid IN ({placeholders})
                """,
                [self.account_id, folder, *batch_uids],
            ).fetchall()
            for row in rows:
                uid = str(row["uid"])
                new_provider_spam = 1 if locations.get(uid) in {"spam", "junk"} else 0
                old_provider_spam = int(row["provider_spam"] or 0)
                if new_provider_spam == old_provider_spam:
                    continue

                category = str(row["security_category"] or "Unclassified").strip()
                spam_override = int(row["spam_override"] or 0)
                if new_provider_spam:
                    new_is_spam = 1
                    moved_to_spam.add(uid)
                else:
                    # Returning the physical message to the provider Inbox never
                    # overrides MailMind Security. Only Safe/Misclassified and
                    # Promotional may re-enter the MailMind Inbox workspace.
                    new_is_spam = 1 if _category_routes_to_security_workspace(category) else 0
                    moved_to_inbox.add(uid)

                evidence_parts = [
                    part.strip()
                    for part in str(row["spam_evidence"] or "").split("|")
                    if part.strip()
                    and "provider-folder=spam" not in part.casefold()
                    and "provider-folder=junk" not in part.casefold()
                ]
                if new_provider_spam:
                    evidence_parts.insert(0, "X-MailMind-Provider-Folder=spam")
                refreshed_evidence = " | ".join(dict.fromkeys(evidence_parts))

                reason_parts = [
                    part.strip()
                    for part in str(row["spam_reason"] or "").split(";")
                    if part.strip()
                ]
                if not new_provider_spam:
                    reason_parts = [
                        part for part in reason_parts
                        if part.casefold() != "the email provider placed it in spam/junk"
                    ]
                refreshed_reason = "; ".join(dict.fromkeys(reason_parts))

                self.conn.execute(
                    """
                    UPDATE emails
                    SET provider_spam=?, is_spam=?, spam_evidence=?, spam_reason=?,
                        synced_at=datetime('now')
                    WHERE account_id=? AND folder=? AND uid=?
                    """,
                    (
                        new_provider_spam, new_is_spam, refreshed_evidence, refreshed_reason,
                        self.account_id, folder, uid,
                    ),
                )

        self.conn.commit()
        return {"moved_to_inbox": moved_to_inbox, "moved_to_spam": moved_to_spam}

    # Load saved attachments for one email.
    def get_attachments(self, folder: str, uid: str) -> List[Dict]:
        rows = self.conn.execute("""
            SELECT filename, content_type, size, data
            FROM attachments
            WHERE account_id=? AND folder=? AND uid=?
        """, (self.account_id, folder, str(uid))).fetchall()
        return [dict(r) for r in rows]

    # Load the saved sync state for one folder.
    def get_sync_state(self, folder: str = "INBOX") -> Optional[Dict]:
        row = self.conn.execute(
            """
            SELECT folder, full_sync_complete, remote_total, synced_count,
                   last_error, updated_at
            FROM sync_state
            WHERE account_id=? AND folder=?
            """,
            (self.account_id, folder),
        ).fetchone()
        return dict(row) if row else None

    # Close the SQLite connection.
    def close(self):
        self.conn.close()
