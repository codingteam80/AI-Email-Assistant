import imaplib
import base64
import re
import ssl
from functools import wraps
from threading import RLock
from typing import Dict, List, Optional

from config import MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS


RECONNECTABLE_IMAP_ERRORS = (
    ssl.SSLEOFError,
    imaplib.IMAP4.abort,
    imaplib.IMAP4.error,
    OSError,
)


def _synchronized(method):
    # Serialize access to one IMAP socket across UI/background workers.
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


# Handle IMAP connections and message fetching.
class IMAPClient:
    ALL_MAIL = "ALL_MAIL"
    # Store connection settings and initialize caches.
    def __init__(
        self,
        server: str,
        port: int,
        email_address: str,
        password: Optional[str] = None,
        oauth_token_provider=None,
    ):
        self.server = server
        self.port = port
        self.email_address = email_address
        self.password = password
        self.oauth_token_provider = oauth_token_provider
        self._lock = RLock()
        self.conn: Optional[imaplib.IMAP4_SSL] = None

        self._known_total: Optional[int] = None
        self._uid_list_folder: Optional[str] = None
        self._uid_list: List[bytes] = []
        self._page_cache: Dict[int, Dict] = {}
        self._supports_gmail_thread_id = False
        self._all_mail_locations: List[tuple[str, bytes]] = []
        self._received_folders: List[str] = []
        self._security_folder_count_signature = ()

    @staticmethod
    def _location_uid(folder: str, uid: bytes) -> str:
        encoded = base64.urlsafe_b64encode(folder.encode("utf-8")).decode("ascii").rstrip("=")
        return f"{encoded}.{uid.decode('ascii')}"

    @staticmethod
    def _decode_location_uid(value: str) -> tuple[str, str]:
        encoded, separator, uid = str(value).partition(".")
        if not separator or not uid.isdigit():
            raise ValueError("Invalid all-mail message identifier.")
        encoded += "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(encoded).decode("utf-8"), uid

    def list_received_folders(self) -> List[str]:
        # MailMind only needs active received mail for its Inbox/security view:
        # the provider Inbox plus Spam/Junk. Archive, custom-label folders,
        # Sent, Drafts, Trash, and other folders are intentionally excluded so
        # login never scans the whole mailbox just to detect spam.
        self.ensure_connection()
        if self._received_folders:
            return list(self._received_folders)
        status, rows = self.conn.list()
        if status != "OK":
            raise ValueError("Could not list mailbox folders.")

        junk_folders = []
        for row in rows or []:
            text = bytes(row).decode("utf-8", errors="replace")
            flags_match = re.match(r"\(([^)]*)\)", text)
            flags = {
                item.casefold()
                for item in (flags_match.group(1).split() if flags_match else [])
            }
            if "\\noselect" in flags:
                continue
            quoted = re.search(r' "((?:[^"\\]|\\.)*)"\s*$', text)
            folder = (
                quoted.group(1).replace(r'\"', '"').replace(r'\\', '\\')
                if quoted
                else text.rsplit(" ", 1)[-1].strip('"')
            )
            lower_name = str(folder or "").strip().casefold()
            # IMAP providers are not consistent about the display name of the
            # server-side spam mailbox. Prefer SPECIAL-USE flags when present,
            # then accept only well-known system-folder aliases. This keeps
            # custom folders out of the startup security scope.
            normalized_leaf = re.split(r"[/\\.]", lower_name)[-1].strip()
            junk_aliases = {"spam", "junk", "junk email", "bulk mail", "bulk"}
            is_junk = (
                "\\junk" in flags
                or "\\spam" in flags
                or normalized_leaf in junk_aliases
            )
            if is_junk and folder and folder.upper() != "INBOX" and folder not in junk_folders:
                junk_folders.append(folder)

        # Put Junk first so the legacy composite UID snapshot ends with Inbox;
        # full sync itself is folder-batched and does not depend on this order.
        self._received_folders = [*junk_folders, "INBOX"]
        return list(self._received_folders)

    def _load_all_mail_locations(self, refresh: bool = False) -> List[tuple[str, bytes]]:
        if self._all_mail_locations and not refresh:
            return list(self._all_mail_locations)
        locations = []
        for mailbox in self.list_received_folders():
            self._select_folder(mailbox)
            status, data = self.conn.uid("search", None, "ALL")
            if status == "OK":
                locations.extend((mailbox, uid) for uid in ((data[0] or b"").split()) if uid.isdigit())
        self._all_mail_locations = locations
        self._known_total = len(locations)
        self._page_cache = {}
        return list(locations)

    @staticmethod
    def _inject_provider_folder_header(raw: bytes, mailbox: str) -> bytes:
        lower = mailbox.casefold()
        category = "spam" if any(token in lower for token in ("spam", "junk", "bulk")) else "mail"
        return raw.rstrip(b"\r\n") + f"\r\nX-MailMind-Provider-Folder: {category}\r\n\r\n".encode()

    # Open and authenticate the IMAP connection.
    @_synchronized
    def connect(self) -> bool:
        new_conn = None
        try:
            new_conn = imaplib.IMAP4_SSL(
                self.server,
                self.port,
                timeout=MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS,
            )
            if self.oauth_token_provider is not None:
                access_token = self.oauth_token_provider.get_access_token()
                oauth_payload = (
                    f"user={self.email_address}\x01"
                    f"auth=Bearer {access_token}\x01\x01"
                ).encode("utf-8")
                new_conn.authenticate("XOAUTH2", lambda _challenge: oauth_payload)
            else:
                new_conn.login(self.email_address, self.password or "")
            self.conn = new_conn
            capabilities = {
                item.upper() if isinstance(item, bytes) else str(item).encode().upper()
                for item in (getattr(new_conn, "capabilities", ()) or ())
            }
            self._supports_gmail_thread_id = b"X-GM-EXT-1" in capabilities
            return True
        except imaplib.IMAP4.error as error:
            self._close_connection(new_conn)
            self.conn = None
            raise ConnectionError(f"IMAP login failed: {error}")
        except Exception as error:
            self._close_connection(new_conn)
            self.conn = None
            raise ConnectionError(f"Could not connect to {self.server}: {error}")

    # Close one IMAP socket safely, including partially authenticated sockets.
    @staticmethod
    def _close_connection(conn):
        if conn is None:
            return
        try:
            sock = getattr(conn, "sock", None)
            if sock is not None:
                sock.settimeout(2.0)
            state = str(getattr(conn, "state", "")).upper()
            if state in {"AUTH", "SELECTED"}:
                conn.logout()
            else:
                conn.shutdown()
        except Exception:
            try:
                conn.shutdown()
            except Exception:
                try:
                    sock = getattr(conn, "sock", None)
                    if sock is not None:
                        sock.close()
                except Exception:
                    pass

    # Close the IMAP connection without delaying logout.
    @_synchronized
    def disconnect(self):
        conn = self.conn
        self.conn = None
        self._close_connection(conn)

        self._known_total = None
        self._uid_list_folder = None
        self._uid_list = []
        self._page_cache = {}
        self._supports_gmail_thread_id = False
        self._all_mail_locations = []
        self._received_folders = []

    # Reconnect after the current connection is lost.
    @_synchronized
    def reconnect(self):
        self.disconnect()
        self.connect()

    # Return a safely quoted IMAP mailbox argument. Gmail system folders such
    # as [Gmail]/All Mail contain spaces; passing the raw folder name to
    # imaplib makes the server parse it as multiple SELECT arguments.
    @staticmethod
    def _mailbox_argument(folder: str) -> str:
        value = str(folder or "INBOX")
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    # Select a folder and return its current message count.
    def _select_folder(self, folder: str) -> int:
        status, select_data = self.conn.select(self._mailbox_argument(folder))
        if status != "OK":
            raise ValueError(f"Could not open folder: {folder}")
        try:
            return int(select_data[0])
        except (TypeError, ValueError, IndexError):
            return 0

    # Load stable IMAP UIDs for the selected folder.
    def _load_uid_list(self, folder: str, refresh: bool = False) -> List[bytes]:
        total = self._select_folder(folder)
        should_reload = (
            refresh
            or self._uid_list_folder != folder
            or self._known_total != total
            or not self._uid_list
        )
        if should_reload:
            status, data = self.conn.uid("search", None, "ALL")
            if status != "OK":
                raise ValueError(f"Could not read message UIDs from folder: {folder}")
            raw_ids = data[0] if data and data[0] else b""
            self._uid_list = [item for item in raw_ids.split() if item.isdigit()]
            self._uid_list_folder = folder
            self._known_total = len(self._uid_list)
            self._page_cache = {}
        return list(self._uid_list)

    # Return all stable IMAP UIDs without downloading message content.
    @_synchronized
    def list_uids(self, folder: str = "INBOX", refresh: bool = True) -> List[str]:
        self.ensure_connection()
        if folder == self.ALL_MAIL:
            return [self._location_uid(mailbox, uid) for mailbox, uid in self._load_all_mail_locations(refresh)]
        try:
            uid_list = self._load_uid_list(folder, refresh=refresh)
        except RECONNECTABLE_IMAP_ERRORS:
            self.reconnect()
            uid_list = self._load_uid_list(folder, refresh=True)
        return [uid.decode("ascii", errors="ignore") for uid in uid_list]

    # Check whether one stable UID still exists in the selected folder.
    @_synchronized
    def uid_exists(self, folder: str, uid: str) -> bool:
        self.ensure_connection()
        if folder == self.ALL_MAIL:
            folder, uid = self._decode_location_uid(uid)

        def _check() -> bool:
            self._select_folder(folder)
            status, data = self.conn.uid("search", None, "UID", str(uid))
            if status != "OK":
                raise ValueError("Could not validate the selected email.")
            found = data[0].split() if data and data[0] else []
            return str(uid).encode("ascii", errors="ignore") in found

        try:
            return _check()
        except RECONNECTABLE_IMAP_ERRORS:
            self.reconnect()
            return _check()

    # Fetch one header-only page from an IMAP folder.
    @_synchronized
    def fetch_inbox(
        self,
        folder: str = "INBOX",
        limit: int = 50,
        offset: int = 0,
        refresh: bool = False,
        include_thread_counts: bool = True,
    ) -> Dict:
        self.ensure_connection()

        if folder == self.ALL_MAIL:
            locations = self._load_all_mail_locations(refresh)
            if not refresh and offset in self._page_cache:
                return dict(self._page_cache[offset])
            end = len(locations) - offset
            start = max(0, end - limit) if end > 0 else 0
            page_locations = list(reversed(locations[start:end])) if end > 0 else []
            by_mailbox: Dict[str, List[bytes]] = {}
            for mailbox, provider_uid in page_locations:
                by_mailbox.setdefault(mailbox, []).append(provider_uid)

            raw_by_location = {}
            for mailbox, provider_uids in by_mailbox.items():
                self._select_folder(mailbox)
                header_by_uid = self._fetch_headers_batch(provider_uids)
                for provider_uid, raw in header_by_uid.items():
                    raw_by_location[(mailbox, provider_uid)] = raw

            emails = []
            for mailbox, provider_uid in page_locations:
                raw = raw_by_location.get((mailbox, provider_uid))
                if raw:
                    emails.append({"uid": self._location_uid(mailbox, provider_uid), "raw": self._inject_provider_folder_header(raw, mailbox)})
            result = {"emails": emails, "total": len(locations), "has_more": start > 0}
            self._page_cache[offset] = result
            return dict(result)

        try:
            uid_list = self._load_uid_list(folder, refresh=refresh)
            if not refresh and offset in self._page_cache:
                return self._page_cache[offset]
            header_by_uid, page_uids, total, start = self._fetch_uid_page(
                uid_list, limit, offset
            )
        except RECONNECTABLE_IMAP_ERRORS:
            self.reconnect()
            uid_list = self._load_uid_list(folder, refresh=True)
            header_by_uid, page_uids, total, start = self._fetch_uid_page(
                uid_list, limit, offset
            )

        emails = []
        for uid in page_uids:
            raw = header_by_uid.get(uid)
            if raw:
                emails.append({"uid": uid.decode(), "raw": raw})

        result = {
            "emails": emails,
            "total": total,
            "has_more": start > 0,
        }
        self._page_cache[offset] = result
        return result

    # Slice one page from the UID list and fetch its headers plus lightweight
    # BODYSTRUCTURE metadata. The latter lets the local database know which
    # messages have attachments without downloading every full message body.
    def _fetch_uid_page(self, uid_list: List[bytes], limit: int, offset: int):
        total = len(uid_list)
        end = total - offset
        if end <= 0:
            return {}, [], total, 0

        start = max(0, end - limit) if limit else 0
        page_uids = list(reversed(uid_list[start:end]))
        header_by_uid = self._fetch_headers_batch(page_uids)
        attachment_by_uid = self._fetch_attachment_flags_batch(page_uids)

        # Add one private header consumed by email_parser.parse_email(). This
        # keeps Graph and IMAP on the same has_attachment field.
        for uid, raw in list(header_by_uid.items()):
            flag = b"1" if attachment_by_uid.get(uid, False) else b"0"
            header_by_uid[uid] = (
                raw.rstrip(b"\r\n")
                + b"\r\nX-MailMind-Has-Attachment: "
                + flag
                + b"\r\n\r\n"
            )
        return header_by_uid, page_uids, total, start

    # Return the current message count for a folder.
    @_synchronized
    def get_message_count(self, folder: str = "INBOX") -> Optional[int]:
        # This is a background poll, so a temporary authentication or network
        # failure must not crash the whole Streamlit page.
        try:
            self.ensure_connection()
            if folder == self.ALL_MAIL:
                total = 0
                folder_counts = []
                for mailbox in self.list_received_folders():
                    status, data = self.conn.status(
                        self._mailbox_argument(mailbox), "(MESSAGES)"
                    )
                    if status != "OK" or not data or not data[0]:
                        raise ValueError(f"Could not read message count: {mailbox}")
                    match = re.search(rb"MESSAGES (\d+)", data[0])
                    count = int(match.group(1)) if match else 0
                    total += count
                    folder_counts.append((str(mailbox), count))
                self._security_folder_count_signature = tuple(folder_counts)
                return total
            status, data = self.conn.status(self._mailbox_argument(folder), "(MESSAGES)")
        except (ConnectionError, *RECONNECTABLE_IMAP_ERRORS):
            try:
                self.reconnect()
                status, data = self.conn.status(self._mailbox_argument(folder), "(MESSAGES)")
            except (ConnectionError, *RECONNECTABLE_IMAP_ERRORS):
                return None

        if status != "OK" or not data or not data[0]:
            return None

        match = re.search(rb"MESSAGES (\d+)", data[0])
        return int(match.group(1)) if match else None

    def get_security_location_count_signature(self):
        # get_message_count(ALL_MAIL) already reads Inbox + Spam/Junk counts.
        # Expose that cached pair/list so the mailbox monitor can detect a folder
        # move even when the combined message total did not change.
        with self._lock:
            return tuple(self._security_folder_count_signature)

    @_synchronized
    def fetch_recent_security_headers(
        self, known_uids, page_size: int = 250, max_pages: int = 20
    ) -> Dict:
        # Check Inbox and Spam/Junk independently. This prevents a busy Inbox
        # from hiding a new Spam message (or vice versa) when the combined local
        # view is monitored after login.
        self.ensure_connection()
        known = {str(uid) for uid in (known_uids or set()) if str(uid)}
        page_size = max(1, int(page_size or 250))
        max_pages = max(1, int(max_pages or 20))
        collected = []
        total = 0

        for mailbox in self.list_received_folders():
            self._select_folder(mailbox)
            status, data = self.conn.uid("search", None, "ALL")
            if status != "OK":
                raise ValueError(f"Could not read message UIDs from folder: {mailbox}")
            raw_ids = data[0] if data and data[0] else b""
            uid_list = [item for item in raw_ids.split() if item.isdigit()]
            total += len(uid_list)

            pages_checked = 0
            end = len(uid_list)
            while end > 0 and pages_checked < max_pages:
                start = max(0, end - page_size)
                page_uids = list(reversed(uid_list[start:end]))
                page_ids = [self._location_uid(mailbox, uid) for uid in page_uids]
                unknown_uids = [
                    uid for uid, composite in zip(page_uids, page_ids)
                    if composite not in known
                ]
                if unknown_uids:
                    header_by_uid = self._fetch_headers_batch(unknown_uids)
                    attachment_by_uid = self._fetch_attachment_flags_batch(unknown_uids)
                    for uid in unknown_uids:
                        raw = header_by_uid.get(uid)
                        if not raw:
                            continue
                        flag = b"1" if attachment_by_uid.get(uid, False) else b"0"
                        raw = (
                            raw.rstrip(b"\r\n")
                            + b"\r\nX-MailMind-Has-Attachment: "
                            + flag
                            + b"\r\n\r\n"
                        )
                        collected.append({
                            "uid": self._location_uid(mailbox, uid),
                            "raw": self._inject_provider_folder_header(raw, mailbox),
                        })

                pages_checked += 1
                if any(composite in known for composite in page_ids):
                    break
                end = start

        return {"emails": collected, "total": total}

    def iter_security_pages(self, page_size: int = 250):
        # Stream Inbox + Spam/Junk directly during first-time sync. This avoids
        # building/fetching Gmail All Mail (which also contains archived/custom
        # labels) and batches each mailbox instead of switching folders per UID.
        self.ensure_connection()
        page_size = max(1, int(page_size or 250))
        for mailbox in self.list_received_folders():
            self._select_folder(mailbox)
            status, data = self.conn.uid("search", None, "ALL")
            if status != "OK":
                raise ValueError(f"Could not read message UIDs from folder: {mailbox}")
            raw_ids = data[0] if data and data[0] else b""
            uid_list = [item for item in raw_ids.split() if item.isdigit()]
            for end in range(len(uid_list), 0, -page_size):
                start = max(0, end - page_size)
                page_uids = list(reversed(uid_list[start:end]))
                header_by_uid = self._fetch_headers_batch(page_uids)
                attachment_by_uid = self._fetch_attachment_flags_batch(page_uids)
                items = []
                for uid in page_uids:
                    raw = header_by_uid.get(uid)
                    if not raw:
                        continue
                    flag = b"1" if attachment_by_uid.get(uid, False) else b"0"
                    raw = (
                        raw.rstrip(b"\r\n")
                        + b"\r\nX-MailMind-Has-Attachment: "
                        + flag
                        + b"\r\n\r\n"
                    )
                    items.append({
                        "uid": self._location_uid(mailbox, uid),
                        "raw": self._inject_provider_folder_header(raw, mailbox),
                    })
                if items:
                    yield items

    # Fetch one full raw email from a folder by stable IMAP UID.
    @_synchronized
    def fetch_single(self, folder: str, uid: str) -> Optional[bytes]:
        self.ensure_connection()

        if folder == self.ALL_MAIL:
            folder, uid = self._decode_location_uid(uid)

        try:
            self._select_folder(folder)
            return self._fetch_raw(str(uid).encode())
        except RECONNECTABLE_IMAP_ERRORS:
            self.reconnect()
            self._select_folder(folder)
            return self._fetch_raw(str(uid).encode())

    # Fetch raw content for one stable IMAP UID.
    def _fetch_raw(self, uid: bytes) -> Optional[bytes]:
        fetch_item = "(RFC822 X-GM-THRID)" if self._supports_gmail_thread_id else "(RFC822)"
        status, msg_data = self.conn.uid("fetch", uid, fetch_item)
        if status != "OK":
            return None
        for part in msg_data:
            if isinstance(part, tuple):
                return self._inject_gmail_thread_header(part[1], part[0])
        return None

    # Fetch headers for a group of stable IMAP UIDs.
    def _fetch_headers_batch(self, uids: List[bytes]) -> Dict[bytes, bytes]:
        fetch_item = (
            "UID X-GM-THRID " if self._supports_gmail_thread_id else "UID "
        ) + "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO CC REPLY-TO RETURN-PATH DATE MESSAGE-ID IN-REPLY-TO REFERENCES X-SPAM-FLAG X-SPAM-STATUS X-MICROSOFT-ANTISPAM AUTHENTICATION-RESULTS)]"
        results = self._fetch_batch(uids, f"({fetch_item})", include_response=True)
        return {
            uid: self._inject_gmail_thread_header(raw, response_header)
            for uid, (raw, response_header) in results.items()
        }

    @staticmethod
    def _inject_gmail_thread_header(raw: bytes, response_header: bytes) -> bytes:
        # Expose Gmail's IMAP thread ID to the shared RFC822 parser.
        match = re.search(rb"\bX-GM-THRID (\d+)\b", bytes(response_header or b""))
        if not match:
            return raw
        payload = bytes(raw or b"")
        separator = b"\r\n\r\n"
        head, found, body = payload.partition(separator)
        if not found:
            separator = b"\n\n"
            head, found, body = payload.partition(separator)
        line_break = b"\r\n" if b"\r\n" in head else b"\n"
        injected_head = (
            head.rstrip(b"\r\n")
            + line_break
            + b"X-MailMind-Gmail-Thread-ID: "
            + match.group(1)
        )
        return injected_head + (found or b"\r\n\r\n") + body

    @staticmethod
    def _bodystructure_has_attachment(payload: bytes) -> bool:
        # Return whether an IMAP BODYSTRUCTURE advertises a file attachment.
        #
        # This mirrors email_parser: an explicit ATTACHMENT disposition or a
        # non-empty NAME/FILENAME parameter is treated as downloadable content.
        upper = bytes(payload or b"").upper()
        if b'"ATTACHMENT"' in upper:
            return True
        filename_patterns = (
            rb'"FILENAME"\s+"[^"\r\n]+"',
            rb'"NAME"\s+"[^"\r\n]+"',
        )
        return any(re.search(pattern, upper) for pattern in filename_patterns)

    # Fetch BODYSTRUCTURE for a UID batch without downloading message bodies.
    def _fetch_attachment_flags_batch(self, uids: List[bytes]) -> Dict[bytes, bool]:
        if not uids:
            return {}

        uid_set = b",".join(uids)
        status, msg_data = self.conn.uid("fetch", uid_set, "(UID BODYSTRUCTURE)")
        if status != "OK":
            return {}

        results: Dict[bytes, bool] = {}
        for part in msg_data:
            if isinstance(part, tuple):
                payload = b" ".join(
                    value for value in part if isinstance(value, (bytes, bytearray))
                )
            elif isinstance(part, (bytes, bytearray)):
                payload = bytes(part)
            else:
                continue
            match = re.search(rb"\bUID (\d+)\b", payload)
            if match:
                results[match.group(1)] = self._bodystructure_has_attachment(payload)
        return results

    # Run one UID batch fetch and map results by stable UID.
    def _fetch_batch(
        self, uids: List[bytes], fetch_item: str, include_response: bool = False
    ) -> Dict:
        if not uids:
            return {}

        uid_set = b",".join(uids)
        status, msg_data = self.conn.uid("fetch", uid_set, fetch_item)
        if status != "OK":
            return {}

        results: Dict = {}
        for part in msg_data:
            if not isinstance(part, tuple):
                continue
            response_header, raw = part[0], part[1]
            match = re.search(rb"\bUID (\d+)\b", response_header)
            if match:
                results[match.group(1)] = (
                    (raw, response_header) if include_response else raw
                )
        return results

    # Check the connection before an IMAP request.
    @_synchronized
    def ensure_connection(self):
        if not self.conn:
            self.connect()
            return

        state = str(getattr(self.conn, "state", "")).upper()
        if state not in {"AUTH", "SELECTED"}:
            self.reconnect()
            return

        try:
            self.conn.noop()
        except RECONNECTABLE_IMAP_ERRORS:
            self.reconnect()
