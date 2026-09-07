# Microsoft Graph mailbox client with the interface used by the existing app.
from __future__ import annotations

from collections import OrderedDict
import base64
from datetime import datetime
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import format_datetime, formataddr
from threading import RLock
from email_handler.outbound_format import normalize_plain_text, plain_text_to_html
from typing import Dict, List, Optional
from urllib.parse import quote, urlencode

import requests

from config import (
    MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS,
    MICROSOFT_GRAPH_BASE_URL,
    MICROSOFT_GRAPH_THREAD_CACHE_LIMIT,
)


GRAPH_BASE_URL = MICROSOFT_GRAPH_BASE_URL
GRAPH_TIMEOUT_SECONDS = MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS
GRAPH_PREFER_HEADER = 'IdType="ImmutableId"'


class GraphMailClient:
    # Read a signed-in Outlook mailbox through delegated Microsoft Graph.
    ALL_MAIL = "ALL_MAIL"

    def __init__(self, token_provider):
        self.token_provider = token_provider
        self.email_address = ""
        self._profile: Dict = {}
        self._inbox_folder_id = ""
        self._excluded_folder_ids = set()
        self._junk_folder_id = ""
        self._active_folder = "INBOX"
        self._lock = RLock()
        self._page_size: Optional[int] = None
        self._page_url_by_offset: Dict[int, Optional[str]] = {0: None}
        self._page_cache: Dict[int, Dict] = {}
        self._seen_uids: List[str] = []
        self._seen_uid_set = set()
        self._uid_snapshot_complete = False
        self._security_location_by_uid: Dict[str, str] = {}
        self._thread_count_cache: Dict[str, int] = {}
        self._thread_message_cache = OrderedDict()
        self._thread_message_cache_limit = MICROSOFT_GRAPH_THREAD_CACHE_LIMIT
        self._full_sync_active = False
        self._full_sync_folder = ""
        self._full_sync_conversation_counts: Dict[str, int] = {}
        self._all_mail_total_hint = 0
        self._security_folder_count_signature = ()

    def connect(self) -> Dict:
        profile = self._request_json(
            "GET",
            "/me",
            params={"$select": "displayName,mail,userPrincipalName"},
        )
        self._profile = profile
        self.email_address = str(
            profile.get("mail") or profile.get("userPrincipalName") or ""
        ).strip()
        self._load_inbox_folder()
        return dict(profile)

    def disconnect(self):
        with self._lock:
            self._profile = {}
            self._inbox_folder_id = ""
            self._excluded_folder_ids = set()
            self._junk_folder_id = ""
            self._full_sync_active = False
            self._full_sync_folder = ""
            self._full_sync_conversation_counts = {}
            self._all_mail_total_hint = 0
            self._security_folder_count_signature = ()
            self._security_location_by_uid = {}
            self._reset_pagination()

    def reconnect(self):
        self.connect()

    def ensure_connection(self):
        self.token_provider.get_access_token()
        if not self._inbox_folder_id:
            self._load_inbox_folder()

    def get_message_count(self, folder: str = "INBOX") -> Optional[int]:
        try:
            self.ensure_connection()
            if folder == self.ALL_MAIL:
                # One lightweight Graph batch replaces a mailbox-wide /me/messages
                # scan. The security view only tracks Inbox + Junk Email.
                requests_body = [
                    {
                        "id": "inbox",
                        "method": "GET",
                        "url": "/me/mailFolders/inbox?$select=id,totalItemCount",
                    },
                    {
                        "id": "junk",
                        "method": "GET",
                        "url": "/me/mailFolders/junkemail?$select=id,totalItemCount",
                    },
                ]
                payload = self._request_json(
                    "POST", "/$batch", json_body={"requests": requests_body}
                ) or {}
                responses = {
                    str(item.get("id") or ""): item
                    for item in payload.get("responses", [])
                }
                total = 0
                folder_counts = []
                for key in ("inbox", "junk"):
                    response = responses.get(key) or {}
                    if int(response.get("status") or 0) != 200:
                        raise ConnectionError("Could not read Outlook folder count.")
                    body = response.get("body") or {}
                    folder_id = str(body.get("id") or "")
                    if key == "inbox" and folder_id:
                        self._inbox_folder_id = folder_id
                    elif key == "junk" and folder_id:
                        self._junk_folder_id = folder_id
                    count = int(body.get("totalItemCount") or 0)
                    total += count
                    folder_counts.append((key, count))
                with self._lock:
                    self._security_folder_count_signature = tuple(folder_counts)
                return total
            data = self._request_json(
                "GET",
                "/me/mailFolders/inbox",
                params={"$select": "id,totalItemCount"},
            )
            folder_id = str(data.get("id") or "")
            if folder_id:
                self._inbox_folder_id = folder_id
            return int(data.get("totalItemCount") or 0)
        except Exception:
            return None

    def get_security_location_count_signature(self):
        # Cached from the same lightweight Graph batch used by get_message_count;
        # this adds no provider request to the normal mailbox poll.
        with self._lock:
            return tuple(self._security_folder_count_signature)

    def fetch_inbox(
        self,
        folder: str = "INBOX",
        limit: int = 50,
        offset: int = 0,
        refresh: bool = False,
        include_thread_counts: bool = True,
    ) -> Dict:
        self._require_supported_folder(folder)
        self.ensure_connection()
        self._active_folder = folder
        limit = max(1, min(int(limit or 50), 250))
        offset = max(int(offset or 0), 0)

        with self._lock:
            if refresh or self._page_size != limit:
                self._page_size = limit
                self._reset_pagination()

            if offset in self._page_cache:
                return dict(self._page_cache[offset])

            self._materialize_until_offset(offset, limit, include_thread_counts)
            result = self._fetch_page(offset, limit, include_thread_counts)
            self._page_cache[offset] = result
            return dict(result)

    def begin_full_sync(self, folder: str = "INBOX") -> None:
        # During a full ALL_MAIL traversal, conversation IDs from the same page
        # stream provide the exact non-draft thread counts. Accumulate them and
        # avoid separate per-conversation Graph requests while login is blocked.
        with self._lock:
            self._full_sync_active = True
            self._full_sync_folder = str(folder or "INBOX").upper()
            self._full_sync_conversation_counts = {}

    def finish_full_sync(self) -> Dict[str, int]:
        with self._lock:
            counts = dict(self._full_sync_conversation_counts)
            for conversation_id, count in counts.items():
                self._thread_count_cache[conversation_id] = max(1, int(count or 1))
            self._full_sync_active = False
            self._full_sync_folder = ""
            self._full_sync_conversation_counts = {}
            return counts

    def cancel_full_sync(self) -> None:
        with self._lock:
            self._full_sync_active = False
            self._full_sync_folder = ""
            self._full_sync_conversation_counts = {}

    def list_uids(self, folder: str = "INBOX", refresh: bool = True) -> List[str]:
        self._require_supported_folder(folder)
        self.ensure_connection()

        with self._lock:
            if not refresh and self._uid_snapshot_complete:
                return list(self._seen_uids)
            if refresh:
                self._seen_uids = []
                self._seen_uid_set = set()
                self._uid_snapshot_complete = False

        remote_uids: List[str] = []
        security_locations: Dict[str, str] = {}
        sources = (
            self._security_message_sources()
            if folder == self.ALL_MAIL
            else (("mail", self._messages_path(folder)),)
        )
        for source_kind, source_url in sources:
            url = source_url
            params = {
                "$top": "250",
                "$select": "id",
                "$orderby": "receivedDateTime desc",
            }
            while url:
                data = self._request_json("GET", url, params=params)
                params = None
                for item in data.get("value", []):
                    uid = str(item.get("id") or "")
                    if uid:
                        remote_uids.append(uid)
                        if folder == self.ALL_MAIL:
                            security_locations[uid] = (
                                "spam" if source_kind == "spam" else "inbox"
                            )
                url = str(data.get("@odata.nextLink") or "")

        with self._lock:
            self._seen_uids = list(remote_uids)
            self._seen_uid_set = set(remote_uids)
            self._uid_snapshot_complete = True
            if folder == self.ALL_MAIL:
                self._security_location_by_uid = dict(security_locations)
        return remote_uids

    def get_security_location_snapshot(self) -> Dict[str, str]:
        # Outlook uses immutable message IDs, so moving a message between Junk
        # and Inbox does not create a new UID. list_uids(ALL_MAIL) already walks
        # both folders; expose that same snapshot so reconciliation can update
        # MailMind's provider_spam location without downloading message bodies.
        with self._lock:
            return dict(self._security_location_by_uid)

    def uid_exists(self, folder: str, uid: str) -> bool:
        self._require_supported_folder(folder)
        self.ensure_connection()
        encoded_uid = quote(str(uid), safe="")
        data = self._request_json(
            "GET",
            f"/me/messages/{encoded_uid}",
            params={"$select": "id,parentFolderId"},
            allow_not_found=True,
        )
        if data is None:
            return False
        if folder == self.ALL_MAIL:
            self._load_inbox_folder()
            if not self._junk_folder_id:
                self._load_excluded_folders()
            parent_id = str(data.get("parentFolderId") or "")
            return parent_id in {self._inbox_folder_id, self._junk_folder_id}
        self._load_inbox_folder()
        return str(data.get("parentFolderId") or "") == self._inbox_folder_id

    def fetch_single(self, folder: str, uid: str) -> Optional[bytes]:
        self._require_supported_folder(folder)
        self.ensure_connection()
        encoded_uid = quote(str(uid), safe="")
        response = self.request_raw(
            "GET",
            f"/me/messages/{encoded_uid}/$value",
            allow_not_found=True,
        )
        if response is None:
            return None
        return bytes(response.content)

    def request_raw(
        self,
        method: str,
        path_or_url: str,
        *,
        params=None,
        json_body=None,
        data_body=None,
        content_type: str = "",
        allow_not_found: bool = False,
    ):
        url = self._absolute_url(path_or_url)
        response = self._send(
            method, url, params=params, json_body=json_body,
            data_body=data_body, content_type=content_type,
        )
        if response.status_code == 404 and allow_not_found:
            return None
        if response.status_code >= 400:
            raise ConnectionError(self._graph_error(response))
        return response

    def _request_json(
        self,
        method: str,
        path_or_url: str,
        *,
        params=None,
        json_body=None,
        allow_not_found: bool = False,
    ):
        response = self.request_raw(
            method,
            path_or_url,
            params=params,
            json_body=json_body,
            allow_not_found=allow_not_found,
        )
        if response is None:
            return None
        try:
            return response.json()
        except ValueError as error:
            raise ConnectionError("Microsoft Graph returned an invalid response.") from error

    def _send(self, method: str, url: str, *, params=None, json_body=None, data_body=None, content_type: str = ""):
        token = self.token_provider.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Prefer": GRAPH_PREFER_HEADER,
        }
        if content_type:
            headers["Content-Type"] = content_type
        try:
            response = requests.request(
                method,
                url,
                params=params,
                json=json_body if data_body is None else None,
                data=data_body,
                headers=headers,
                timeout=GRAPH_TIMEOUT_SECONDS,
            )
        except requests.RequestException as error:
            raise ConnectionError(f"Could not reach Microsoft Graph: {error}") from error

        if response.status_code == 401:
            token = self.token_provider.get_access_token(force_refresh=True)
            headers["Authorization"] = f"Bearer {token}"
            try:
                response = requests.request(
                    method,
                    url,
                    params=params,
                    json=json_body if data_body is None else None,
                    data=data_body,
                    headers=headers,
                    timeout=GRAPH_TIMEOUT_SECONDS,
                )
            except requests.RequestException as error:
                raise ConnectionError(f"Could not reach Microsoft Graph: {error}") from error
        return response

    def send_reply(
        self,
        uid: str,
        body: str,
        *,
        attachments: list[dict] | None = None,
        subject: str = "",
        recipient: str = "",
    ) -> None:
        # Send a reply; MIME is used only when file attachments are present.
        self.ensure_connection()
        encoded_uid = quote(str(uid), safe="")
        body = normalize_plain_text(body)
        attachments = attachments or []
        if not attachments:
            self.request_raw(
                "POST",
                f"/me/messages/{encoded_uid}/reply",
                json_body={
                    "message": {
                        "body": {
                            "contentType": "HTML",
                            "content": plain_text_to_html(body),
                        }
                    }
                },
            )
            return

        message = EmailMessage()
        if self.email_address:
            message["From"] = self.email_address
        if recipient:
            message["To"] = recipient
        reply_subject = str(subject or "").strip() or "(No Subject)"
        message["Subject"] = (
            reply_subject if reply_subject.casefold().startswith("re:")
            else f"Re: {reply_subject}"
        )
        message.set_content(body)
        message.add_alternative(plain_text_to_html(body), subtype="html")
        for attachment in attachments:
            data = attachment.get("data") or b""
            if not data:
                continue
            content_type = str(attachment.get("content_type") or "application/octet-stream")
            maintype, _, subtype = content_type.partition("/")
            if not maintype or not subtype:
                maintype, subtype = "application", "octet-stream"
            message.add_attachment(
                data,
                maintype=maintype,
                subtype=subtype,
                filename=str(attachment.get("filename") or "attachment"),
            )
        payload = base64.b64encode(message.as_bytes()).decode("ascii")
        self.request_raw(
            "POST",
            f"/me/messages/{encoded_uid}/reply",
            data_body=payload,
            content_type="text/plain",
        )

    def fetch_thread(self, conversation_id: str) -> List[Dict]:
        # Return every non-draft message in one Outlook conversation.
        #
        # Unlike the Inbox page, /me/messages spans the mailbox, so replies saved
        # in Sent Items participate in the same conversation view as Outlook. A
        # small per-session LRU cache prevents reopening or summarizing the same
        # thread from downloading all MIME messages again. Refresh clears it.
        self.ensure_connection()
        conversation_id = str(conversation_id or "").strip()
        if not conversation_id:
            return []

        with self._lock:
            cached = self._thread_message_cache.get(conversation_id)
            if cached is not None:
                self._thread_message_cache.move_to_end(conversation_id)
                return [dict(item) for item in cached]

        escaped_id = conversation_id.replace("'", "''")
        url = "/me/messages"
        params = {
            "$top": "100",
            "$select": "id,conversationId,isDraft",
            "$filter": f"conversationId eq '{escaped_id}'",
        }
        messages: List[Dict] = []
        seen = set()
        while url:
            data = self._request_json("GET", url, params=params)
            params = None
            for item in data.get("value", []):
                uid = str(item.get("id") or "")
                if not uid or uid in seen or bool(item.get("isDraft")):
                    continue
                seen.add(uid)
                response = self.request_raw(
                    "GET",
                    f"/me/messages/{quote(uid, safe='')}/$value",
                    allow_not_found=True,
                )
                if response is not None:
                    messages.append({"uid": uid, "raw": bytes(response.content)})
            url = str(data.get("@odata.nextLink") or "")

        if messages:
            with self._lock:
                self._thread_message_cache[conversation_id] = [dict(item) for item in messages]
                self._thread_message_cache.move_to_end(conversation_id)
                while len(self._thread_message_cache) > self._thread_message_cache_limit:
                    self._thread_message_cache.popitem(last=False)
                self._thread_count_cache[conversation_id] = max(1, len(messages))
        return messages

    def fetch_thread_counts(self, conversation_ids) -> Dict[str, int]:
        # Count Outlook conversations with one Graph roundtrip per 20 IDs.
        #
        # Inbox pages can contain many distinct conversations. JSON batching
        # avoids the previous N+1 pattern where each row triggered its own HTTP
        # request just to render the thread badge. Rare conversations longer than
        # 100 messages fall back to the paged single-conversation counter.
        ordered = []
        seen = set()
        for value in conversation_ids or []:
            conversation_id = str(value or "").strip()
            if conversation_id and conversation_id not in seen:
                seen.add(conversation_id)
                ordered.append(conversation_id)

        counts = {}
        missing = []
        for conversation_id in ordered:
            cached = self._thread_count_cache.get(conversation_id)
            if cached is None:
                cached_thread = self._thread_message_cache.get(conversation_id)
                if cached_thread is not None:
                    cached = max(1, len(cached_thread))
                    self._thread_count_cache[conversation_id] = cached
            if cached is None:
                missing.append(conversation_id)
            else:
                counts[conversation_id] = cached

        for start in range(0, len(missing), 20):
            chunk = missing[start:start + 20]
            requests_body = []
            request_to_conversation = {}
            for index, conversation_id in enumerate(chunk):
                request_id = str(index + 1)
                escaped_id = conversation_id.replace("'", "''")
                query = urlencode({
                    "$top": "100",
                    "$select": "id,isDraft",
                    "$filter": f"conversationId eq '{escaped_id}'",
                })
                requests_body.append({
                    "id": request_id,
                    "method": "GET",
                    "url": f"/me/messages?{query}",
                })
                request_to_conversation[request_id] = conversation_id

            try:
                payload = self._request_json(
                    "POST", "/$batch", json_body={"requests": requests_body}
                ) or {}
            except (ConnectionError, OSError, RuntimeError, ValueError):
                payload = {}

            responses = {
                str(item.get("id") or ""): item
                for item in payload.get("responses", [])
            }
            for request_id, conversation_id in request_to_conversation.items():
                response = responses.get(request_id) or {}
                body = response.get("body") or {}
                if int(response.get("status") or 0) != 200:
                    count = 1
                elif body.get("@odata.nextLink"):
                    # Keep correctness for unusually large threads without
                    # making normal Inbox pages pay the pagination cost.
                    try:
                        count = self.fetch_thread_count(conversation_id)
                    except (ConnectionError, OSError, RuntimeError, ValueError):
                        count = 1
                else:
                    count = sum(
                        1 for item in body.get("value", [])
                        if not bool(item.get("isDraft"))
                    )
                    count = max(1, count)
                    self._thread_count_cache[conversation_id] = count
                counts[conversation_id] = count

        return counts

    def fetch_thread_count(self, conversation_id: str) -> int:
        # Count every non-draft mailbox message in an Outlook conversation.
        conversation_id = str(conversation_id or "").strip()
        if not conversation_id:
            return 1
        cached = self._thread_count_cache.get(conversation_id)
        if cached is not None:
            return cached

        escaped_id = conversation_id.replace("'", "''")
        url = "/me/messages"
        params = {
            "$top": "100",
            "$select": "id,isDraft",
            "$filter": f"conversationId eq '{escaped_id}'",
        }
        count = 0
        while url:
            data = self._request_json("GET", url, params=params)
            params = None
            count += sum(1 for item in data.get("value", []) if not bool(item.get("isDraft")))
            url = str(data.get("@odata.nextLink") or "")
        count = max(1, count)
        self._thread_count_cache[conversation_id] = count
        return count

    def _load_inbox_folder(self):
        if self._inbox_folder_id:
            return
        data = self._request_json(
            "GET",
            "/me/mailFolders/inbox",
            params={"$select": "id"},
        )
        self._inbox_folder_id = str(data.get("id") or "")
        if not self._inbox_folder_id:
            raise ConnectionError("Microsoft Graph could not identify the Inbox folder.")

    def _load_excluded_folders(self):
        # Resolve Outlook folders that never represent received mail.
        if self._excluded_folder_ids:
            return
        names = ("sentitems", "drafts", "deleteditems", "outbox", "junkemail")
        requests_body = [
            {
                "id": str(index + 1),
                "method": "GET",
                "url": f"/me/mailFolders/{name}?$select=id",
            }
            for index, name in enumerate(names)
        ]
        try:
            payload = self._request_json(
                "POST", "/$batch", json_body={"requests": requests_body}
            ) or {}
            responses = {
                str(item.get("id") or ""): item
                for item in payload.get("responses", [])
            }
            resolved = {}
            for index, name in enumerate(names):
                response = responses.get(str(index + 1)) or {}
                body = response.get("body") or {}
                if int(response.get("status") or 0) == 200:
                    folder_id = str(body.get("id") or "")
                    if folder_id:
                        resolved[name] = folder_id
        except (ConnectionError, OSError, RuntimeError, TypeError, ValueError):
            resolved = {}

        # Keep the previous sequential lookup as a correctness fallback when a
        # tenant or transient Graph error does not return every batch item.
        for name in names:
            if name in resolved:
                continue
            data = self._request_json(
                "GET", f"/me/mailFolders/{name}", params={"$select": "id"}
            )
            folder_id = str(data.get("id") or "")
            if folder_id:
                resolved[name] = folder_id

        self._excluded_folder_ids = {
            resolved[name]
            for name in ("sentitems", "drafts", "deleteditems", "outbox")
            if resolved.get(name)
        }
        self._junk_folder_id = str(resolved.get("junkemail") or "")

    @staticmethod
    def _security_message_sources():
        # Only active Inbox and provider Junk are part of MailMind's security
        # mailbox view. Custom folders/archive are deliberately excluded.
        return (
            ("mail", "/me/mailFolders/inbox/messages"),
            ("spam", "/me/mailFolders/junkemail/messages"),
        )

    def fetch_recent_security_headers(
        self, known_uids, page_size: int = 250, max_pages: int = 20
    ) -> Dict:
        # Poll Inbox and Junk independently so no custom/archive folder is
        # scanned and new mail in either source cannot be hidden by the other.
        self.ensure_connection()
        known = {str(uid) for uid in (known_uids or set()) if str(uid)}
        page_size = max(1, min(int(page_size or 250), 250))
        max_pages = max(1, int(max_pages or 20))
        select_fields = (
            "id,subject,from,toRecipients,ccRecipients,receivedDateTime,"
            "internetMessageId,conversationId,bodyPreview,hasAttachments"
        )
        collected = []

        for source_kind, source_url in self._security_message_sources():
            url = source_url
            params = {
                "$top": str(page_size),
                "$select": select_fields,
                "$orderby": "receivedDateTime desc",
            }
            pages_checked = 0
            while url and pages_checked < max_pages:
                data = self._request_json("GET", url, params=params)
                params = None
                items = list(data.get("value", []))
                page_ids = [
                    str(item.get("id") or "")
                    for item in items
                    if str(item.get("id") or "")
                ]
                unknown_items = [
                    item for item in items
                    if str(item.get("id") or "") not in known
                ]
                conversation_ids = [
                    str(item.get("conversationId") or "").strip()
                    for item in unknown_items
                    if str(item.get("conversationId") or "").strip()
                ]
                try:
                    thread_counts = self.fetch_thread_counts(conversation_ids)
                except (ConnectionError, OSError, RuntimeError, ValueError):
                    thread_counts = {}

                for item in unknown_items:
                    uid = str(item.get("id") or "")
                    if not uid:
                        continue
                    if source_kind == "spam":
                        item["_mailmind_provider_folder"] = "spam"
                    conversation_id = str(item.get("conversationId") or "").strip()
                    collected.append({
                        "uid": uid,
                        "raw": self._header_message_bytes(
                            item, thread_counts.get(conversation_id, 1)
                        ),
                    })

                pages_checked += 1
                if any(uid in known for uid in page_ids):
                    break
                url = str(data.get("@odata.nextLink") or "")

        return {
            "emails": collected,
            "total": int(self.get_message_count(self.ALL_MAIL) or 0),
        }

    def iter_security_pages(self, page_size: int = 250):
        # Stream Inbox and Junk directly for first-time sync instead of scanning
        # /me/messages across every Outlook folder.
        self.ensure_connection()
        page_size = max(1, min(int(page_size or 250), 250))
        select_fields = (
            "id,subject,from,toRecipients,ccRecipients,receivedDateTime,"
            "internetMessageId,conversationId,bodyPreview,hasAttachments"
        )
        for source_kind, source_url in self._security_message_sources():
            url = source_url
            params = {
                "$top": str(page_size),
                "$select": select_fields,
                "$orderby": "receivedDateTime desc",
            }
            while url:
                data = self._request_json("GET", url, params=params)
                params = None
                items = list(data.get("value", []))
                page = []
                for item in items:
                    uid = str(item.get("id") or "")
                    if not uid:
                        continue
                    conversation_id = str(item.get("conversationId") or "").strip()
                    if self._full_sync_active and conversation_id:
                        self._full_sync_conversation_counts[conversation_id] = (
                            self._full_sync_conversation_counts.get(conversation_id, 0) + 1
                        )
                    if source_kind == "spam":
                        item["_mailmind_provider_folder"] = "spam"
                    page.append({
                        "uid": uid,
                        "raw": self._header_message_bytes(item, 1),
                    })
                if page:
                    yield page
                url = str(data.get("@odata.nextLink") or "")

    def _reset_pagination(self):
        self._page_url_by_offset = {0: None}
        self._page_cache = {}
        self._seen_uids = []
        self._seen_uid_set = set()
        self._uid_snapshot_complete = False
        self._thread_count_cache = {}
        self._thread_message_cache.clear()

    def _materialize_until_offset(self, target_offset: int, limit: int,
                                  include_thread_counts: bool = True):
        while target_offset not in self._page_url_by_offset:
            candidates = [value for value in self._page_url_by_offset if value < target_offset]
            if not candidates:
                raise ValueError("Could not locate the requested Microsoft Graph page.")
            start = max(candidates)
            if start not in self._page_cache:
                self._page_cache[start] = self._fetch_page(
                    start, limit, include_thread_counts
                )
            result = self._page_cache[start]
            next_offset = start + len(result.get("emails", []))
            if not result.get("has_more") or next_offset <= start:
                raise ValueError("The requested inbox page is no longer available.")
            if next_offset > target_offset:
                raise ValueError("Microsoft Graph returned an unexpected page boundary.")

    def _fetch_page(self, offset: int, limit: int,
                    include_thread_counts: bool = True) -> Dict:
        page_url = self._page_url_by_offset.get(offset)
        params = None
        if offset == 0 and not page_url:
            page_url = self._messages_path(self._active_folder)
            params = {
                "$top": str(limit),
                "$select": (
                    "id,subject,from,toRecipients,ccRecipients,receivedDateTime,"
                    "internetMessageId,conversationId,bodyPreview,hasAttachments"
                ),
                "$orderby": "receivedDateTime desc",
            }
            if self._active_folder == self.ALL_MAIL:
                params["$filter"] = "isDraft eq false"
                params["$select"] += ",parentFolderId"
                self._load_excluded_folders()
        if not page_url:
            return {"emails": [], "total": self.get_message_count() or 0, "has_more": False}

        data = self._request_json("GET", page_url, params=params)
        items = list(data.get("value", []))
        emails = []
        conversation_ids = [
            str(item.get("conversationId") or "").strip() for item in items
            if str(item.get("conversationId") or "").strip()
        ]
        bulk_counting = (
            self._full_sync_active
            and self._full_sync_folder == self.ALL_MAIL
            and self._active_folder == self.ALL_MAIL
        )
        if bulk_counting:
            for conversation_id in conversation_ids:
                self._full_sync_conversation_counts[conversation_id] = (
                    self._full_sync_conversation_counts.get(conversation_id, 0) + 1
                )

        if include_thread_counts and not bulk_counting:
            try:
                thread_counts = self.fetch_thread_counts(conversation_ids)
            except (ConnectionError, OSError, RuntimeError, ValueError):
                thread_counts = {}
        else:
            thread_counts = {}

        for item in items:
            if self._active_folder == self.ALL_MAIL and str(item.get("parentFolderId") or "") in self._excluded_folder_ids:
                continue
            uid = str(item.get("id") or "")
            if not uid:
                continue
            conversation_id = str(item.get("conversationId") or "").strip()
            if self._active_folder == self.ALL_MAIL and str(item.get("parentFolderId") or "") == self._junk_folder_id:
                item["_mailmind_provider_folder"] = "spam"
            emails.append({
                "uid": uid,
                "raw": self._header_message_bytes(
                    item, thread_counts.get(conversation_id, 1)
                ),
            })
            if uid not in self._seen_uid_set:
                self._seen_uid_set.add(uid)
                self._seen_uids.append(uid)

        next_link = str(data.get("@odata.nextLink") or "")
        if next_link and not emails and self._active_folder == self.ALL_MAIL:
            # /me/messages pages can occasionally contain only folders that
            # MailMind excludes (for example, a burst of Sent Items). Continue
            # from the same logical offset so a zero eligible page never ends
            # an otherwise valid ALL_MAIL traversal early.
            self._page_url_by_offset[offset] = next_link
            return self._fetch_page(offset, limit, include_thread_counts)

        next_offset = offset + len(emails)
        if next_link and next_offset > offset:
            self._page_url_by_offset[next_offset] = next_link
        elif not next_link:
            self._uid_snapshot_complete = offset == 0 or bool(self._seen_uids)

        if self._active_folder == self.ALL_MAIL:
            observed_total = offset + len(emails)
            if next_link:
                observed_total += 1
            self._all_mail_total_hint = max(self._all_mail_total_hint, observed_total)
            if not next_link:
                self._all_mail_total_hint = max(
                    self._all_mail_total_hint, len(self._seen_uids)
                )
            total = self._all_mail_total_hint
        else:
            total = self.get_message_count() or len(self._seen_uids)

        return {
            "emails": emails,
            "total": total,
            "has_more": bool(next_link),
        }

    @staticmethod
    def _header_message_bytes(item: Dict, thread_count: int = 1) -> bytes:
        message = EmailMessage(policy=default_policy)
        message["Subject"] = str(item.get("subject") or "(No Subject)")

        sender = (item.get("from") or {}).get("emailAddress") or {}
        sender_address = str(sender.get("address") or "")
        sender_name = str(sender.get("name") or "")
        message["From"] = formataddr((sender_name, sender_address)) if sender_address else sender_name

        recipients = []
        for recipient in item.get("toRecipients") or []:
            email_address = (recipient or {}).get("emailAddress") or {}
            address = str(email_address.get("address") or "")
            name = str(email_address.get("name") or "")
            if address:
                recipients.append(formataddr((name, address)))
            elif name:
                recipients.append(name)
        if recipients:
            message["To"] = ", ".join(recipients)

        cc_recipients = []
        for recipient in item.get("ccRecipients") or []:
            email_address = (recipient or {}).get("emailAddress") or {}
            address = str(email_address.get("address") or "")
            name = str(email_address.get("name") or "")
            if address:
                cc_recipients.append(formataddr((name, address)))
            elif name:
                cc_recipients.append(name)
        if cc_recipients:
            message["Cc"] = ", ".join(cc_recipients)

        received = GraphMailClient._parse_graph_datetime(item.get("receivedDateTime"))
        if received is not None:
            message["Date"] = format_datetime(received)

        internet_message_id = str(item.get("internetMessageId") or "").strip()
        if internet_message_id:
            message["Message-ID"] = internet_message_id
        conversation_id = str(item.get("conversationId") or "").strip()
        if conversation_id:
            message["X-MailMind-Conversation-ID"] = conversation_id
        message["X-MailMind-Thread-Count"] = str(max(1, int(thread_count or 1)))
        message["X-MailMind-Has-Attachment"] = (
            "1" if bool(item.get("hasAttachments")) else "0"
        )
        if item.get("_mailmind_provider_folder"):
            message["X-MailMind-Provider-Folder"] = str(item["_mailmind_provider_folder"])

        message.set_content(str(item.get("bodyPreview") or ""))
        return message.as_bytes()

    @staticmethod
    def _parse_graph_datetime(value) -> Optional[datetime]:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _absolute_url(path_or_url: str) -> str:
        value = str(path_or_url or "")
        if value.startswith(("https://", "http://")):
            return value
        if not value.startswith("/"):
            value = "/" + value
        return GRAPH_BASE_URL + value

    @staticmethod
    def _graph_error(response) -> str:
        try:
            payload = response.json()
            error = payload.get("error") or {}
            code = str(error.get("code") or "")
            message = str(error.get("message") or "")
            detail = ": ".join(part for part in (code, message) if part)
        except Exception:
            detail = str(response.text or "").strip()
        if response.status_code == 403:
            return (
                "Microsoft Graph denied mailbox access. Confirm that delegated "
                "Mail.Read and Mail.Send are configured and approve the permissions "
                "during sign-in."
            )
        return detail or f"Microsoft Graph request failed with HTTP {response.status_code}."

    @staticmethod
    def _require_supported_folder(folder: str):
        if str(folder or "INBOX").upper() not in {"INBOX", GraphMailClient.ALL_MAIL}:
            raise ValueError("Unsupported Microsoft Graph mailbox view.")

    @staticmethod
    def _messages_path(folder: str) -> str:
        return "/me/messages" if folder == GraphMailClient.ALL_MAIL else "/me/mailFolders/inbox/messages"
