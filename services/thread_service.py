# Reconstruct reply chains before AI summarization.
import re
from email.utils import getaddresses

from email_handler.email_parser import parse_email
from email_handler.display_time import parse_timestamp
from services.email_service import get_full_email
from email_handler.thread_identity import canonical_thread_id, message_ids
from services.summary_eligibility_service import evaluate_summary_eligibility
from services.spam_detection_service import detect_spam


def _looks_like_network_error(error) -> bool:
    # Keep thread assembly independent of Streamlit/session services. We only
    # need to preserve a transient provider/network cause so the reader can
    # route it through the normal user-action Toast path.
    text = str(error or "").strip().casefold()
    return any(
        token in text
        for token in (
            "timed out",
            "timeout",
            "could not connect",
            "could not reach",
            "connection refused",
            "connection reset",
            "connection aborted",
            "network is unreachable",
            "name or service not known",
            "temporary failure in name resolution",
            "getaddrinfo failed",
            "remote end closed connection",
            "server disconnected",
            "failed to establish a new connection",
            "max retries exceeded",
        )
    )


_REPLY_PREFIX = re.compile(r"^(?:(?:re|fw|fwd)\s*:\s*)+", re.IGNORECASE)
_MESSAGE_ID = re.compile(r"<[^>]+>")
_QUOTED_START = re.compile(
    r"^(?:on .+ wrote:|from:\s|sent:\s|-----original message-----)",
    re.IGNORECASE,
)


def _subject(value: str) -> str:
    return " ".join(_REPLY_PREFIX.sub("", str(value or "")).casefold().split())


def _ids(value: str) -> set[str]:
    return set(message_ids(value))


def _linked(left: dict, right: dict) -> bool:
    left_canonical = canonical_thread_id(left)
    right_canonical = canonical_thread_id(right)
    if left_canonical and left_canonical == right_canonical:
        return True

    left_conversation = str(left.get("conversation_id") or "").strip()
    right_conversation = str(right.get("conversation_id") or "").strip()
    if left_conversation and left_conversation == right_conversation:
        return True

    left_message = _ids(left.get("message_id", ""))
    right_message = _ids(right.get("message_id", ""))
    left_links = _ids(left.get("in_reply_to", "")) | _ids(left.get("reference_ids", ""))
    right_links = _ids(right.get("in_reply_to", "")) | _ids(right.get("reference_ids", ""))
    if (left_message & right_links) or (right_message & left_links):
        return True
    if left_links & right_links:
        return True

    # Never merge on subject or participants alone. Without an explicit
    # provider/RFC relationship, each message remains its own thread.
    return False


def resolve_thread_headers(store, selected: dict, folder: str = "INBOX") -> list[dict]:
    # Return the connected reply component containing the selected message.
    #
    # Newer databases persist an indexed canonical thread key, so the normal
    # path is one small SQLite query instead of loading/scanning the entire
    # mailbox. The legacy graph walk remains as a compatibility fallback for
    # older/custom stores used before canonical IDs were persisted.
    selected_uid = str(selected.get("uid", ""))
    thread_id = canonical_thread_id(selected)

    if thread_id.startswith("local:"):
        # No explicit provider/RFC relationship exists, so by definition this
        # message is an isolated thread and no mailbox-wide scan is useful.
        return [selected]

    get_thread_members = getattr(store, "get_thread_members", None)
    if thread_id and callable(get_thread_members):
        members = list(get_thread_members(folder, thread_id) or [])
        if members:
            return members

    candidates = store.get_thread_candidates(folder)
    by_uid = {str(item.get("uid")): item for item in candidates}
    component = {selected_uid}
    changed = True
    while changed:
        changed = False
        members = [by_uid[uid] for uid in component if uid in by_uid]
        for uid, candidate in by_uid.items():
            if uid in component:
                continue
            if any(_linked(candidate, member) for member in members):
                component.add(uid)
                changed = True
    return [by_uid[uid] for uid in component if uid in by_uid] or [selected]


def resolve_security_thread_headers(
    store, selected: dict, folder: str = "INBOX"
) -> list[dict]:
    """Resolve the full explicit reply component for Spam/Security only.

    The normal Inbox/Summary resolver intentionally prefers the persisted
    canonical thread index. Security needs a stricter fallback because some
    providers can fragment conversation IDs across consecutive inbound replies.
    For the Spam projection only, walk the already-indexed mailbox metadata and
    reconnect messages when provider IDs or RFC Message-ID/References prove the
    relationship. Subject similarity is never used.
    """
    selected_uid = str(selected.get("uid") or "").strip()
    get_candidates = getattr(store, "get_thread_candidates", None)
    if not selected_uid or not callable(get_candidates):
        return resolve_thread_headers(store, selected, folder)

    try:
        candidates = list(get_candidates(folder) or [])
    except Exception:
        return resolve_thread_headers(store, selected, folder)

    by_uid = {
        str(item.get("uid") or "").strip(): dict(item)
        for item in candidates
        if str(item.get("uid") or "").strip()
    }
    if selected_uid not in by_uid:
        by_uid[selected_uid] = dict(selected)

    component = {selected_uid}
    changed = True
    while changed:
        changed = False
        members = [by_uid[uid] for uid in component if uid in by_uid]
        for uid, candidate in by_uid.items():
            if uid in component:
                continue
            if any(_linked(candidate, member) for member in members):
                component.add(uid)
                changed = True

    resolved = [by_uid[uid] for uid in component if uid in by_uid]
    resolved.sort(
        key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or ""))
    )
    return resolved or [selected]


def _without_quoted_copy(body: str) -> str:
    # Remove quoted history so an incremental input contains only this message.
    lines = str(body or "").splitlines()
    kept = []
    for line in lines:
        if line.lstrip().startswith(">") or _QUOTED_START.match(line.strip()):
            break
        kept.append(line)
    return "\n".join(kept).strip()


def _quoted_history_was_removed(body: str) -> bool:
    """Return True only when de-quoting removed real content.

    ``_without_quoted_copy`` normalizes CRLF/CR line endings to LF because it
    uses ``splitlines()`` and joins with ``\n``. Comparing that result directly
    with the provider body therefore misclassifies an untouched Outlook message
    as quoted whenever its original text uses CRLF. That false positive is what
    made the first/original Outlook turn drop its UI HTML/image while later
    replies (already LF-normalized) rendered correctly.
    """
    raw = str(body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    cleaned = _without_quoted_copy(body)
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n").strip()
    return cleaned != raw


def build_thread_email(
    client, store, selected: dict, folder: str = "INBOX", *,
    prefer_local: bool = False, reader_projection: bool = False,
) -> dict:
    # Fetch and assemble a chronological, deduplicated conversation document.
    #
    # Reader views can prefer the already-hydrated SQLite copy so opening an
    # email never waits on a provider conversation-expansion request when the
    # full message is already cached locally. Summary/original-email flows keep
    # the default provider expansion behavior for maximum conversation coverage.
    messages = []
    expanded_from_provider = False
    provider_load_errors: list[str] = []
    conversation_id = str(selected.get("conversation_id") or "").strip()

    # Outlook can expand a conversation directly from Graph. Do that before
    # touching the local thread graph so an older cache never triggers a
    # mailbox-wide compatibility scan just to generate one summary.
    if not prefer_local and conversation_id and hasattr(client, "fetch_thread"):
        try:
            messages = [
                parse_email(item["raw"], uid=str(item.get("uid") or ""))
                for item in client.fetch_thread(conversation_id)
                if item.get("raw")
            ]
            expanded_from_provider = bool(messages)
        except (ConnectionError, OSError, RuntimeError, ValueError) as error:
            # Keep the Inbox usable when Graph cannot expand the conversation;
            # locally synchronized members remain a safe fallback. Preserve the
            # cause so a total fallback failure is not mislabeled as a missing
            # thread when the real problem is provider/network connectivity.
            provider_load_errors.append(str(error))
            messages = []

    headers = [selected]
    # Lightweight/custom callers used by drafting/tests may not expose the local
    # thread index. Reconcile published local members whenever the store supports
    # indexed/candidate lookup; otherwise keep the provider-expanded behavior.
    if callable(getattr(store, "get_thread_members", None)) or callable(
        getattr(store, "get_thread_candidates", None)
    ):
        headers = resolve_thread_headers(store, selected, folder)

    if not messages:
        for header in headers:
            result = get_full_email(client, str(header.get("uid", "")), folder, store)
            if result.get("success"):
                messages.append(result["email"])
            elif result.get("error"):
                provider_load_errors.append(str(result.get("error") or ""))
    else:
        # Provider conversation expansion can be briefly stale immediately after
        # one or more new replies cross MailMind's Security-finalized local
        # boundary. The Inbox list/count is already built from those published
        # local rows, so the reader must reconcile *every* locally known member,
        # not only the row the user happened to click. Otherwise a provider cache
        # containing the older one-message conversation can make a (2) thread
        # collapse back to one message after opening.
        #
        # Keep provider-only Sent Items already returned by Graph/Gmail, then add
        # only local members absent by both provider UID and RFC Message-ID. The
        # later workspace filter still owns Safe-vs-Spam separation, so locally
        # known unsafe turns can be reconciled here without ever leaking into the
        # Inbox reader or Summary.
        provider_uids = {
            str(item.get("uid") or "").strip()
            for item in messages
            if str(item.get("uid") or "").strip()
        }
        provider_message_ids: set[str] = set()
        for item in messages:
            provider_message_ids.update(_ids(item.get("message_id", "")))

        for header in headers:
            header_uid = str(header.get("uid") or "").strip()
            header_message_ids = _ids(header.get("message_id", ""))
            already_present = bool(
                (header_uid and header_uid in provider_uids)
                or (header_message_ids and header_message_ids & provider_message_ids)
            )
            if already_present or not header_uid:
                continue

            local_result = get_full_email(client, header_uid, folder, store)
            if local_result.get("success"):
                local_email = local_result["email"]
                messages.append(local_email)
                provider_uids.add(header_uid)
                provider_message_ids.update(_ids(local_email.get("message_id", "")))
            elif local_result.get("error"):
                provider_load_errors.append(str(local_result.get("error") or ""))

    deduplicated = {}
    for item in messages:
        key = (
            str(item.get("message_id") or "").strip().casefold()
            or str(item.get("uid") or "")
        )
        deduplicated[key] = item
    messages = list(deduplicated.values())
    if not messages:
        network_error = next(
            (error for error in provider_load_errors if _looks_like_network_error(error)),
            "",
        )
        if network_error:
            raise RuntimeError(network_error)
        raise RuntimeError("No messages in the selected email thread could be loaded.")
    messages.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))

    # Reader-only Outlook HTML hydration. The normal local-first reader path can
    # have a complete text copy for an older turn while its stored body_html is
    # empty (for example, a header/full-body cache created before the HTML reader
    # projection existed). Do not mutate shared thread messages or any Summary /
    # Security / draft input. When the reader explicitly asks for its projection,
    # use Graph's provider-native MIME conversation only to fill the transient
    # per-turn HTML sidecar for turns that are missing HTML locally.
    reader_provider_html_by_uid: dict[str, str] = {}
    reader_provider_html_by_message_id: dict[str, str] = {}
    if reader_projection:
        missing_outlook_items = [
            item
            for item in messages
            if not str(item.get("gmail_thread_id") or "").strip()
            and not str(item.get("body_html") or "").strip()
        ]

        # First try the provider conversation when the reader was assembled
        # local-first. This is cheap when Graph has the whole conversation and
        # preserves the existing reader-only backfill behavior.
        if (
            missing_outlook_items
            and conversation_id
            and not expanded_from_provider
            and callable(getattr(client, "fetch_thread", None))
        ):
            try:
                for provider_item in client.fetch_thread(conversation_id) or []:
                    raw = provider_item.get("raw")
                    if not raw:
                        continue
                    parsed_provider = parse_email(
                        raw, uid=str(provider_item.get("uid") or "")
                    )
                    provider_html = str(parsed_provider.get("body_html") or "").strip()
                    if not provider_html:
                        continue
                    provider_uid = str(parsed_provider.get("uid") or "").strip()
                    if provider_uid:
                        reader_provider_html_by_uid[provider_uid] = provider_html
                    for provider_message_id in _ids(parsed_provider.get("message_id", "")):
                        reader_provider_html_by_message_id[provider_message_id] = provider_html
            except (ConnectionError, OSError, RuntimeError, ValueError):
                pass

        # Outlook can expose the first/original turn differently from later
        # replies. In that case the conversation expansion may contain rich HTML
        # for reply turns while the original turn is present only as a cached
        # text row. Hydrate only those still-missing reader turns by their exact
        # immutable provider UID. This is transient UI data: do not save it to
        # SQLite and do not mutate the shared thread_messages contract used by
        # Security, Summary, Draft, cold-start, or incremental processing.
        fetch_single = getattr(client, "fetch_single", None)
        if missing_outlook_items and callable(fetch_single):
            for item in missing_outlook_items:
                item_uid = str(item.get("uid") or "").strip()
                if not item_uid or reader_provider_html_by_uid.get(item_uid):
                    continue
                if any(
                    reader_provider_html_by_message_id.get(item_message_id)
                    for item_message_id in _ids(item.get("message_id", ""))
                ):
                    continue
                try:
                    raw = fetch_single(folder, item_uid)
                    if not raw:
                        continue
                    parsed_provider = parse_email(raw, uid=item_uid)
                    provider_html = str(parsed_provider.get("body_html") or "").strip()
                    if not provider_html:
                        continue
                    reader_provider_html_by_uid[item_uid] = provider_html
                    for provider_message_id in _ids(parsed_provider.get("message_id", "")):
                        reader_provider_html_by_message_id[provider_message_id] = provider_html
                except (ConnectionError, OSError, RuntimeError, ValueError):
                    # Reader-only enhancement: cached text remains usable if the
                    # exact provider MIME cannot be loaded.
                    continue

    sections = []
    many_messages = len(messages) > 1
    attachments = []
    for index, item in enumerate(messages):
        body = str(item.get("body_text") or item.get("snippet") or "")
        # Provider expansion already includes Sent Items, so every turn can be
        # de-quoted. Inbox-only IMAP keeps the newest quoted history because it
        # may be the only available copy of a sent reply.
        if many_messages and (expanded_from_provider or index < len(messages) - 1):
            body = _without_quoted_copy(body)
        sections.append(
            f"[{item.get('date_display') or 'Unknown date'} | "
            f"{item.get('from') or 'Unknown sender'} -> {item.get('to') or 'Unknown recipient'}]\n"
            f"Subject: {item.get('subject') or '(No Subject)'}\n{body}"
        )
        for attachment in item.get("attachments") or []:
            attachments.append({**attachment, "message_uid": str(item.get("uid", ""))})

    latest = dict(messages[-1])
    # Keep a standalone message's provider-native body untouched for the Inbox
    # reader. The synthetic metadata-prefixed conversation document is only
    # needed when two or more real conversation turns are being assembled.
    # This prevents plain-text Gmail/Outlook messages from displaying duplicate
    # Date/From/To/Subject lines that already exist in the reader header.
    if many_messages:
        latest["body_text"] = "\n\n--- Conversation turn ---\n\n".join(sections)
    else:
        latest["body_text"] = str(
            messages[-1].get("body_text") or messages[-1].get("snippet") or ""
        )
    latest["attachments"] = attachments
    latest["source_uids"] = [str(item.get("uid", "")) for item in messages]
    latest["thread_count"] = len(messages)
    if reader_projection:
        # UI-only Outlook HTML map. Keep thread_messages/body_html exactly on
        # their established shared contract so Summary, Security, draft, and
        # incremental/cold-start logic receive the same data as before.
        latest["_mailmind_ui_thread_html_by_uid"] = {}
        for item in messages:
            item_uid = str(item.get("uid") or "").strip()
            if not item_uid or str(item.get("gmail_thread_id") or "").strip():
                continue
            item_html = str(item.get("body_html") or "").strip()
            if not item_html:
                item_html = str(reader_provider_html_by_uid.get(item_uid) or "").strip()
            if not item_html:
                for item_message_id in _ids(item.get("message_id", "")):
                    item_html = str(
                        reader_provider_html_by_message_id.get(item_message_id) or ""
                    ).strip()
                    if item_html:
                        break
            if item_html:
                latest["_mailmind_ui_thread_html_by_uid"][item_uid] = item_html
        latest["_mailmind_ui_thread_had_quote_by_uid"] = {
            str(item.get("uid") or ""): (
                _quoted_history_was_removed(
                    str(item.get("body_text") or item.get("snippet") or "")
                )
            )
            for item in messages
            if str(item.get("uid") or "").strip()
            and not str(item.get("gmail_thread_id") or "").strip()
        }
    latest["thread_messages"] = [
        {
            **item,
            "body_text": _without_quoted_copy(
                str(item.get("body_text") or item.get("snippet") or "")
            ),
            # Gmail already gives us the original RFC822 HTML body. Keep that
            # provider-native representation so branded/signature-heavy Gmail
            # messages render the same way they did before the generic plain
            # text thread view was introduced. Outlook/Graph keeps the current
            # deterministic text-thread rendering to avoid repeated quoted
            # conversation HTML.
            "body_html": (
                str(item.get("body_html") or "")
                if str(item.get("gmail_thread_id") or "").strip()
                else ""
            ),
        }
        for item in messages
    ]
    latest["canonical_thread_id"] = canonical_thread_id(selected) or canonical_thread_id(headers[0])
    latest["thread_subject"] = _REPLY_PREFIX.sub("", str(latest.get("subject") or "")).strip()
    return latest



def _rebuild_workspace_thread_email(
    thread_email: dict,
    messages: list[dict],
    *,
    workspace_local_count: int,
    excluded_uids: list[str],
) -> dict:
    # Rebuild the reader-facing conversation from only turns allowed in the
    # active MailMind workspace. Provider conversation expansion can span Inbox,
    # Junk/Spam, Sent Items, and other folders; the Inbox reader must never pull
    # a Security-routed Spam turn back into the visible conversation just because
    # Outlook/Gmail still gives it the same provider thread identity.
    visible = []
    for item in (messages or []):
        clean_item = dict(item)
        raw_body = str(clean_item.get("body_text") or clean_item.get("snippet") or "")
        clean_body = _without_quoted_copy(raw_body)
        clean_item["body_text"] = clean_body

        # A locally backfilled thread turn can still carry the whole quoted
        # conversation in its provider-native HTML even after body_text is
        # de-quoted. The reader prefers body_html when present, which would make
        # one Spam/Security expander appear to contain several emails again.
        # Clear HTML only when this turn actually contained quoted history;
        # already-clean Inbox/Gmail thread turns retain their existing HTML
        # rendering behavior.
        if _quoted_history_was_removed(raw_body):
            clean_item["body_html"] = ""
        visible.append(clean_item)

    if not visible:
        raise RuntimeError("No messages in this thread are available in the current MailMind workspace.")
    visible.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))

    sections: list[str] = []
    attachments: list[dict] = []
    for item in visible:
        body = _without_quoted_copy(str(item.get("body_text") or item.get("snippet") or ""))
        sections.append(
            f"[{item.get('date_display') or 'Unknown date'} | "
            f"{item.get('from') or 'Unknown sender'} -> {item.get('to') or 'Unknown recipient'}]\n"
            f"Subject: {item.get('subject') or '(No Subject)'}\n{body}"
        )
        for attachment in item.get("attachments") or []:
            attachments.append({**attachment, "message_uid": str(item.get("uid", ""))})

    latest = dict(visible[-1])
    if len(visible) > 1:
        latest["body_text"] = "\n\n--- Conversation turn ---\n\n".join(sections)
    else:
        latest["body_text"] = str(
            visible[-1].get("body_text") or visible[-1].get("snippet") or ""
        )
    latest["attachments"] = attachments
    latest["source_uids"] = [
        str(item.get("uid", "")) for item in visible if str(item.get("uid", ""))
    ]
    latest["thread_count"] = len(visible)
    latest["thread_messages"] = visible
    reader_html_by_uid = dict(thread_email.get("_mailmind_ui_thread_html_by_uid") or {})
    reader_quote_by_uid = dict(thread_email.get("_mailmind_ui_thread_had_quote_by_uid") or {})
    if reader_html_by_uid or reader_quote_by_uid:
        visible_uids = {
            str(item.get("uid") or "").strip() for item in visible
            if str(item.get("uid") or "").strip()
        }
        latest["_mailmind_ui_thread_html_by_uid"] = {
            uid: str(value or "")
            for uid, value in reader_html_by_uid.items()
            if uid in visible_uids and str(value or "").strip()
        }
        latest["_mailmind_ui_thread_had_quote_by_uid"] = {
            uid: bool(value)
            for uid, value in reader_quote_by_uid.items()
            if uid in visible_uids
        }
    latest["canonical_thread_id"] = str(thread_email.get("canonical_thread_id") or "")
    latest["thread_subject"] = str(thread_email.get("thread_subject") or "")
    # The Inbox card badge is intentionally scoped to MailMind rows that are
    # actually visible in that workspace. Trusted Sent turns can still provide
    # conversation context in the reader, but they must not make the card badge
    # jump after opening the thread.
    latest["workspace_thread_count"] = max(1, int(workspace_local_count or 0))
    latest["excluded_workspace_uids"] = list(dict.fromkeys(excluded_uids or []))
    return latest


def filter_thread_email_for_workspace(
    thread_email: dict,
    store,
    folder: str = "INBOX",
    *,
    spam_view: bool = False,
    thread_headers: list[dict] | None = None,
) -> dict:
    # Keep provider-expanded conversations inside the active MailMind workspace.
    #
    # For the Inbox reader:
    #   * locally routed Spam/Security turns are excluded;
    #   * locally routed Inbox turns remain visible;
    #   * provider-only Sent turns from the signed-in account remain available as
    #     reply context; and
    #   * unknown inbound provider turns fail closed instead of bypassing the
    #     local Security routing boundary.
    #
    # The function is deliberately independent of Summary eligibility. Inbox can
    # render ordinary Safe/Promotional mail, while Summary applies its stricter
    # Security-finalized eligibility gate separately.
    messages = [dict(item) for item in (thread_email.get("thread_messages") or [])]
    if not messages:
        return thread_email

    canonical_id = str(thread_email.get("canonical_thread_id") or "").strip()
    selected = dict(thread_email)
    if canonical_id:
        selected["canonical_thread_id"] = canonical_id
    headers = (
        list(thread_headers)
        if thread_headers is not None
        else resolve_thread_headers(store, selected, folder)
    )
    by_uid, by_message_id = _summary_security_lookup(headers)
    account_email = str(getattr(store, "account_email", "") or "").strip().casefold()

    visible: list[dict] = []
    excluded_uids: list[str] = []
    workspace_local_count = 0
    for item in messages:
        stored = _match_security_header(item, by_uid, by_message_id)
        if stored is not None:
            stored_in_spam = bool(int(stored.get("is_spam") or 0))
            if stored_in_spam == bool(spam_view):
                visible.append(dict(item))
                workspace_local_count += 1
            else:
                uid = str(item.get("uid") or "").strip()
                if uid:
                    excluded_uids.append(uid)
            continue

        # Sent Items are not part of the monitored Inbox/Spam corpus, but are
        # useful conversation context. Permit them only in the normal Inbox view
        # and only when the provider message sender matches the signed-in account.
        if not spam_view:
            sender_addresses = _mailbox_addresses(item.get("from", ""))
            if account_email and account_email in sender_addresses:
                sent_item = dict(item)
                sent_item["_mailmind_reader_context"] = "trusted_sent"
                visible.append(sent_item)
                continue

        uid = str(item.get("uid") or "").strip()
        if uid:
            excluded_uids.append(uid)

    return _rebuild_workspace_thread_email(
        thread_email,
        visible,
        workspace_local_count=workspace_local_count,
        excluded_uids=excluded_uids,
    )


def build_incremental_thread_email(thread_email: dict, known_uids) -> dict | None:
    # Return a summary input containing only turns absent from a saved thread.
    known = {str(value or "").strip() for value in (known_uids or []) if str(value or "").strip()}
    unseen = [
        dict(item) for item in (thread_email.get("thread_messages") or [])
        if str(item.get("uid") or "").strip() not in known
    ]
    if not unseen:
        return None
    unseen.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))
    sections, attachments = [], []
    for item in unseen:
        body = _without_quoted_copy(str(item.get("body_text") or item.get("snippet") or ""))
        sections.append(
            f"[{item.get('date_display') or 'Unknown date'} | "
            f"{item.get('from') or 'Unknown sender'} -> {item.get('to') or 'Unknown recipient'}]\n"
            f"Subject: {item.get('subject') or '(No Subject)'}\n{body}"
        )
        for attachment in item.get("attachments") or []:
            attachments.append({**attachment, "message_uid": str(item.get("uid", ""))})
    incremental = dict(unseen[-1])
    incremental["body_text"] = "\n\n--- New conversation turn ---\n\n".join(sections)
    incremental["body_html"] = ""
    incremental["attachments"] = attachments
    incremental["source_uids"] = [str(item.get("uid", "")) for item in unseen]
    incremental["thread_count"] = len(unseen)
    incremental["canonical_thread_id"] = str(thread_email.get("canonical_thread_id") or "")
    incremental["thread_subject"] = str(thread_email.get("thread_subject") or "")
    return incremental



def _mailbox_addresses(value: str) -> set[str]:
    # Normalize one RFC-style address field for direction checks. This is used
    # only to recognize the signed-in user's own Sent turns; inbound turns still
    # require a persisted Security-finalized mailbox record before Summary can
    # consume them.
    return {
        str(address or "").strip().casefold()
        for _name, address in getaddresses([str(value or "")])
        if str(address or "").strip()
    }


def _summary_security_lookup(headers: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    by_uid: dict[str, dict] = {}
    by_message_id: dict[str, dict] = {}
    for header in headers or []:
        uid = str(header.get("uid") or "").strip()
        if uid:
            by_uid[uid] = header
        for message_id in message_ids(header.get("message_id", "")):
            key = str(message_id or "").strip().casefold()
            if key:
                by_message_id[key] = header
    return by_uid, by_message_id


def _match_security_header(
    item: dict,
    by_uid: dict[str, dict],
    by_message_id: dict[str, dict],
) -> dict | None:
    uid = str(item.get("uid") or "").strip()
    if uid and uid in by_uid:
        return by_uid[uid]
    for message_id in message_ids(item.get("message_id", "")):
        match = by_message_id.get(str(message_id or "").strip().casefold())
        if match is not None:
            return match
    return None


def _rebuild_summary_thread_email(thread_email: dict, messages: list[dict]) -> dict:
    # Rebuild the synthetic conversation document from the Security-approved
    # turns only. The original provider thread_email object remains untouched so
    # reader/reply conversation reconstruction continues to see the real thread.
    approved = [dict(item) for item in messages or []]
    if not approved:
        raise RuntimeError("No Security-eligible messages remain in this email thread.")
    approved.sort(key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or "")))

    sections: list[str] = []
    attachments: list[dict] = []
    for item in approved:
        body = _without_quoted_copy(str(item.get("body_text") or item.get("snippet") or ""))
        sections.append(
            f"[{item.get('date_display') or 'Unknown date'} | "
            f"{item.get('from') or 'Unknown sender'} -> {item.get('to') or 'Unknown recipient'}]\n"
            f"Subject: {item.get('subject') or '(No Subject)'}\n{body}"
        )
        for attachment in item.get("attachments") or []:
            attachments.append({**attachment, "message_uid": str(item.get("uid", ""))})

    latest = dict(approved[-1])
    if len(approved) > 1:
        latest["body_text"] = "\n\n--- Conversation turn ---\n\n".join(sections)
    else:
        latest["body_text"] = str(
            approved[-1].get("body_text") or approved[-1].get("snippet") or ""
        )
    latest["body_html"] = ""
    latest["attachments"] = attachments
    latest["source_uids"] = [str(item.get("uid", "")) for item in approved if str(item.get("uid", ""))]
    latest["thread_count"] = len(approved)
    latest["thread_messages"] = approved
    latest["canonical_thread_id"] = str(thread_email.get("canonical_thread_id") or "")
    latest["thread_subject"] = str(thread_email.get("thread_subject") or "")
    return latest


def freeze_thread_email_for_summary_snapshot(
    thread_email: dict, *, boundary_date: str = "", known_uids=None
) -> dict:
    """Freeze a provider-expanded thread to the state known when an Auto job launched.

    Provider conversation expansion can reveal a reply that arrives while an
    automatic summary is already running.  That newer turn belongs to the next
    queued update, not to the in-flight snapshot.  Locally known members are
    always retained; provider-only context is retained only when its message
    timestamp is at or before the queued thread boundary.
    """
    messages = [dict(item) for item in (thread_email.get("thread_messages") or [])]
    if not messages:
        return thread_email

    known = {str(value or "").strip() for value in (known_uids or []) if str(value or "").strip()}
    boundary = parse_timestamp(boundary_date)
    frozen: list[dict] = []
    excluded: list[str] = []

    for item in messages:
        uid = str(item.get("uid") or "").strip()
        if uid and uid in known:
            frozen.append(item)
            continue

        item_time = parse_timestamp(item.get("date"))
        if boundary is not None and item_time is not None and item_time <= boundary:
            frozen.append(item)
            continue

        if uid:
            excluded.append(uid)

    if not frozen:
        # The selected queued message is normally in ``known``.  If a provider
        # rewrites identifiers unexpectedly, fail closed to the oldest available
        # turn rather than absorbing the newest post-launch reply.
        ordered = sorted(
            messages, key=lambda item: (str(item.get("date") or ""), str(item.get("uid") or ""))
        )
        frozen = [ordered[0]]

    rebuilt = _rebuild_summary_thread_email(thread_email, frozen)
    rebuilt["snapshot_excluded_uids"] = list(dict.fromkeys(excluded))
    return rebuilt


def filter_thread_email_for_summary(
    thread_email: dict, store, folder: str = "INBOX", *,
    allow_historical_provider_safe: bool = False,
) -> dict:
    # Security gate EVERY inbound turn before it is sent to the Summary LLM.
    #
    # A provider conversation may legitimately contain a mix such as:
    #   Safe -> Safe -> Spam -> Safe
    # The real conversation identity stays intact, but Summary receives only
    # Security-finalized, summary-eligible inbound turns plus the signed-in
    # user's own Sent turns. This prevents a later Safe reply from indirectly
    # carrying an earlier Spam/Phishing/Malware turn into an incremental summary.
    messages = [dict(item) for item in (thread_email.get("thread_messages") or [])]
    if not messages:
        return thread_email

    canonical_id = str(thread_email.get("canonical_thread_id") or "").strip()
    selected = dict(messages[-1])
    if canonical_id:
        selected["canonical_thread_id"] = canonical_id
    headers = resolve_thread_headers(store, selected, folder)
    by_uid, by_message_id = _summary_security_lookup(headers)
    account_email = str(getattr(store, "account_email", "") or "").strip().casefold()

    approved: list[dict] = []
    excluded_uids: list[str] = []
    for item in messages:
        # If this turn exists in the locally monitored Inbox/Spam corpus, its
        # persisted Security verdict ALWAYS wins -- even when the From header
        # equals the signed-in account (which can be spoofed). Only a provider
        # conversation turn absent from that monitored corpus may qualify as a
        # trusted Sent-context turn by sender identity.
        stored = _match_security_header(item, by_uid, by_message_id)
        if stored is None:
            sender_addresses = _mailbox_addresses(item.get("from", ""))
            if account_email and account_email in sender_addresses:
                sent_item = dict(item)
                sent_item["_mailmind_summary_context"] = "trusted_sent"
                approved.append(sent_item)
                continue

            # Fresh DB / first-summary reconstruction can see older provider
            # conversation turns before those historical messages have local
            # MailMind rows. Do not silently reduce the task to the newest
            # locally indexed reply. For this INITIAL reconstruction only, run
            # the deterministic Security classifier first and admit only
            # clearly Safe/Promotional historical turns. Suspicious, Spam,
            # Phishing, Malware, Scam/Fraud, Impersonation, provider-Junk, and
            # ambiguous turns still fail closed. Existing-summary incremental
            # updates keep the stricter persisted-verdict-only path.
            if allow_historical_provider_safe:
                provider_location = str(
                    item.get("folder") or item.get("mail_folder") or item.get("parent_folder") or ""
                ).strip().casefold()
                provider_flagged = bool(
                    item.get("provider_spam") or item.get("is_spam")
                    or provider_location in {"spam", "junk", "junk email", "junkemail"}
                )
                if not provider_flagged:
                    verdict = detect_spam(item)
                    category = str(verdict.get("category") or "").strip()
                    if (
                        not bool(verdict.get("is_spam"))
                        and category in {"Safe / Misclassified", "Promotional"}
                    ):
                        historical_item = dict(item)
                        historical_item["security_category"] = category
                        historical_item["provider_spam"] = 0
                        historical_item["_mailmind_summary_context"] = "historical_provider_safe"
                        approved.append(historical_item)
                        continue

            uid = str(item.get("uid") or "").strip()
            if uid:
                excluded_uids.append(uid)
            continue

        if int(stored.get("security_input_version") or 0) < 2:
            uid = str(item.get("uid") or "").strip()
            if uid:
                excluded_uids.append(uid)
            continue

        eligibility = evaluate_summary_eligibility(
            stored,
            lifecycle_state="EXISTING",
            already_summarized=False,
        )
        if not eligibility.can_generate:
            uid = str(item.get("uid") or "").strip()
            if uid:
                excluded_uids.append(uid)
            continue

        approved_item = dict(item)
        # Preserve the current persisted Security/location metadata for tracing
        # and future deterministic checks without changing provider content.
        approved_item["security_category"] = str(stored.get("security_category") or "")
        approved_item["provider_spam"] = int(bool(stored.get("provider_spam")))
        approved.append(approved_item)

    filtered = _rebuild_summary_thread_email(thread_email, approved)
    filtered["excluded_summary_uids"] = list(dict.fromkeys(excluded_uids))
    return filtered
