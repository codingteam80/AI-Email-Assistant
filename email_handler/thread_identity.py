# Provider-neutral thread identity derived from explicit reply metadata.
import re


_MESSAGE_ID = re.compile(r"<[^>]+>")


def message_ids(value: str) -> list[str]:
    # Return normalized RFC Message-IDs while preserving header order.
    text = str(value or "")
    found = [item.casefold() for item in _MESSAGE_ID.findall(text)]
    if not found and text.strip():
        found = [text.strip().casefold()]
    return found


def canonical_thread_id(item: dict) -> str:
    # Map Outlook and RFC/IMAP metadata to one stable application thread key.
    #
    # Gmail's native thread ID and Outlook's Graph conversationId are
    # authoritative. Yahoo and other IMAP providers use the oldest ID in
    # References, then In-Reply-To, then the message's own Message-ID. Messages
    # without explicit thread metadata receive an isolated local key; subject
    # similarity is intentionally never sufficient to merge unrelated messages.
    existing = str(item.get("canonical_thread_id") or "").strip()
    if existing:
        return existing

    gmail_thread_id = str(item.get("gmail_thread_id") or "").strip()
    if gmail_thread_id:
        return f"gmail:{gmail_thread_id.casefold()}"

    conversation_id = str(item.get("conversation_id") or "").strip()
    if conversation_id:
        return f"outlook:{conversation_id.casefold()}"

    references = message_ids(item.get("reference_ids") or item.get("references", ""))
    if references:
        return f"rfc822:{references[0]}"
    parents = message_ids(item.get("in_reply_to", ""))
    if parents:
        return f"rfc822:{parents[0]}"
    own_ids = message_ids(item.get("message_id", ""))
    if own_ids:
        return f"rfc822:{own_ids[0]}"

    uid = str(item.get("uid") or "").strip()
    return f"local:{uid}" if uid else ""


