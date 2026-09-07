# Email service: fetch, parse, cache, search, and one-time full sync.
from email_handler.email_parser import parse_email
from services.deletion_detection_service import reconcile_folder


def refresh_inbox(client, limit: int, offset: int = 0, refresh: bool = False,
                   store=None, folder: str = "INBOX", sync_source: str = "page",
                   reconcile: bool = False) -> dict:
    # Fetch one inbox page and save it when a store is provided.
    try:
        page = client.fetch_inbox(
            folder=folder,
            limit=limit,
            offset=offset,
            refresh=refresh,
            include_thread_counts=sync_source not in {"initial_page", "full_sync"},
        )
        parsed = [parse_email(item["raw"], uid=item["uid"]) for item in page["emails"]]
        result = {
            "success": True,
            "emails": parsed,
            "total": page["total"],
            "has_more": page["has_more"],
            "missing_uids": [],
            "remote_uids": [],
        }
        if store is not None and parsed:
            try:
                store.save_page(folder, parsed, source=sync_source)
            except Exception as store_error:
                result["store_error"] = str(store_error)
        if store is not None and reconcile:
            reconciliation = reconcile_folder(client, store, folder)
            if not reconciliation.success:
                raise RuntimeError(
                    f"Could not reconcile mailbox deletions: "
                    f"{reconciliation.error}"
                )
            result["missing_uids"] = reconciliation.missing_uids
            result["remote_uids"] = reconciliation.remote_uids
        return result
    except Exception as error:
        return {"success": False, "error": str(error)}



def refresh_security_changes(
    client, known_uids, store, folder: str, page_size: int = 250, max_pages: int = 20
) -> dict:
    # Fetch only messages that are new to the local Inbox + Spam/Junk view.
    # Providers inspect Inbox and Spam/Junk independently, so custom/archive
    # folders are never scanned by the normal mailbox monitor.
    try:
        fetch_recent = getattr(client, "fetch_recent_security_headers", None)
        if not callable(fetch_recent):
            return {"success": False, "error": "Security mailbox delta fetch is unavailable."}
        page = fetch_recent(
            known_uids, page_size=page_size, max_pages=max_pages
        )
        parsed = [
            parse_email(item["raw"], uid=item["uid"])
            for item in page.get("emails", [])
        ]
        if parsed:
            store.save_page(folder, parsed, source="automatic_mailbox_monitor")
        return {
            "success": True,
            "emails": parsed,
            "new_uids": {str(item.get("uid") or "") for item in parsed if str(item.get("uid") or "")},
            "total": int(page.get("total", 0) or 0),
        }
    except Exception as error:
        return {"success": False, "error": str(error)}

def load_cached_inbox(
    store,
    limit: int,
    offset: int = 0,
    folder: str = "INBOX",
    filter_key: str = "all",
    arrange_by: str = "date",
    sort_order: str = "newest",
    unread_uids=None,
    query: str = "",
    security_category: str = "all",
    security_detected_only: bool = False,
) -> dict:
    # Load one filtered/sorted page directly from SQLite; no mail request.
    try:
        page = store.get_page(
            folder,
            limit=limit,
            offset=offset,
            filter_key=filter_key,
            arrange_by=arrange_by,
            sort_order=sort_order,
            unread_uids=unread_uids,
            query=query,
            security_category=security_category,
            security_detected_only=security_detected_only,
        )
        return {"success": True, **page}
    except Exception as error:
        return {"success": False, "error": str(error)}


def get_full_email(
    client, uid: str, folder: str = "INBOX", store=None, *, force_remote: bool = False
) -> dict:
    # Return a cached full message when available; otherwise fetch it once.
    # Security preclassification can request a one-time remote copy so provider
    # authentication headers are available even when the cached body is full.
    try:
        if store is not None and not force_remote:
            cached = store.get_email(folder, uid)
            if cached and cached.get("is_full"):
                cached["attachments"] = store.get_attachments(folder, uid)
                return {"success": True, "email": cached}

        raw = client.fetch_single(folder, uid)
        if not raw:
            return {
                "success": False,
                "missing": True,
                "error": "Message not found (it may have been deleted or moved).",
            }
        parsed = parse_email(raw, uid=uid)
        result = {"success": True, "email": parsed}
        if store is not None:
            try:
                store.save_full(folder, parsed)
            except Exception as store_error:
                result["store_error"] = str(store_error)
        return result
    except Exception as error:
        return {"success": False, "error": str(error)}


# Search saved emails for the current account.
def search_inbox(store, query: str, folder: str = "INBOX",
                  limit: int = 200) -> dict:
    try:
        result = store.search_emails(folder, query, limit=limit)
        return {"success": True, **result}
    except Exception as error:
        return {"success": False, "error": str(error)}


def sync_all_inbox(client, store, folder: str = "INBOX", page_size: int = 100,
                    progress_callback=None) -> dict:
    # Save the full mailbox once and reuse the same remote snapshot for deletion
    # reconciliation. For the provider-neutral ALL_MAIL view, clients can expose
    # iter_security_pages() so first login scans Inbox + Spam/Junk only instead
    # of archive/custom folders or the whole Outlook mailbox.
    synced = 0
    total = 0
    remote_uids = []
    seen_uids = set()
    bulk_sync_started = False
    store.mark_sync_started(folder)

    begin_bulk_sync = getattr(client, "begin_full_sync", None)
    finish_bulk_sync = getattr(client, "finish_full_sync", None)
    cancel_bulk_sync = getattr(client, "cancel_full_sync", None)
    if callable(begin_bulk_sync):
        begin_bulk_sync(folder)
        bulk_sync_started = True

    try:
        security_iterator = getattr(client, "iter_security_pages", None)
        use_security_iterator = (
            str(folder or "").upper() == str(getattr(client, "ALL_MAIL", "")).upper()
            and callable(security_iterator)
        )

        if use_security_iterator:
            total = int(client.get_message_count(folder) or 0)
            for raw_page in security_iterator(page_size=page_size):
                parsed = [
                    parse_email(item["raw"], uid=item["uid"])
                    for item in raw_page
                ]
                if parsed:
                    store.save_page(folder, parsed, source="full_sync")
                for item in raw_page:
                    uid = str(item.get("uid") or "")
                    if uid and uid not in seen_uids:
                        seen_uids.add(uid)
                        remote_uids.append(uid)
                synced += len(parsed)
                if progress_callback is not None:
                    progress_callback(synced, max(total, synced))
        else:
            offset = 0
            while True:
                result = refresh_inbox(
                    client,
                    limit=page_size,
                    offset=offset,
                    refresh=(offset == 0),
                    store=store,
                    folder=folder,
                    sync_source="full_sync",
                )
                if not result["success"]:
                    raise RuntimeError(result["error"])

                total = max(int(result.get("total", 0) or 0), total)
                batch_count = len(result["emails"])
                synced += batch_count
                for email_data in result["emails"]:
                    uid = str(email_data.get("uid") or "")
                    if uid and uid not in seen_uids:
                        seen_uids.add(uid)
                        remote_uids.append(uid)

                if progress_callback is not None:
                    progress_callback(synced, max(total, synced))

                if not result["has_more"] or batch_count == 0:
                    break
                offset += batch_count

        thread_counts = {}
        if bulk_sync_started and callable(finish_bulk_sync):
            thread_counts = finish_bulk_sync() or {}
            bulk_sync_started = False
        if thread_counts and hasattr(store, "update_provider_thread_counts"):
            store.update_provider_thread_counts(folder, thread_counts)

        missing_uids = store.reconcile_remote_uids(folder, remote_uids)
    except Exception as error:
        store.mark_sync_failed(folder, str(error), synced)
        return {
            "success": False,
            "error": str(error),
            "synced": synced,
            "total": total,
            "missing_uids": [],
            "remote_uids": [],
        }
    finally:
        if bulk_sync_started and callable(cancel_bulk_sync):
            cancel_bulk_sync()

    total = max(total, synced)
    store.mark_sync_complete(folder, total, synced)
    return {
        "success": True,
        "synced": synced,
        "total": total,
        "missing_uids": missing_uids,
        "remote_uids": remote_uids,
    }
