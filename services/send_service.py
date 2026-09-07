# Provider-aware outbound reply delivery.
from email.message import EmailMessage
from email.utils import parseaddr
from email_handler.thread_identity import message_ids
import smtplib
import ssl

from config import MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS
from email_handler.outbound_format import normalize_plain_text, plain_text_to_html


_SMTP_BY_IMAP = {
    "imap.gmail.com": ("smtp.gmail.com", 465),
    "imap.mail.yahoo.com": ("smtp.mail.yahoo.com", 465),
    "imap.mail.me.com": ("smtp.mail.me.com", 587),
    "imap.aol.com": ("smtp.aol.com", 465),
    "imap.zoho.com": ("smtp.zoho.com", 465),
    "imap.gmx.com": ("mail.gmx.com", 465),
}


def _smtp_settings(imap_server: str) -> tuple[str, int]:
    server = str(imap_server or "").strip().casefold()
    if server in _SMTP_BY_IMAP:
        return _SMTP_BY_IMAP[server]
    if server.startswith("imap."):
        return "smtp." + server.removeprefix("imap."), 465
    raise RuntimeError(
        "SMTP settings could not be inferred for this custom mail server."
    )


def _reply_subject(subject: str) -> str:
    subject = str(subject or "").strip() or "(No Subject)"
    return subject if subject.casefold().startswith("re:") else f"Re: {subject}"


def _build_smtp_message(
    account_address: str,
    recipient: str,
    subject: str,
    body: str,
    *,
    message_id: str = "",
    references: str = "",
    attachments: list[dict] | None = None,
) -> EmailMessage:
    # Build multipart email so both plain-text and HTML clients keep spacing.
    message = EmailMessage()
    message["From"] = account_address
    message["To"] = recipient
    message["Subject"] = _reply_subject(subject)
    parent_ids = message_ids(message_id)
    if parent_ids:
        message["In-Reply-To"] = parent_ids[-1]
        reference_chain = message_ids(references)
        for parent_id in parent_ids:
            if parent_id not in reference_chain:
                reference_chain.append(parent_id)
        message["References"] = " ".join(reference_chain)
    message.set_content(body)
    message.add_alternative(plain_text_to_html(body), subtype="html")
    for attachment in attachments or []:
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
    return message


def send_reply(client, summary: dict, body: str, *, attachments: list[dict] | None = None) -> None:
    # Send an edited draft through Graph or the signed-in account's SMTP server.
    body = normalize_plain_text(body)
    if not body:
        raise ValueError("The reply cannot be empty.")

    uid = str(summary.get("uid", ""))
    if hasattr(client, "send_reply"):
        client.send_reply(
            uid,
            body,
            attachments=attachments or [],
            subject=summary.get("subject", ""),
            recipient=parseaddr(summary.get("from", ""))[1],
        )
        return

    sender_address = parseaddr(summary.get("from", ""))[1]
    account_address = str(getattr(client, "email_address", "") or "").strip()
    password = getattr(client, "password", None)
    if not sender_address:
        raise ValueError("The sender email address is unavailable.")
    if not account_address or not password:
        raise RuntimeError("The signed-in account cannot authenticate an SMTP reply.")

    smtp_server, smtp_port = _smtp_settings(getattr(client, "server", ""))
    message = _build_smtp_message(
        account_address,
        sender_address,
        summary.get("subject", ""),
        body,
        message_id=summary.get("message_id", ""),
        references=summary.get("reference_ids") or summary.get("references", ""),
        attachments=attachments or [],
    )

    context = ssl.create_default_context()
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS) as smtp:
            smtp.login(account_address, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=MAIL_PROVIDER_NETWORK_TIMEOUT_SECONDS) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(account_address, password)
            smtp.send_message(message)
