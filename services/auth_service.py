# Auth service: validation + connection logic for any IMAP provider.

import re

from email_handler.provider_factory import create_imap_client
from email_handler.provider_detect import detect_provider


_LOCAL_PART_PATTERN = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


_MICROSOFT_PASSWORD_DOMAINS = {"outlook.com", "hotmail.com", "live.com"}


def is_valid_email_address(email_address: str) -> bool:
    # Return True only for a complete email address with a dotted domain.
    #
    # This intentionally rejects incomplete addresses such as ``name@gmail`` while
    # still allowing normal domains such as ``.com``, ``.ph``, ``.org``, and
    # multi-part domains such as ``.com.ph``.
    email_address = (email_address or "").strip()

    if not email_address or len(email_address) > 254 or email_address.count("@") != 1:
        return False

    local_part, domain = email_address.rsplit("@", 1)
    if not local_part or not domain or len(local_part) > 64:
        return False

    if (
        local_part.startswith(".")
        or local_part.endswith(".")
        or ".." in local_part
        or not _LOCAL_PART_PATTERN.fullmatch(local_part)
    ):
        return False

    labels = domain.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False

    if not all(_DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
        return False

    top_level_domain = labels[-1]
    return len(top_level_domain) >= 2 and not top_level_domain.isdigit()


def login(email_address: str, password: str, server: str = None, port: int = None) -> dict:
    # Validate the account and connect to its IMAP server.
    email_address = (email_address or "").strip()

    if not is_valid_email_address(email_address):
        return {
            "success": False,
            "error": "Enter a complete email address, such as name@example.com.",
        }

    if not password:
        return {
            "success": False,
            "error": "Please enter your password.",
        }

    domain = email_address.rsplit("@", 1)[-1].lower()
    if domain in _MICROSOFT_PASSWORD_DOMAINS:
        return {
            "success": False,
            "error": (
                "Outlook.com requires OAuth2. Use the 'Continue with Microsoft' "
                "button instead of an app password."
            ),
            "field": "microsoft_oauth",
        }

    if server is None or port is None:
        detected = detect_provider(email_address)
        if not detected["supported"]:
            return {
                "success": False,
                "error": "Couldn't find this account",
                "field": "email",
            }
        server, port = detected["server"], detected["port"]

    try:
        client = create_imap_client(server, port, email_address, password)
        client.connect()
        return {"success": True, "client": client}
    except Exception as e:
        return {"success": False, "error": f"Login failed: {e}"}


def logout(client) -> None:
    # Disconnect the IMAP client when one exists.
    if client:
        client.disconnect()
