# Create the provider-specific mailbox client used by the shared controllers.
from email_handler.graph_client import GraphMailClient
from email_handler.imap_client import IMAPClient


def create_imap_client(
    server: str,
    port: int,
    email_address: str,
    password: str,
) -> IMAPClient:
    # Create the existing IMAP client for Gmail and other IMAP providers.
    return IMAPClient(server, port, email_address, password)


def create_graph_client(token_provider) -> GraphMailClient:
    # Create the Microsoft Graph client for Outlook/Microsoft accounts.
    return GraphMailClient(token_provider)
