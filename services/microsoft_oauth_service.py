# Microsoft Graph OAuth support for the Streamlit Outlook login.
#
# This module uses the authorization-code flow for a confidential web app.  The
# resulting delegated Microsoft Graph token is then used by GraphMailClient to
# read the signed-in user's Inbox and send replies with Mail.Read and Mail.Send.
from __future__ import annotations

import base64
import time
from threading import Lock
from typing import Any, Dict, Optional

import requests

from email_handler.graph_client import GraphMailClient
from email_handler.provider_factory import create_graph_client


class MicrosoftOAuthError(RuntimeError):
    # Raised when Microsoft authorization cannot be started or completed.
    pass


class MicrosoftGraphTokenProvider:
    # Own an MSAL confidential client and silently renew Graph access tokens.

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        authority: str,
        redirect_uri: str,
        scopes: list[str],
    ):
        client_id = (client_id or "").strip()
        client_secret = (client_secret or "").strip()
        authority = (authority or "").strip()
        redirect_uri = (redirect_uri or "").strip()
        scopes = [str(scope).strip() for scope in scopes if str(scope).strip()]

        missing = []
        if not client_id:
            missing.append("MICROSOFT_CLIENT_ID")
        if not client_secret:
            missing.append("MICROSOFT_CLIENT_SECRET")
        if not authority:
            missing.append("MICROSOFT_AUTHORITY")
        if not redirect_uri:
            missing.append("MICROSOFT_REDIRECT_URI")
        if not scopes:
            missing.append("MICROSOFT_SCOPES")
        if missing:
            raise MicrosoftOAuthError(
                "Microsoft Graph OAuth is incomplete. Missing: " + ", ".join(missing)
            )

        try:
            import msal
        except ImportError as error:
            raise MicrosoftOAuthError(
                "The 'msal' package is missing. Run: pip install -r requirements.txt"
            ) from error

        self.client_id = client_id
        self.client_secret = client_secret
        self.authority = authority
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self._lock = Lock()
        self._cache = msal.SerializableTokenCache()
        self._app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority,
            token_cache=self._cache,
        )
        self._account: Optional[Dict[str, Any]] = None
        self._access_token = ""
        self._access_token_expires_at = 0.0

    def initiate_authorization_code_flow(self) -> Dict[str, Any]:
        # Create a state- and PKCE-protected Microsoft authorization request.
        flow = self._app.initiate_auth_code_flow(
            scopes=self.scopes,
            redirect_uri=self.redirect_uri,
            prompt="select_account",
        )
        if not flow.get("auth_uri") or not flow.get("state"):
            message = flow.get("error_description") or flow.get("error")
            raise MicrosoftOAuthError(
                f"Could not start Microsoft sign-in: {message or 'unknown error'}"
            )
        return flow

    def complete_authorization_code_flow(
        self,
        flow: Dict[str, Any],
        auth_response: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Exchange the callback code, verify Graph access, and build a client.
        try:
            result = self._app.acquire_token_by_auth_code_flow(
                flow,
                auth_response,
            )
        except ValueError as error:
            raise MicrosoftOAuthError(
                "Microsoft sign-in could not be validated. Start the login again."
            ) from error

        access_token = result.get("access_token")
        if not access_token:
            description = result.get("error_description") or result.get("error")
            raise MicrosoftOAuthError(
                _friendly_microsoft_error(description or "Microsoft sign-in failed.")
            )

        self._remember_token(result)
        accounts = self._app.get_accounts()
        if accounts:
            self._account = accounts[0]

        client = create_graph_client(self)
        try:
            profile = client.connect()
        except Exception as error:
            raise MicrosoftOAuthError(
                "Microsoft sign-in succeeded, but Microsoft Graph could not open "
                f"the mailbox. Technical detail: {error}"
            ) from error

        email_address = (
            str(profile.get("mail") or "").strip()
            or str(profile.get("userPrincipalName") or "").strip()
            or _email_from_token_result(result)
        )
        if "@" not in email_address:
            raise MicrosoftOAuthError(
                "Microsoft signed in, but the mailbox email address was not returned."
            )

        return {
            "client": client,
            "email_address": email_address,
            "profile_image_url": _load_profile_image(client),
        }

    def get_access_token(self, force_refresh: bool = False) -> str:
        # Return a valid Graph token, silently refreshing it when necessary.
        with self._lock:
            if (
                not force_refresh
                and self._access_token
                and time.time() < self._access_token_expires_at
            ):
                return self._access_token

            account = self._account
            if account is None:
                accounts = self._app.get_accounts()
                account = accounts[0] if accounts else None
                self._account = account

            if account is None:
                raise ConnectionError(
                    "Microsoft authorization is unavailable. Sign in with Microsoft again."
                )

            result = self._app.acquire_token_silent(
                self.scopes,
                account=account,
                force_refresh=force_refresh,
            )
            token = result.get("access_token") if result else None
            if token:
                self._remember_token(result)
                return self._access_token

            description = (result or {}).get("error_description")
            raise ConnectionError(
                _friendly_microsoft_error(
                    description
                    or "Microsoft authorization expired. Sign in with Microsoft again."
                )
            )

    def _remember_token(self, result: Dict[str, Any]) -> None:
        self._access_token = str(result.get("access_token") or "")
        try:
            expires_in = max(int(result.get("expires_in", 0)), 0)
        except (TypeError, ValueError):
            expires_in = 0
        self._access_token_expires_at = time.time() + max(expires_in - 60, 0)


def _email_from_token_result(result: Dict[str, Any]) -> str:
    claims = result.get("id_token_claims") or {}
    for key in ("preferred_username", "email", "upn"):
        value = str(claims.get(key) or "").strip()
        if "@" in value:
            return value
    return ""


def _load_profile_image(client: GraphMailClient) -> str:
    try:
        response = client.request_raw("GET", "/me/photo/$value", allow_not_found=True)
    except Exception:
        return ""
    if response is None or not response.content:
        return ""
    content_type = response.headers.get("Content-Type", "image/jpeg")
    encoded = base64.b64encode(response.content).decode("ascii")
    return f"data:{content_type};base64,{encoded}"


def _friendly_microsoft_error(message: str) -> str:
    text = str(message or "").strip()
    lowered = text.lower()
    if "access_denied" in lowered or "authorization_declined" in lowered:
        return "Microsoft sign-in was cancelled or mailbox permission was declined."
    if "aadsts50011" in lowered or "redirect uri" in lowered:
        return (
            "The Microsoft redirect URI does not match. In Entra, register exactly: "
            "http://localhost:8501"
        )
    if "aadsts7000215" in lowered or "invalid client secret" in lowered:
        return "The Microsoft client secret is invalid. Copy the secret Value, not its ID."
    if "aadsts7000222" in lowered or "expired" in lowered and "secret" in lowered:
        return "The Microsoft client secret has expired. Create a new secret Value."
    if "invalid_client" in lowered:
        return "The Microsoft Application (client) ID or client secret is invalid."
    if "consent" in lowered:
        return (
            "Microsoft mailbox permission was not approved. Approve Mail.Read and "
            "Mail.Send and try again."
        )
    return text or "Microsoft sign-in failed."
