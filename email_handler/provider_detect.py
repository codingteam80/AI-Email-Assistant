# Detects IMAP server settings for an arbitrary email address.
#
# Lookup order:
#   1. KNOWN_PROVIDERS in config.py (exact domain match).
#   2. DNS SRV record for _imaps._tcp.<domain> (RFC 6186 autoconfig).
#   3. Conventional guess: imap.<domain>:993, verified with a live probe.
import socket
import ssl
from typing import Optional, Dict

from config import KNOWN_PROVIDERS, PROVIDER_DETECTION_CONNECT_TIMEOUT_SECONDS



# Extract the domain from an email address.
def _domain_of(email_address: str) -> Optional[str]:
    if not email_address or "@" not in email_address:
        return None
    return email_address.rsplit("@", 1)[-1].strip().lower()


def _probe(server: str, port: int) -> bool:
    # Return True if server:port answers with a valid IMAP TLS banner.
    try:
        with socket.create_connection((server, port), timeout=PROVIDER_DETECTION_CONNECT_TIMEOUT_SECONDS) as sock:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=server) as tls:
                banner = tls.recv(64)
                return banner.startswith(b"* OK")
    except Exception:
        return False


def _srv_lookup(domain: str) -> Optional[Dict]:
    # Try the RFC 6186 IMAP-over-TLS autoconfig SRV record.
    try:
        import dns.resolver  # Skip DNS lookup when the package is unavailable.
        answers = dns.resolver.resolve(f"_imaps._tcp.{domain}", "SRV")
        best = sorted(answers, key=lambda r: (r.priority, r.weight))[0]
        return {"server": str(best.target).rstrip("."), "port": int(best.port)}
    except Exception:
        return None


def detect_provider(email_address: str) -> Dict:
    # Resolve IMAP settings for an email address.
    #
    # Returns:
    #     {"supported": bool, "server": str|None, "port": int|None,
    #      "source": "known" | "srv" | "guessed" | None}
    domain = _domain_of(email_address)
    if not domain:
        return {"supported": False, "server": None, "port": None, "source": None}

    if domain in KNOWN_PROVIDERS:
        cfg = KNOWN_PROVIDERS[domain]
        return {"supported": True, "server": cfg["server"], "port": cfg["port"], "source": "known"}

    srv = _srv_lookup(domain)
    if srv and _probe(srv["server"], srv["port"]):
        return {"supported": True, "server": srv["server"], "port": srv["port"], "source": "srv"}

    guess_server = f"imap.{domain}"
    if _probe(guess_server, 993):
        return {"supported": True, "server": guess_server, "port": 993, "source": "guessed"}

    return {"supported": False, "server": None, "port": None, "source": None}