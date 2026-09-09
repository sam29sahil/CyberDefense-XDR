"""
CyberDefense XDR
Notifications Utilities & Security Safeguards
"""

import hashlib
import ipaddress
import re
import socket
import urllib.parse
import uuid
from typing import Optional, Tuple, List


def generate_notification_id() -> str:
    """Generates cryptographically unique identifier for a notification."""
    return f"NOTIF-{uuid.uuid4().hex[:10].upper()}"


def compute_dedup_hash(
    recipient_user_id: int,
    category: str,
    resource_type: Optional[str],
    resource_id: Optional[str],
    severity: str,
) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for deduplication.
    Identical notifications within the dedup window can coalesce into count increments.
    """
    raw = (
        f"{recipient_user_id}:"
        f"{(category or '').strip().upper()}:"
        f"{(resource_type or '').strip().lower()}:"
        f"{(resource_id or '').strip()}:"
        f"{(severity or '').strip().lower()}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_webhook_url(
    url: str, trusted_domains: Optional[List[str]] = None
) -> Tuple[bool, Optional[str]]:
    """
    Strict SSRF validation for outgoing webhook destinations.
    Rejects:
    - Non-HTTP(S) schemes
    - Loopback addresses (127.0.0.0/8, ::1, localhost)
    - RFC 1918 Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Cloud metadata / Link-local addresses (169.254.0.0/16, fe80::/10)
    - Multicast, Unspecified (0.0.0.0, ::), and Reserved ranges
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."

    url = url.strip()
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Malformed URL format: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "Target URL is missing a valid hostname."

    hostname_clean = hostname.strip().lower()

    # Disallow known localhost/internal naming patterns
    if hostname_clean in ("localhost", "localhost.localdomain", "broadcasthost", "127.0.0.1", "::1"):
        return False, "Requests to localhost/loopback destinations are prohibited."

    if hostname_clean.endswith(".local") or hostname_clean.endswith(".internal"):
        return False, "Requests to internal TLDs are prohibited."

    # If an explicit trusted domains whitelist is provided and non-empty:
    if trusted_domains:
        trusted_matches = any(
            hostname_clean == td.lower() or hostname_clean.endswith("." + td.lower())
            for td in trusted_domains
        )
        if not trusted_matches:
            return False, f"Destination domain '{hostname_clean}' is not in the trusted webhook domains list."

    # Resolve hostname to IP addresses and verify none are private/loopback/cloud metadata
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"Failed to resolve hostname '{hostname}': {str(e)}"
    except Exception as e:
        return False, f"DNS resolution error: {str(e)}"

    if not addr_info:
        return False, f"Could not resolve any IP address for host '{hostname}'."

    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Resolved address '{ip_str}' is not a valid IP."

        # Reject loopback, private, link-local, multicast, unspecified, reserved
        if ip.is_loopback:
            return False, f"Destination resolves to loopback IP ({ip_str}), which is blocked for security."
        if ip.is_private:
            return False, f"Destination resolves to private network IP ({ip_str}), which is blocked for security."
        if ip.is_link_local:
            return False, f"Destination resolves to link-local IP ({ip_str}), which is blocked for security."
        if ip.is_multicast:
            return False, f"Destination resolves to multicast IP ({ip_str}), which is blocked for security."
        if ip.is_unspecified:
            return False, f"Destination resolves to unspecified IP ({ip_str}), which is blocked for security."
        if ip.is_reserved:
            return False, f"Destination resolves to reserved IP ({ip_str}), which is blocked for security."

    return True, None


def sanitize_notification_text(value: str) -> str:
    """Sanitizes text to prevent injection or malformed control characters."""
    if not value:
        return ""
    val_str = str(value).strip()
    # Strip null bytes and non-printable control chars except newlines and tabs
    clean = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", val_str)
    return clean

