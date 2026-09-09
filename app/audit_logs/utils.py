"""
CyberDefense XDR
Audit Logs Utilities
Provides security sanitization (credential scrubbing, CSV injection defense),
unique identifier generation, and client request context extractors.
"""

import re
import uuid
from typing import Any, Dict, List, Optional
from flask import request, has_request_context

SENSITIVE_PATTERNS = [
    re.compile(r"passw(or)?d", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth(orization)?", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"hash", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
]


def generate_audit_id() -> str:
    """Generates an 8-10 character cryptographically unique audit identifier."""
    return f"AUD-{uuid.uuid4().hex[:10].upper()}"


def sanitize_audit_details(data: Any) -> Any:
    """
    Recursively scrubs sensitive keys, tokens, and secrets from audit payloads.
    Ensures no passwords, API keys, session tokens, or hashes are persisted.
    """
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_str = str(k)
            # Check if key matches sensitive patterns
            if any(p.search(k_str) for p in SENSITIVE_PATTERNS):
                sanitized[k_str] = "[REDACTED]"
            else:
                sanitized[k_str] = sanitize_audit_details(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_audit_details(item) for item in data]
    elif isinstance(data, tuple):
        return tuple(sanitize_audit_details(item) for item in data)
    elif isinstance(data, (str, int, float, bool)) or data is None:
        return data
    else:
        return str(data)


def get_client_ip(req=None) -> str:
    """Extracts client IP address safely considering proxies and load balancers."""
    r = req or (request if has_request_context() else None)
    if not r:
        return "127.0.0.1"

    forwarded = r.headers.get("X-Forwarded-For")
    if forwarded:
        # First IP in chain is the original client IP
        return forwarded.split(",")[0].strip()
    return r.remote_addr or "127.0.0.1"


def get_user_agent(req=None) -> str:
    """Extracts client user agent string truncated to 255 chars."""
    r = req or (request if has_request_context() else None)
    if not r or not hasattr(r, "user_agent"):
        return "Internal Service"
    ua = str(r.user_agent.string or "")
    return ua[:255] if ua else "Internal Service"


def sanitize_csv_cell(value: Any) -> str:
    """
    Prevents CSV Injection (Formula Injection) attacks.
    Prefixes values starting with '=', '+', '-', '@', '\t', '\r' with an apostrophe.
    """
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str

