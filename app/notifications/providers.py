"""
CyberDefense XDR
Multi-Channel Notification Providers (In-App, Email, Webhook)
"""

import json
import logging
import smtplib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

import requests
from flask import current_app

from app.extensions import db
from app.notifications.models import Notification
from app.notifications.utils import (
    generate_notification_id,
    compute_dedup_hash,
    validate_webhook_url,
    sanitize_notification_text,
)

logger = logging.getLogger(__name__)


class BaseNotificationProvider(ABC):
    """Abstract base provider for notification channels."""

    @abstractmethod
    def send(
        self,
        notification: Dict[str, Any],
        recipient: Any,
        **kwargs: Any,
    ) -> bool:
        """Dispatches notification to channel. Returns True on success, False on failure."""
        pass


class InAppProvider(BaseNotificationProvider):
    """
    Guaranteed In-App Notification Provider.
    Persists notification records to PostgreSQL with deduplication support.
    """

    def send(
        self,
        notification: Dict[str, Any],
        recipient: Any,
        dedup_window_minutes: int = 5,
        **kwargs: Any,
    ) -> bool:
        try:
            recipient_user_id = recipient.id if hasattr(recipient, "id") else int(recipient)
            category = notification.get("category", "SYSTEM")
            resource_type = notification.get("resource_type")
            resource_id = notification.get("resource_id")
            severity = notification.get("severity", "info")

            dedup_hash = compute_dedup_hash(
                recipient_user_id=recipient_user_id,
                category=category,
                resource_type=resource_type,
                resource_id=resource_id,
                severity=severity,
            )

            # Check if deduplication applies
            if dedup_window_minutes > 0 and (resource_id or resource_type):
                threshold_time = datetime.utcnow() - timedelta(minutes=dedup_window_minutes)
                existing = (
                    Notification.query.filter(
                        Notification.recipient_user_id == recipient_user_id,
                        Notification.dedup_hash == dedup_hash,
                        Notification.is_dismissed.is_(False),
                        Notification.created_at >= threshold_time,
                    )
                    .order_by(Notification.created_at.desc())
                    .first()
                )

                if existing:
                    existing.occurrence_count += 1
                    existing.updated_at = datetime.utcnow()
                    # Re-surface if it was already marked as read
                    existing.is_read = False
                    existing.read_at = None
                    db.session.commit()
                    logger.info(
                        f"Deduplicated notification {existing.notification_id} for user {recipient_user_id} (count: {existing.occurrence_count})"
                    )
                    return True

            # Create new notification record
            meta = notification.get("metadata") or {}
            meta_json = json.dumps(meta) if isinstance(meta, dict) else str(meta or "{}")

            new_notif = Notification(
                notification_id=generate_notification_id(),
                recipient_user_id=recipient_user_id,
                title=sanitize_notification_text(notification.get("title", "Security Notification")),
                message=sanitize_notification_text(notification.get("message", "")),
                category=category,
                severity=severity.lower(),
                source=notification.get("source", "System"),
                resource_type=resource_type,
                resource_id=resource_id,
                action_url=notification.get("action_url"),
                dedup_hash=dedup_hash,
                metadata_json=meta_json,
                expires_at=notification.get("expires_at"),
            )

            db.session.add(new_notif)
            db.session.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to persist In-App notification: {str(e)}", exc_info=True)
            db.session.rollback()
            return False


class EmailProvider(BaseNotificationProvider):
    """
    Fault-tolerant Email / SMTP Provider.
    Dispatches formatted security alert emails.
    Silently fails and logs if SMTP is unavailable or disabled.
    """

    def send(
        self,
        notification: Dict[str, Any],
        recipient: Any,
        **kwargs: Any,
    ) -> bool:
        recipient_email = getattr(recipient, "email", None)
        if not recipient_email and isinstance(recipient, str) and "@" in recipient:
            recipient_email = recipient

        if not recipient_email:
            logger.warning("EmailProvider: No valid recipient email provided.")
            return False

        # Check application config for SMTP settings
        config = current_app.config if current_app else {}
        smtp_enabled = config.get("SMTP_ENABLED", False)
        if not smtp_enabled:
            logger.debug("EmailProvider: SMTP is disabled in config. Skipping delivery.")
            return True

        host = config.get("SMTP_HOST", "localhost")
        port = config.get("SMTP_PORT", 587)
        user = config.get("SMTP_USER", "")
        password = config.get("SMTP_PASSWORD", "")
        use_tls = config.get("SMTP_USE_TLS", True)
        sender = config.get("SMTP_SENDER", "xdr-alerts@cyberdefense.local")

        title = notification.get("title", "CyberDefense XDR Alert")
        severity = notification.get("severity", "info").upper()
        message = notification.get("message", "")
        action_url = notification.get("action_url", "")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity}] {title}"
        msg["From"] = sender
        msg["To"] = recipient_email

        body_text = f"{title}\n\nSeverity: {severity}\n\n{message}\n\nLink: {action_url}"
        msg.attach(MIMEText(body_text, "plain"))

        try:
            with smtplib.SMTP(host, port, timeout=5) as server:
                if use_tls:
                    server.starttls()
                if user and password:
                    server.login(user, password)
                server.sendmail(sender, [recipient_email], msg.as_string())
            logger.info(f"Email sent successfully to {recipient_email}")
            return True
        except Exception as e:
            logger.error(f"EmailProvider: Delivery to {recipient_email} failed: {str(e)}")
            return False


class WebhookProvider(BaseNotificationProvider):
    """
    SSRF-Hardened Webhook Provider.
    Strictly validates destination IP and dispatches formatted webhook payloads.
    Never raises uncaught exceptions.
    """

    def send(
        self,
        notification: Dict[str, Any],
        recipient: Any = None,
        webhook_url: Optional[str] = None,
        **kwargs: Any,
    ) -> bool:
        target_url = webhook_url
        if not target_url and isinstance(recipient, str) and recipient.startswith("http"):
            target_url = recipient

        if not target_url:
            logger.warning("WebhookProvider: No webhook URL provided.")
            return False

        # Validate URL against SSRF attacks
        trusted_domains = kwargs.get("trusted_domains")
        is_safe, error = validate_webhook_url(target_url, trusted_domains=trusted_domains)
        if not is_safe:
            logger.warning(f"WebhookProvider: SSRF check rejected destination '{target_url}': {error}")
            return False

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CyberDefense-XDR-Notifier/1.0",
        }
        if "auth_token" in kwargs and kwargs["auth_token"]:
            headers["Authorization"] = f"Bearer {kwargs['auth_token']}"

        payload = {
            "event": "xdr_notification",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "notification": notification,
        }

        try:
            response = requests.post(
                target_url,
                json=payload,
                headers=headers,
                timeout=3.0,
                allow_redirects=False,  # Disallow redirects to prevent open-redirect SSRF bypasses
            )
            success = 200 <= response.status_code < 300
            if not success:
                logger.warning(
                    f"WebhookProvider: Endpoint returned HTTP {response.status_code} for {target_url}"
                )
            return success
        except Exception as e:
            logger.error(f"WebhookProvider: Delivery to {target_url} failed: {str(e)}")
            return False

