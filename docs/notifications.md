# Notifications Module

## Overview
The Notifications module is a multi-channel dispatcher for system alerts, security warnings, SOAR workflows, and operational updates. It offers robust routing, deduplication, quiet hours, user preferences, and in-app read tracking.

## Architecture

### Dispatching (`dispatch_notification`)
- **Recipient Resolution**: Finds target users via explicit ID, specific role string, or by an RBAC permission (`recipient_permission`). Defaults to Admins if no matches occur.
- **Fan-Out**: Iterates over resolved users, checking their `NotificationSettings`.
- **Quiet Hours**: Suspends external channels (Email, Webhook, Slack) if the current UTC time falls within the user's `quiet_hours_from` to `quiet_hours_to` interval—unless the event is `critical`.
- **Severity Threshold**: Drops external dispatch if the event severity is below the user's `min_severity` preference.

### Channels / Providers
- **InAppProvider**: Guaranteed persistence to PostgreSQL. Computes a deterministic SHA-256 deduplication hash based on recipient, category, resource, and severity. If an identical event occurs within `dedup_window_minutes`, it increments `occurrence_count` and resurfaces the event rather than creating a duplicate.
- **EmailProvider**: Connects to SMTP (if `SMTP_ENABLED`) and delivers multi-part emails. Silently fails/logs if the service is unreachable.
- **WebhookProvider**: SSRF-hardened dispatcher. Validates target URLs against local/private network ranges and trusted domains. Delivers a standard JSON payload (`{"event": "xdr_notification", ...}`).

### User Preferences
Users manage their notification thresholds and channels via `/api/preferences` (backed by `NotificationSettings` model):
- Enable/disable Email, Slack, SMS, Webhook channels.
- `min_severity` mapping.
- Quiet hours toggles and windows.
- Any update creates an `UPDATE_NOTIFICATION_PREFERENCES` audit log.

## Endpoints
- **Navbar Integration**: 
  - `/api/count` continuously fetched for the unread badge.
  - `/api/unread` fetched for a dropdown preview of latest alerts.
- **Inbox Management**: 
  - `/api` provides paginated access.
  - Action APIs: `/api/<id>/read`, `/api/read-all`, `/api/<id>/dismiss`.

## Data Models

### Notification
- **Metadata**: `notification_id` (public UUID), `title`, `message`, `category`, `severity`, `source`, `resource_type`, `resource_id`, `action_url`, `metadata_json`.
- **Deduplication**: `dedup_hash`, `occurrence_count`.
- **Tracking**: `is_read`, `read_at`, `is_dismissed`, `dismissed_at`, `expires_at`.

## Security Features
- **IDOR Protection**: The `get_notification_by_id` checks user ID ownership unless the requesting user holds Admin (`*`) permissions.
- **Sanitization**: All titles and messages are run through `sanitize_notification_text` to strip unprintable control characters.
- **SSRF Defense**: Loopback, RFC 1918, link-local, and broadcast IPs are blocked by the Webhook provider.

## Limitations / Notes
- Slack/SMS are configured structurally in `NotificationSettings` but actual `SlackProvider`/`SMSProvider` logic defaults to stub implementations/webhooks.
- Quiet hours evaluate against server UTC time, not user localized timezones.
