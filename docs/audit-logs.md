# Audit Logs

## Overview
The Audit Logs module implements a tamper-resistant, structured record system for administrative, authentication, security, and operational compliance events.

## Architecture & Service Logic

### `record_audit_event`
The primary ingestion service for logging an event.
- **Auto-enrichment**: Grabs `actor` (username) and `actor_id` from the Flask `current_user` if available, otherwise assumes "System". 
- **Context parsing**: Uses `get_client_ip` and `get_user_agent` to extract network attribution, resolving `X-Forwarded-For` proxy headers when applicable.
- **Sanitization**: Payloads pushed into `details` are scrubbed by `sanitize_audit_details`. Any key matching `password`, `secret`, `token`, `api_key`, `auth`, `hash`, or `session` has its value replaced with `[REDACTED]`.
- **SIEM Sync**: If `sync_to_siem` is True, it automatically mirrors the audit event into the XDR SIEM pipeline (`SiemEvent`) for unified operational telemetry.

### Querying and Analytics
- **`list_audit_logs`**: Provides paginated search across text fields and filters (category, result, severity, action).
- **`get_audit_statistics`**: Returns live scalar counts and category distributions (e.g. `total_events`, `authentication_failures`, `events_today`) directly backed by SQL aggregations.

### Export System
- **CSV Export**: Exposes `/api/export` generating RFC 4180 compliant CSVs.
- **CSV Injection Defense**: Cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r` are prefixed with an apostrophe (`'`) via `sanitize_csv_cell` to neutralize Excel formula injection execution vulnerabilities.

## Data Models

### AuditLog
- **Identifiers**: `id` (int), `audit_id` (UUID format, `AUD-XXXXXXXXXX`).
- **Context**: `timestamp`, `actor`, `actor_id` (FK to users).
- **Action Info**: `action`, `category`, `resource_type`, `resource_id`.
- **Status**: `result` (e.g. SUCCESS, FAILURE, DENIED), `severity` (info, low, medium, high, critical).
- **Network Data**: `source_ip`, `user_agent`.
- **Content**: `message`, `details_json` (extensible JSON store for parameters).

## Supported Categories & Events
Categories tracked include:
Authentication, Authorization, User Management, Alert Center, Incident Response, Detection Engine, Asset Management, Vulnerability Scanner, Network IDS, Threat Intelligence, Threat Hunting, Correlation, AI Assistant, SOAR, Reports, and Settings.

## Limitations / Notes
- The logs are stored in a standard relational table. In ultra-high throughput environments, standard row insertion may bottleneck. Currently designed for B.Tech workload volumes.
- There is no automated data archival/rotation built-in; records persist indefinitely.
