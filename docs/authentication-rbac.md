# Authentication & Role-Based Access Control (RBAC)

## Overview
CyberDefense XDR includes a robust authentication and authorization system enforcing secure session handling, rate limiting, and Role-Based Access Control (RBAC). It includes specialized defenses against credential stuffing, brute-force attacks, and user enumeration.

## Authentication Flows

### Login (`/login`)
- Accepts `email` and `password`.
- Brute-force rate limiting: 5 failed attempts per IP+Email block access for 15 minutes (in-memory tracking via `_failed_logins`).
- Database lockout: 5 failed attempts on a valid user account locks it for 15 minutes (`failed_login_count`, `account_locked_until`, `status="locked"`).
- Updates `last_login` timestamp and clears failures on success.

### Registration (`/register`)
- Requires first name, last name, work email, company, password, and TOS acceptance.
- Internal username is generated automatically from the email prefix, appending an integer counter to prevent collisions.
- Minimum password length: 12 characters.

### Password Reset (`/forgot-password`, `/reset-password/<token>`)
- User Enumeration Prevention: The `/forgot-password` endpoint always returns a generic success message ("If an account exists... instructions have been generated.") regardless of whether the email exists.
- Uses `URLSafeTimedSerializer` for secure password reset tokens (valid for 1 hour).
- Resets enforce the 12-character password minimum.

### Logout (`/logout`)
- Clears the session and triggers an explicit audit log event (`LOGOUT`).

## RBAC Architecture

### 5 Canonical Roles
The system strictly supports 5 canonical roles mapping to specific capability matrices:
1. **ADMIN**: Full application administration, user management, security configurations, and privileged approvals.
2. **SOC_ANALYST**: Security operations, alert triage, incident response, SOAR execution/approvals, and threat hunting.
3. **SECURITY_ANALYST**: Vulnerability scanning, asset assessment, threat intelligence, correlation analysis, and investigation.
4. **INCIDENT_RESPONDER**: Incident containment, evidence investigation, case handling, and response workflows.
5. **VIEWER**: Read-only access to executive dashboards, telemetry, reports, and analytics without modification rights.

Role Aliases map legacy/alternate names (e.g., `analyst` -> `SOC_ANALYST`, `read_only` -> `VIEWER`) back to canonical roles.

### 38 Granular Permissions
Roles define sets of granular permissions. 

- **dashboard.view**: View system, executive, and SOC dashboards
- **assets.view**: View asset inventory and endpoint profiles
- **assets.create**: Add new assets to asset inventory
- **assets.modify**: Modify asset metadata, criticality, and tags
- **assets.delete**: Delete assets from inventory
- **assets.scan**: Initiate vulnerability scan on an asset
- **siem.view**: View SIEM security events, logs, and saved searches
- **detection.view**: View detection rules and trigger events
- **detection.create**: Create custom detection rules
- **detection.modify**: Modify or toggle detection rules
- **detection.delete**: Delete detection rules
- **alerts.view**: View alert center alerts and triage data
- **alerts.modify**: Acknowledge, assign, update status, or resolve alerts
- **alerts.delete**: Delete alert records
- **incidents.view**: View incidents and response case files
- **incidents.create**: Create new incidents or escalate alerts
- **incidents.modify**: Update incident status, severity, notes, and milestones
- **incidents.delete**: Delete incident records
- **incidents.assign**: Assign incidents to security analysts
- **threatintel.view**: View IOCs, threat actors, feeds, and campaigns
- **threatintel.modify**: Add, edit, enrich, or delete IOCs and threat actors
- **scanner.view**: View vulnerability scans, findings, and targets
- **scanner.run**: Execute vulnerability scans (Nmap, Nuclei, Nikto, etc.)
- **scanner.delete**: Delete scans or target entries
- **ids.view**: View Suricata network IDS events and traffic
- **ids.control**: Control IDS sensor daemon (start, stop, restart)
- **ids.rules.modify**: Update or modify Suricata rulesets
- **packet_analysis.view**: View PCAP analyses, flows, and dissected frames
- **packet_analysis.upload**: Upload PCAP/PCAPNG capture files for TShark analysis
- **packet_analysis.delete**: Delete PCAP captures and analysis records
- **reports.view**: View and download generated security reports
- **reports.generate**: Generate new on-demand or scheduled PDF/CSV reports
- **reports.delete**: Delete generated reports
- **analytics.view**: View threat analytics, MITRE matrices, and MTTR/MTTD
- **threat_hunting.view**: View threat hunting dashboard and history
- **threat_hunting.search**: Execute multi-domain threat hunts and save queries
- **correlation.view**: View correlation graph and risk scores
- **correlation.search**: Execute graph correlation queries
- **ai.view**: Access AI assistant interface and conversation history
- **ai.use**: Interact with AI assistant and request investigations
- **soar.view**: View playbook library, execution history, and approval queue
- **soar.execute**: Execute automated SOC playbooks
- **soar.approve**: Approve or reject high-impact staged security actions
- **users.view**: View user accounts and role assignments
- **users.create**: Provision new user accounts
- **users.modify**: Update user profiles, roles, and account status
- **users.delete**: Deactivate or delete user accounts
- **settings.view**: View system and user settings
- **settings.modify**: Modify security settings, integrations, and configurations
- **audit.view**: View administrative and security audit logs
- **notifications.view**: View in-app notifications and notification history
- **notifications.modify**: Manage, mark as read, dismiss notifications, and configure preferences

## Decorators for Access Control
Routes and API endpoints are protected using reusable decorators:
- `@permission_required("permission.name")`: Enforces a specific granular permission. Falls back to admin checks if the method is missing. Handles API vs HTML 403 responses automatically and records an `AUTHORIZATION_DENIED` audit log.
- `@role_required("ROLE_NAME")`: Enforces explicit role matching.
- `@admin_required`: Convenience decorator wrapping `@role_required("ADMIN")`.

## Data Models
### User
- Identifiers: `id`, `username`, `email`
- Details: `first_name`, `last_name`, `company`
- Auth state: `password_hash`, `role`, `status`, `is_active`, `last_login`
- Lockout mechanism: `failed_login_count`, `account_locked_until`
- Property overrides: `is_locked`, `is_admin`, `full_name`, `get_canonical_role()`, `has_permission(permission)`, `has_role(*roles)`

## Limitations / Notes
- The brute-force tracker for IP+Email relies on a thread-safe in-memory dictionary. In a multi-worker deployment (e.g., Gunicorn with multiple processes), rate limits are scoped per-worker. Redis could be added later for distributed rate tracking.
