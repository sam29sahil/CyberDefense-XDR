"""
CyberDefense XDR
Role-Based Access Control (RBAC) & Permissions Architecture
Defines standard roles, capability mappings, and role aliases for backwards compatibility.
"""

from typing import Set, Dict, Any

ALL_PERMISSIONS: Dict[str, str] = {
    # Dashboard
    "dashboard.view": "View system, executive, and SOC dashboards",

    # Assets
    "assets.view": "View asset inventory and endpoint profiles",
    "assets.create": "Add new assets to asset inventory",
    "assets.modify": "Modify asset metadata, criticality, and tags",
    "assets.delete": "Delete assets from inventory",
    "assets.scan": "Initiate vulnerability scan on an asset",

    # SIEM
    "siem.view": "View SIEM security events, logs, and saved searches",

    # Detection
    "detection.view": "View detection rules and trigger events",
    "detection.create": "Create custom detection rules",
    "detection.modify": "Modify or toggle detection rules",
    "detection.delete": "Delete detection rules",

    # Alerts
    "alerts.view": "View alert center alerts and triage data",
    "alerts.modify": "Acknowledge, assign, update status, or resolve alerts",
    "alerts.delete": "Delete alert records",

    # Incidents
    "incidents.view": "View incidents and response case files",
    "incidents.create": "Create new incidents or escalate alerts",
    "incidents.modify": "Update incident status, severity, notes, and milestones",
    "incidents.delete": "Delete incident records",
    "incidents.assign": "Assign incidents to security analysts",

    # Threat Intelligence
    "threatintel.view": "View IOCs, threat actors, feeds, and campaigns",
    "threatintel.modify": "Add, edit, enrich, or delete IOCs and threat actors",

    # Vulnerability Scanner
    "scanner.view": "View vulnerability scans, findings, and targets",
    "scanner.run": "Execute vulnerability scans (Nmap, Nuclei, Nikto, etc.)",
    "scanner.delete": "Delete scans or target entries",

    # Network IDS
    "ids.view": "View Suricata network IDS events and traffic",
    "ids.control": "Control IDS sensor daemon (start, stop, restart)",
    "ids.rules.modify": "Update or modify Suricata rulesets",

    # Packet Analysis
    "packet_analysis.view": "View PCAP analyses, flows, and dissected frames",
    "packet_analysis.upload": "Upload PCAP/PCAPNG capture files for TShark analysis",
    "packet_analysis.delete": "Delete PCAP captures and analysis records",

    # Reports
    "reports.view": "View and download generated security reports",
    "reports.generate": "Generate new on-demand or scheduled PDF/CSV reports",
    "reports.delete": "Delete generated reports",

    # Analytics
    "analytics.view": "View threat analytics, MITRE matrices, and MTTR/MTTD",

    # Threat Hunting
    "threat_hunting.view": "View threat hunting dashboard and history",
    "threat_hunting.search": "Execute multi-domain threat hunts and save queries",

    # Correlation
    "correlation.view": "View correlation graph and risk scores",
    "correlation.search": "Execute graph correlation queries",

    # AI Security Assistant
    "ai.view": "Access AI assistant interface and conversation history",
    "ai.use": "Interact with AI assistant and request investigations",

    # SOAR
    "soar.view": "View playbook library, execution history, and approval queue",
    "soar.execute": "Execute automated SOC playbooks",
    "soar.approve": "Approve or reject high-impact staged security actions",

    # User Management
    "users.view": "View user accounts and role assignments",
    "users.create": "Provision new user accounts",
    "users.modify": "Update user profiles, roles, and account status",
    "users.delete": "Deactivate or delete user accounts",

    # Settings
    "settings.view": "View system and user settings",
    "settings.modify": "Modify security settings, integrations, and configurations",

    # Audit
    "audit.view": "View administrative and security audit logs",

    # Notifications
    "notifications.view": "View in-app notifications and notification history",
    "notifications.modify": "Manage, mark as read, dismiss notifications, and configure preferences",
}

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "ADMIN": {
        "*",  # Administrator has all permissions
        "dashboard.view",
        "assets.view", "assets.create", "assets.modify", "assets.delete", "assets.scan",
        "siem.view",
        "detection.view", "detection.create", "detection.modify", "detection.delete",
        "alerts.view", "alerts.modify", "alerts.delete",
        "incidents.view", "incidents.create", "incidents.modify", "incidents.delete", "incidents.assign",
        "threatintel.view", "threatintel.modify",
        "scanner.view", "scanner.run", "scanner.delete",
        "ids.view", "ids.control", "ids.rules.modify",
        "packet_analysis.view", "packet_analysis.upload", "packet_analysis.delete",
        "reports.view", "reports.generate", "reports.delete",
        "analytics.view",
        "threat_hunting.view", "threat_hunting.search",
        "correlation.view", "correlation.search",
        "ai.view", "ai.use",
        "soar.view", "soar.execute", "soar.approve",
        "users.view", "users.create", "users.modify", "users.delete",
        "settings.view", "settings.modify",
        "audit.view",
        "notifications.view", "notifications.modify",
    },
    "SOC_ANALYST": {
        "dashboard.view",
        "assets.view", "assets.create", "assets.modify", "assets.delete", "assets.scan",
        "siem.view",
        "detection.view", "detection.create", "detection.modify", "detection.delete",
        "alerts.view", "alerts.modify", "alerts.delete",
        "incidents.view", "incidents.create", "incidents.modify", "incidents.delete", "incidents.assign",
        "threatintel.view", "threatintel.modify",
        "scanner.view", "scanner.run", "scanner.delete",
        "ids.view", "ids.control", "ids.rules.modify",
        "packet_analysis.view", "packet_analysis.upload", "packet_analysis.delete",
        "reports.view", "reports.generate", "reports.delete",
        "analytics.view",
        "threat_hunting.view", "threat_hunting.search",
        "correlation.view", "correlation.search",
        "ai.view", "ai.use",
        "soar.view", "soar.execute", "soar.approve",
        "settings.view", "audit.view",
        "notifications.view", "notifications.modify",
    },
    "SECURITY_ANALYST": {
        "dashboard.view", "assets.view", "assets.create", "assets.modify", "assets.scan",
        "siem.view", "detection.view",
        "alerts.view", "alerts.modify",
        "incidents.view", "incidents.create", "incidents.modify",
        "threatintel.view", "threatintel.modify",
        "scanner.view", "scanner.run",
        "ids.view",
        "packet_analysis.view", "packet_analysis.upload",
        "reports.view", "reports.generate",
        "analytics.view", "threat_hunting.view", "threat_hunting.search",
        "correlation.view", "correlation.search",
        "ai.view", "ai.use",
        "soar.view", "soar.execute",
        "settings.view", "audit.view",
        "notifications.view", "notifications.modify",
    },
    "INCIDENT_RESPONDER": {
        "dashboard.view", "assets.view", "siem.view", "detection.view",
        "alerts.view", "alerts.modify",
        "incidents.view", "incidents.create", "incidents.modify", "incidents.assign",
        "threatintel.view", "scanner.view", "ids.view",
        "packet_analysis.view", "reports.view", "analytics.view",
        "threat_hunting.view", "threat_hunting.search",
        "correlation.view", "correlation.search",
        "ai.view", "ai.use",
        "soar.view", "soar.execute",
        "settings.view", "audit.view",
        "notifications.view", "notifications.modify",
    },
    "VIEWER": {
        "dashboard.view", "assets.view", "siem.view", "detection.view",
        "alerts.view", "incidents.view", "threatintel.view", "scanner.view",
        "ids.view", "packet_analysis.view", "reports.view", "analytics.view",
        "threat_hunting.view", "correlation.view", "ai.view", "soar.view",
        "settings.view",
        "notifications.view", "notifications.modify",
    },
}

ROLE_ALIASES: Dict[str, str] = {
    "admin": "ADMIN",
    "administrator": "ADMIN",
    "soc_analyst": "SOC_ANALYST",
    "soc analyst": "SOC_ANALYST",
    "security_analyst": "SECURITY_ANALYST",
    "security analyst": "SECURITY_ANALYST",
    "analyst": "SOC_ANALYST",  # Default legacy test/dev role has operational privileges
    "incident_responder": "INCIDENT_RESPONDER",
    "incident responder": "INCIDENT_RESPONDER",
    "viewer": "VIEWER",
    "read_only": "VIEWER",
    "read-only": "VIEWER",
}

ROLE_METADATA: Dict[str, Dict[str, Any]] = {
    "ADMIN": {
        "id": "ADMIN",
        "name": "Administrator",
        "badge_color": "purple",
        "badge_class": "badge-purple",
        "description": "Full application administration, user management, security configurations, and privileged approvals.",
    },
    "SOC_ANALYST": {
        "id": "SOC_ANALYST",
        "name": "SOC Analyst",
        "badge_color": "info",
        "badge_class": "badge-info",
        "description": "Security operations, alert triage, incident response, SOAR execution/approvals, and threat hunting.",
    },
    "SECURITY_ANALYST": {
        "id": "SECURITY_ANALYST",
        "name": "Security Analyst",
        "badge_color": "primary",
        "badge_class": "badge-primary",
        "description": "Vulnerability scanning, asset assessment, threat intelligence, correlation analysis, and investigation.",
    },
    "INCIDENT_RESPONDER": {
        "id": "INCIDENT_RESPONDER",
        "name": "Incident Responder",
        "badge_color": "warning",
        "badge_class": "badge-warning",
        "description": "Incident containment, evidence investigation, case handling, and response workflows.",
    },
    "VIEWER": {
        "id": "VIEWER",
        "name": "Viewer",
        "badge_color": "secondary",
        "badge_class": "badge-secondary",
        "description": "Read-only access to executive dashboards, telemetry, reports, and analytics without modification rights.",
    },
}


def normalize_role(role_name: str) -> str:
    """Normalizes any role input string into a canonical role identifier."""
    if not role_name:
        return "VIEWER"
    key = str(role_name).strip().lower()
    return ROLE_ALIASES.get(key, str(role_name).strip().upper())


def get_permissions_for_role(role_name: str) -> Set[str]:
    """Returns the set of permissions granted to a given role."""
    canon = normalize_role(role_name)
    return ROLE_PERMISSIONS.get(canon, set())
