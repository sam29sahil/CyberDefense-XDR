"""
CyberDefense XDR
Vulnerability Scanner & Scan History Database Models
"""

import json
import random
from datetime import datetime

from app.extensions import db


def generate_scan_id():
    return f"SCAN-{random.randint(1000, 9999)}"


def generate_vuln_id():
    return f"VULN-{random.randint(1000, 9999)}"


def generate_target_id():
    return f"TGT-{random.randint(500, 999)}"


class Scan(db.Model):
    """
    Vulnerability Scan execution record.
    """

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        default=generate_scan_id,
        index=True,
    )

    name = db.Column(
        db.String(255),
        nullable=False,
    )

    scan_type = db.Column(
        db.String(50),
        nullable=False,
        default="Quick Scan",
        index=True,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="queued",
        index=True,
    )

    started_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    completed_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    duration_min = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    initiated_by = db.Column(
        db.String(100),
        nullable=False,
        default="Analyst",
    )

    targets_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    options_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    risk_score = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    total_findings = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    critical_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    high_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    medium_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    low_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    raw_output = db.Column(
        db.Text,
        nullable=True,
    )

    error_message = db.Column(
        db.Text,
        nullable=True,
    )

    profile = db.Column(
        db.String(50),
        nullable=False,
        default="STANDARD",
    )

    tools_used_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    dns_data_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    web_technologies_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    tls_summary_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    service_observations_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    service_observations_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    # Relationships
    findings = db.relationship(
        "VulnerabilityFinding",
        backref="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @property
    def targets(self):
        try:
            return json.loads(self.targets_json or "[]")
        except (TypeError, ValueError):
            return []

    @targets.setter
    def targets(self, val):
        self.targets_json = json.dumps(val if isinstance(val, list) else [])

    @property
    def options(self):
        try:
            return json.loads(self.options_json or "{}")
        except (TypeError, ValueError):
            return {}

    @options.setter
    def options(self, val):
        self.options_json = json.dumps(val if isinstance(val, dict) else {})

    @property
    def findings_summary(self):
        return {
            "critical": self.critical_count or 0,
            "high": self.high_count or 0,
            "medium": self.medium_count or 0,
            "low": self.low_count or 0,
        }

    @findings_summary.setter
    def findings_summary(self, val):
        if isinstance(val, dict):
            self.critical_count = val.get("critical", 0)
            self.high_count = val.get("high", 0)
            self.medium_count = val.get("medium", 0)
            self.low_count = val.get("low", 0)

    @property
    def finding_ids(self):
        return [f.finding_id for f in self.findings.all()]

    @finding_ids.setter
    def finding_ids(self, val):
        pass

    @property
    def tools_used(self):
        try:
            return json.loads(self.tools_used_json or "[]")
        except (TypeError, ValueError):
            return []

    @tools_used.setter
    def tools_used(self, val):
        self.tools_used_json = json.dumps(val if isinstance(val, list) else [])

    @property
    def dns_data(self):
        try:
            return json.loads(self.dns_data_json or "{}")
        except (TypeError, ValueError):
            return {}

    @dns_data.setter
    def dns_data(self, val):
        self.dns_data_json = json.dumps(val if isinstance(val, dict) else {})

    @property
    def web_technologies(self):
        try:
            return json.loads(self.web_technologies_json or "[]")
        except (TypeError, ValueError):
            return []

    @web_technologies.setter
    def web_technologies(self, val):
        self.web_technologies_json = json.dumps(val if isinstance(val, list) else [])

    @property
    def tls_summary(self):
        try:
            return json.loads(self.tls_summary_json or "{}")
        except (TypeError, ValueError):
            return {}

    @tls_summary.setter
    def tls_summary(self, val):
        self.tls_summary_json = json.dumps(val if isinstance(val, dict) else {})

    @property
    def service_observations(self):
        try:
            return json.loads(self.service_observations_json or "[]")
        except (TypeError, ValueError):
            return []

    @service_observations.setter
    def service_observations(self, val):
        obs_list = val if isinstance(val, list) else []
        self.service_observations_json = json.dumps(obs_list)
        self.service_observations_count = len(obs_list)

    def __repr__(self):
        return f"<Scan {self.scan_id} - {self.name} - {self.status}>"

    def to_dict(self):
        """Matches frontend SCANS_DATA schema."""
        finding_ids = [f.finding_id for f in self.findings.all()]
        return {
            "id": self.scan_id,
            "name": self.name,
            "type": self.scan_type,
            "profile": self.profile,
            "status": self.status,
            "startedAt": self.started_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.started_at else None,
            "completedAt": self.completed_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.completed_at else None,
            "durationMin": self.duration_min,
            "initiatedBy": self.initiated_by,
            "targets": self.targets,
            "options": self.options,
            "toolsUsed": self.tools_used,
            "dnsData": self.dns_data,
            "webTechnologies": self.web_technologies,
            "tlsSummary": self.tls_summary,
            "serviceObservations": self.service_observations,
            "serviceObservationsCount": self.service_observations_count,
            "findingsSummary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "findingIds": finding_ids,
            "riskScore": self.risk_score,
            "errorMessage": self.error_message,
        }


class VulnerabilityFinding(db.Model):
    """
    Individual vulnerability or service issue identified during a scan.
    """

    __tablename__ = "vulnerability_findings"

    id = db.Column(db.Integer, primary_key=True)

    finding_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        default=generate_vuln_id,
        index=True,
    )

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    cve = db.Column(
        db.String(50),
        nullable=False,
        default="",
        index=True,
    )

    title = db.Column(
        db.String(255),
        nullable=False,
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="medium",
        index=True,
    )

    cvss_score = db.Column(
        db.Float,
        nullable=False,
        default=5.0,
    )

    cvss_vector = db.Column(
        db.String(100),
        nullable=True,
    )

    description = db.Column(
        db.Text,
        nullable=True,
    )

    remediation = db.Column(
        db.Text,
        nullable=True,
    )

    host = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    port = db.Column(
        db.Integer,
        nullable=True,
    )

    protocol = db.Column(
        db.String(10),
        nullable=False,
        default="tcp",
    )

    service = db.Column(
        db.String(100),
        nullable=True,
    )

    product = db.Column(
        db.String(100),
        nullable=True,
    )

    version = db.Column(
        db.String(100),
        nullable=True,
    )

    evidence = db.Column(
        db.Text,
        nullable=True,
    )

    tool = db.Column(
        db.String(50),
        nullable=False,
        default="nmap",
        index=True,
    )

    cwe = db.Column(
        db.String(50),
        nullable=True,
    )

    confidence = db.Column(
        db.String(30),
        nullable=False,
        default="high",
    )

    fingerprint = db.Column(
        db.String(64),
        nullable=True,
        index=True,
    )

    threat_intel_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    affected_assets_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    references_json = db.Column(
        db.Text,
        nullable=False,
        default="[]",
    )

    status = db.Column(
        db.String(30),
        nullable=False,
        default="open",
        index=True,
    )

    published_date = db.Column(
        db.String(30),
        nullable=True,
    )

    discovered_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    @property
    def affected_assets(self):
        try:
            return json.loads(self.affected_assets_json or "[]")
        except (TypeError, ValueError):
            return []

    @affected_assets.setter
    def affected_assets(self, val):
        self.affected_assets_json = json.dumps(val if isinstance(val, list) else [])

    @property
    def references(self):
        try:
            return json.loads(self.references_json or "[]")
        except (TypeError, ValueError):
            return []

    @references.setter
    def references(self, val):
        self.references_json = json.dumps(val if isinstance(val, list) else [])

    @property
    def threat_intel(self):
        try:
            return json.loads(self.threat_intel_json or "{}")
        except (TypeError, ValueError):
            return {}

    @threat_intel.setter
    def threat_intel(self, val):
        self.threat_intel_json = json.dumps(val if isinstance(val, dict) else {})

    def __repr__(self):
        return f"<VulnerabilityFinding {self.finding_id} - {self.title} - {self.severity}>"

    def to_dict(self):
        """Matches frontend VULNERABILITIES_DATA schema."""
        return {
            "id": self.finding_id,
            "cve": self.cve if (self.cve and self.cve.strip()) else None,
            "cwe": self.cwe or "",
            "title": self.title,
            "severity": self.severity.lower(),
            "cvssScore": self.cvss_score if (self.cvss_score is not None and self.cvss_score > 0) else None,
            "cvssVector": self.cvss_vector or "",
            "description": self.description or "",
            "remediation": self.remediation or "",
            "affectedAssets": self.affected_assets or [self.host],
            "status": self.status,
            "publishedDate": self.published_date or (self.discovered_at.strftime("%Y-%m-%d") if self.discovered_at else ""),
            "discoveredAt": self.discovered_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.discovered_at else "",
            "references": self.references,
            "port": self.port,
            "service": self.service or "",
            "product": self.product or "",
            "version": self.version or "",
            "host": self.host,
            "protocol": self.protocol,
            "evidence": self.evidence or "",
            "tool": self.tool,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint or "",
            "threatIntel": self.threat_intel,
        }


class ScanTarget(db.Model):
    """
    Configured scan targets (hosts, subnets, asset groups).
    """

    __tablename__ = "scan_targets"

    id = db.Column(db.Integer, primary_key=True)

    target_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        default=generate_target_id,
        index=True,
    )

    name = db.Column(
        db.String(255),
        nullable=False,
    )

    target_value = db.Column(
        db.String(255),
        nullable=False,
    )

    type = db.Column(
        db.String(50),
        nullable=False,
        default="Host",
    )

    asset_count = db.Column(
        db.Integer,
        nullable=False,
        default=1,
    )

    owner = db.Column(
        db.String(100),
        nullable=False,
        default="Analyst",
    )

    risk_score = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    target_type = db.Column(
        db.String(50),
        nullable=False,
        default="Host",
    )

    normalized_value = db.Column(
        db.String(255),
        nullable=True,
    )

    dns_records_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    is_authorized = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    parsed_url_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    last_scanned = db.Column(
        db.DateTime,
        nullable=True,
    )

    next_scheduled = db.Column(
        db.DateTime,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    @property
    def dns_records(self):
        try:
            return json.loads(self.dns_records_json or "{}")
        except (TypeError, ValueError):
            return {}

    @dns_records.setter
    def dns_records(self, val):
        self.dns_records_json = json.dumps(val if isinstance(val, dict) else {})

    @property
    def parsed_url(self):
        try:
            return json.loads(self.parsed_url_json or "{}")
        except (TypeError, ValueError):
            return {}

    @parsed_url.setter
    def parsed_url(self, val):
        self.parsed_url_json = json.dumps(val if isinstance(val, dict) else {})

    def __repr__(self):
        return f"<ScanTarget {self.target_id} - {self.name}>"

    def to_dict(self):
        """Matches frontend TARGETS_DATA schema."""
        return {
            "id": self.target_id,
            "name": self.name,
            "targetValue": self.target_value,
            "targetInput": self.target_value,
            "type": self.type,
            "targetType": self.target_type,
            "normalizedValue": self.normalized_value or self.target_value,
            "assetCount": self.asset_count,
            "lastScanned": self.last_scanned.strftime("%Y-%m-%dT%H:%M:%SZ") if self.last_scanned else None,
            "nextScheduled": self.next_scheduled.strftime("%Y-%m-%dT%H:%M:%SZ") if self.next_scheduled else None,
            "riskScore": self.risk_score,
            "owner": self.owner,
            "isAuthorized": self.is_authorized,
            "dnsRecords": self.dns_records,
            "parsedUrl": self.parsed_url,
        }


class ServiceObservation:
    """
    Represents a discovered service or exposure observation.
    Does NOT count as a vulnerability finding, assign arbitrary CWEs,
    or inflate vulnerability risk metrics.
    """

    def __init__(
        self,
        scan_id=None,
        target="",
        host="",
        port=None,
        protocol="tcp",
        service="",
        product="",
        version="",
        extrainfo="",
        state="open",
        tool="nmap",
        evidence="",
        discovered_at=None,
        metadata=None,
        **kwargs,
    ):
        self.scan_id = scan_id
        self.target = target
        self.host = host
        self.port = port
        self.protocol = protocol
        self.service = service
        self.product = product
        self.version = version
        self.extrainfo = extrainfo
        self.state = state
        self.tool = tool
        self.evidence = evidence
        self.discovered_at = discovered_at or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "state": self.state,
            "tool": self.tool,
            "evidence": self.evidence,
            "discovered_at": self.discovered_at,
            "metadata": self.metadata,
        }

