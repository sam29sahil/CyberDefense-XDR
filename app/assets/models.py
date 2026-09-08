"""
CyberDefense XDR
Asset Management Database Models
Provides SQLAlchemy model for enterprise IT/OT asset inventory,
host configurations, network observations, and correlated security posture.
"""

from datetime import datetime
import secrets

from app.extensions import db


def generate_asset_id():
    """Generates unique, human-readable identifier: AST-XXXXXXXX"""
    return f"AST-{secrets.token_hex(4).upper()}"


class Asset(db.Model):
    """
    Represents an authorized IT/OT/Cloud asset within the XDR protected environment.
    Stores host identity, classification, hardware/OS profile, network observations,
    and dynamically correlated security metrics (risk score, open vulns, active alerts).
    """

    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)

    asset_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True,
        default=generate_asset_id,
    )

    # Identity
    name = db.Column(db.String(128), nullable=False, index=True)
    hostname = db.Column(db.String(255), nullable=True, index=True)
    fqdn = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True, index=True)
    mac_address = db.Column(db.String(32), nullable=True, index=True)

    # Classification
    asset_type = db.Column(
        db.String(64),
        nullable=False,
        default="Server",
        index=True,
    )
    environment = db.Column(
        db.String(64),
        nullable=False,
        default="Production",
        index=True,
    )
    criticality = db.Column(
        db.String(32),
        nullable=False,
        default="medium",
        index=True,
    )
    owner = db.Column(db.String(128), nullable=True)
    owner_team = db.Column(db.String(128), nullable=True)
    tags = db.Column(db.JSON, nullable=True, default=list)

    # System / OS
    operating_system = db.Column(db.String(128), nullable=True)
    os_version = db.Column(db.String(64), nullable=True)
    platform = db.Column(db.String(64), nullable=True)
    architecture = db.Column(db.String(32), nullable=True)

    # Network / Service Observations
    discovered_ports = db.Column(db.JSON, nullable=True, default=list)
    discovered_services = db.Column(db.JSON, nullable=True, default=list)

    # Security Posture (derived from real findings, alerts, and incidents)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_severity = db.Column(
        db.String(32),
        nullable=False,
        default="low",
        index=True,
    )
    open_vulnerabilities_count = db.Column(db.Integer, nullable=False, default=0)
    open_alerts_count = db.Column(db.Integer, nullable=False, default=0)

    # Lifecycle & Status
    status = db.Column(
        db.String(32),
        nullable=False,
        default="online",
        index=True,
    )
    first_seen = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )
    last_seen = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    # Extensible metadata
    metadata_json = db.Column(db.JSON, nullable=True, default=dict)

    def to_dict(self, include_details=False):
        """Serializes asset model to API-safe JSON dictionary."""
        tags_list = self.tags if isinstance(self.tags, list) else []

        data = {
            "id": self.id,
            "asset_id": self.asset_id,
            "assetId": self.asset_id,
            "name": self.name,
            "hostname": self.hostname or "",
            "fqdn": self.fqdn or "",
            "ip": self.ip_address or "",
            "ip_address": self.ip_address or "",
            "ipAddress": self.ip_address or "",
            "mac": self.mac_address or "",
            "mac_address": self.mac_address or "",
            "macAddress": self.mac_address or "",
            "type": self.asset_type,
            "asset_type": self.asset_type,
            "assetType": self.asset_type,
            "env": self.environment,
            "environment": self.environment,
            "criticality": self.criticality,
            "owner": self.owner or "Unassigned",
            "owner_team": self.owner_team or self.owner or "Unassigned",
            "ownerTeam": self.owner_team or self.owner or "Unassigned",
            "tags": tags_list,
            "os": self.operating_system or "Unknown OS",
            "operating_system": self.operating_system or "",
            "os_version": self.os_version or "",
            "platform": self.platform or "",
            "architecture": self.architecture or "",
            "status": self.status,
            "risk": self.risk_score,
            "risk_score": self.risk_score,
            "riskScore": self.risk_score,
            "sev": self.risk_severity,
            "risk_severity": self.risk_severity,
            "riskSeverity": self.risk_severity,
            "open_vulnerabilities_count": self.open_vulnerabilities_count,
            "openVulns": self.open_vulnerabilities_count,
            "open_alerts_count": self.open_alerts_count,
            "openAlerts": self.open_alerts_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "lastSeen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_details:
            data["discovered_ports"] = self.discovered_ports or []
            data["discoveredPorts"] = self.discovered_ports or []
            data["discovered_services"] = self.discovered_services or []
            data["discoveredServices"] = self.discovered_services or []
            data["metadata"] = self.metadata_json or {}

        return data

    def __repr__(self):
        return f"<Asset {self.asset_id} ({self.name} - {self.ip_address or 'No IP'})>"

