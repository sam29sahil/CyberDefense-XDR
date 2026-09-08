"""
CyberDefense XDR
Network IDS Database Models
Provides SQLAlchemy models for Suricata Network IDS Events and Sensors.
"""

import json
from datetime import datetime

from app.extensions import db


class NetworkIDSEvent(db.Model):
    """
    Represents a normalized event captured by the Network IDS (Suricata).
    Supports alerts, flows, DNS, HTTP, TLS, SSH, fileinfo, anomaly, and stats.
    """

    __tablename__ = "network_ids_events"

    id = db.Column(db.Integer, primary_key=True)

    event_uuid = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    event_type = db.Column(
        db.String(32),
        nullable=False,
        default="alert",
        index=True,
    )

    sensor_name = db.Column(
        db.String(100),
        nullable=False,
        default="suricata-primary",
        index=True,
    )

    interface = db.Column(
        db.String(32),
        nullable=False,
        default="eth0",
        index=True,
    )

    src_ip = db.Column(
        db.String(64),
        nullable=True,
        index=True,
    )

    src_port = db.Column(
        db.Integer,
        nullable=True,
        index=True,
    )

    dest_ip = db.Column(
        db.String(64),
        nullable=True,
        index=True,
    )

    dest_port = db.Column(
        db.Integer,
        nullable=True,
        index=True,
    )

    protocol = db.Column(
        db.String(20),
        nullable=True,
        index=True,
    )

    app_protocol = db.Column(
        db.String(50),
        nullable=True,
        index=True,
    )

    flow_id = db.Column(
        db.String(64),
        nullable=True,
        index=True,
    )

    signature_id = db.Column(
        db.Integer,
        nullable=True,
        index=True,
    )

    signature = db.Column(
        db.String(500),
        nullable=True,
        index=True,
    )

    category = db.Column(
        db.String(255),
        nullable=True,
        index=True,
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="info",
        index=True,
    )

    action = db.Column(
        db.String(50),
        nullable=False,
        default="allowed",
    )

    source = db.Column(
        db.String(100),
        nullable=False,
        default="Suricata IDS",
        index=True,
    )

    raw_event_json = db.Column(
        db.Text,
        nullable=False,
        default="{}",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    @property
    def sid(self):
        """Convenience alias for signature_id."""
        return self.signature_id

    @property
    def raw_data(self):
        """Returns parsed raw JSON payload safely."""
        try:
            return json.loads(self.raw_event_json or "{}")
        except (TypeError, ValueError):
            return {}

    @property
    def is_diagnostic(self):
        """
        Determines if an event is a known NIC offload or checksum diagnostic event.
        Recognizes SID 2200074 and 'SURICATA TCPv4 invalid checksum' decoder events.
        """
        if self.signature_id == 2200074:
            return True
        sig = (self.signature or "").lower()
        if "invalid checksum" in sig:
            return True
        return False

    @property
    def classification(self):
        """
        Classifies Network IDS events into:
        - 'diagnostic': Known NIC offload / checksum decoder events (e.g. SID 2200074)
        - 'security_alert': Genuine intrusion/exploit detections requiring SOC attention
        - 'telemetry': Normal network flows, DNS queries, TLS handshakes, HTTP metadata
        """
        if self.is_diagnostic:
            return "diagnostic"
        if self.event_type == "alert":
            return "security_alert"
        return "telemetry"

    def to_dict(self):
        """Serializes NetworkIDSEvent to dictionary with camelCase and snake_case support."""
        iso_ts = self.timestamp.isoformat() if self.timestamp else None
        iso_ca = self.created_at.isoformat() if self.created_at else None
        raw = self.raw_data
        is_diag = self.is_diagnostic
        cls_val = self.classification
        return {
            "id": self.id,
            "eventUuid": self.event_uuid,
            "event_uuid": self.event_uuid,
            "timestamp": iso_ts,
            "eventType": self.event_type,
            "event_type": self.event_type,
            "classification": cls_val,
            "isDiagnostic": is_diag,
            "is_diagnostic": is_diag,
            "sensorName": self.sensor_name,
            "sensor_name": self.sensor_name,
            "interface": self.interface,
            "srcIp": self.src_ip,
            "src_ip": self.src_ip,
            "srcPort": self.src_port,
            "src_port": self.src_port,
            "destIp": self.dest_ip,
            "dest_ip": self.dest_ip,
            "destPort": self.dest_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "appProtocol": self.app_protocol,
            "app_protocol": self.app_protocol,
            "flowId": self.flow_id,
            "flow_id": self.flow_id,
            "signatureId": self.signature_id,
            "signature_id": self.signature_id,
            "signature": self.signature,
            "category": self.category,
            "severity": self.severity,
            "action": self.action,
            "source": self.source,
            "rawData": raw,
            "raw_data": raw,
            "createdAt": iso_ca,
            "created_at": iso_ca,
        }


class IDSSensor(db.Model):
    """
    Represents the operational state and runtime status of a Network IDS Sensor.
    Tracks PID, Suricata version, capture interface, and health.
    """

    __tablename__ = "ids_sensors"

    id = db.Column(db.Integer, primary_key=True)

    sensor_id = db.Column(
        db.String(32),
        unique=True,
        nullable=False,
        index=True,
    )

    name = db.Column(
        db.String(100),
        nullable=False,
        default="Primary Network Sensor",
    )

    hostname = db.Column(
        db.String(100),
        nullable=False,
    )

    interface = db.Column(
        db.String(32),
        nullable=False,
        default="eth0",
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="stopped",
        index=True,
    )

    suricata_version = db.Column(
        db.String(50),
        nullable=True,
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=True,
    )

    pid = db.Column(
        db.Integer,
        nullable=True,
    )

    eve_log_path = db.Column(
        db.String(255),
        nullable=True,
    )

    started_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    stopped_at = db.Column(
        db.DateTime,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    def to_dict(self):
        """Serializes IDSSensor to dictionary."""
        return {
            "id": self.id,
            "sensorId": self.sensor_id,
            "name": self.name,
            "hostname": self.hostname,
            "interface": self.interface,
            "status": self.status,
            "suricataVersion": self.suricata_version,
            "lastSeen": self.last_seen.isoformat() if self.last_seen else None,
            "pid": self.pid,
            "eveLogPath": self.eve_log_path,
            "startedAt": self.started_at.isoformat() if self.started_at else None,
            "stoppedAt": self.stopped_at.isoformat() if self.stopped_at else None,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
        }
