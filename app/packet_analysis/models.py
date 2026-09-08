"""
CyberDefense XDR
Packet Analysis Database Models
Provides SQLAlchemy models for PCAP file analysis, protocol breakdowns, and conversation flows.
"""

from datetime import datetime
import uuid

from app.extensions import db


class PacketAnalysis(db.Model):
    """
    Represents an authorized PCAP/PCAPNG capture file analysis.
    Stores high-level metadata, capture statistics, protocol hierarchy,
    top conversations, and endpoints extracted via TShark.
    """

    __tablename__ = "packet_analyses"

    id = db.Column(db.Integer, primary_key=True)

    analysis_uuid = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # File information
    filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    file_type = db.Column(db.String(32), nullable=False, default="pcap")
    sha256 = db.Column(db.String(64), nullable=False, index=True)

    # Lifecycle status: uploaded, queued, running, completed, failed
    status = db.Column(db.String(32), nullable=False, default="uploaded", index=True)
    error_message = db.Column(db.Text, nullable=True)

    # Core packet telemetry
    packet_count = db.Column(db.Integer, nullable=False, default=0)
    duration = db.Column(db.Float, nullable=False, default=0.0)
    first_packet_time = db.Column(db.DateTime, nullable=True)
    last_packet_time = db.Column(db.DateTime, nullable=True)
    encapsulation = db.Column(db.String(64), nullable=True)

    # JSON statistics (hierarchies, top flows, endpoints)
    protocol_stats = db.Column(db.JSON, nullable=True)
    endpoint_stats = db.Column(db.JSON, nullable=True)
    conversation_stats = db.Column(db.JSON, nullable=True)
    summary_metadata = db.Column(db.JSON, nullable=True)

    # Optional loose link to Network IDS event
    ids_event_id = db.Column(db.Integer, nullable=True, index=True)

    # Timestamps
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

    # Relationships
    user = db.relationship("User", backref=db.backref("packet_analyses", lazy="dynamic"))

    def to_dict(self, include_details=False):
        """Serializes model to API-safe JSON dictionary."""
        data = {
            "id": self.id,
            "analysis_uuid": self.analysis_uuid,
            "uuid": self.analysis_uuid,
            "userId": self.user_id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "System / Analyst",
            "filename": self.filename,
            "fileSize": self.file_size,
            "file_size": self.file_size,
            "fileSizeFormatted": self._format_size(self.file_size),
            "fileType": self.file_type,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "status": self.status,
            "errorMessage": self.error_message,
            "error_message": self.error_message,
            "packetCount": self.packet_count,
            "packet_count": self.packet_count,
            "duration": round(self.duration, 4) if self.duration else 0.0,
            "firstPacketTime": self.first_packet_time.isoformat() if self.first_packet_time else None,
            "lastPacketTime": self.last_packet_time.isoformat() if self.last_packet_time else None,
            "encapsulation": self.encapsulation,
            "idsEventId": self.ids_event_id,
            "ids_event_id": self.ids_event_id,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_details:
            data["protocolStats"] = self.protocol_stats or {}
            data["protocol_stats"] = self.protocol_stats or {}
            data["endpointStats"] = self.endpoint_stats or {}
            data["endpoint_stats"] = self.endpoint_stats or {}
            data["conversationStats"] = self.conversation_stats or {}
            data["conversation_stats"] = self.conversation_stats or {}
            data["summaryMetadata"] = self.summary_metadata or {}
            data["summary_metadata"] = self.summary_metadata or {}

        return data

    @staticmethod
    def _format_size(num_bytes):
        """Human-readable byte size."""
        if not num_bytes:
            return "0 B"
        num = float(num_bytes)
        for unit in ["B", "KB", "MB", "GB"]:
            if abs(num) < 1024.0:
                return f"{num:3.1f} {unit}"
            num /= 1024.0
        return f"{num:.1f} TB"

