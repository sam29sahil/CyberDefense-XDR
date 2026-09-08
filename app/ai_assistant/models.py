"""
CyberDefense XDR
AI Security Assistant Database Models
Persists conversations, messages, and evidence artifacts.
"""

from datetime import datetime
from app.extensions import db


class AIConversation(db.Model):
    """Tracks chat sessions with the AI Security Assistant."""

    __tablename__ = "ai_conversations"

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False, default="Security Investigation")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    entity_type = db.Column(db.String(64), nullable=True)
    entity_id = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    messages = db.relationship(
        "AIMessage",
        backref="conversation",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="AIMessage.created_at.asc()",
    )

    def to_dict(self, include_messages=False):
        data = {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "title": self.title,
            "user_id": self.user_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "created_at": self.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.created_at else None,
            "updated_at": self.updated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.updated_at else None,
        }
        if include_messages:
            data["messages"] = [m.to_dict() for m in self.messages.all()]
        return data


class AIMessage(db.Model):
    """Stores individual conversational turns with structured security outputs."""

    __tablename__ = "ai_messages"

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("ai_conversations.id"), nullable=False, index=True)
    role = db.Column(db.String(32), nullable=False)  # "user", "assistant", "system"
    content = db.Column(db.Text, nullable=False)
    evidence_json = db.Column(db.Text, nullable=True)
    analysis_json = db.Column(db.Text, nullable=True)
    recommendations_json = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(32), nullable=True)
    tokens_used = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self):
        import json

        def _parse(val):
            if not val:
                return None
            try:
                return json.loads(val)
            except (ValueError, TypeError):
                return val

        return {
            "id": self.id,
            "role": self.role,
            "content": self.content,
            "evidence": _parse(self.evidence_json),
            "analysis": _parse(self.analysis_json),
            "recommendations": _parse(self.recommendations_json),
            "risk_level": self.risk_level,
            "tokens_used": self.tokens_used,
            "created_at": self.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.created_at else None,
        }

