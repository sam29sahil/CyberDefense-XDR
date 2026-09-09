"""
CyberDefense XDR
User Model
"""

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False, index=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)

    first_name = db.Column(db.String(100), nullable=False)

    last_name = db.Column(db.String(100), nullable=False)

    company = db.Column(db.String(255), nullable=True)

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(50), nullable=False, default="analyst")

    status = db.Column(db.String(20), nullable=False, default="active", server_default="active")

    is_active = db.Column(db.Boolean, nullable=False, default=True)

    last_login = db.Column(db.DateTime, nullable=True)

    failed_login_count = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    account_locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def get_canonical_role(self) -> str:
        from app.user_management.permissions import normalize_role
        return normalize_role(self.role)

    def has_permission(self, permission: str) -> bool:
        from app.user_management.permissions import get_permissions_for_role
        if not self.is_active or self.is_locked:
            return False
        perms = get_permissions_for_role(self.role)
        return "*" in perms or permission in perms

    def has_role(self, *roles: str) -> bool:
        from app.user_management.permissions import normalize_role
        canon = self.get_canonical_role()
        for r in roles:
            if canon == normalize_role(r):
                return True
        return False

    @property
    def is_admin(self) -> bool:
        return self.has_role("ADMIN")

    @property
    def is_locked(self) -> bool:
        if self.status == "locked":
            return True
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False

    def to_dict(self, include_permissions=False):
        from app.user_management.permissions import get_permissions_for_role, ROLE_METADATA
        canon_role = self.get_canonical_role()
        meta = ROLE_METADATA.get(canon_role, {})
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "company": self.company,
            "role": canon_role,
            "role_name": meta.get("name", canon_role),
            "role_badge": meta.get("badge_class", "badge-secondary"),
            "status": self.status,
            "is_active": self.is_active,
            "is_locked": self.is_locked,
            "last_login": self.last_login.strftime("%Y-%m-%d %H:%M:%S") if self.last_login else None,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
            "updated_at": self.updated_at.strftime("%Y-%m-%d %H:%M:%S") if self.updated_at else None,
        }
        if include_permissions:
            data["permissions"] = sorted(list(get_permissions_for_role(self.role)))
        return data

    def __repr__(self):
        return f"<User {self.email}>"
        return f"<User {self.email} ({self.role})>"
