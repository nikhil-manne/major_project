"""Local login and admin-only user management endpoints."""
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
import uuid
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from shared.auth import UserContext, VALID_ROLES, get_current_user, require_roles
from shared.config import settings
from shared.db import AuthCredential, SessionLocal, Tenant, User, get_db

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
PBKDF2_ITERATIONS = 310_000
PASSWORD_MIN_LENGTH = 6
ROLE_LABELS = {"admin": "Administrator", "red": "Red Team", "blue": "Blue Team", "soc": "SOC Analyst"}


def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(derived.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _make_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "iss": "cyberrange-local",
        "aud": "cyberrange-api",
        "iat": now,
        "exp": now + timedelta(minutes=max(5, settings.AUTH_TOKEN_TTL_MINUTES)),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, settings.AUTH_SECRET_KEY, algorithm="HS256")


def ensure_initial_admin() -> None:
    """Create/update the first admin credential from environment-backed settings."""
    username = settings.INITIAL_ADMIN_USERNAME.strip().lower()
    password = settings.INITIAL_ADMIN_PASSWORD
    if not username or len(password) < PASSWORD_MIN_LENGTH:
        raise RuntimeError(f"INITIAL_ADMIN_USERNAME must be set and INITIAL_ADMIN_PASSWORD must be at least {PASSWORD_MIN_LENGTH} characters")
    with SessionLocal() as db:
        tenant_id = settings.DEFAULT_TENANT_ID
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if tenant is None:
            tenant = Tenant(id=tenant_id, name="Default Enterprise")
            db.add(tenant)
            db.flush()
        user = db.query(User).filter(User.username == username).first()
        if user is not None and user.tenant_id != tenant_id:
            raise RuntimeError(f"Configured initial admin username '{username}' is already used in another tenant")
        if user is None:
            user = User(id=str(uuid.uuid4()), tenant_id=tenant_id, username=username, role="admin")
            db.add(user)
            db.flush()
        elif user.role != "admin":
            user.role = "admin"
        credential = db.query(AuthCredential).filter(AuthCredential.user_id == user.id).first()
        password_hash = _hash_password(password)
        if credential is None:
            credential = AuthCredential(user_id=user.id, password_hash=password_hash, is_active=1)
            db.add(credential)
        else:
            # Environment is the source of truth for the bootstrap administrator password.
            credential.password_hash = password_hash
            credential.is_active = 1
            credential.password_updated_at = datetime.now(timezone.utc)
        db.commit()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=1024)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=1024)
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in VALID_ROLES:
            raise ValueError("role must be one of: admin, red, blue, soc")
        return value


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip().lower()
        if value not in VALID_ROLES:
            raise ValueError("role must be one of: admin, red, blue, soc")
        return value


@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    username = request.username.strip().lower()
    user = db.query(User).filter(User.username == username).first()
    credential = db.query(AuthCredential).filter(AuthCredential.user_id == user.id).first() if user else None
    if not user or not credential or not credential.is_active or not _verify_password(request.password, credential.password_hash):
        # Do not reveal whether the username exists.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return {
        "access_token": _make_token(user),
        "token_type": "bearer",
        "expires_in": max(5, settings.AUTH_TOKEN_TTL_MINUTES) * 60,
        "user": {"id": user.id, "username": user.username, "role": user.role, "role_label": ROLE_LABELS[user.role], "tenant_id": user.tenant_id},
    }


@router.get("/me")
def me(user: UserContext = Depends(get_current_user)):
    return {"id": user.user_id, "username": user.username, "role": user.role, "role_label": ROLE_LABELS.get(user.role, user.role), "tenant_id": user.tenant_id}


@router.get("/users")
def list_users(
    current_user: UserContext = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(User, AuthCredential)
        .join(AuthCredential, AuthCredential.user_id == User.id)
        .filter(User.tenant_id == current_user.tenant_id)
        .order_by(User.created_at.desc())
        .all()
    )
    return [{
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "role_label": ROLE_LABELS.get(user.role, user.role),
        "is_active": bool(credential.is_active),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    } for user, credential in rows]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    request: CreateUserRequest,
    current_user: UserContext = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db),
):
    username = request.username.strip().lower()
    duplicate = db.query(User).filter(User.username == username).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="A user with this username already exists")
    user = User(id=str(uuid.uuid4()), tenant_id=current_user.tenant_id, username=username, role=request.role)
    db.add(user)
    db.flush()
    db.add(AuthCredential(user_id=user.id, password_hash=_hash_password(request.password), is_active=1))
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role, "role_label": ROLE_LABELS[user.role], "is_active": True, "created_at": user.created_at.isoformat() if user.created_at else None}


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    request: UpdateUserRequest,
    current_user: UserContext = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id, User.tenant_id == current_user.tenant_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    credential = db.query(AuthCredential).filter(AuthCredential.user_id == user.id).first()
    if credential is None:
        raise HTTPException(status_code=409, detail="This legacy user has no login credential. Create a replacement user through the admin screen.")
    if request.is_active is False and user.id == current_user.user_id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    if request.role is not None:
        if user.id == current_user.user_id and request.role != "admin":
            raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")
        if user.role == "admin" and request.role != "admin":
            active_admins = (
                db.query(User.id)
                .join(AuthCredential, AuthCredential.user_id == User.id)
                .filter(User.tenant_id == current_user.tenant_id, User.role == "admin", AuthCredential.is_active == 1)
                .count()
            )
            if active_admins <= 1:
                raise HTTPException(status_code=400, detail="Cannot demote the last active administrator")
        user.role = request.role
    if request.is_active is not None:
        if request.is_active is False and user.role == "admin":
            active_admins = (
                db.query(User.id)
                .join(AuthCredential, AuthCredential.user_id == User.id)
                .filter(User.tenant_id == current_user.tenant_id, User.role == "admin", AuthCredential.is_active == 1)
                .count()
            )
            if active_admins <= 1:
                raise HTTPException(status_code=400, detail="Cannot deactivate the last active administrator")
        credential.is_active = 1 if request.is_active else 0
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role, "role_label": ROLE_LABELS[user.role], "is_active": bool(credential.is_active)}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    current_user: UserContext = Depends(require_roles(["admin"])),
    db: Session = Depends(get_db),
):
    """Permanently delete a user account. Requires admin role."""
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if user.role == "admin":
        active_admins = (
            db.query(User.id)
            .join(AuthCredential, AuthCredential.user_id == User.id)
            .filter(User.role == "admin", AuthCredential.is_active == 1)
            .count()
        )
        if active_admins <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last active administrator")

    deleted_username = user.username
    db.query(AuthCredential).filter(AuthCredential.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return {"status": "deleted", "user_id": user_id, "username": deleted_username}
