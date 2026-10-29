"""Authentication and role-based access control.

Local username/password login issues signed bearer tokens and verifies account status
on each request. Verified Keycloak RS256 tokens remain supported. Legacy development
role-switching headers require DEV_AUTH_ENABLED=true and a loopback request.
"""
from functools import lru_cache
import logging
from typing import List, Optional, Dict, Any

import httpx
import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from shared.config import settings

logger = logging.getLogger("cyberrange.auth")
security = HTTPBearer(auto_error=False)
VALID_ROLES = {"red", "blue", "soc", "admin"}


class UserContext(BaseModel):
    user_id: str
    username: str
    role: str
    tenant_id: str
    is_authenticated: bool = True
    token: Optional[str] = None


class KeycloakAuth:
    def __init__(self):
        self.server_url = settings.KEYCLOAK_URL.rstrip("/")
        self.realm = settings.KEYCLOAK_REALM
        self.client_id = settings.KEYCLOAK_CLIENT_ID
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_loaded_at = 0.0

    @property
    def issuer(self) -> str:
        return f"{self.server_url}/realms/{self.realm}"

    async def get_jwks(self, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
        """Retrieve and briefly cache Keycloak's public signing keys."""
        import time
        if self._jwks and not force_refresh and time.time() - self._jwks_loaded_at < 300:
            return self._jwks
        url = f"{self.issuer}/protocol/openid-connect/certs"
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
                    raise ValueError("Keycloak JWKS response did not contain a keys array")
                self._jwks = data
                self._jwks_loaded_at = time.time()
                return data
        except Exception as exc:
            logger.warning("Could not retrieve Keycloak signing keys: %s", exc)
            if force_refresh:
                self._jwks = None
            return self._jwks

    async def validate_token(self, token: str) -> UserContext:
        """Verify signature, issuer, time claims, audience (when configured), and identity claims."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid bearer token") from exc

        if header.get("alg") != "RS256" or not header.get("kid"):
            raise HTTPException(status_code=401, detail="Unsupported token signing algorithm")

        jwks = await self.get_jwks()
        key_info = next((item for item in (jwks or {}).get("keys", []) if item.get("kid") == header.get("kid")), None)
        if key_info is None:
            jwks = await self.get_jwks(force_refresh=True)
            key_info = next((item for item in (jwks or {}).get("keys", []) if item.get("kid") == header.get("kid")), None)
        if key_info is None:
            raise HTTPException(status_code=401, detail="Token signing key is unknown")

        audience = settings.KEYCLOAK_JWT_AUDIENCE.strip() or None
        try:
            signing_key = jwt.PyJWK.from_dict(key_info).key
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=audience,
                options={
                    "require": ["exp", "iat", "sub", "iss"],
                    "verify_aud": audience is not None,
                },
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            logger.info("Rejected Keycloak token: %s", exc)
            raise HTTPException(status_code=401, detail="Bearer token validation failed") from exc

        role_values = set((claims.get("realm_access") or {}).get("roles") or [])
        client_roles = (claims.get("resource_access") or {}).get(self.client_id, {})
        role_values.update(client_roles.get("roles") or [])
        role = next((candidate for candidate in ("admin", "red", "blue", "soc") if candidate in role_values), None)
        if not role:
            raise HTTPException(status_code=403, detail="Token does not contain an authorized platform role")

        tenant_id = claims.get("tenant_id") or claims.get("org_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise HTTPException(status_code=403, detail="Token does not contain a tenant binding")

        return UserContext(
            user_id=str(claims["sub"]),
            username=str(claims.get("preferred_username") or claims.get("email") or claims["sub"]),
            role=role,
            tenant_id=tenant_id,
            is_authenticated=True,
            token=token,
        )


keycloak_auth = KeycloakAuth()


def _is_local_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


async def get_current_user(
    request: Request,
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_dev_role: Optional[str] = Header(None, alias="X-Dev-Role"),
    x_dev_tenant: Optional[str] = Header(None, alias="X-Dev-Tenant"),
    x_dev_user: Optional[str] = Header(None, alias="X-Dev-User"),
) -> UserContext:
    """Resolve a signed local login token, verified Keycloak token, or enabled local test identity."""
    token = auth.credentials if auth else None
    if token:
        # Local application tokens are issued only after username/password verification.
        # Do not downgrade invalid tokens to the optional development identity.
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid bearer token") from exc

        if header.get("alg") == "HS256":
            try:
                claims = jwt.decode(
                    token,
                    key=settings.AUTH_SECRET_KEY,
                    algorithms=["HS256"],
                    issuer="cyberrange-local",
                    audience="cyberrange-api",
                    options={"require": ["exp", "iat", "sub", "iss", "aud", "tenant_id", "role"]},
                    leeway=15,
                )
            except jwt.PyJWTError as exc:
                raise HTTPException(status_code=401, detail="Session token is invalid or expired; log in again") from exc
            role = str(claims.get("role", "")).lower()
            tenant_id = claims.get("tenant_id")
            if role not in VALID_ROLES or not isinstance(tenant_id, str) or not tenant_id:
                raise HTTPException(status_code=401, detail="Session token has invalid identity claims")
            # Check the account on each request so disabling a user or changing their role
            # takes effect immediately rather than waiting for the token to expire.
            from shared.db import AuthCredential, SessionLocal, User
            with SessionLocal() as db:
                account = db.query(User).filter(User.id == str(claims["sub"]), User.tenant_id == tenant_id).first()
                credential = db.query(AuthCredential).filter(AuthCredential.user_id == str(claims["sub"])).first() if account else None
                if not account or not credential or not credential.is_active:
                    raise HTTPException(status_code=401, detail="Account is disabled or no longer exists; log in again")
                if account.role not in VALID_ROLES:
                    raise HTTPException(status_code=403, detail="Account role is not authorized")
                return UserContext(
                    user_id=account.id,
                    username=account.username,
                    role=account.role,
                    tenant_id=account.tenant_id,
                    is_authenticated=True,
                    token=token,
                )

        # Existing Keycloak integration remains supported.
        return await keycloak_auth.validate_token(token)

    if settings.DEV_AUTH_ENABLED and _is_local_request(request):
        role = (x_dev_role or "soc").strip().lower()
        if role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail="X-Dev-Role must be red, blue, soc, or admin")
        tenant_id = (x_dev_tenant or "00000000-0000-0000-0000-000000000123").strip()
        if not tenant_id:
            raise HTTPException(status_code=400, detail="Development tenant cannot be empty")
        known_users = {
            "00000000-0000-0000-0000-000000000123": {
                "red": "11111111-1111-1111-1111-111111111111",
                "blue": "22222222-2222-2222-2222-222222222222",
                "soc": "33333333-3333-3333-3333-333333333333",
                "admin": "44444444-4444-4444-4444-444444444444",
            },
            "00000000-0000-0000-0000-000000000999": {
                "blue": "55555555-5555-5555-5555-555555555555",
            },
        }
        user_id = known_users.get(tenant_id, {}).get(role)
        if not user_id:
            raise HTTPException(status_code=403, detail="No development identity is provisioned for this role and tenant")
        username = (x_dev_user or f"{role}1").strip()
        return UserContext(
            user_id=user_id, username=username, role=role,
            tenant_id=tenant_id, is_authenticated=True, token=None
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_roles(allowed_roles: List[str]):
    """Build a dependency that enforces an explicit role allowlist."""
    invalid = set(allowed_roles) - VALID_ROLES
    if invalid:
        raise ValueError(f"Unknown roles in access policy: {sorted(invalid)}")

    async def role_checker(user: UserContext = Depends(get_current_user)) -> UserContext:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{user.role}' not authorized. Required: {allowed_roles}",
            )
        return user
    return role_checker
