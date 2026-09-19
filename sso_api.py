from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from jwt import InvalidTokenError, PyJWK
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import ACCESS_TOKEN_EXPIRE_MINUTES, TOKEN_TYPE, create_access_token, get_current_user, hash_password
from database import get_db
from identity_models import FederatedIdentity, SSOExchangeCode, TenantIdentityProvider
from models import AuditLog, Tenant, User
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").lower()
SSO_COOKIE_NAME = "safety360_sso_tx"
SSO_TRANSACTION_TTL_SECONDS = int(os.getenv("SSO_TRANSACTION_TTL_SECONDS", "300"))
SSO_EXCHANGE_TTL_SECONDS = int(os.getenv("SSO_EXCHANGE_TTL_SECONDS", "60"))
SSO_HTTP_TIMEOUT_SECONDS = float(os.getenv("SSO_HTTP_TIMEOUT_SECONDS", "8"))
SSO_CALLBACK_URL = os.getenv("SSO_CALLBACK_URL", "http://127.0.0.1:8000/auth/sso/callback").strip()
SSO_FRONTEND_CALLBACK_URL = os.getenv(
    "SSO_FRONTEND_CALLBACK_URL",
    "http://127.0.0.1:5173/sso/callback",
).strip()
SSO_ALLOWED_ISSUERS = {
    value.strip().rstrip("/")
    for value in os.getenv("SSO_ALLOWED_ISSUERS", "").split(",")
    if value.strip()
}
SSO_SECRET_ENV_PREFIX = "SAFETY360_SSO_SECRET_"

_SECRET_KEY = os.getenv("SAFETY360_SECRET_KEY")
if not _SECRET_KEY:
    if ENVIRONMENT == "production":
        raise RuntimeError("SAFETY360_SECRET_KEY muss in Produktion für SSO gesetzt sein.")
    _SECRET_KEY = secrets.token_urlsafe(64)

_TRANSACTION_KEY = base64.urlsafe_b64encode(hashlib.sha256(_SECRET_KEY.encode("utf-8")).digest())
_TRANSACTION_FERNET = Fernet(_TRANSACTION_KEY)


class SSOProviderConfigRequest(BaseModel):
    name: str = Field(default="Corporate SSO", min_length=2, max_length=120)
    issuer_url: str = Field(min_length=8, max_length=500)
    client_id: str = Field(min_length=2, max_length=255)
    client_secret_env: str | None = Field(default=None, max_length=160)
    scopes: str = Field(default="openid profile email", min_length=6, max_length=500)
    allowed_domains: list[str] = Field(default_factory=list, max_length=50)
    enabled: bool = False
    auto_provision: bool = False
    auto_link_verified_email: bool = False


class SSOProviderConfigResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    issuer_url: str
    client_id: str
    client_secret_env: str | None
    scopes: str
    allowed_domains: list[str]
    enabled: bool
    auto_provision: bool
    auto_link_verified_email: bool
    secret_configured: bool


class SSOPublicMetadata(BaseModel):
    tenant_slug: str
    enabled: bool
    provider_name: str | None = None
    login_url: str | None = None


class SSOExchangeRequest(BaseModel):
    code: str = Field(min_length=24, max_length=200)


class SSOExchangeResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_issuer(value: str) -> str:
    issuer = value.strip().rstrip("/")
    parsed = urlparse(issuer)
    allow_http_dev = ENVIRONMENT != "production" and parsed.hostname in {"127.0.0.1", "localhost"}
    if parsed.scheme != "https" and not allow_http_dev:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SSO-Issuer muss HTTPS verwenden.",
        )
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SSO-Issuer ist ungültig.",
        )
    if ENVIRONMENT == "production":
        if not SSO_ALLOWED_ISSUERS:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="SSO_ALLOWED_ISSUERS ist in Produktion nicht konfiguriert.",
            )
        if issuer not in SSO_ALLOWED_ISSUERS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Dieser SSO-Issuer ist für die Produktionsumgebung nicht freigegeben.",
            )
    return issuer


def _validate_callback_url(value: str, setting_name: str) -> str:
    parsed = urlparse(value)
    allow_http_dev = ENVIRONMENT != "production" and parsed.hostname in {"127.0.0.1", "localhost"}
    if parsed.scheme != "https" and not allow_http_dev:
        raise RuntimeError(f"{setting_name} muss HTTPS verwenden.")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError(f"{setting_name} ist ungültig.")
    return value


def _validate_secret_env(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip()
    if not normalized.startswith(SSO_SECRET_ENV_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"SSO-Client-Secrets dürfen nur über Umgebungsvariablen mit Präfix {SSO_SECRET_ENV_PREFIX} referenziert werden.",
        )
    if not normalized.replace("_", "").isalnum() or normalized.upper() != normalized:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Name der SSO-Secret-Umgebungsvariable ist ungültig.",
        )
    return normalized


def _normalize_domains(domains: list[str]) -> list[str]:
    normalized: list[str] = []
    for domain in domains:
        value = domain.strip().lower().lstrip("@")
        if not value or "." not in value or any(char.isspace() for char in value):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Ungültige SSO-E-Mail-Domain: {domain}",
            )
        if value not in normalized:
            normalized.append(value)
    return normalized


def _provider_domains(provider: TenantIdentityProvider) -> list[str]:
    try:
        parsed = json.loads(provider.allowed_domains_json or "[]")
    except json.JSONDecodeError:
        return []
    return [str(item).lower() for item in parsed if isinstance(item, str)]


def _serialize_provider(provider: TenantIdentityProvider) -> SSOProviderConfigResponse:
    secret_configured = bool(provider.client_secret_env and os.getenv(provider.client_secret_env))
    return SSOProviderConfigResponse(
        id=provider.id,
        tenant_id=provider.tenant_id,
        name=provider.name,
        issuer_url=provider.issuer_url,
        client_id=provider.client_id,
        client_secret_env=provider.client_secret_env,
        scopes=provider.scopes,
        allowed_domains=_provider_domains(provider),
        enabled=provider.enabled,
        auto_provision=provider.auto_provision,
        auto_link_verified_email=provider.auto_link_verified_email,
        secret_configured=secret_configured,
    )


def _tenant_admin_id(current_user: User) -> int:
    require_permission(current_user, "sso.manage")
    if current_user.tenant_id is None:
        raise HTTPException(status_code=409, detail="Benutzer ist keinem Mandanten zugeordnet.")
    return current_user.tenant_id


def _same_origin(reference: str, candidate: str) -> bool:
    left = urlparse(reference)
    right = urlparse(candidate)
    return (left.scheme, left.hostname, left.port) == (right.scheme, right.hostname, right.port)


def _validate_provider_endpoint(issuer: str, endpoint: str, label: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise HTTPException(status_code=502, detail=f"OIDC-{label} ist ungültig.")
    if ENVIRONMENT == "production" and parsed.scheme != "https":
        raise HTTPException(status_code=502, detail=f"OIDC-{label} verwendet kein HTTPS.")
    if not _same_origin(issuer, endpoint):
        raise HTTPException(
            status_code=502,
            detail=f"OIDC-{label} liegt außerhalb des freigegebenen Issuer-Ursprungs.",
        )
    return endpoint


def _oidc_discovery(provider: TenantIdentityProvider) -> dict[str, object]:
    issuer = _normalize_issuer(provider.issuer_url)
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=SSO_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = client.get(discovery_url, headers={"Accept": "application/json"})
            response.raise_for_status()
            metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="OIDC-Discovery konnte nicht sicher geladen werden.") from exc

    if not isinstance(metadata, dict) or str(metadata.get("issuer", "")).rstrip("/") != issuer:
        raise HTTPException(status_code=502, detail="OIDC-Discovery liefert einen unerwarteten Issuer.")

    for key, label in (
        ("authorization_endpoint", "Authorization Endpoint"),
        ("token_endpoint", "Token Endpoint"),
        ("jwks_uri", "JWKS Endpoint"),
    ):
        endpoint = metadata.get(key)
        if not isinstance(endpoint, str):
            raise HTTPException(status_code=502, detail=f"OIDC-{label} fehlt.")
        _validate_provider_endpoint(issuer, endpoint, label)
    return metadata


def _transaction_encrypt(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _TRANSACTION_FERNET.encrypt(raw).decode("ascii")


def _transaction_decrypt(token: str) -> dict[str, object]:
    try:
        raw = _TRANSACTION_FERNET.decrypt(token.encode("ascii"), ttl=SSO_TRANSACTION_TTL_SECONDS)
        payload = json.loads(raw.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="SSO-Anmeldevorgang ist ungültig oder abgelaufen.") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="SSO-Anmeldevorgang ist ungültig.")
    return payload


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _hash_code(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _frontend_redirect_with_code(code: str) -> str:
    callback = _validate_callback_url(SSO_FRONTEND_CALLBACK_URL, "SSO_FRONTEND_CALLBACK_URL")
    parsed = urlparse(callback)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["sso_code"] = code
    return urlunparse(parsed._replace(query=urlencode(query)))


def _email_allowed(email: str, provider: TenantIdentityProvider) -> bool:
    domains = _provider_domains(provider)
    if not domains:
        return True
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower()
    return domain in domains


def _resolve_jwk(metadata: dict[str, object], id_token: str) -> object:
    jwks_uri = str(metadata["jwks_uri"])
    try:
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        alg = header.get("alg")
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="OIDC-ID-Token ist ungültig.") from exc

    if alg not in {"RS256", "RS384", "RS512", "ES256", "ES384"}:
        raise HTTPException(status_code=401, detail="OIDC-ID-Token verwendet einen nicht zugelassenen Algorithmus.")
    if not kid:
        raise HTTPException(status_code=401, detail="OIDC-ID-Token enthält keine Schlüssel-ID.")

    try:
        with httpx.Client(timeout=SSO_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = client.get(jwks_uri, headers={"Accept": "application/json"})
            response.raise_for_status()
            jwks = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="OIDC-Signaturschlüssel konnten nicht geladen werden.") from exc

    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    for candidate in keys:
        if isinstance(candidate, dict) and candidate.get("kid") == kid:
            try:
                return PyJWK.from_dict(candidate, algorithm=alg).key
            except (InvalidTokenError, ValueError) as exc:
                raise HTTPException(status_code=401, detail="OIDC-Signaturschlüssel ist ungültig.") from exc
    raise HTTPException(status_code=401, detail="Passender OIDC-Signaturschlüssel wurde nicht gefunden.")


@router.get("/config", response_model=SSOProviderConfigResponse)
def get_provider_config(current_user: CurrentUser, db: DBSession) -> SSOProviderConfigResponse:
    tenant_id = _tenant_admin_id(current_user)
    provider = db.query(TenantIdentityProvider).filter(TenantIdentityProvider.tenant_id == tenant_id).first()
    if provider is None:
        raise HTTPException(status_code=404, detail="Für diesen Mandanten ist noch kein SSO-Provider konfiguriert.")
    return _serialize_provider(provider)


@router.put("/config", response_model=SSOProviderConfigResponse)
def configure_provider(
    data: SSOProviderConfigRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> SSOProviderConfigResponse:
    tenant_id = _tenant_admin_id(current_user)
    issuer = _normalize_issuer(data.issuer_url)
    secret_env = _validate_secret_env(data.client_secret_env)
    domains = _normalize_domains(data.allowed_domains)
    scopes = " ".join(dict.fromkeys(data.scopes.split()))
    required_scopes = {"openid"}
    if not required_scopes.issubset(set(scopes.split())):
        raise HTTPException(status_code=422, detail="OIDC-Scope 'openid' ist zwingend erforderlich.")

    if data.enabled and secret_env and not os.getenv(secret_env):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der referenzierte SSO-Client-Secret ist in der Laufzeitumgebung nicht gesetzt.",
        )

    provider = db.query(TenantIdentityProvider).filter(TenantIdentityProvider.tenant_id == tenant_id).first()
    if provider is None:
        provider = TenantIdentityProvider(
            tenant_id=tenant_id,
            created_by_id=current_user.id,
        )
        db.add(provider)

    provider.name = data.name.strip()
    provider.issuer_url = issuer
    provider.client_id = data.client_id.strip()
    provider.client_secret_env = secret_env
    provider.scopes = scopes
    provider.allowed_domains_json = json.dumps(domains, separators=(",", ":"))
    provider.enabled = data.enabled
    provider.auto_provision = data.auto_provision
    provider.auto_link_verified_email = data.auto_link_verified_email

    db.add(
        AuditLog(
            event=f"sso_provider_configured:{tenant_id}:{issuer}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="SSO-Konfiguration konnte nicht gespeichert werden.") from exc
    db.refresh(provider)
    return _serialize_provider(provider)


@router.get("/{tenant_slug}", response_model=SSOPublicMetadata)
def public_sso_metadata(tenant_slug: str, db: DBSession) -> SSOPublicMetadata:
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug, Tenant.is_active.is_(True)).first()
    if tenant is None:
        return SSOPublicMetadata(tenant_slug=tenant_slug, enabled=False)
    provider = db.query(TenantIdentityProvider).filter(TenantIdentityProvider.tenant_id == tenant.id).first()
    if provider is None or not provider.enabled:
        return SSOPublicMetadata(tenant_slug=tenant_slug, enabled=False)
    return SSOPublicMetadata(
        tenant_slug=tenant_slug,
        enabled=True,
        provider_name=provider.name,
        login_url=f"/auth/sso/{tenant_slug}/login",
    )


@router.get("/{tenant_slug}/login")
def begin_sso_login(tenant_slug: str, db: DBSession) -> RedirectResponse:
    _validate_callback_url(SSO_CALLBACK_URL, "SSO_CALLBACK_URL")
    _validate_callback_url(SSO_FRONTEND_CALLBACK_URL, "SSO_FRONTEND_CALLBACK_URL")

    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug, Tenant.is_active.is_(True)).first()
    if tenant is None:
        raise HTTPException(status_code=404, detail="Mandant wurde nicht gefunden.")
    provider = db.query(TenantIdentityProvider).filter(TenantIdentityProvider.tenant_id == tenant.id).first()
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=404, detail="SSO ist für diesen Mandanten nicht aktiviert.")

    metadata = _oidc_discovery(provider)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    transaction = _transaction_encrypt(
        {
            "tenant_id": tenant.id,
            "provider_id": provider.id,
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "exp": int((_utc_now() + timedelta(seconds=SSO_TRANSACTION_TTL_SECONDS)).timestamp()),
        }
    )

    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": SSO_CALLBACK_URL,
        "scope": provider.scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    location = f"{metadata['authorization_endpoint']}?{urlencode(params)}"
    response = RedirectResponse(location, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=SSO_COOKIE_NAME,
        value=transaction,
        max_age=SSO_TRANSACTION_TTL_SECONDS,
        httponly=True,
        secure=ENVIRONMENT == "production",
        samesite="lax",
        path="/auth/sso",
    )
    return response


@router.get("/callback", include_in_schema=False)
def sso_callback(
    request: Request,
    code: str,
    state_value: str | None = None,
    db: DBSession = Depends(get_db),
):
    state = state_value or request.query_params.get("state")
    transaction_cookie = request.cookies.get(SSO_COOKIE_NAME)
    if not transaction_cookie or not state:
        raise HTTPException(status_code=401, detail="SSO-State oder Transaktions-Cookie fehlt.")

    transaction = _transaction_decrypt(transaction_cookie)
    if not secrets.compare_digest(str(transaction.get("state", "")), state):
        raise HTTPException(status_code=401, detail="SSO-State stimmt nicht überein.")
    if int(transaction.get("exp", 0)) < int(_utc_now().timestamp()):
        raise HTTPException(status_code=401, detail="SSO-Anmeldevorgang ist abgelaufen.")

    tenant_id = int(transaction.get("tenant_id", 0))
    provider_id = int(transaction.get("provider_id", 0))
    provider = (
        db.query(TenantIdentityProvider)
        .filter(
            TenantIdentityProvider.id == provider_id,
            TenantIdentityProvider.tenant_id == tenant_id,
            TenantIdentityProvider.enabled.is_(True),
        )
        .first()
    )
    if provider is None:
        raise HTTPException(status_code=401, detail="SSO-Provider ist nicht mehr aktiv.")

    metadata = _oidc_discovery(provider)
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": SSO_CALLBACK_URL,
        "client_id": provider.client_id,
        "code_verifier": str(transaction.get("verifier", "")),
    }
    if provider.client_secret_env:
        client_secret = os.getenv(provider.client_secret_env)
        if not client_secret:
            raise HTTPException(status_code=503, detail="SSO-Client-Secret ist nicht verfügbar.")
        token_payload["client_secret"] = client_secret

    try:
        with httpx.Client(timeout=SSO_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            token_response = client.post(
                str(metadata["token_endpoint"]),
                data=token_payload,
                headers={"Accept": "application/json"},
            )
            token_response.raise_for_status()
            tokens = token_response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="OIDC-Tokenaustausch ist fehlgeschlagen.") from exc

    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    if not isinstance(id_token, str):
        raise HTTPException(status_code=401, detail="OIDC-Provider hat kein ID-Token geliefert.")

    key = _resolve_jwk(metadata, id_token)
    try:
        header = jwt.get_unverified_header(id_token)
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=[header["alg"]],
            audience=provider.client_id,
            issuer=provider.issuer_url.rstrip("/"),
            options={"require": ["exp", "iat", "sub"]},
        )
    except (InvalidTokenError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="OIDC-ID-Token konnte nicht verifiziert werden.") from exc

    if not secrets.compare_digest(str(claims.get("nonce", "")), str(transaction.get("nonce", ""))):
        raise HTTPException(status_code=401, detail="OIDC-Nonce stimmt nicht überein.")

    subject = str(claims.get("sub", "")).strip()
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    full_name = str(claims.get("name") or "").strip()[:200] or None
    if not subject or not email or "@" not in email:
        raise HTTPException(status_code=401, detail="OIDC-ID-Token enthält keine nutzbare Identität.")
    if claims.get("email_verified") is False:
        raise HTTPException(status_code=401, detail="OIDC-E-Mail-Adresse ist ausdrücklich nicht verifiziert.")
    if not _email_allowed(email, provider):
        raise HTTPException(status_code=403, detail="E-Mail-Domain ist für diesen Mandanten nicht freigegeben.")

    identity = (
        db.query(FederatedIdentity)
        .filter(
            FederatedIdentity.provider_id == provider.id,
            FederatedIdentity.subject == subject,
        )
        .first()
    )
    user: User | None = None
    if identity is not None:
        user = db.query(User).filter(User.id == identity.user_id, User.tenant_id == tenant_id).first()
        identity.last_login_at = _utc_now()
    else:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user is not None:
            if existing_user.tenant_id != tenant_id:
                raise HTTPException(status_code=409, detail="E-Mail-Adresse ist bereits einem anderen Mandanten zugeordnet.")
            if not provider.auto_link_verified_email:
                raise HTTPException(
                    status_code=409,
                    detail="Für dieses bestehende Konto ist eine ausdrückliche SSO-Verknüpfung erforderlich.",
                )
            user = existing_user
        elif provider.auto_provision:
            user = User(
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(48)),
                full_name=full_name,
                role="user",
                language="de",
                tenant_id=tenant_id,
                is_active=True,
            )
            db.add(user)
            db.flush()
        else:
            raise HTTPException(
                status_code=403,
                detail="SSO-Benutzer ist noch nicht provisioniert. Bitte Tenant-Admin kontaktieren.",
            )

        identity = FederatedIdentity(
            tenant_id=tenant_id,
            provider_id=provider.id,
            user_id=user.id,
            issuer=provider.issuer_url,
            subject=subject,
            email_at_link=email,
            last_login_at=_utc_now(),
        )
        db.add(identity)

    if user is None or not user.is_active:
        raise HTTPException(status_code=403, detail="Benutzerkonto ist deaktiviert oder nicht verfügbar.")

    raw_exchange_code = secrets.token_urlsafe(48)
    exchange = SSOExchangeCode(
        code_hash=_hash_code(raw_exchange_code),
        tenant_id=tenant_id,
        user_id=user.id,
        expires_at=_utc_now() + timedelta(seconds=SSO_EXCHANGE_TTL_SECONDS),
    )
    db.add(exchange)
    db.add(
        AuditLog(
            event=f"sso_login_verified:{provider.id}:{user.id}",
            user_id=user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()

    response = RedirectResponse(_frontend_redirect_with_code(raw_exchange_code), status_code=302)
    response.delete_cookie(SSO_COOKIE_NAME, path="/auth/sso")
    return response


@router.post("/exchange", response_model=SSOExchangeResponse)
def exchange_sso_code(data: SSOExchangeRequest, response: Response, db: DBSession) -> SSOExchangeResponse:
    now = _utc_now()
    record = (
        db.query(SSOExchangeCode)
        .filter(
            SSOExchangeCode.code_hash == _hash_code(data.code),
            SSOExchangeCode.consumed_at.is_(None),
        )
        .first()
    )
    if record is None or _as_utc(record.expires_at) <= now:
        raise HTTPException(status_code=401, detail="SSO-Austauschcode ist ungültig oder abgelaufen.")

    user = (
        db.query(User)
        .filter(
            User.id == record.user_id,
            User.tenant_id == record.tenant_id,
            User.is_active.is_(True),
        )
        .first()
    )
    if user is None:
        raise HTTPException(status_code=401, detail="SSO-Benutzer ist nicht verfügbar.")

    record.consumed_at = now
    db.add(
        AuditLog(
            event=f"sso_exchange_completed:{record.id}:{user.id}",
            user_id=user.id,
            tenant_id=user.tenant_id,
        )
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return SSOExchangeResponse(
        access_token=create_access_token(user),
        token_type=TOKEN_TYPE,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
