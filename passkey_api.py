import base64
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from audit_integrity import append_audit_event
from auth import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TTL_MINUTES,
    _hash_secret,
    _now,
    _set_browser_session_cookies,
    get_current_user,
)
from database import get_db
from models import AuditLog, User
from passkey_models import PasskeyCredential, WebAuthnCeremony, WebAuthnUserHandle
from schemas import UserResponse
from session_models import BrowserSession

router = APIRouter()

ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").lower()
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost").strip()
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Safety360").strip()
WEBAUTHN_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv("WEBAUTHN_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]
WEBAUTHN_CEREMONY_TTL_SECONDS = max(
    60,
    min(int(os.getenv("WEBAUTHN_CEREMONY_TTL_SECONDS", "300")), 600),
)
WEBAUTHN_TIMEOUT_MS = max(
    15000,
    min(int(os.getenv("WEBAUTHN_TIMEOUT_MS", "60000")), 180000),
)
WEBAUTHN_RECENT_AUTH_SECONDS = max(
    60,
    min(int(os.getenv("WEBAUTHN_RECENT_AUTH_SECONDS", "600")), 3600),
)

if not WEBAUTHN_RP_ID or not WEBAUTHN_RP_NAME or not WEBAUTHN_ORIGINS:
    raise RuntimeError("WebAuthn RP-ID, RP-Name und mindestens ein Origin sind erforderlich.")
if any("*" in origin for origin in WEBAUTHN_ORIGINS):
    raise RuntimeError("Wildcard-Origins sind für WebAuthn nicht zulässig.")
if ENVIRONMENT == "production":
    if "WEBAUTHN_RP_ID" not in os.environ or "WEBAUTHN_ORIGINS" not in os.environ:
        raise RuntimeError(
            "WEBAUTHN_RP_ID und WEBAUTHN_ORIGINS müssen in Produktion explizit gesetzt sein."
        )
    if any(not origin.startswith("https://") for origin in WEBAUTHN_ORIGINS):
        raise RuntimeError("WebAuthn Origins müssen in Produktion HTTPS verwenden.")

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


class CeremonyOptionsResponse(BaseModel):
    ceremony_id: str
    public_key: dict[str, Any]


class PasskeyRegistrationVerify(BaseModel):
    ceremony_id: str = Field(min_length=36, max_length=36)
    credential: dict[str, Any]
    nickname: str | None = Field(default=None, max_length=120)


class PasskeyAuthenticationVerify(BaseModel):
    ceremony_id: str = Field(min_length=36, max_length=36)
    credential: dict[str, Any]


class PasskeyResponse(BaseModel):
    id: int
    nickname: str | None
    credential_id_hint: str
    device_type: str | None
    backed_up: bool
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class PasskeyCapabilitiesResponse(BaseModel):
    enabled: bool
    rp_id: str
    rp_name: str
    user_verification: str
    discoverable_credentials: bool
    recent_auth_seconds: int


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if len(value) > 4096:
        raise ValueError("Base64URL value is too long")
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _credential_hint(credential_id: str) -> str:
    if len(credential_id) <= 12:
        return credential_id
    return f"{credential_id[:6]}…{credential_id[-6:]}"


def _get_or_create_user_handle(db: Session, user: User) -> WebAuthnUserHandle:
    existing = (
        db.query(WebAuthnUserHandle)
        .filter(WebAuthnUserHandle.user_id == user.id)
        .first()
    )
    if existing is not None:
        return existing

    handle = WebAuthnUserHandle(
        user_id=user.id,
        handle=_b64url_encode(secrets.token_bytes(32)),
    )
    db.add(handle)
    try:
        db.flush()
        return handle
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(WebAuthnUserHandle)
            .filter(WebAuthnUserHandle.user_id == user.id)
            .first()
        )
        if existing is None:
            raise
        return existing


def _require_recent_browser_session(request: Request, user: User, db: Session) -> BrowserSession:
    raw_session = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_session or len(raw_session) > 512:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Für diese Sicherheitsänderung ist eine aktuelle Browser-Anmeldung erforderlich.",
        )

    browser_session = (
        db.query(BrowserSession)
        .filter(
            BrowserSession.session_hash == _hash_secret(raw_session),
            BrowserSession.user_id == user.id,
            BrowserSession.revoked_at.is_(None),
        )
        .first()
    )
    if browser_session is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Für diese Sicherheitsänderung ist eine aktuelle Browser-Anmeldung erforderlich.",
        )

    created_at = _as_utc(browser_session.created_at)
    expires_at = _as_utc(browser_session.expires_at)
    now = _now()
    if (
        created_at is None
        or expires_at is None
        or expires_at <= now
        or created_at + timedelta(seconds=WEBAUTHN_RECENT_AUTH_SECONDS) < now
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bitte melde dich erneut an, bevor du Passkeys änderst.",
        )
    return browser_session


def _create_ceremony(
    db: Session,
    *,
    purpose: str,
    challenge: bytes,
    user_id: int | None,
) -> WebAuthnCeremony:
    now = _now()
    ceremony = WebAuthnCeremony(
        ceremony_id=str(uuid.uuid4()),
        purpose=purpose,
        user_id=user_id,
        challenge=_b64url_encode(challenge),
        created_at=now,
        expires_at=now + timedelta(seconds=WEBAUTHN_CEREMONY_TTL_SECONDS),
    )
    db.add(ceremony)
    db.commit()
    db.refresh(ceremony)
    return ceremony


def _consume_ceremony(
    db: Session,
    *,
    ceremony_id: str,
    purpose: str,
    user_id: int | None,
) -> WebAuthnCeremony:
    ceremony = (
        db.query(WebAuthnCeremony)
        .filter(
            WebAuthnCeremony.ceremony_id == ceremony_id,
            WebAuthnCeremony.purpose == purpose,
        )
        .first()
    )
    if ceremony is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ungültige oder abgelaufene Passkey-Anfrage.",
        )

    now = _now()
    expires_at = _as_utc(ceremony.expires_at)
    if ceremony.used_at is not None or expires_at is None or expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ungültige oder abgelaufene Passkey-Anfrage.",
        )
    if user_id is not None and ceremony.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ungültige oder abgelaufene Passkey-Anfrage.",
        )

    updated = (
        db.query(WebAuthnCeremony)
        .filter(
            WebAuthnCeremony.id == ceremony.id,
            WebAuthnCeremony.used_at.is_(None),
        )
        .update({WebAuthnCeremony.used_at: now}, synchronize_session=False)
    )
    if updated != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ungültige oder abgelaufene Passkey-Anfrage.",
        )
    db.commit()
    db.refresh(ceremony)
    return ceremony


def _active_credentials(db: Session, user_id: int) -> list[PasskeyCredential]:
    return (
        db.query(PasskeyCredential)
        .filter(
            PasskeyCredential.user_id == user_id,
            PasskeyCredential.revoked_at.is_(None),
        )
        .order_by(PasskeyCredential.created_at.asc())
        .all()
    )


def _issue_browser_session(
    db: Session,
    response: Response,
    user: User,
    authentication_mode: str,
) -> None:
    session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(minutes=SESSION_TTL_MINUTES)
    browser_session = BrowserSession(
        session_hash=_hash_secret(session_token),
        csrf_hash=_hash_secret(csrf_token),
        user_id=user.id,
        tenant_id=user.tenant_id,
        expires_at=expires_at,
    )
    db.add(browser_session)
    db.flush()
    db.add(
        AuditLog(
            event=f"browser_session_created:{browser_session.id}",
            user_id=user.id,
            tenant_id=user.tenant_id,
        )
    )
    append_audit_event(
        db,
        tenant_id=user.tenant_id,
        actor_user_id=user.id,
        action="auth.browser_session.created",
        object_type="browser_session",
        object_id=browser_session.id,
        source="auth",
        details={
            "authentication_mode": authentication_mode,
            "ttl_minutes": SESSION_TTL_MINUTES,
        },
    )
    db.commit()
    _set_browser_session_cookies(response, session_token, csrf_token, expires_at)


@router.get("/capabilities", response_model=PasskeyCapabilitiesResponse)
def passkey_capabilities() -> PasskeyCapabilitiesResponse:
    return PasskeyCapabilitiesResponse(
        enabled=True,
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_verification="required",
        discoverable_credentials=True,
        recent_auth_seconds=WEBAUTHN_RECENT_AUTH_SECONDS,
    )


@router.get("", response_model=list[PasskeyResponse])
def list_passkeys(current_user: CurrentUser, db: DBSession) -> list[PasskeyResponse]:
    credentials = (
        db.query(PasskeyCredential)
        .filter(PasskeyCredential.user_id == current_user.id)
        .order_by(PasskeyCredential.created_at.desc())
        .all()
    )
    return [
        PasskeyResponse(
            id=credential.id,
            nickname=credential.nickname,
            credential_id_hint=_credential_hint(credential.credential_id),
            device_type=credential.device_type,
            backed_up=bool(credential.backed_up),
            created_at=credential.created_at,
            last_used_at=credential.last_used_at,
            revoked_at=credential.revoked_at,
        )
        for credential in credentials
    ]


@router.post("/registration/options", response_model=CeremonyOptionsResponse)
def registration_options(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> CeremonyOptionsResponse:
    _require_recent_browser_session(request, current_user, db)
    user_handle = _get_or_create_user_handle(db, current_user)
    active_credentials = _active_credentials(db, current_user.id)

    descriptors = []
    for credential in active_credentials:
        try:
            descriptors.append(
                PublicKeyCredentialDescriptor(id=_b64url_decode(credential.credential_id))
            )
        except ValueError:
            continue

    options = generate_registration_options(
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=_b64url_decode(user_handle.handle),
        user_name=current_user.email,
        user_display_name=current_user.full_name or current_user.email,
        timeout=WEBAUTHN_TIMEOUT_MS,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=descriptors,
    )
    ceremony = _create_ceremony(
        db,
        purpose="registration",
        challenge=options.challenge,
        user_id=current_user.id,
    )
    return CeremonyOptionsResponse(
        ceremony_id=ceremony.ceremony_id,
        public_key=json.loads(options_to_json(options)),
    )


@router.post("/registration/verify", response_model=PasskeyResponse)
def registration_verify(
    payload: PasskeyRegistrationVerify,
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> PasskeyResponse:
    _require_recent_browser_session(request, current_user, db)
    ceremony = _consume_ceremony(
        db,
        ceremony_id=payload.ceremony_id,
        purpose="registration",
        user_id=current_user.id,
    )

    try:
        verification = verify_registration_response(
            credential=payload.credential,
            expected_challenge=_b64url_decode(ceremony.challenge),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGINS,
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passkey konnte nicht verifiziert werden.",
        )

    credential_id = _b64url_encode(verification.credential_id)
    existing = (
        db.query(PasskeyCredential)
        .filter(PasskeyCredential.credential_id == credential_id)
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Dieser Passkey ist bereits registriert.",
        )

    response_data = payload.credential.get("response")
    transports: list[str] = []
    if isinstance(response_data, dict):
        raw_transports = response_data.get("transports")
        if isinstance(raw_transports, list):
            transports = [
                str(item)[:30]
                for item in raw_transports
                if isinstance(item, str)
            ][:10]

    device_type = getattr(verification.credential_device_type, "value", None)
    passkey = PasskeyCredential(
        credential_id=credential_id,
        credential_public_key=_b64url_encode(verification.credential_public_key),
        sign_count=max(0, int(verification.sign_count)),
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        nickname=payload.nickname.strip() if payload.nickname and payload.nickname.strip() else None,
        transports_json=json.dumps(transports) if transports else None,
        device_type=str(device_type) if device_type is not None else None,
        backed_up=bool(verification.credential_backed_up),
        aaguid=str(verification.aaguid)[:36] if verification.aaguid else None,
    )
    db.add(passkey)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Dieser Passkey ist bereits registriert.",
        )

    append_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="auth.passkey.registered",
        object_type="passkey_credential",
        object_id=passkey.id,
        source="auth",
        details={
            "device_type": passkey.device_type,
            "backed_up": passkey.backed_up,
        },
    )
    db.commit()
    db.refresh(passkey)
    return PasskeyResponse(
        id=passkey.id,
        nickname=passkey.nickname,
        credential_id_hint=_credential_hint(passkey.credential_id),
        device_type=passkey.device_type,
        backed_up=bool(passkey.backed_up),
        created_at=passkey.created_at,
        last_used_at=passkey.last_used_at,
        revoked_at=passkey.revoked_at,
    )


@router.post("/authentication/options", response_model=CeremonyOptionsResponse)
def authentication_options(db: DBSession) -> CeremonyOptionsResponse:
    options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        timeout=WEBAUTHN_TIMEOUT_MS,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    ceremony = _create_ceremony(
        db,
        purpose="authentication",
        challenge=options.challenge,
        user_id=None,
    )
    return CeremonyOptionsResponse(
        ceremony_id=ceremony.ceremony_id,
        public_key=json.loads(options_to_json(options)),
    )


@router.post("/authentication/verify", response_model=UserResponse)
def authentication_verify(
    payload: PasskeyAuthenticationVerify,
    response: Response,
    db: DBSession,
) -> User:
    ceremony = _consume_ceremony(
        db,
        ceremony_id=payload.ceremony_id,
        purpose="authentication",
        user_id=None,
    )

    credential_id = payload.credential.get("id")
    if not isinstance(credential_id, str) or not credential_id or len(credential_id) > 1024:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Passkey-Anmeldung fehlgeschlagen.",
        )

    passkey = (
        db.query(PasskeyCredential)
        .filter(
            PasskeyCredential.credential_id == credential_id,
            PasskeyCredential.revoked_at.is_(None),
        )
        .first()
    )
    if passkey is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Passkey-Anmeldung fehlgeschlagen.",
        )

    user = (
        db.query(User)
        .filter(User.id == passkey.user_id, User.is_active.is_(True))
        .first()
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Passkey-Anmeldung fehlgeschlagen.",
        )

    try:
        verification = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=_b64url_decode(ceremony.challenge),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGINS,
            credential_public_key=_b64url_decode(passkey.credential_public_key),
            credential_current_sign_count=max(0, int(passkey.sign_count)),
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, TypeError):
        append_audit_event(
            db,
            tenant_id=user.tenant_id,
            actor_user_id=user.id,
            action="auth.passkey.login.failed",
            object_type="passkey_credential",
            object_id=passkey.id,
            outcome="failure",
            source="auth",
            details={"reason": "verification_failed"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Passkey-Anmeldung fehlgeschlagen.",
        )

    passkey.sign_count = max(0, int(verification.new_sign_count))
    passkey.last_used_at = _now()
    append_audit_event(
        db,
        tenant_id=user.tenant_id,
        actor_user_id=user.id,
        action="auth.passkey.login.succeeded",
        object_type="passkey_credential",
        object_id=passkey.id,
        source="auth",
        details={"authentication_mode": "passkey"},
    )
    _issue_browser_session(db, response, user, "passkey")
    return user


@router.delete("/{passkey_id}")
def revoke_passkey(
    passkey_id: int,
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    _require_recent_browser_session(request, current_user, db)
    passkey = (
        db.query(PasskeyCredential)
        .filter(
            PasskeyCredential.id == passkey_id,
            PasskeyCredential.user_id == current_user.id,
            PasskeyCredential.revoked_at.is_(None),
        )
        .first()
    )
    if passkey is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey wurde nicht gefunden.",
        )

    passkey.revoked_at = _now()
    append_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="auth.passkey.revoked",
        object_type="passkey_credential",
        object_id=passkey.id,
        source="auth",
        details={"reason": "user_revoked"},
    )
    db.commit()
    return {"status": "revoked"}
