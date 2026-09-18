import hashlib
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, Tenant, TenantInvitation, User
from schemas import (
    TenantCreate,
    TenantInvitationAccept,
    TenantInvitationCreate,
    TenantInvitationCreated,
    TenantInvitationListResponse,
    TenantInvitationResponse,
    TenantResponse,
    UserResponse,
)

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

TENANT_ADMIN_ROLE = "tenant_admin"
ASSIGNABLE_ROLES = {
    "user",
    "viewer",
    "manager",
    "hse_manager",
    "document_controller",
    "tenant_admin",
}


def _slugify(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_value.lower()).strip("-")
    return slug[:100]


def _next_available_slug(db: Session, requested: str) -> str:
    base = _slugify(requested)
    if not base:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Aus dem Firmennamen konnte kein gültiger Mandanten-Slug erzeugt werden.",
        )

    candidate = base
    counter = 2
    while db.query(Tenant).filter(Tenant.slug == candidate).first() is not None:
        suffix = f"-{counter}"
        candidate = f"{base[:100 - len(suffix)]}{suffix}"
        counter += 1

    return candidate


def _require_tenant_admin(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Benutzer ist noch keinem Mandanten zugeordnet.",
        )
    if current_user.role != TENANT_ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Für diese Aktion sind Tenant-Admin-Rechte erforderlich.",
        )
    return current_user.tenant_id


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_expired(invitation: TenantInvitation) -> bool:
    return _as_utc(invitation.expires_at) <= datetime.now(timezone.utc)


@router.post(
    "",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_tenant(
    tenant_data: TenantCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> Tenant:
    if current_user.tenant_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Benutzer ist bereits einem Mandanten zugeordnet.",
        )

    name = tenant_data.name.strip()
    if len(name) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Der Firmenname ist zu kurz.",
        )

    requested_slug = tenant_data.slug.strip() if tenant_data.slug else name
    slug = _next_available_slug(db, requested_slug)

    tenant = Tenant(name=name, slug=slug, is_active=True)
    db.add(tenant)

    try:
        db.flush()
        current_user.tenant_id = tenant.id
        current_user.role = TENANT_ADMIN_ROLE
        db.add(
            AuditLog(
                event=f"tenant_created:{tenant.id}",
                user_id=current_user.id,
                tenant_id=tenant.id,
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Mandant konnte wegen eines Namenskonflikts nicht angelegt werden.",
        )

    db.refresh(tenant)
    return tenant


@router.get("/current", response_model=TenantResponse)
def current_tenant(
    current_user: CurrentUser,
    db: DBSession,
) -> Tenant:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Der Benutzer ist noch keinem Mandanten zugeordnet.",
        )

    tenant = (
        db.query(Tenant)
        .filter(Tenant.id == current_user.tenant_id, Tenant.is_active.is_(True))
        .first()
    )
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Der zugeordnete Mandant wurde nicht gefunden oder ist deaktiviert.",
        )

    return tenant


@router.post(
    "/invitations",
    response_model=TenantInvitationCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_invitation(
    invitation_data: TenantInvitationCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> TenantInvitationCreated:
    tenant_id = _require_tenant_admin(current_user)
    normalized_email = str(invitation_data.email).strip().lower()
    normalized_role = invitation_data.role.strip().lower()

    if normalized_role not in ASSIGNABLE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Die angegebene Rolle ist für Mandanteneinladungen nicht zulässig.",
        )

    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user is not None and existing_user.tenant_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für diese E-Mail-Adresse kann aktuell keine Einladung erstellt werden.",
        )

    pending_invitations = (
        db.query(TenantInvitation)
        .filter(
            TenantInvitation.tenant_id == tenant_id,
            TenantInvitation.email == normalized_email,
            TenantInvitation.accepted_at.is_(None),
        )
        .all()
    )
    if any(not _is_expired(invitation) for invitation in pending_invitations):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für diese E-Mail-Adresse besteht bereits eine aktive Einladung.",
        )

    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    invitation = TenantInvitation(
        tenant_id=tenant_id,
        email=normalized_email,
        role=normalized_role,
        token_hash=_token_hash(raw_token),
        created_by_id=current_user.id,
        expires_at=now + timedelta(hours=invitation_data.expires_in_hours),
        accepted_at=None,
    )
    db.add(invitation)

    try:
        db.flush()
        db.add(
            AuditLog(
                event=f"tenant_invitation_created:{invitation.id}:{normalized_role}",
                user_id=current_user.id,
                tenant_id=tenant_id,
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Die Einladung konnte nicht eindeutig erstellt werden.",
        )

    db.refresh(invitation)
    invitation_response = TenantInvitationResponse.model_validate(invitation)
    return TenantInvitationCreated(
        **invitation_response.model_dump(),
        invitation_token=raw_token,
    )


@router.get(
    "/invitations",
    response_model=TenantInvitationListResponse,
)
def list_invitations(
    current_user: CurrentUser,
    db: DBSession,
    include_closed: bool = Query(default=False),
) -> TenantInvitationListResponse:
    tenant_id = _require_tenant_admin(current_user)
    invitations = (
        db.query(TenantInvitation)
        .filter(TenantInvitation.tenant_id == tenant_id)
        .order_by(TenantInvitation.created_at.desc())
        .all()
    )

    if not include_closed:
        invitations = [
            invitation
            for invitation in invitations
            if invitation.accepted_at is None and not _is_expired(invitation)
        ]

    return TenantInvitationListResponse(invitations=invitations)


@router.post(
    "/invitations/accept",
    response_model=UserResponse,
)
def accept_invitation(
    invitation_data: TenantInvitationAccept,
    current_user: CurrentUser,
    db: DBSession,
) -> User:
    invitation = (
        db.query(TenantInvitation)
        .filter(
            TenantInvitation.token_hash == _token_hash(invitation_data.invitation_token),
        )
        .first()
    )
    if invitation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Die Einladung ist ungültig oder nicht mehr verfügbar.",
        )

    if invitation.accepted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Die Einladung wurde bereits verwendet.",
        )

    if _is_expired(invitation):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Die Einladung ist abgelaufen.",
        )

    if current_user.email.strip().lower() != invitation.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Die Einladung ist für eine andere E-Mail-Adresse bestimmt.",
        )

    if current_user.tenant_id is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Benutzer ist bereits einem Mandanten zugeordnet.",
        )

    tenant = (
        db.query(Tenant)
        .filter(Tenant.id == invitation.tenant_id, Tenant.is_active.is_(True))
        .first()
    )
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Der Zielmandant ist nicht verfügbar.",
        )

    now = datetime.now(timezone.utc)
    current_user.tenant_id = invitation.tenant_id
    current_user.role = invitation.role
    invitation.accepted_at = now
    db.add(
        AuditLog(
            event=f"tenant_invitation_accepted:{invitation.id}:{invitation.role}",
            user_id=current_user.id,
            tenant_id=invitation.tenant_id,
        )
    )
    db.commit()
    db.refresh(current_user)
    return current_user
