import re
import unicodedata
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, Tenant, User
from schemas import TenantCreate, TenantResponse

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


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
        current_user.role = "tenant_admin"
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
