from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from audit_integrity import audit_event_to_dict, verify_audit_chain
from audit_models import AuditEvent
from auth import get_current_user
from database import get_db
from models import User
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
EventLimit = Annotated[int, Query(ge=1, le=500)]
ExportLimit = Annotated[int, Query(ge=1, le=5000)]
BeforeId = Annotated[int | None, Query(ge=1)]
ActionFilter = Annotated[str | None, Query(max_length=120)]
ObjectTypeFilter = Annotated[str | None, Query(max_length=120)]


def _resolve_tenant_scope(current_user: User, requested_tenant_id: int | None) -> int | None:
    if current_user.role == "admin":
        if requested_tenant_id is not None:
            return requested_tenant_id
        return current_user.tenant_id

    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für Audit-Abfragen muss der Benutzer einem Mandanten zugeordnet sein.",
        )
    if requested_tenant_id is not None and requested_tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit-Daten anderer Mandanten dürfen nicht gelesen werden.",
        )
    return current_user.tenant_id


@router.get("/events")
def list_audit_events(
    current_user: CurrentUser,
    db: DBSession,
    tenant_id: int | None = None,
    limit: EventLimit = 100,
    before_id: BeforeId = None,
    action: ActionFilter = None,
    object_type: ObjectTypeFilter = None,
):
    require_permission(current_user, "audit.read")
    scope_tenant_id = _resolve_tenant_scope(current_user, tenant_id)

    query = db.query(AuditEvent)
    if scope_tenant_id is None:
        query = query.filter(AuditEvent.tenant_id.is_(None))
    else:
        query = query.filter(AuditEvent.tenant_id == scope_tenant_id)
    if before_id is not None:
        query = query.filter(AuditEvent.id < before_id)
    if action:
        query = query.filter(AuditEvent.action == action.strip().lower())
    if object_type:
        query = query.filter(AuditEvent.object_type == object_type.strip().lower())

    events = query.order_by(AuditEvent.id.desc()).limit(limit).all()
    return {
        "tenant_id": scope_tenant_id,
        "events": [audit_event_to_dict(event) for event in events],
        "next_before_id": events[-1].id if len(events) == limit else None,
    }


@router.get("/verify")
def verify_audit_integrity(
    current_user: CurrentUser,
    db: DBSession,
    tenant_id: int | None = None,
):
    require_permission(current_user, "audit.verify")
    scope_tenant_id = _resolve_tenant_scope(current_user, tenant_id)
    return verify_audit_chain(db, tenant_id=scope_tenant_id)


@router.get("/export")
def export_audit_events(
    current_user: CurrentUser,
    db: DBSession,
    tenant_id: int | None = None,
    limit: ExportLimit = 1000,
):
    require_permission(current_user, "audit.export")
    scope_tenant_id = _resolve_tenant_scope(current_user, tenant_id)

    query = db.query(AuditEvent)
    if scope_tenant_id is None:
        query = query.filter(AuditEvent.tenant_id.is_(None))
    else:
        query = query.filter(AuditEvent.tenant_id == scope_tenant_id)
    events = query.order_by(AuditEvent.sequence.asc()).limit(limit).all()
    verification = verify_audit_chain(db, tenant_id=scope_tenant_id)

    return {
        "format": "safety360-audit-export-v1",
        "tenant_id": scope_tenant_id,
        "verification": verification,
        "events": [audit_event_to_dict(event) for event in events],
        "truncated": len(events) == limit,
    }
