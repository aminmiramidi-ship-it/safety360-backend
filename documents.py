from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, Document, User
from schemas import (
    DocumentCreate,
    DocumentListResponse,
    DocumentResponse,
    DocumentRevisionCreate,
)

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

APPROVER_ROLES = {"tenant_admin", "hse_manager", "document_controller"}
DOCUMENT_STATUSES = {"draft", "review", "approved", "obsolete"}


def _require_tenant(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vor der Dokumentenverwaltung muss ein Mandant angelegt oder zugeordnet werden.",
        )
    return current_user.tenant_id


def _tenant_document(db: Session, document_id: int, tenant_id: int) -> Document:
    document = (
        db.query(Document)
        .filter(Document.id == document_id, Document.tenant_id == tenant_id)
        .first()
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dokument wurde nicht gefunden.",
        )
    return document


def _audit(db: Session, event: str, current_user: User, tenant_id: int) -> None:
    db.add(
        AuditLog(
            event=event,
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_document(
    data: DocumentCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> Document:
    tenant_id = _require_tenant(current_user)

    document = Document(
        logical_id=str(uuid4()),
        title=data.title.strip(),
        document_type=data.document_type.strip().lower(),
        status="draft",
        version=1,
        content_summary=data.content_summary.strip() if data.content_summary else None,
        tenant_id=tenant_id,
        created_by_id=current_user.id,
    )
    db.add(document)
    db.flush()
    _audit(db, f"document_created:{document.id}", current_user, tenant_id)
    db.commit()
    db.refresh(document)
    return document


@router.get("", response_model=DocumentListResponse)
def list_documents(
    current_user: CurrentUser,
    db: DBSession,
    latest_only: bool = Query(default=True),
    document_type: str | None = Query(default=None, max_length=80),
    document_status: str | None = Query(default=None, alias="status", max_length=30),
) -> DocumentListResponse:
    tenant_id = _require_tenant(current_user)
    query = db.query(Document).filter(Document.tenant_id == tenant_id)

    if document_type:
        query = query.filter(Document.document_type == document_type.strip().lower())
    if document_status:
        normalized_status = document_status.strip().lower()
        if normalized_status not in DOCUMENT_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Ungültiger Dokumentstatus.",
            )
        query = query.filter(Document.status == normalized_status)

    documents = query.order_by(Document.logical_id, Document.version.desc()).all()

    if latest_only:
        latest: dict[str, Document] = {}
        for document in documents:
            latest.setdefault(document.logical_id, document)
        documents = list(latest.values())

    documents.sort(key=lambda item: item.updated_at, reverse=True)
    return DocumentListResponse(documents=documents)


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document(
    document_id: int,
    current_user: CurrentUser,
    db: DBSession,
) -> Document:
    tenant_id = _require_tenant(current_user)
    return _tenant_document(db, document_id, tenant_id)


@router.post(
    "/{document_id}/submit-review",
    response_model=DocumentResponse,
)
def submit_for_review(
    document_id: int,
    current_user: CurrentUser,
    db: DBSession,
) -> Document:
    tenant_id = _require_tenant(current_user)
    document = _tenant_document(db, document_id, tenant_id)

    if document.status != "draft":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Nur Dokumente im Status 'draft' können zur Prüfung eingereicht werden.",
        )

    document.status = "review"
    _audit(db, f"document_submitted_for_review:{document.id}", current_user, tenant_id)
    db.commit()
    db.refresh(document)
    return document


@router.post(
    "/{document_id}/approve",
    response_model=DocumentResponse,
)
def approve_document(
    document_id: int,
    current_user: CurrentUser,
    db: DBSession,
) -> Document:
    tenant_id = _require_tenant(current_user)
    if current_user.role not in APPROVER_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Für die Dokumentfreigabe fehlen die erforderlichen Rechte.",
        )

    document = _tenant_document(db, document_id, tenant_id)
    if document.status != "review":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Nur Dokumente im Status 'review' können freigegeben werden.",
        )

    document.status = "approved"
    document.approved_by_id = current_user.id
    document.approved_at = datetime.now(timezone.utc)
    _audit(db, f"document_approved:{document.id}", current_user, tenant_id)
    db.commit()
    db.refresh(document)
    return document


@router.post(
    "/{document_id}/revisions",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_revision(
    document_id: int,
    data: DocumentRevisionCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> Document:
    tenant_id = _require_tenant(current_user)
    source = _tenant_document(db, document_id, tenant_id)

    latest_version = (
        db.query(Document.version)
        .filter(
            Document.tenant_id == tenant_id,
            Document.logical_id == source.logical_id,
        )
        .order_by(Document.version.desc())
        .first()
    )
    max_version = latest_version[0] if latest_version else source.version

    if source.version != max_version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Eine neue Revision kann nur vom neuesten Dokumentstand erzeugt werden.",
        )

    revision = Document(
        logical_id=source.logical_id,
        title=data.title.strip() if data.title else source.title,
        document_type=source.document_type,
        status="draft",
        version=max_version + 1,
        content_summary=(
            data.content_summary.strip()
            if data.content_summary is not None
            else source.content_summary
        ),
        tenant_id=tenant_id,
        created_by_id=current_user.id,
    )
    db.add(revision)
    db.flush()

    if source.status == "approved":
        source.status = "obsolete"

    _audit(
        db,
        f"document_revision_created:{source.id}->{revision.id}",
        current_user,
        tenant_id,
    )
    db.commit()
    db.refresh(revision)
    return revision
