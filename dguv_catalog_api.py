import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from dguv_catalog_models import DguvCatalogChange, DguvPublication
from models import AuditLog, User
from permissions import require_permission
from source_usage_policy import SourceUsageDenied, assert_source_operation_allowed

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

PUBLICATION_TYPES = {
    "vorschrift",
    "regel",
    "branchenregel",
    "information",
    "grundsatz",
    "technische_regel",
    "elektronisches_medium",
}


class DguvPublicationImport(BaseModel):
    publication_type: str = Field(min_length=3, max_length=40)
    publication_number: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=2, max_length=500)
    edition: str = Field(default="unknown", min_length=1, max_length=40)
    language: str = Field(default="de", min_length=2, max_length=20)
    status: str = Field(default="current", min_length=2, max_length=40)
    article_id: str | None = Field(default=None, max_length=80)
    source_url: HttpUrl
    responsible_carrier: str | None = Field(default=None, max_length=250)
    topic: str | None = Field(default=None, max_length=160)
    industry_scope: str | None = Field(default=None, max_length=500)
    notes: str | None = None


class DguvCatalogBatchImport(BaseModel):
    acquisition_mode: Literal[
        "manual_reference_entry",
        "user_authorized_upload",
        "licensed_feed_ingest",
        "automated_metadata_sync",
        "bulk_catalog_ingest",
    ]
    rights_confirmed: bool = False
    items: list[DguvPublicationImport] = Field(min_length=1, max_length=5000)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalized_metadata(item: DguvPublicationImport) -> str:
    payload = {
        "publication_type": item.publication_type.strip().lower(),
        "publication_number": item.publication_number.strip(),
        "title": item.title.strip(),
        "edition": item.edition.strip(),
        "language": item.language.strip().lower(),
        "status": item.status.strip().lower(),
        "article_id": item.article_id.strip() if item.article_id else None,
        "source_url": str(item.source_url),
        "responsible_carrier": item.responsible_carrier.strip() if item.responsible_carrier else None,
        "topic": item.topic.strip() if item.topic else None,
        "industry_scope": item.industry_scope.strip() if item.industry_scope else None,
        "notes": item.notes.strip() if item.notes else None,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _metadata_hash(item: DguvPublicationImport) -> str:
    return hashlib.sha256(_normalized_metadata(item).encode("utf-8")).hexdigest()


def _serialize_publication(item: DguvPublication) -> dict[str, object]:
    return {
        "id": item.id,
        "publication_type": item.publication_type,
        "publication_number": item.publication_number,
        "title": item.title,
        "edition": item.edition,
        "language": item.language,
        "status": item.status,
        "article_id": item.article_id,
        "source_url": item.source_url,
        "responsible_carrier": item.responsible_carrier,
        "topic": item.topic,
        "industry_scope": item.industry_scope,
        "rights_basis": item.rights_basis,
        "rights_confirmed": item.rights_confirmed,
        "human_review_required": item.human_review_required,
        "last_seen_at": item.last_seen_at,
        "last_verified_at": item.last_verified_at,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


@router.get("/policy")
def get_catalog_policy(current_user: CurrentUser):
    require_permission(current_user, "regulatory.read")
    return {
        "source": "DGUV Publikationsdatenbank / Vorschriften- und Regelwerk",
        "terms_url": "https://publikationen.dguv.de/nutzungsbestimmungen",
        "supported_publication_types": sorted(PUBLICATION_TYPES),
        "safe_modes": [
            "manual_reference_entry",
            "user_authorized_upload",
            "licensed_feed_ingest",
        ],
        "rights_gated_modes": [
            "automated_metadata_sync",
            "bulk_catalog_ingest",
        ],
        "blocked_modes": [
            "automated_content_scrape",
            "automated_pdf_fetch_for_ai",
            "text_data_mining",
            "model_training",
            "commercial_republication",
        ],
        "principle": (
            "Safety360 führt DGUV-Referenzen und Änderungsereignisse, verarbeitet aber keine DGUV-"
            "Volltexte automatisiert per KI/TDM ohne dokumentierte Nutzungs- oder Lizenzfreigabe."
        ),
    }


@router.post("/catalog/import", status_code=status.HTTP_200_OK)
def import_catalog(
    data: DguvCatalogBatchImport,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "regulatory.manage")

    try:
        assert_source_operation_allowed(
            "dguv-publications",
            data.acquisition_mode,
            rights_confirmed=data.rights_confirmed,
        )
    except SourceUsageDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    now = _utc_now()
    created = 0
    updated = 0
    unchanged = 0
    rejected = 0

    for incoming in data.items:
        publication_type = incoming.publication_type.strip().lower()
        if publication_type not in PUBLICATION_TYPES:
            rejected += 1
            continue

        publication_number = incoming.publication_number.strip()
        edition = incoming.edition.strip()
        new_hash = _metadata_hash(incoming)

        item = (
            db.query(DguvPublication)
            .filter(
                DguvPublication.publication_type == publication_type,
                DguvPublication.publication_number == publication_number,
                DguvPublication.edition == edition,
            )
            .first()
        )

        if item is None:
            item = DguvPublication(
                publication_type=publication_type,
                publication_number=publication_number,
                title=incoming.title.strip(),
                edition=edition,
                language=incoming.language.strip().lower(),
                status=incoming.status.strip().lower(),
                article_id=incoming.article_id.strip() if incoming.article_id else None,
                source_url=str(incoming.source_url),
                responsible_carrier=(
                    incoming.responsible_carrier.strip() if incoming.responsible_carrier else None
                ),
                topic=incoming.topic.strip() if incoming.topic else None,
                industry_scope=incoming.industry_scope.strip() if incoming.industry_scope else None,
                source_metadata_hash=new_hash,
                rights_basis=data.acquisition_mode,
                rights_confirmed=data.rights_confirmed,
                human_review_required=True,
                last_seen_at=now,
                notes=incoming.notes.strip() if incoming.notes else None,
            )
            db.add(item)
            db.flush()
            db.add(
                DguvCatalogChange(
                    publication_id=item.id,
                    change_type="created",
                    previous_hash=None,
                    new_hash=new_hash,
                    human_review_required=True,
                )
            )
            created += 1
            continue

        previous_hash = item.source_metadata_hash
        item.last_seen_at = now
        if previous_hash == new_hash:
            unchanged += 1
            continue

        item.title = incoming.title.strip()
        item.language = incoming.language.strip().lower()
        item.status = incoming.status.strip().lower()
        item.article_id = incoming.article_id.strip() if incoming.article_id else None
        item.source_url = str(incoming.source_url)
        item.responsible_carrier = (
            incoming.responsible_carrier.strip() if incoming.responsible_carrier else None
        )
        item.topic = incoming.topic.strip() if incoming.topic else None
        item.industry_scope = incoming.industry_scope.strip() if incoming.industry_scope else None
        item.source_metadata_hash = new_hash
        item.rights_basis = data.acquisition_mode
        item.rights_confirmed = data.rights_confirmed
        item.human_review_required = True
        item.last_verified_at = None
        item.notes = incoming.notes.strip() if incoming.notes else None
        db.add(
            DguvCatalogChange(
                publication_id=item.id,
                change_type="updated",
                previous_hash=previous_hash,
                new_hash=new_hash,
                human_review_required=True,
            )
        )
        updated += 1

    db.add(
        AuditLog(
            event=(
                "dguv_catalog_import:"
                f"created={created}:updated={updated}:unchanged={unchanged}:rejected={rejected}:"
                f"mode={data.acquisition_mode}"
            ),
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()

    return {
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "rejected": rejected,
        "rights_basis": data.acquisition_mode,
        "rights_confirmed": data.rights_confirmed,
    }


@router.get("/catalog")
def list_catalog(
    current_user: CurrentUser,
    db: DBSession,
    publication_type: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    publication_number: str | None = None,
):
    require_permission(current_user, "regulatory.read")
    query = db.query(DguvPublication)
    if publication_type:
        query = query.filter(DguvPublication.publication_type == publication_type.strip().lower())
    if status_filter:
        query = query.filter(DguvPublication.status == status_filter.strip().lower())
    if publication_number:
        query = query.filter(DguvPublication.publication_number == publication_number.strip())

    items = query.order_by(
        DguvPublication.publication_type.asc(),
        DguvPublication.publication_number.asc(),
        DguvPublication.edition.desc(),
    ).limit(5000).all()
    return {"publications": [_serialize_publication(item) for item in items]}


@router.get("/changes")
def list_catalog_changes(
    current_user: CurrentUser,
    db: DBSession,
    review_status: str | None = None,
):
    require_permission(current_user, "regulatory.read")
    query = db.query(DguvCatalogChange)
    if review_status:
        query = query.filter(DguvCatalogChange.review_status == review_status.strip().lower())
    rows = query.order_by(DguvCatalogChange.detected_at.desc()).limit(1000).all()
    return {
        "changes": [
            {
                "id": row.id,
                "publication_id": row.publication_id,
                "change_type": row.change_type,
                "previous_hash": row.previous_hash,
                "new_hash": row.new_hash,
                "detected_at": row.detected_at,
                "review_status": row.review_status,
                "impact": json.loads(row.impact_json or "{}"),
                "human_review_required": row.human_review_required,
                "reviewed_at": row.reviewed_at,
            }
            for row in rows
        ]
    }
