import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from permissions import require_permission
from regulatory_models import RegulatoryChange, RegulatoryRequirement, RegulatorySource

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


OFFICIAL_SOURCE_SEEDS: tuple[dict[str, object], ...] = (
    {
        "authority": "Bundesministerium der Justiz / Bundesamt für Justiz",
        "source_key": "gesetze-im-internet",
        "name": "Gesetze im Internet",
        "jurisdiction": "DE",
        "source_type": "law",
        "base_url": "https://www.gesetze-im-internet.de/",
        "is_primary": True,
        "terms_note": "Amtliche bzw. amtlich bereitgestellte Rechtsquelle; konkrete Nutzung und Aktualität je Norm prüfen.",
    },
    {
        "authority": "BAuA",
        "source_key": "baua",
        "name": "Bundesanstalt für Arbeitsschutz und Arbeitsmedizin",
        "jurisdiction": "DE",
        "source_type": "authority_guidance",
        "base_url": "https://www.baua.de/",
        "is_primary": True,
        "terms_note": "Behördenquelle für Arbeitsschutzwissen, Technische Regeln und Fachinformationen.",
    },
    {
        "authority": "DGUV",
        "source_key": "dguv",
        "name": "Deutsche Gesetzliche Unfallversicherung",
        "jurisdiction": "DE",
        "source_type": "accident_insurance_rules",
        "base_url": "https://www.dguv.de/",
        "is_primary": True,
        "terms_note": "Primäre Unfallversicherungsträger-Quelle; Geltungsbereich und Fassung je Regelwerk prüfen.",
    },
    {
        "authority": "European Union",
        "source_key": "eur-lex",
        "name": "EUR-Lex",
        "jurisdiction": "EU",
        "source_type": "eu_law",
        "base_url": "https://eur-lex.europa.eu/",
        "is_primary": True,
        "terms_note": "Offizielle EU-Rechtsquelle.",
    },
    {
        "authority": "ISO",
        "source_key": "iso-catalogue",
        "name": "ISO Standards Catalogue",
        "jurisdiction": "GLOBAL",
        "source_type": "management_system_standard_metadata",
        "base_url": "https://www.iso.org/standards.html",
        "is_primary": True,
        "terms_note": "Nur bibliografische/öffentliche Metadaten und zulässige Zusammenfassungen speichern; keine geschützten Normentexte übernehmen.",
    },
)


class SourceCreate(BaseModel):
    authority: str = Field(min_length=2, max_length=160)
    source_key: str = Field(min_length=2, max_length=160)
    name: str = Field(min_length=2, max_length=250)
    jurisdiction: str = Field(min_length=2, max_length=80)
    source_type: str = Field(min_length=2, max_length=80)
    base_url: HttpUrl
    is_primary: bool = True
    enabled: bool = True
    terms_note: str | None = Field(default=None, max_length=1000)


class RequirementUpsert(BaseModel):
    source_id: int
    external_key: str = Field(min_length=1, max_length=240)
    title: str = Field(min_length=2, max_length=500)
    citation: str | None = Field(default=None, max_length=500)
    summary: str | None = None
    jurisdiction: str = Field(min_length=2, max_length=80)
    topic: str = Field(min_length=2, max_length=120)
    management_system: str | None = Field(default=None, max_length=120)
    status: str = Field(default="current", min_length=2, max_length=40)
    source_version: str | None = Field(default=None, max_length=160)
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    applicability: dict[str, object] = Field(default_factory=dict)
    human_review_required: bool = True


class RequirementReview(BaseModel):
    verified: bool = True
    review_status: str = Field(default="reviewed", min_length=2, max_length=40)
    impact: dict[str, object] = Field(default_factory=dict)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalized_payload(data: RequirementUpsert) -> str:
    payload = {
        "external_key": data.external_key.strip(),
        "title": data.title.strip(),
        "citation": data.citation.strip() if data.citation else None,
        "summary": data.summary.strip() if data.summary else None,
        "jurisdiction": data.jurisdiction.strip().upper(),
        "topic": data.topic.strip().lower(),
        "management_system": data.management_system.strip().upper() if data.management_system else None,
        "status": data.status.strip().lower(),
        "source_version": data.source_version.strip() if data.source_version else None,
        "effective_from": data.effective_from.isoformat() if data.effective_from else None,
        "effective_to": data.effective_to.isoformat() if data.effective_to else None,
        "applicability": data.applicability,
        "human_review_required": data.human_review_required,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _payload_hash(data: RequirementUpsert) -> str:
    return hashlib.sha256(_normalized_payload(data).encode("utf-8")).hexdigest()


def _serialize_source(source: RegulatorySource) -> dict[str, object]:
    return {
        "id": source.id,
        "authority": source.authority,
        "source_key": source.source_key,
        "name": source.name,
        "jurisdiction": source.jurisdiction,
        "source_type": source.source_type,
        "base_url": source.base_url,
        "is_primary": source.is_primary,
        "enabled": source.enabled,
        "terms_note": source.terms_note,
        "last_checked_at": source.last_checked_at,
        "created_at": source.created_at,
        "updated_at": source.updated_at,
    }


def _serialize_requirement(requirement: RegulatoryRequirement) -> dict[str, object]:
    return {
        "id": requirement.id,
        "source_id": requirement.source_id,
        "external_key": requirement.external_key,
        "title": requirement.title,
        "citation": requirement.citation,
        "summary": requirement.summary,
        "jurisdiction": requirement.jurisdiction,
        "topic": requirement.topic,
        "management_system": requirement.management_system,
        "status": requirement.status,
        "source_version": requirement.source_version,
        "effective_from": requirement.effective_from,
        "effective_to": requirement.effective_to,
        "content_hash": requirement.content_hash,
        "applicability": json.loads(requirement.applicability_json or "{}"),
        "human_review_required": requirement.human_review_required,
        "verified_at": requirement.verified_at,
        "verified_by_id": requirement.verified_by_id,
        "last_seen_at": requirement.last_seen_at,
        "created_at": requirement.created_at,
        "updated_at": requirement.updated_at,
    }


@router.post("/sources/seed", status_code=status.HTTP_201_CREATED)
def seed_official_sources(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "regulatory.manage")
    created = 0
    for payload in OFFICIAL_SOURCE_SEEDS:
        existing = db.query(RegulatorySource).filter(
            RegulatorySource.authority == payload["authority"],
            RegulatorySource.source_key == payload["source_key"],
        ).first()
        if existing:
            continue
        db.add(RegulatorySource(**payload))
        created += 1

    db.add(
        AuditLog(
            event=f"regulatory_sources_seeded:{created}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()
    return {"created": created, "source_count": len(OFFICIAL_SOURCE_SEEDS)}


@router.post("/sources", status_code=status.HTTP_201_CREATED)
def create_source(data: SourceCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "regulatory.manage")
    duplicate = db.query(RegulatorySource).filter(
        RegulatorySource.authority == data.authority.strip(),
        RegulatorySource.source_key == data.source_key.strip().lower(),
    ).first()
    if duplicate:
        raise HTTPException(status_code=409, detail="Regelwerksquelle ist bereits registriert.")

    source = RegulatorySource(
        authority=data.authority.strip(),
        source_key=data.source_key.strip().lower(),
        name=data.name.strip(),
        jurisdiction=data.jurisdiction.strip().upper(),
        source_type=data.source_type.strip().lower(),
        base_url=str(data.base_url),
        is_primary=data.is_primary,
        enabled=data.enabled,
        terms_note=data.terms_note.strip() if data.terms_note else None,
    )
    db.add(source)
    db.flush()
    db.add(
        AuditLog(
            event=f"regulatory_source_created:{source.id}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()
    db.refresh(source)
    return _serialize_source(source)


@router.get("/sources")
def list_sources(current_user: CurrentUser, db: DBSession, enabled_only: bool = True):
    require_permission(current_user, "regulatory.read")
    query = db.query(RegulatorySource)
    if enabled_only:
        query = query.filter(RegulatorySource.enabled.is_(True))
    return {"sources": [_serialize_source(item) for item in query.order_by(RegulatorySource.authority.asc()).all()]}


@router.put("/requirements/upsert")
def upsert_requirement(data: RequirementUpsert, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "regulatory.manage")
    source = db.query(RegulatorySource).filter(RegulatorySource.id == data.source_id).first()
    if source is None or not source.enabled:
        raise HTTPException(status_code=404, detail="Aktive Regelwerksquelle wurde nicht gefunden.")

    new_hash = _payload_hash(data)
    now = _utc_now()
    requirement = db.query(RegulatoryRequirement).filter(
        RegulatoryRequirement.source_id == data.source_id,
        RegulatoryRequirement.external_key == data.external_key.strip(),
    ).first()

    if requirement is None:
        requirement = RegulatoryRequirement(
            source_id=data.source_id,
            external_key=data.external_key.strip(),
            title=data.title.strip(),
            citation=data.citation.strip() if data.citation else None,
            summary=data.summary.strip() if data.summary else None,
            jurisdiction=data.jurisdiction.strip().upper(),
            topic=data.topic.strip().lower(),
            management_system=data.management_system.strip().upper() if data.management_system else None,
            status=data.status.strip().lower(),
            source_version=data.source_version.strip() if data.source_version else None,
            effective_from=data.effective_from,
            effective_to=data.effective_to,
            content_hash=new_hash,
            applicability_json=json.dumps(data.applicability, ensure_ascii=False, sort_keys=True),
            human_review_required=data.human_review_required,
            last_seen_at=now,
        )
        db.add(requirement)
        db.flush()
        db.add(
            RegulatoryChange(
                requirement_id=requirement.id,
                change_type="created",
                previous_hash=None,
                new_hash=new_hash,
                source_version=requirement.source_version,
                human_review_required=True,
            )
        )
        change_type = "created"
    else:
        previous_hash = requirement.content_hash
        requirement.last_seen_at = now
        source.last_checked_at = now
        if previous_hash == new_hash:
            db.commit()
            db.refresh(requirement)
            return {"change": "unchanged", "requirement": _serialize_requirement(requirement)}

        requirement.title = data.title.strip()
        requirement.citation = data.citation.strip() if data.citation else None
        requirement.summary = data.summary.strip() if data.summary else None
        requirement.jurisdiction = data.jurisdiction.strip().upper()
        requirement.topic = data.topic.strip().lower()
        requirement.management_system = data.management_system.strip().upper() if data.management_system else None
        requirement.status = data.status.strip().lower()
        requirement.source_version = data.source_version.strip() if data.source_version else None
        requirement.effective_from = data.effective_from
        requirement.effective_to = data.effective_to
        requirement.content_hash = new_hash
        requirement.applicability_json = json.dumps(data.applicability, ensure_ascii=False, sort_keys=True)
        requirement.human_review_required = True
        requirement.verified_at = None
        requirement.verified_by_id = None
        db.add(
            RegulatoryChange(
                requirement_id=requirement.id,
                change_type="updated",
                previous_hash=previous_hash,
                new_hash=new_hash,
                source_version=requirement.source_version,
                human_review_required=True,
            )
        )
        change_type = "updated"

    source.last_checked_at = now
    db.add(
        AuditLog(
            event=f"regulatory_requirement_{change_type}:{requirement.id}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()
    db.refresh(requirement)
    return {"change": change_type, "requirement": _serialize_requirement(requirement)}


@router.get("/requirements")
def list_requirements(
    current_user: CurrentUser,
    db: DBSession,
    jurisdiction: str | None = None,
    topic: str | None = None,
    management_system: str | None = None,
    review_required: bool | None = Query(default=None),
):
    require_permission(current_user, "regulatory.read")
    query = db.query(RegulatoryRequirement)
    if jurisdiction:
        query = query.filter(RegulatoryRequirement.jurisdiction == jurisdiction.strip().upper())
    if topic:
        query = query.filter(RegulatoryRequirement.topic == topic.strip().lower())
    if management_system:
        query = query.filter(RegulatoryRequirement.management_system == management_system.strip().upper())
    if review_required is not None:
        query = query.filter(RegulatoryRequirement.human_review_required.is_(review_required))
    items = query.order_by(RegulatoryRequirement.updated_at.desc()).all()
    return {"requirements": [_serialize_requirement(item) for item in items]}


@router.get("/changes")
def list_changes(current_user: CurrentUser, db: DBSession, review_status: str | None = None):
    require_permission(current_user, "regulatory.read")
    query = db.query(RegulatoryChange)
    if review_status:
        query = query.filter(RegulatoryChange.review_status == review_status.strip().lower())
    changes = query.order_by(RegulatoryChange.detected_at.desc()).limit(500).all()
    return {
        "changes": [
            {
                "id": item.id,
                "requirement_id": item.requirement_id,
                "change_type": item.change_type,
                "previous_hash": item.previous_hash,
                "new_hash": item.new_hash,
                "source_version": item.source_version,
                "detected_at": item.detected_at,
                "review_status": item.review_status,
                "impact": json.loads(item.impact_json or "{}"),
                "human_review_required": item.human_review_required,
                "reviewed_by_id": item.reviewed_by_id,
                "reviewed_at": item.reviewed_at,
            }
            for item in changes
        ]
    }


@router.post("/requirements/{requirement_id}/review")
def review_requirement(
    requirement_id: int,
    data: RequirementReview,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "regulatory.review")
    requirement = db.query(RegulatoryRequirement).filter(RegulatoryRequirement.id == requirement_id).first()
    if requirement is None:
        raise HTTPException(status_code=404, detail="Regelwerksanforderung wurde nicht gefunden.")

    now = _utc_now()
    requirement.human_review_required = not data.verified
    requirement.verified_at = now if data.verified else None
    requirement.verified_by_id = current_user.id if data.verified else None

    pending_changes = db.query(RegulatoryChange).filter(
        RegulatoryChange.requirement_id == requirement.id,
        RegulatoryChange.review_status == "pending",
    ).all()
    for change in pending_changes:
        change.review_status = data.review_status.strip().lower()
        change.impact_json = json.dumps(data.impact, ensure_ascii=False, sort_keys=True)
        change.human_review_required = not data.verified
        change.reviewed_by_id = current_user.id if data.verified else None
        change.reviewed_at = now if data.verified else None

    db.add(
        AuditLog(
            event=f"regulatory_requirement_reviewed:{requirement.id}:{data.verified}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()
    db.refresh(requirement)
    return _serialize_requirement(requirement)
