import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from industry_models import IndustryActivityTemplate
from learning_content_models import LearningArtifact, LearningContentPack
from models import AuditLog, User
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

ARTIFACT_TYPES = (
    "risk_assessment_outline",
    "operating_instruction_outline",
    "training_outline",
    "presentation_outline",
    "quiz_outline",
    "inspection_checklist",
    "toolbox_talk",
    "one_pager",
    "video_script_outline",
)


class ContentPackCreate(BaseModel):
    pack_key: str = Field(min_length=2, max_length=200)
    title: str = Field(min_length=2, max_length=500)
    activity_template_id: int | None = None
    activity_ref: str | None = Field(default=None, max_length=320)
    industry_scheme: str | None = Field(default=None, max_length=40)
    industry_code: str | None = Field(default=None, max_length=40)
    jurisdiction: str = Field(default="DE", min_length=2, max_length=80)
    target_audience: str = Field(default="employees", min_length=2, max_length=120)
    language: str = Field(default="de", min_length=2, max_length=20)
    depth_profile: str = Field(default="standard", pattern="^(short|standard|deep)$")
    source_refs: list[str] = Field(default_factory=list, max_length=100)
    requirement_refs: list[str] = Field(default_factory=list, max_length=100)
    change_reason: str | None = Field(default=None, max_length=500)


class ArtifactApproval(BaseModel):
    approved: bool = True


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tenant_id(user: User) -> int:
    if user.tenant_id is None:
        raise HTTPException(status_code=409, detail="Benutzer ist keinem Mandanten zugeordnet.")
    return int(user.tenant_id)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _hash(value: object) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _load_list(raw: str | None) -> list[object]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return value if isinstance(value, list) else []


def _require_pack(db: Session, tenant_id: int, pack_id: int) -> LearningContentPack:
    pack = db.query(LearningContentPack).filter(
        LearningContentPack.id == pack_id,
        LearningContentPack.tenant_id == tenant_id,
    ).first()
    if pack is None:
        raise HTTPException(status_code=404, detail="Content Pack wurde nicht gefunden.")
    return pack


def _serialize_pack(item: LearningContentPack) -> dict[str, object]:
    return {
        "id": item.id,
        "pack_key": item.pack_key,
        "version": item.version,
        "title": item.title,
        "activity_template_id": item.activity_template_id,
        "activity_ref": item.activity_ref,
        "industry_scheme": item.industry_scheme,
        "industry_code": item.industry_code,
        "jurisdiction": item.jurisdiction,
        "target_audience": item.target_audience,
        "language": item.language,
        "depth_profile": item.depth_profile,
        "status": item.status,
        "currentness_status": item.currentness_status,
        "source_refs": _load_list(item.source_refs_json),
        "requirement_refs": _load_list(item.requirement_refs_json),
        "content_hash": item.content_hash,
        "human_review_required": item.human_review_required,
        "approved_at": item.approved_at,
        "review_due_at": item.review_due_at,
    }


def _artifact_payload(
    pack: LearningContentPack,
    activity: IndustryActivityTemplate | None,
    artifact_type: str,
) -> dict[str, object]:
    activity_title = activity.title if activity else pack.activity_ref or pack.title
    hazards = _load_list(activity.hazard_factors_json) if activity else []
    controls = _load_list(activity.controls_json) if activity else []
    training_topics = _load_list(activity.training_topics_json) if activity else []
    operating_topics = _load_list(activity.operating_instruction_topics_json) if activity else []
    process_steps = _load_list(activity.process_steps_json) if activity else []

    common = {
        "activity": activity_title,
        "target_audience": pack.target_audience,
        "language": pack.language,
        "depth_profile": pack.depth_profile,
        "jurisdiction": pack.jurisdiction,
        "hazards": hazards,
        "controls": controls,
        "process_steps": process_steps,
        "review_gate": "draft_requires_human_review",
    }
    templates: dict[str, dict[str, object]] = {
        "risk_assessment_outline": {
            **common,
            "sections": ["scope", "activity_steps", "hazards", "risk_evaluation", "controls", "residual_risk", "effectiveness_review"],
        },
        "operating_instruction_outline": {
            **common,
            "topics": operating_topics,
            "sections": ["scope", "hazards", "protective_measures", "safe_behavior", "emergency_response", "first_aid", "disposal_or_shutdown"],
        },
        "training_outline": {
            **common,
            "topics": training_topics,
            "sections": ["learning_objectives", "hazards", "controls", "safe_work", "emergencies", "knowledge_check"],
        },
        "presentation_outline": {
            **common,
            "slides": ["title", "why_it_matters", "activity", "hazards", "controls", "safe_work", "emergency", "summary", "knowledge_check"],
        },
        "quiz_outline": {
            **common,
            "question_blueprint": ["hazard_recognition", "control_selection", "safe_behavior", "emergency_response"],
        },
        "inspection_checklist": {
            **common,
            "check_sections": ["work_area", "equipment", "controls", "ppe", "documentation", "behavior", "follow_up"],
        },
        "toolbox_talk": {
            **common,
            "sections": ["purpose", "top_hazards", "three_key_controls", "stop_work_triggers", "questions"],
        },
        "one_pager": {
            **common,
            "sections": ["activity", "top_hazards", "must_do", "must_not_do", "emergency", "contact_or_escalation"],
        },
        "video_script_outline": {
            **common,
            "sections": ["opening", "scene_context", "hazards", "correct_behavior", "wrong_behavior_examples", "emergency", "recap"],
            "production_note": "Only approved, licensed or self-produced media may be used.",
        },
    }
    return templates[artifact_type]


@router.post("/packs", status_code=status.HTTP_201_CREATED)
def create_pack(data: ContentPackCreate, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.create")
    tenant_id = _tenant_id(current_user)
    if data.activity_template_id is not None:
        activity = db.query(IndustryActivityTemplate).filter(
            IndustryActivityTemplate.id == data.activity_template_id
        ).first()
        if activity is None:
            raise HTTPException(status_code=404, detail="Tätigkeitstemplate wurde nicht gefunden.")
    latest = db.query(LearningContentPack).filter(
        LearningContentPack.tenant_id == tenant_id,
        LearningContentPack.pack_key == data.pack_key.strip(),
    ).order_by(LearningContentPack.version.desc()).first()
    version = 1 if latest is None else latest.version + 1
    source_refs = [value.strip() for value in data.source_refs if value.strip()]
    requirement_refs = [value.strip() for value in data.requirement_refs if value.strip()]
    fingerprint = {
        "pack_key": data.pack_key.strip(),
        "version": version,
        "activity_template_id": data.activity_template_id,
        "activity_ref": data.activity_ref,
        "industry_scheme": data.industry_scheme,
        "industry_code": data.industry_code,
        "jurisdiction": data.jurisdiction,
        "target_audience": data.target_audience,
        "language": data.language,
        "depth_profile": data.depth_profile,
        "source_refs": source_refs,
        "requirement_refs": requirement_refs,
    }
    item = LearningContentPack(
        tenant_id=tenant_id,
        pack_key=data.pack_key.strip(),
        version=version,
        title=data.title.strip(),
        activity_template_id=data.activity_template_id,
        activity_ref=data.activity_ref.strip() if data.activity_ref else None,
        industry_scheme=data.industry_scheme.strip() if data.industry_scheme else None,
        industry_code=data.industry_code.strip() if data.industry_code else None,
        jurisdiction=data.jurisdiction.strip(),
        target_audience=data.target_audience.strip(),
        language=data.language.strip(),
        depth_profile=data.depth_profile,
        currentness_status="current",
        source_refs_json=_json(source_refs),
        requirement_refs_json=_json(requirement_refs),
        content_hash=_hash(fingerprint),
        change_reason=data.change_reason.strip() if data.change_reason else None,
        supersedes_id=latest.id if latest else None,
        created_by_id=current_user.id,
        human_review_required=True,
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(event=f"learning_content_pack_created:{item.id}:v{version}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    db.refresh(item)
    return _serialize_pack(item)


@router.get("/packs")
def list_packs(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.read")
    tenant_id = _tenant_id(current_user)
    items = db.query(LearningContentPack).filter(
        LearningContentPack.tenant_id == tenant_id
    ).order_by(LearningContentPack.updated_at.desc()).all()
    return {"packs": [_serialize_pack(item) for item in items]}


@router.get("/packs/{pack_id}")
def get_pack(pack_id: int, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.read")
    tenant_id = _tenant_id(current_user)
    pack = _require_pack(db, tenant_id, pack_id)
    artifacts = db.query(LearningArtifact).filter(
        LearningArtifact.tenant_id == tenant_id,
        LearningArtifact.content_pack_id == pack.id,
    ).order_by(LearningArtifact.artifact_type.asc(), LearningArtifact.version.desc()).all()
    return {
        "pack": _serialize_pack(pack),
        "artifacts": [
            {
                "id": item.id,
                "artifact_type": item.artifact_type,
                "title": item.title,
                "version": item.version,
                "language": item.language,
                "status": item.status,
                "content": json.loads(item.content_json),
                "content_hash": item.content_hash,
                "human_review_required": item.human_review_required,
            }
            for item in artifacts
        ],
    }


@router.post("/packs/{pack_id}/generate-outlines")
def generate_outlines(pack_id: int, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.generate")
    tenant_id = _tenant_id(current_user)
    pack = _require_pack(db, tenant_id, pack_id)
    activity = None
    if pack.activity_template_id is not None:
        activity = db.query(IndustryActivityTemplate).filter(
            IndustryActivityTemplate.id == pack.activity_template_id
        ).first()
    source_refs = _load_list(pack.source_refs_json)
    created: list[dict[str, object]] = []
    for artifact_type in ARTIFACT_TYPES:
        latest = db.query(LearningArtifact).filter(
            LearningArtifact.tenant_id == tenant_id,
            LearningArtifact.content_pack_id == pack.id,
            LearningArtifact.artifact_type == artifact_type,
        ).order_by(LearningArtifact.version.desc()).first()
        version = 1 if latest is None else latest.version + 1
        payload = _artifact_payload(pack, activity, artifact_type)
        artifact = LearningArtifact(
            tenant_id=tenant_id,
            content_pack_id=pack.id,
            artifact_type=artifact_type,
            title=f"{pack.title} – {artifact_type.replace('_', ' ')}",
            version=version,
            language=pack.language,
            status="draft",
            content_json=_json(payload),
            source_refs_json=_json(source_refs),
            content_hash=_hash(payload),
            human_review_required=True,
        )
        db.add(artifact)
        db.flush()
        created.append({"id": artifact.id, "artifact_type": artifact.artifact_type, "version": version})
    db.add(AuditLog(event=f"learning_content_outlines_generated:{pack.id}:{len(created)}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {
        "pack_id": pack.id,
        "artifacts": created,
        "governance": "All generated outlines are drafts and require qualified human review before operational use.",
    }


@router.post("/artifacts/{artifact_id}/review")
def review_artifact(artifact_id: int, data: ArtifactApproval, current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "content.approve")
    tenant_id = _tenant_id(current_user)
    item = db.query(LearningArtifact).filter(
        LearningArtifact.id == artifact_id,
        LearningArtifact.tenant_id == tenant_id,
    ).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Lern-/Unterweisungsartefakt wurde nicht gefunden.")
    item.status = "approved" if data.approved else "rejected"
    item.human_review_required = not data.approved
    item.approved_by_id = current_user.id if data.approved else None
    item.approved_at = _now() if data.approved else None
    db.add(AuditLog(event=f"learning_artifact_reviewed:{item.id}:{item.status}", user_id=current_user.id, tenant_id=tenant_id))
    db.commit()
    return {
        "id": item.id,
        "status": item.status,
        "approved_at": item.approved_at,
        "human_review_required": item.human_review_required,
    }
