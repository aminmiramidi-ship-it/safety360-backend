from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from permissions import require_permission

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

AgentId = Literal[
    "hse_ims",
    "document_storage",
    "security_privacy",
    "translation_i18n",
    "data_quality",
    "product_innovation",
    "ux_assistance",
    "market_marketing",
    "sales_intelligence",
    "deployment_ci",
    "governance_audit",
]

Outcome = Literal["accepted", "rejected", "corrected", "completed", "failed"]
RiskLevel = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class AgentDefinition:
    id: AgentId
    name: str
    purpose: str
    risk_level: RiskLevel
    human_review_default: bool
    keywords: tuple[str, ...]
    default_task: str


AGENTS: tuple[AgentDefinition, ...] = (
    AgentDefinition(
        id="hse_ims",
        name="HSE & IMS Agent",
        purpose="Orchestriert Tätigkeiten, Gefährdungsbeurteilungen, Maßnahmen, Betriebsanweisungen, Unterweisungen, Audits und Management Reviews.",
        risk_level="critical",
        human_review_default=True,
        keywords=(
            "hse",
            "ehs",
            "ims",
            "gefährd",
            "gefaehrd",
            "risiko",
            "risk",
            "betriebsanweisung",
            "unterweisung",
            "training",
            "audit",
            "iso 45001",
            "iso 14001",
            "iso 50001",
            "iso 9001",
            "27001",
            "50600",
        ),
        default_task="Analysiere den fachlichen Kontext, erkenne fehlende IMS-Artefakte und bereite nachvollziehbare Draft-Folgeschritte mit Human-Review vor.",
    ),
    AgentDefinition(
        id="document_storage",
        name="Document & Storage Agent",
        purpose="Optimiert sichere Ablage, Dokumentenlenkung, Versionierung, Metadaten, Retention und Integrität.",
        risk_level="high",
        human_review_default=True,
        keywords=("dokument", "document", "ablage", "storage", "datei", "file", "version", "retention", "archiv"),
        default_task="Prüfe Ablage, Metadaten, Versionierung, Freigaben, Retention und Integritätsnachweise auf Lücken und konsistente Verknüpfungen.",
    ),
    AgentDefinition(
        id="security_privacy",
        name="Security & Privacy Agent",
        purpose="Prüft Tenant-Isolation, RBAC, Secrets, Verschlüsselung, Datenschutz, sichere KI-Nutzung und Enterprise-Security.",
        risk_level="critical",
        human_review_default=True,
        keywords=("security", "sicherheit", "privacy", "datenschutz", "bank", "behörde", "behoerde", "rechenzentrum", "data center", "mfa", "sso", "verschlüssel"),
        default_task="Prüfe Security- und Privacy-Kontrollen, priorisiere Risiken und schlage reversible technische Verbesserungen mit Nachweisen vor.",
    ),
    AgentDefinition(
        id="translation_i18n",
        name="Translation & i18n Agent",
        purpose="Sichert Mehrsprachigkeit, BCP-47, RTL, Terminologie und kontrollierte Übersetzungsworkflows.",
        risk_level="medium",
        human_review_default=True,
        keywords=("übersetz", "uebersetz", "sprache", "language", "i18n", "rtl", "locale", "international"),
        default_task="Prüfe Sprachneutralität, Terminologie, BCP-47/RTL und markiere kritische maschinelle Übersetzungen für Human-Review.",
    ),
    AgentDefinition(
        id="data_quality",
        name="Data & Quality Agent",
        purpose="Verbessert Datenqualität, Vollständigkeit, Konsistenz, Validierungen und Qualitätskennzahlen.",
        risk_level="medium",
        human_review_default=False,
        keywords=("daten", "data", "qualität", "quality", "valid", "konsistenz", "vollständig", "metric", "kennzahl"),
        default_task="Prüfe Datenvollständigkeit, Validierungen, Dubletten, Konsistenz und messbare Qualitätsindikatoren.",
    ),
    AgentDefinition(
        id="product_innovation",
        name="Product & Innovation Agent",
        purpose="Findet praktische, sichere und messbar nützliche Produktinnovationen.",
        risk_level="medium",
        human_review_default=False,
        keywords=("innovation", "produkt", "feature", "neu", "automatis", "intelligent", "verbesser", "roadmap"),
        default_task="Ermittle Produktlücken und priorisiere Innovationen nach Kundennutzen, Risiko, Aufwand, Erklärbarkeit und Testbarkeit.",
    ),
    AgentDefinition(
        id="ux_assistance",
        name="UX & Assistance Agent",
        purpose="Reduziert Klicks, Wiederholungen und Fehler durch geführte Workflows und kontextuelle KI-Hilfe.",
        risk_level="low",
        human_review_default=False,
        keywords=("ux", "ui", "bedien", "hilfe", "einfach", "klick", "barriere", "mobile", "app", "web", "pwa"),
        default_task="Optimiere den Nutzerfluss, reduziere unnötige Eingaben und definiere kontextuelle Hilfen, Defaults und klare Statusanzeigen.",
    ),
    AgentDefinition(
        id="market_marketing",
        name="Market & Marketing Agent",
        purpose="Analysiert Marktsegmente, Positionierung, Content, Differenzierung und Kampagnenideen anhand zulässiger Daten.",
        risk_level="high",
        human_review_default=True,
        keywords=("markt", "marketing", "position", "wettbewerb", "kampagne", "content", "brand", "werbung", "branche"),
        default_task="Analysiere Markt- und Positionierungssignale und erstelle überprüfbare, rechtskonforme Marketingvorschläge ohne automatischen Outreach-Versand.",
    ),
    AgentDefinition(
        id="sales_intelligence",
        name="Sales Intelligence Agent",
        purpose="Erkennt passende Zielunternehmen und Opportunity-Hypothesen aus öffentlichen Unternehmenssignalen.",
        risk_level="high",
        human_review_default=True,
        keywords=("vertrieb", "sales", "kunde", "firmen", "unternehmen", "lead", "opportunity", "akquise", "account"),
        default_task="Ordne öffentlich erkennbare Unternehmensbedarfe passenden Safety360-Modulen zu und erstelle prüfbare Opportunity-Hypothesen ohne unzulässigen Versand.",
    ),
    AgentDefinition(
        id="deployment_ci",
        name="Deployment & CI Agent",
        purpose="Prüft Builds, Tests, Migrationen, Security-Scans, Deployments und Regressionen.",
        risk_level="high",
        human_review_default=True,
        keywords=("deploy", "ci", "github", "build", "test", "migration", "release", "vercel", "pipeline"),
        default_task="Prüfe Builds, Tests, Migrationen, Security-Scans und Deployment-Konfiguration und priorisiere eindeutig behebbare Regressionen.",
    ),
    AgentDefinition(
        id="governance_audit",
        name="Governance & Audit Agent",
        purpose="Sichert Nachvollziehbarkeit, Freigaben, Quellen, Versionen und kontrollierte KI-Entscheidungen.",
        risk_level="critical",
        human_review_default=True,
        keywords=("governance", "audit trail", "nachweis", "freigabe", "quelle", "entscheidung", "compliance"),
        default_task="Prüfe Nachvollziehbarkeit, Freigaben, Quellen, Audit-Nachweise und Human-in-the-loop-Grenzen des geplanten Vorgehens.",
    ),
)

AGENT_BY_ID: dict[str, AgentDefinition] = {agent.id: agent for agent in AGENTS}


class AgentCatalogItem(BaseModel):
    id: AgentId
    name: str
    purpose: str
    risk_level: RiskLevel
    human_review_default: bool


class AgentCatalogResponse(BaseModel):
    agents: list[AgentCatalogItem]
    learning_mode: str
    learning_guardrails: list[str]


class AgentPlanRequest(BaseModel):
    objective: str = Field(min_length=3, max_length=4000)
    context: str | None = Field(default=None, max_length=12000)
    requested_agents: list[AgentId] = Field(default_factory=list, max_length=11)


class AgentTask(BaseModel):
    agent_id: AgentId
    agent_name: str
    task: str
    priority: int = Field(ge=1, le=100)
    risk_level: RiskLevel
    human_review_required: bool
    safe_to_auto_execute: bool
    adaptation_adjustment: int = Field(ge=-10, le=10)


class AgentPlanResponse(BaseModel):
    run_id: str
    tasks: list[AgentTask]
    learning_mode: str
    governance_note: str


class AgentFeedbackRequest(BaseModel):
    run_id: str = Field(min_length=8, max_length=80)
    agent_id: AgentId
    outcome: Outcome
    rating: int = Field(ge=1, le=5)
    workflow: str = Field(default="general", min_length=1, max_length=80)


class AgentFeedbackResponse(BaseModel):
    accepted: bool
    run_id: str
    agent_id: AgentId
    learned_adjustment: int


class AgentAdaptationItem(BaseModel):
    agent_id: AgentId
    feedback_count: int
    average_rating: float | None
    learned_adjustment: int


class AgentAdaptationResponse(BaseModel):
    tenant_id: int
    agents: list[AgentAdaptationItem]
    learning_mode: str


def _require_tenant(user: User) -> int:
    if user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für den Agent-Autopilot muss zuerst ein Mandant ausgewählt oder erstellt werden.",
        )
    return user.tenant_id


def _feedback_rows(db: Session, tenant_id: int) -> list[AuditLog]:
    return (
        db.query(AuditLog)
        .filter(
            AuditLog.tenant_id == tenant_id,
            AuditLog.event.like("agent_feedback:%"),
        )
        .order_by(AuditLog.created_at.desc())
        .limit(500)
        .all()
    )


def _parse_feedback(event: str) -> dict[str, object] | None:
    if not event.startswith("agent_feedback:"):
        return None
    try:
        payload = json.loads(event.removeprefix("agent_feedback:"))
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _adaptation_map(db: Session, tenant_id: int) -> dict[str, AgentAdaptationItem]:
    ratings: dict[str, list[int]] = {agent.id: [] for agent in AGENTS}
    outcomes: dict[str, list[str]] = {agent.id: [] for agent in AGENTS}

    for row in _feedback_rows(db, tenant_id):
        payload = _parse_feedback(row.event)
        if not payload:
            continue
        agent_id = str(payload.get("agent_id", ""))
        rating = payload.get("rating")
        outcome = str(payload.get("outcome", ""))
        if agent_id in ratings and isinstance(rating, int) and 1 <= rating <= 5:
            ratings[agent_id].append(rating)
            outcomes[agent_id].append(outcome)

    result: dict[str, AgentAdaptationItem] = {}
    for agent in AGENTS:
        values = ratings[agent.id]
        if not values:
            result[agent.id] = AgentAdaptationItem(
                agent_id=agent.id,
                feedback_count=0,
                average_rating=None,
                learned_adjustment=0,
            )
            continue

        average = sum(values) / len(values)
        adjustment = round((average - 3.0) * 5)
        recent_outcomes = outcomes[agent.id][-20:]
        adjustment += min(2, recent_outcomes.count("completed"))
        adjustment -= min(2, recent_outcomes.count("failed"))
        adjustment = max(-10, min(10, adjustment))
        result[agent.id] = AgentAdaptationItem(
            agent_id=agent.id,
            feedback_count=len(values),
            average_rating=round(average, 2),
            learned_adjustment=adjustment,
        )
    return result


def _keyword_score(agent: AgentDefinition, text: str) -> int:
    hits = sum(1 for keyword in agent.keywords if keyword in text)
    return min(20, hits * 5)


def _safe_to_auto_execute(agent: AgentDefinition) -> bool:
    return agent.id in {
        "data_quality",
        "product_innovation",
        "ux_assistance",
    }


@router.get("/catalog", response_model=AgentCatalogResponse)
def catalog(current_user: CurrentUser) -> AgentCatalogResponse:
    require_permission(current_user, "agents.use")
    return AgentCatalogResponse(
        agents=[
            AgentCatalogItem(
                id=agent.id,
                name=agent.name,
                purpose=agent.purpose,
                risk_level=agent.risk_level,
                human_review_default=agent.human_review_default,
            )
            for agent in AGENTS
        ],
        learning_mode="feedback_and_outcome_adaptation",
        learning_guardrails=[
            "Kein autonomes Training von Modellgewichten mit Mandantendaten.",
            "Anpassung erfolgt nachvollziehbar über Feedback, Outcomes und versionierte Regeln.",
            "Kritische HSE-, Security-, Compliance-, Marketing-Outreach- und Produktionsentscheidungen benötigen Human-Review.",
            "Mandantenfeedback wird strikt tenant-isoliert ausgewertet.",
        ],
    )


@router.post("/plan", response_model=AgentPlanResponse)
def create_plan(
    data: AgentPlanRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> AgentPlanResponse:
    require_permission(current_user, "agents.use")
    tenant_id = _require_tenant(current_user)
    adaptation = _adaptation_map(db, tenant_id)

    combined = f"{data.objective}\n{data.context or ''}".lower()
    selected_ids: set[str] = set(data.requested_agents)

    if not selected_ids:
        for agent in AGENTS:
            if _keyword_score(agent, combined) > 0:
                selected_ids.add(agent.id)

    selected_ids.add("governance_audit")
    selected_ids.add("security_privacy")

    if len(selected_ids) == 2:
        selected_ids.update({"product_innovation", "ux_assistance"})

    tasks: list[AgentTask] = []
    for agent in AGENTS:
        if agent.id not in selected_ids:
            continue
        adaptive = adaptation[agent.id].learned_adjustment
        priority = 60 + _keyword_score(agent, combined) + adaptive
        if agent.id in {"governance_audit", "security_privacy"}:
            priority += 10
        priority = max(1, min(100, priority))
        tasks.append(
            AgentTask(
                agent_id=agent.id,
                agent_name=agent.name,
                task=agent.default_task,
                priority=priority,
                risk_level=agent.risk_level,
                human_review_required=agent.human_review_default,
                safe_to_auto_execute=_safe_to_auto_execute(agent),
                adaptation_adjustment=adaptive,
            )
        )

    tasks.sort(key=lambda item: (-item.priority, item.agent_id))
    run_id = str(uuid.uuid4())

    db.add(
        AuditLog(
            event="agent_plan_created:"
            + json.dumps(
                {
                    "run_id": run_id,
                    "agents": [task.agent_id for task in tasks],
                    "learning_mode": "feedback_and_outcome_adaptation",
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()

    return AgentPlanResponse(
        run_id=run_id,
        tasks=tasks,
        learning_mode="feedback_and_outcome_adaptation",
        governance_note=(
            "Safety360 passt Prioritäten anhand tenant-isolierten Feedbacks und Outcomes an. "
            "Es trainiert nicht autonom Modellgewichte auf vertraulichen Mandantendaten. "
            "Kritische oder irreversible Aktionen bleiben freigabepflichtig."
        ),
    )


@router.post("/feedback", response_model=AgentFeedbackResponse)
def submit_feedback(
    data: AgentFeedbackRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> AgentFeedbackResponse:
    require_permission(current_user, "agents.feedback")
    tenant_id = _require_tenant(current_user)

    payload = {
        "run_id": data.run_id,
        "agent_id": data.agent_id,
        "outcome": data.outcome,
        "rating": data.rating,
        "workflow": data.workflow.strip().lower(),
    }
    db.add(
        AuditLog(
            event="agent_feedback:" + json.dumps(payload, separators=(",", ":"), sort_keys=True),
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()

    learned = _adaptation_map(db, tenant_id)[data.agent_id].learned_adjustment
    return AgentFeedbackResponse(
        accepted=True,
        run_id=data.run_id,
        agent_id=data.agent_id,
        learned_adjustment=learned,
    )


@router.get("/adaptation", response_model=AgentAdaptationResponse)
def adaptation_status(
    current_user: CurrentUser,
    db: DBSession,
) -> AgentAdaptationResponse:
    require_permission(current_user, "agents.use")
    tenant_id = _require_tenant(current_user)
    adaptation = _adaptation_map(db, tenant_id)
    return AgentAdaptationResponse(
        tenant_id=tenant_id,
        agents=[adaptation[agent.id] for agent in AGENTS],
        learning_mode="feedback_and_outcome_adaptation",
    )
