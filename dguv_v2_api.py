import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from permissions import require_permission
from regulatory_models import RegulatoryChange, RegulatoryRequirement, RegulatorySource

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

DGUV_V2_SOURCE = {
    "authority": "DGUV",
    "source_key": "dguv-v2-2024-mustertext",
    "name": "DGUV Vorschrift 2 (2024) – Betriebsärztinnen und Betriebsärzte sowie Fachkräfte für Arbeitssicherheit",
    "jurisdiction": "DE",
    "source_type": "accident_insurance_model_regulation",
    "base_url": "https://publikationen.dguv.de/widgets/pdf/download/article/5054",
    "is_primary": True,
    "enabled": True,
    "terms_note": (
        "DGUV-Mustertext, Ausgabedatum 2024.11; im Dokument ist eine formale Korrektur aus 2025-12 vermerkt. "
        "Die für einen Betrieb verbindliche Fassung ist beim zuständigen Unfallversicherungsträger zu prüfen."
    ),
}

DGUV_V2_REQUIREMENTS: tuple[dict[str, object], ...] = (
    {
        "external_key": "dguv-v2-2024-s1-scope",
        "title": "Geltungsbereich und Verbindung zum Arbeitssicherheitsgesetz",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 1",
        "summary": (
            "Die Vorschrift konkretisiert die organisatorischen Pflichten des Unternehmers aus dem Arbeitssicherheitsgesetz "
            "zur betriebsärztlichen und sicherheitstechnischen Betreuung."
        ),
        "topic": "occupational_health_and_safety_organization",
        "management_system": "ISO 45001",
        "applicability": {
            "applies_to": ["employers", "organizations_with_employees"],
            "system_actions": ["determine_accident_insurer", "verify_applicable_uvt_version"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s2-appointment",
        "title": "Schriftliche Bestellung von Betriebsarzt und Fachkraft für Arbeitssicherheit",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 2 Abs. 1",
        "summary": (
            "Betriebsärztinnen bzw. Betriebsärzte und Fachkräfte für Arbeitssicherheit sind für die Aufgaben nach ASiG "
            "schriftlich zu bestellen; die Erfüllung muss auf Verlangen nachweisbar sein."
        ),
        "topic": "appointment_and_responsibility",
        "management_system": "ISO 45001",
        "applicability": {
            "evidence": ["appointment_document", "scope_of_tasks", "provider_or_internal_role"],
            "system_actions": ["track_appointment", "track_provider", "retain_evidence"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s2-care-model",
        "title": "Betreuungsmodell nach Betriebsgröße und Unfallversicherungsträger bestimmen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 2 Abs. 2-4",
        "summary": (
            "Bis einschließlich 20 Beschäftigte und bei mehr als 20 Beschäftigten gelten unterschiedliche Regelbetreuungsmodelle. "
            "Alternative Betreuungsmodelle können abhängig von der trägerspezifischen Regelung möglich sein."
        ),
        "topic": "care_model",
        "management_system": "ISO 45001",
        "applicability": {
            "thresholds": {"small_business_max": 20, "alternative_model_max_template": 50},
            "system_actions": ["calculate_weighted_headcount", "determine_care_model", "verify_uvt_specific_limits"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s2-headcount",
        "title": "Beschäftigtenzahl für Schwellenwerte gewichtet berechnen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 2 Abs. 5",
        "summary": (
            "Für die Schwellenwerte ist die jährliche Durchschnittszahl maßgeblich. Teilzeitbeschäftigte werden je regelmäßiger "
            "Wochenarbeitszeit mit 0,5, 0,75 oder 1,0 gewichtet."
        ),
        "topic": "headcount_calculation",
        "management_system": "ISO 45001",
        "applicability": {
            "part_time_factors": [
                {"weekly_hours_max": 20, "factor": 0.5},
                {"weekly_hours_min_exclusive": 20, "weekly_hours_max": 30, "factor": 0.75},
                {"weekly_hours_min_exclusive": 30, "factor": 1.0},
            ],
            "system_actions": ["calculate_annual_average_headcount", "retain_calculation_basis"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s2-employee-information",
        "title": "Beschäftigte über Art und Personen der Betreuung informieren",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 2 Abs. 7",
        "summary": (
            "Beschäftigte sind über die Art der betriebsärztlichen und sicherheitstechnischen Betreuung und über die zuständigen "
            "Betriebsärztinnen/Betriebsärzte, Fachkräfte für Arbeitssicherheit oder Kompetenzzentren zu informieren."
        ),
        "topic": "employee_information",
        "management_system": "ISO 45001",
        "applicability": {
            "system_actions": ["publish_care_model", "publish_responsible_contacts", "track_information_status"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s3-medical-qualification",
        "title": "Arbeitsmedizinische Fachkunde nachweisen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 3",
        "summary": (
            "Für die betriebsärztliche Fachkunde ist die Berechtigung zur Gebietsbezeichnung Arbeitsmedizin oder zur "
            "Zusatzbezeichnung Betriebsmedizin nachzuweisen."
        ),
        "topic": "occupational_physician_qualification",
        "management_system": "ISO 45001",
        "applicability": {
            "system_actions": ["verify_qualification", "track_evidence_validity"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s4-sifa-qualification",
        "title": "Sicherheitstechnische Fachkunde der Fachkraft für Arbeitssicherheit nachweisen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 4",
        "summary": (
            "Die sicherheitstechnische Fachkunde richtet sich nach beruflicher Grundqualifikation, praktischer Berufserfahrung, "
            "erfolgreicher SiFa-Qualifizierung und erforderlichen branchenspezifischen Kenntnissen. Bei bestimmten gleichwertigen "
            "Qualifikationen oder Funktionen kann eine behördliche Einzelfallzulassung erforderlich sein."
        ),
        "topic": "sifa_qualification",
        "management_system": "ISO 45001",
        "applicability": {
            "system_actions": ["verify_base_qualification", "verify_experience", "verify_sifa_training", "verify_sector_knowledge"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s5-reporting",
        "title": "Regelmäßige Berichte zur betriebsärztlichen und sicherheitstechnischen Betreuung",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 5",
        "summary": (
            "Bestellte Betriebsärzte und Fachkräfte für Arbeitssicherheit müssen regelmäßig elektronisch oder schriftlich über die "
            "Erfüllung ihrer Aufgaben berichten. Die Berichte sollen Zusammenarbeit und erforderliche Fortbildungsnachweise abbilden."
        ),
        "topic": "osh_reporting",
        "management_system": "ISO 45001",
        "applicability": {
            "system_actions": ["schedule_reports", "capture_service_evidence", "capture_collaboration", "capture_training_evidence"],
        },
    },
    {
        "external_key": "dguv-v2-2024-s6-digital-care",
        "title": "Digitale Informations- und Kommunikationstechnologien in der Betreuung kontrolliert einsetzen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), § 6",
        "summary": (
            "Betreuung ist grundsätzlich als persönliche Fachleistung zu erbringen. Digitale Erbringung ist unter festgelegten "
            "Voraussetzungen möglich, insbesondere wenn die betrieblichen Verhältnisse bekannt sind; erforderliche Präsenz bleibt vorrangig."
        ),
        "topic": "digital_osh_care",
        "management_system": "ISO 45001",
        "applicability": {
            "default_remote_share_limit": 0.333333,
            "template_absolute_remote_share_cap": 0.5,
            "prerequisites": ["initial_site_inspection", "known_operational_conditions", "no_presence_reason_required"],
            "system_actions": ["track_delivery_mode", "calculate_remote_share", "document_in_report", "verify_uvt_specific_cap"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex1-small-business",
        "title": "Regelbetreuung in Betrieben mit bis zu 20 Beschäftigten",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 1",
        "summary": (
            "Art und Umfang der Betreuung orientieren sich an den betrieblichen Gefährdungen und den ASiG-Aufgaben. Betriebsarzt und "
            "Fachkraft für Arbeitssicherheit sind in Erstellung und Aktualisierung der Gefährdungsbeurteilung einzubeziehen; zusätzlich "
            "ist eine anlassbezogene Betreuung vorzusehen."
        ),
        "topic": "small_business_regular_care",
        "management_system": "ISO 45001",
        "applicability": {
            "weighted_headcount_max": 20,
            "system_actions": ["link_risk_assessment_to_advisers", "monitor_change_events", "schedule_periodic_review_by_uvt_group"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex1-triggers",
        "title": "Anlässe für zusätzliche betriebsärztliche oder sicherheitstechnische Betreuung erkennen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 1 Abschnitt II",
        "summary": (
            "Besondere betriebliche Veränderungen und Gefährdungen können anlassbezogene Beratung auslösen, etwa neue oder geänderte "
            "Anlagen, Arbeitsmittel, Arbeitsverfahren, Arbeitsplätze oder Arbeitsstoffe."
        ),
        "topic": "event_driven_care",
        "management_system": "ISO 45001",
        "applicability": {
            "triggers": ["new_facility", "changed_facility", "new_high_risk_equipment", "new_process", "changed_process", "new_workplace", "new_hazardous_material"],
            "system_actions": ["detect_change", "create_advisory_review", "link_to_management_of_change"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex2-total-care",
        "title": "Gesamtbetreuung bei mehr als 20 Beschäftigten aus Grund- und betriebsspezifischer Betreuung bilden",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 2 Abschnitt I",
        "summary": (
            "Bei Betrieben mit mehr als 20 Beschäftigten setzt sich die Betreuung aus Grundbetreuung und betriebsspezifischer Betreuung zusammen."
        ),
        "topic": "large_business_total_care",
        "management_system": "ISO 45001",
        "applicability": {
            "weighted_headcount_min_exclusive": 20,
            "system_actions": ["calculate_basic_care", "determine_company_specific_care", "combine_total_care"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex2-basic-care-hours",
        "title": "Grundbetreuungszeit anhand der Betreuungsgruppe berechnen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 2 Abschnitt II",
        "summary": (
            "Die Grundbetreuung verwendet drei Betreuungsgruppen mit 2,5, 1,5 oder 0,5 Stunden je Beschäftigtem und Jahr. "
            "Für Betriebsarzt und Fachkraft für Arbeitssicherheit ist jeweils mindestens 20 Prozent der Grundbetreuungszeit vorzusehen."
        ),
        "topic": "basic_care_time",
        "management_system": "ISO 45001",
        "applicability": {
            "hours_per_employee_year": {"I": 2.5, "II": 1.5, "III": 0.5},
            "minimum_share_per_profession": 0.2,
            "system_actions": ["map_industry_to_care_group", "calculate_required_hours", "validate_professional_split"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex2-basic-care-fields",
        "title": "Aufgabenfelder der Grundbetreuung vollständig abbilden",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 2 Abschnitt II",
        "summary": (
            "Die Grundbetreuung umfasst unter anderem Gefährdungsbeurteilung, Arbeitsgestaltung und Prävention, Unterweisungen und "
            "Betriebsanweisungen, Integration in Organisation und Führung, Erste Hilfe, Ereignisuntersuchung, Beratung und kontinuierliche Verbesserung."
        ),
        "topic": "basic_care_tasks",
        "management_system": "ISO 45001",
        "applicability": {
            "workflow_links": ["risk_assessment", "operating_instruction", "training", "organization", "first_aid", "incident_investigation", "management_review"],
            "system_actions": ["map_service_evidence_to_task_fields", "identify_coverage_gaps"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex2-company-specific-care",
        "title": "Betriebsspezifischen Betreuungsbedarf systematisch ermitteln",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 2 Abschnitt III",
        "summary": (
            "Zusätzlich zur Grundbetreuung ist der betriebsindividuelle Bedarf anhand besonderer Gefährdungen, Arbeitsorganisation, "
            "Personaleinsatz und Veränderungen in Arbeitsbedingungen oder Organisation zu bestimmen."
        ),
        "topic": "company_specific_care",
        "management_system": "ISO 45001",
        "applicability": {
            "system_actions": ["evaluate_specific_hazards", "evaluate_change_management", "derive_additional_care", "record_rationale"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex2-industry-group",
        "title": "Betriebsart über WZ 2008 der passenden Betreuungsgruppe zuordnen",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlage 2 Abschnitt IV",
        "summary": (
            "Die Zuordnung zur Betreuungsgruppe erfolgt anhand der Betriebsart nach der Wirtschaftszweigklassifikation WZ 2008. "
            "Die konkrete Zuordnung ist für den jeweiligen Betrieb und Unfallversicherungsträger zu verifizieren."
        ),
        "topic": "industry_classification",
        "management_system": "ISO 45001",
        "applicability": {
            "classification_system": "WZ 2008",
            "system_actions": ["capture_industry_code", "map_to_care_group", "verify_uvt_specific_version"],
        },
    },
    {
        "external_key": "dguv-v2-2024-annex3-4-alternative-care",
        "title": "Alternative Betreuung nur nach trägerspezifischen Voraussetzungen anwenden",
        "citation": "DGUV Vorschrift 2 (Mustertext 2024), Anlagen 3 und 4",
        "summary": (
            "Alternative Betreuungsmodelle setzen trägerspezifische Voraussetzungen, aktive Einbindung der Unternehmensführung, "
            "Qualifizierungs- bzw. Informationsmaßnahmen, anlassbezogene Betreuung und schriftliche Nachweise voraus."
        ),
        "topic": "alternative_care_model",
        "management_system": "ISO 45001",
        "applicability": {
            "system_actions": ["verify_uvt_eligibility", "track_owner_training", "track_event_driven_care", "retain_written_evidence"],
        },
    },
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _requirement_hash(payload: dict[str, object]) -> str:
    normalized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _ensure_source(db: Session) -> RegulatorySource:
    source = db.query(RegulatorySource).filter(
        RegulatorySource.authority == DGUV_V2_SOURCE["authority"],
        RegulatorySource.source_key == DGUV_V2_SOURCE["source_key"],
    ).first()
    if source is not None:
        source.name = str(DGUV_V2_SOURCE["name"])
        source.jurisdiction = str(DGUV_V2_SOURCE["jurisdiction"])
        source.source_type = str(DGUV_V2_SOURCE["source_type"])
        source.base_url = str(DGUV_V2_SOURCE["base_url"])
        source.is_primary = True
        source.enabled = True
        source.terms_note = str(DGUV_V2_SOURCE["terms_note"])
        source.last_checked_at = _utc_now()
        return source

    source = RegulatorySource(**DGUV_V2_SOURCE, last_checked_at=_utc_now())
    db.add(source)
    db.flush()
    return source


@router.post("/seed", status_code=status.HTTP_201_CREATED)
def seed_dguv_v2_baseline(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "regulatory.manage")
    source = _ensure_source(db)
    created = 0
    updated = 0
    unchanged = 0
    now = _utc_now()

    for item in DGUV_V2_REQUIREMENTS:
        payload = {
            "external_key": item["external_key"],
            "title": item["title"],
            "citation": item["citation"],
            "summary": item["summary"],
            "jurisdiction": "DE",
            "topic": item["topic"],
            "management_system": item["management_system"],
            "status": "master_template_review_required",
            "source_version": "2024.11; formale Korrektur 2025-12",
            "applicability": item["applicability"],
            "human_review_required": True,
        }
        new_hash = _requirement_hash(payload)
        existing = db.query(RegulatoryRequirement).filter(
            RegulatoryRequirement.source_id == source.id,
            RegulatoryRequirement.external_key == item["external_key"],
        ).first()

        if existing is None:
            requirement = RegulatoryRequirement(
                source_id=source.id,
                external_key=str(item["external_key"]),
                title=str(item["title"]),
                citation=str(item["citation"]),
                summary=str(item["summary"]),
                jurisdiction="DE",
                topic=str(item["topic"]),
                management_system=str(item["management_system"]),
                status="master_template_review_required",
                source_version="2024.11; formale Korrektur 2025-12",
                content_hash=new_hash,
                applicability_json=json.dumps(item["applicability"], ensure_ascii=False, sort_keys=True),
                human_review_required=True,
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
                    review_status="pending",
                    impact_json=json.dumps(
                        {
                            "note": "Mustertext: vor betrieblicher Anwendung zuständigen Unfallversicherungsträger und gültige Fassung verifizieren."
                        },
                        ensure_ascii=False,
                    ),
                    human_review_required=True,
                )
            )
            created += 1
            continue

        existing.last_seen_at = now
        if existing.content_hash == new_hash:
            unchanged += 1
            continue

        previous_hash = existing.content_hash
        existing.title = str(item["title"])
        existing.citation = str(item["citation"])
        existing.summary = str(item["summary"])
        existing.topic = str(item["topic"])
        existing.management_system = str(item["management_system"])
        existing.status = "master_template_review_required"
        existing.source_version = "2024.11; formale Korrektur 2025-12"
        existing.content_hash = new_hash
        existing.applicability_json = json.dumps(item["applicability"], ensure_ascii=False, sort_keys=True)
        existing.human_review_required = True
        existing.verified_at = None
        existing.verified_by_id = None
        db.add(
            RegulatoryChange(
                requirement_id=existing.id,
                change_type="updated",
                previous_hash=previous_hash,
                new_hash=new_hash,
                source_version=existing.source_version,
                review_status="pending",
                impact_json=json.dumps(
                    {
                        "note": "Strukturierte Safety360-Zusammenfassung geändert; trägerspezifische Fassung erneut prüfen."
                    },
                    ensure_ascii=False,
                ),
                human_review_required=True,
            )
        )
        updated += 1

    db.add(
        AuditLog(
            event=f"dguv_v2_2024_baseline_seeded:created={created}:updated={updated}:unchanged={unchanged}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()

    return {
        "source_id": source.id,
        "source_key": source.source_key,
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "requirements": len(DGUV_V2_REQUIREMENTS),
        "status": "master_template_review_required",
        "binding_version_rule": (
            "Vor verbindlicher Anwendung muss Safety360 den zuständigen Unfallversicherungsträger des Kunden und dessen aktuell "
            "in Kraft gesetzte DGUV-Vorschrift-2-Fassung verifizieren."
        ),
    }


@router.get("/status")
def dguv_v2_status(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "regulatory.read")
    source = db.query(RegulatorySource).filter(
        RegulatorySource.authority == DGUV_V2_SOURCE["authority"],
        RegulatorySource.source_key == DGUV_V2_SOURCE["source_key"],
    ).first()
    if source is None:
        raise HTTPException(status_code=404, detail="DGUV-Vorschrift-2-Basis ist noch nicht initialisiert.")

    requirements = db.query(RegulatoryRequirement).filter(
        RegulatoryRequirement.source_id == source.id,
    ).all()
    return {
        "source": {
            "id": source.id,
            "name": source.name,
            "url": source.base_url,
            "source_version": "2024.11; formale Korrektur 2025-12",
            "last_checked_at": source.last_checked_at,
        },
        "requirements": len(requirements),
        "review_required": sum(1 for item in requirements if item.human_review_required),
        "important_notice": (
            "Dies ist der DGUV-Mustertext. Die für einen konkreten Betrieb geltende Vorschrift wird vom zuständigen "
            "Unfallversicherungsträger in Kraft gesetzt und muss mandantenspezifisch geprüft werden."
        ),
    }
