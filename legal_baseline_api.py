import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from permissions import require_permission
from regulatory_models import RegulatoryChange, RegulatoryRequirement, RegulatorySource

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

SOURCE_DEFINITIONS: dict[str, dict[str, object]] = {
    "gesetze-im-internet": {
        "authority": "Bundesministerium der Justiz / Bundesamt für Justiz",
        "name": "Gesetze im Internet",
        "jurisdiction": "DE",
        "source_type": "law",
        "base_url": "https://www.gesetze-im-internet.de/",
        "is_primary": True,
        "terms_note": "Aktuelle konsolidierte Bundesrechtsfassungen; Stand und Änderungsnachweise je Instrument prüfen.",
    },
    "baua": {
        "authority": "BAuA",
        "name": "Bundesanstalt für Arbeitsschutz und Arbeitsmedizin",
        "jurisdiction": "DE",
        "source_type": "technical_rules",
        "base_url": "https://www.baua.de/DE/Angebote/Regelwerk",
        "is_primary": True,
        "terms_note": "Offizielle Fachquelle für ASR, TRBS, TRGS, TRBA, RAB, TRLV, TROS, TREMF und weitere Regelwerke.",
    },
    "eur-lex": {
        "authority": "European Union",
        "name": "EUR-Lex",
        "jurisdiction": "EU",
        "source_type": "eu_law",
        "base_url": "https://eur-lex.europa.eu/",
        "is_primary": True,
        "terms_note": "Offizielle EU-Rechtsquelle; konsolidierte Fassung und Geltungsstand prüfen.",
    },
    "umweltbundesamt": {
        "authority": "Umweltbundesamt",
        "name": "Umweltbundesamt",
        "jurisdiction": "DE",
        "source_type": "environment_authority_guidance",
        "base_url": "https://www.umweltbundesamt.de/",
        "is_primary": True,
        "terms_note": "Behördenquelle für Umweltfachinformationen und Vollzugshilfen; Rechtsverbindlichkeit je Dokument gesondert prüfen.",
    },
    "iso-catalogue": {
        "authority": "ISO",
        "name": "ISO Standards Catalogue",
        "jurisdiction": "GLOBAL",
        "source_type": "management_system_standard_metadata",
        "base_url": "https://www.iso.org/standards.html",
        "is_primary": True,
        "terms_note": "Nur öffentliche Metadaten speichern. Normvolltexte und lizenzierte Inhalte nicht kopieren; Detailmapping nur aus kundenseitig rechtmäßig bereitgestellten Inhalten.",
    },
}

LEGAL_INSTRUMENTS: tuple[dict[str, object], ...] = (
    # Occupational safety and health - federal laws / ordinances
    {"key": "de-arbschg", "title": "Arbeitsschutzgesetz (ArbSchG)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/arbschg/", "applicability_hint": "Grundgesetzlicher Rahmen für Sicherheit und Gesundheitsschutz bei der Arbeit, Organisation, Gefährdungsbeurteilung, Dokumentation und Unterweisung."},
    {"key": "de-asig", "title": "Arbeitssicherheitsgesetz (ASiG)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/asig/", "applicability_hint": "Betriebsärztliche und sicherheitstechnische Betreuung; Bestellung und Aufgaben von Betriebsärzten und Fachkräften für Arbeitssicherheit."},
    {"key": "de-arbst-ttv", "title": "Arbeitsstättenverordnung (ArbStättV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/arbst_ttv_2004/", "applicability_hint": "Einrichten und Betreiben von Arbeitsstätten; wird durch ASR konkretisiert."},
    {"key": "de-betrsichv", "title": "Betriebssicherheitsverordnung (BetrSichV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/betrsichv_2015/", "applicability_hint": "Bereitstellung und Benutzung von Arbeitsmitteln sowie überwachungsbedürftige Anlagen; wird durch TRBS konkretisiert."},
    {"key": "de-gefstoffv", "title": "Gefahrstoffverordnung (GefStoffV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/gefstoffv_2010/", "applicability_hint": "Tätigkeiten mit Gefahrstoffen, Gefährdungsbeurteilung, Schutzmaßnahmen, Betriebsanweisung und Unterweisung; wird durch TRGS konkretisiert."},
    {"key": "de-biostoffv", "title": "Biostoffverordnung (BioStoffV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/biostoffv_2013/", "applicability_hint": "Tätigkeiten mit biologischen Arbeitsstoffen; wird durch TRBA konkretisiert."},
    {"key": "de-arbmedvv", "title": "Verordnung zur arbeitsmedizinischen Vorsorge (ArbMedVV)", "domain": "occupational_health", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/arbmedvv/", "applicability_hint": "Pflicht-, Angebots- und Wunschvorsorge sowie Vorsorgekartei und arbeitsmedizinische Prävention."},
    {"key": "de-baustellv", "title": "Baustellenverordnung (BaustellV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/baustellv/", "applicability_hint": "Sicherheit und Gesundheitsschutz auf Baustellen, Koordination und SiGe-Plan; ergänzt durch RAB."},
    {"key": "de-laermvibrationsarbschv", "title": "Lärm- und Vibrations-Arbeitsschutzverordnung", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/l_rmvibrationsarbschv/", "applicability_hint": "Gefährdungen durch Lärm und Vibrationen; Konkretisierung durch TRLV."},
    {"key": "de-ostrv", "title": "Arbeitsschutzverordnung zu künstlicher optischer Strahlung (OStrV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/ostrv/", "applicability_hint": "Gefährdungen durch künstliche optische Strahlung; Konkretisierung durch TROS."},
    {"key": "de-emfv", "title": "Arbeitsschutzverordnung zu elektromagnetischen Feldern (EMFV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/emfv/", "applicability_hint": "Gefährdungen durch elektromagnetische Felder; Konkretisierung durch TREMF."},
    {"key": "de-lasthandhabv", "title": "Lastenhandhabungsverordnung (LasthandhabV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/lasthandhabv/", "applicability_hint": "Manuelle Handhabung von Lasten und ergonomische Risiken."},
    {"key": "de-psa-bv", "title": "PSA-Benutzungsverordnung (PSA-BV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/psa-bv/", "applicability_hint": "Bereitstellung und Benutzung persönlicher Schutzausrüstung."},
    {"key": "de-muschg", "title": "Mutterschutzgesetz (MuSchG)", "domain": "occupational_health", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/muschg_2018/", "applicability_hint": "Besonderer Gesundheitsschutz für schwangere und stillende Beschäftigte einschließlich anlassbezogener Gefährdungsbeurteilung."},
    {"key": "de-jarbschg", "title": "Jugendarbeitsschutzgesetz (JArbSchG)", "domain": "occupational_health", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/jarbschg/", "applicability_hint": "Besonderer Schutz jugendlicher Beschäftigter einschließlich Arbeitszeit und Untersuchungen."},
    {"key": "de-arbzg", "title": "Arbeitszeitgesetz (ArbZG)", "domain": "occupational_health", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/arbzg/", "applicability_hint": "Arbeits-, Ruhe- und Nachtarbeitszeiten als Bestandteil gesundheitsgerechter Arbeitsorganisation."},
    {"key": "de-sgb-vii", "title": "SGB VII - Gesetzliche Unfallversicherung", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/sgb_7/", "applicability_hint": "Rechtsrahmen der gesetzlichen Unfallversicherung und Prävention."},
    # BAuA technical-rule families
    {"key": "de-asr-family", "title": "Technische Regeln für Arbeitsstätten (ASR)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/ASR/ASR", "applicability_hint": "Konkretisieren ArbStättV; aktuelle Einzelregeln und GMBl-Änderungen separat überwachen."},
    {"key": "de-trbs-family", "title": "Technische Regeln für Betriebssicherheit (TRBS)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/TRBS/TRBS", "applicability_hint": "Konkretisieren BetrSichV; aktuelle Einzelregeln und Bekanntmachungen separat überwachen."},
    {"key": "de-trgs-family", "title": "Technische Regeln für Gefahrstoffe (TRGS)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/TRGS/TRGS", "applicability_hint": "Konkretisieren GefStoffV; aktuelle Einzelregeln und Bekanntmachungen separat überwachen."},
    {"key": "de-trba-family", "title": "Technische Regeln für Biologische Arbeitsstoffe (TRBA)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/TRBA/TRBA", "applicability_hint": "Konkretisieren BioStoffV; aktuelle Einzelregeln und Bekanntmachungen separat überwachen."},
    {"key": "de-rab-family", "title": "Regeln zum Arbeitsschutz auf Baustellen (RAB)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/RAB/RAB", "applicability_hint": "Konkretisieren Anforderungen des Baustellenarbeitsschutzes."},
    {"key": "de-trlv-family", "title": "Technische Regeln zur Lärm- und Vibrations-Arbeitsschutzverordnung (TRLV)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/TRLV/TRLV", "applicability_hint": "Konkretisieren LärmVibrationsArbSchV."},
    {"key": "de-tros-family", "title": "Technische Regeln zur Arbeitsschutzverordnung zu künstlicher optischer Strahlung (TROS)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/TROS/TROS", "applicability_hint": "Konkretisieren OStrV."},
    {"key": "de-tremf-family", "title": "Technische Regeln zur Arbeitsschutzverordnung zu elektromagnetischen Feldern (TREMF)", "domain": "occupational_safety", "jurisdiction": "DE", "source_key": "baua", "legal_level": "technical_rule_family", "url": "https://www.baua.de/DE/Angebote/Regelwerk/TREMF/TREMF", "applicability_hint": "Konkretisieren EMFV."},
    # Environment
    {"key": "de-bimschg", "title": "Bundes-Immissionsschutzgesetz (BImSchG)", "domain": "environment", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/bimschg/", "applicability_hint": "Immissionsschutz, genehmigungsbedürftige Anlagen, Luft, Lärm und weitere Umwelteinwirkungen; zugehörige BImSchV nach Anlagen-/Tätigkeitsprofil ergänzen."},
    {"key": "de-krwg", "title": "Kreislaufwirtschaftsgesetz (KrWG)", "domain": "environment", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/krwg/", "applicability_hint": "Abfallhierarchie, Kreislaufwirtschaft und Abfallbewirtschaftung; ergänzende Verordnungen nach Abfallströmen prüfen."},
    {"key": "de-whg", "title": "Wasserhaushaltsgesetz (WHG)", "domain": "environment", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/whg_2009/", "applicability_hint": "Gewässerschutz, Benutzungen, wassergefährdende Stoffe und betriebliche Wasserpflichten."},
    {"key": "de-awsv", "title": "Verordnung über Anlagen zum Umgang mit wassergefährdenden Stoffen (AwSV)", "domain": "environment", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_ordinance", "url": "https://www.gesetze-im-internet.de/awsv/", "applicability_hint": "Einstufung wassergefährdender Stoffe und technische/organisatorische Anforderungen an Anlagen."},
    {"key": "de-bbodschg", "title": "Bundes-Bodenschutzgesetz (BBodSchG)", "domain": "environment", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/bbodschg/", "applicability_hint": "Bodenschutz, schädliche Bodenveränderungen und Altlasten."},
    {"key": "de-ksg", "title": "Bundes-Klimaschutzgesetz (KSG)", "domain": "climate", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/ksg/", "applicability_hint": "Bundesrechtlicher Klimaschutzrahmen; betriebliche direkte Pflichten nur soweit anwendbar und mit weiteren Instrumenten verknüpft."},
    {"key": "de-tehg", "title": "Treibhausgas-Emissionshandelsgesetz (TEHG)", "domain": "climate", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/tehg_2011/", "applicability_hint": "Emissionshandel für erfasste Anlagen/Tätigkeiten; Anwendbarkeit an Anlagenprofil und EU-ETS koppeln."},
    # Energy and data centers
    {"key": "de-enefg", "title": "Energieeffizienzgesetz (EnEfG)", "domain": "energy", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/enefg/", "applicability_hint": "Energieeffizienz, Energie-/Umweltmanagementsysteme, Umsetzungspläne, Abwärme und besondere Pflichten für Rechenzentren."},
    {"key": "de-edl-g", "title": "Gesetz über Energiedienstleistungen und andere Energieeffizienzmaßnahmen (EDL-G)", "domain": "energy", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/edl-g/", "applicability_hint": "Energieaudits, Nachweisführung und weitere Energieeffizienzpflichten für erfasste Unternehmen und öffentliche Stellen."},
    {"key": "de-geg", "title": "Gebäudeenergiegesetz (GEG)", "domain": "energy", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/geg/", "applicability_hint": "Energetische Anforderungen an Gebäude und Anlagentechnik; Relevanz nach Gebäudeeigentum/-betrieb und Maßnahmenprofil."},
    # Sustainability / supply chain / EU reporting
    {"key": "de-lksg", "title": "Lieferkettensorgfaltspflichtengesetz (LkSG)", "domain": "sustainability", "jurisdiction": "DE", "source_key": "gesetze-im-internet", "legal_level": "federal_law", "url": "https://www.gesetze-im-internet.de/lksg/", "applicability_hint": "Menschenrechtliche und umweltbezogene Sorgfaltspflichten, Risikomanagement, Risikoanalyse, Prävention, Beschwerden und Dokumentation."},
    {"key": "eu-csrd-2022-2464", "title": "Corporate Sustainability Reporting Directive (EU) 2022/2464 (CSRD)", "domain": "sustainability", "jurisdiction": "EU", "source_key": "eur-lex", "legal_level": "eu_directive", "url": "https://eur-lex.europa.eu/eli/dir/2022/2464/oj", "applicability_hint": "Nachhaltigkeitsberichterstattung; aktuelle Änderungs-, Übergangs- und nationale Umsetzungslage separat überwachen."},
    {"key": "eu-esrs-2023-2772", "title": "European Sustainability Reporting Standards - Delegierte Verordnung (EU) 2023/2772", "domain": "sustainability", "jurisdiction": "EU", "source_key": "eur-lex", "legal_level": "eu_delegated_regulation", "url": "https://eur-lex.europa.eu/eli/reg_del/2023/2772/oj", "applicability_hint": "ESRS-Berichtsstandards; konsolidierte Fassung und Änderungen überwachen."},
    {"key": "eu-taxonomy-2020-852", "title": "EU-Taxonomie-Verordnung (EU) 2020/852", "domain": "sustainability", "jurisdiction": "EU", "source_key": "eur-lex", "legal_level": "eu_regulation", "url": "https://eur-lex.europa.eu/eli/reg/2020/852/oj", "applicability_hint": "Rahmen für ökologisch nachhaltige Wirtschaftstätigkeiten; delegierte Rechtsakte und technische Bewertungskriterien separat überwachen."},
    {"key": "eu-csddd-2024-1760", "title": "Corporate Sustainability Due Diligence Directive (EU) 2024/1760 (CSDDD/CS3D)", "domain": "sustainability", "jurisdiction": "EU", "source_key": "eur-lex", "legal_level": "eu_directive", "url": "https://eur-lex.europa.eu/eli/dir/2024/1760/", "applicability_hint": "Unternehmerische menschenrechtliche und umweltbezogene Sorgfaltspflichten; aktuelle konsolidierte Fassung und Umsetzung überwachen."},
    # Management-system metadata only
    {"key": "iso-45001", "title": "ISO 45001 - Occupational health and safety management systems", "domain": "management_system", "jurisdiction": "GLOBAL", "source_key": "iso-catalogue", "legal_level": "standard_metadata", "url": "https://www.iso.org/standards.html", "management_system": "ISO 45001", "applicability_hint": "Nur öffentliche Metadaten und kundenseitig lizenzierte Norminhalte für Detailmapping verwenden."},
    {"key": "iso-14001", "title": "ISO 14001 - Environmental management systems", "domain": "management_system", "jurisdiction": "GLOBAL", "source_key": "iso-catalogue", "legal_level": "standard_metadata", "url": "https://www.iso.org/standards.html", "management_system": "ISO 14001", "applicability_hint": "Nur öffentliche Metadaten und kundenseitig lizenzierte Norminhalte für Detailmapping verwenden."},
    {"key": "iso-50001", "title": "ISO 50001 - Energy management systems", "domain": "management_system", "jurisdiction": "GLOBAL", "source_key": "iso-catalogue", "legal_level": "standard_metadata", "url": "https://www.iso.org/standards.html", "management_system": "ISO 50001", "applicability_hint": "Nur öffentliche Metadaten und kundenseitig lizenzierte Norminhalte für Detailmapping verwenden."},
    {"key": "iso-9001", "title": "ISO 9001 - Quality management systems", "domain": "management_system", "jurisdiction": "GLOBAL", "source_key": "iso-catalogue", "legal_level": "standard_metadata", "url": "https://www.iso.org/standards.html", "management_system": "ISO 9001", "applicability_hint": "Nur öffentliche Metadaten und kundenseitig lizenzierte Norminhalte für Detailmapping verwenden."},
    {"key": "iso-iec-27001", "title": "ISO/IEC 27001 - Information security management systems", "domain": "management_system", "jurisdiction": "GLOBAL", "source_key": "iso-catalogue", "legal_level": "standard_metadata", "url": "https://www.iso.org/standards.html", "management_system": "ISO/IEC 27001", "applicability_hint": "Nur öffentliche Metadaten und kundenseitig lizenzierte Norminhalte für Detailmapping verwenden."},
    {"key": "en-50600-family", "title": "EN 50600 - Information technology - Data centre facilities and infrastructures", "domain": "management_system", "jurisdiction": "EU", "source_key": "iso-catalogue", "legal_level": "standard_family_metadata", "url": "https://www.iso.org/standards.html", "management_system": "EN 50600", "applicability_hint": "Normenfamilie für Rechenzentren; konkrete Teile/Fassungen nur aus rechtmäßig lizenzierten Quellen mappen."},
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _instrument_hash(item: dict[str, object]) -> str:
    normalized = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _source_by_key(db: Session, source_key: str) -> RegulatorySource:
    source = db.query(RegulatorySource).filter(RegulatorySource.source_key == source_key).first()
    if source:
        return source

    definition = SOURCE_DEFINITIONS[source_key]
    source = RegulatorySource(
        authority=str(definition["authority"]),
        source_key=source_key,
        name=str(definition["name"]),
        jurisdiction=str(definition["jurisdiction"]),
        source_type=str(definition["source_type"]),
        base_url=str(definition["base_url"]),
        is_primary=bool(definition["is_primary"]),
        enabled=True,
        terms_note=str(definition["terms_note"]),
    )
    db.add(source)
    db.flush()
    return source


@router.get("/catalog")
def legal_baseline_catalog(current_user: CurrentUser):
    require_permission(current_user, "regulatory.read")
    return {
        "status": "reference_baseline",
        "warning": (
            "Der Katalog ist eine überwachte Startbasis und keine abschließende Rechtsliste. "
            "Anwendbarkeit, aktuelle Fassung, Landesrecht, Genehmigungen und branchenspezifische Anforderungen "
            "müssen mandantenbezogen geprüft werden."
        ),
        "instruments": list(LEGAL_INSTRUMENTS),
    }


@router.get("/coverage")
def legal_baseline_coverage(current_user: CurrentUser):
    require_permission(current_user, "regulatory.read")
    domains = Counter(str(item["domain"]) for item in LEGAL_INSTRUMENTS)
    jurisdictions = Counter(str(item["jurisdiction"]) for item in LEGAL_INSTRUMENTS)
    source_keys = Counter(str(item["source_key"]) for item in LEGAL_INSTRUMENTS)
    return {
        "total": len(LEGAL_INSTRUMENTS),
        "domains": dict(sorted(domains.items())),
        "jurisdictions": dict(sorted(jurisdictions.items())),
        "sources": dict(sorted(source_keys.items())),
        "monitoring_principle": "official-source-first + version/hash comparison + human review for binding impact",
    }


@router.post("/seed", status_code=status.HTTP_201_CREATED)
def seed_legal_baseline(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "regulatory.manage")
    created = 0
    updated = 0
    unchanged = 0
    now = _utc_now()

    for item in LEGAL_INSTRUMENTS:
        source = _source_by_key(db, str(item["source_key"]))
        source.last_checked_at = now
        content_hash = _instrument_hash(item)
        existing = db.query(RegulatoryRequirement).filter(
            RegulatoryRequirement.source_id == source.id,
            RegulatoryRequirement.external_key == str(item["key"]),
        ).first()

        applicability = {
            "official_url": item["url"],
            "legal_level": item["legal_level"],
            "applicability_hint": item["applicability_hint"],
            "monitor": True,
            "version_policy": "verify-current-official-source-before-binding-use",
        }
        applicability_json = json.dumps(applicability, ensure_ascii=False, sort_keys=True)

        if existing is None:
            requirement = RegulatoryRequirement(
                source_id=source.id,
                external_key=str(item["key"]),
                title=str(item["title"]),
                citation=str(item["url"]),
                summary=str(item["applicability_hint"]),
                jurisdiction=str(item["jurisdiction"]),
                topic=str(item["domain"]),
                management_system=(str(item["management_system"]) if item.get("management_system") else None),
                status="current",
                source_version=None,
                content_hash=content_hash,
                applicability_json=applicability_json,
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
                    new_hash=content_hash,
                    source_version=None,
                    human_review_required=True,
                )
            )
            created += 1
            continue

        existing.last_seen_at = now
        if existing.content_hash == content_hash:
            unchanged += 1
            continue

        previous_hash = existing.content_hash
        existing.title = str(item["title"])
        existing.citation = str(item["url"])
        existing.summary = str(item["applicability_hint"])
        existing.jurisdiction = str(item["jurisdiction"])
        existing.topic = str(item["domain"])
        existing.management_system = str(item["management_system"]) if item.get("management_system") else None
        existing.content_hash = content_hash
        existing.applicability_json = applicability_json
        existing.human_review_required = True
        existing.verified_at = None
        existing.verified_by_id = None
        db.add(
            RegulatoryChange(
                requirement_id=existing.id,
                change_type="updated",
                previous_hash=previous_hash,
                new_hash=content_hash,
                source_version=None,
                human_review_required=True,
            )
        )
        updated += 1

    db.add(
        AuditLog(
            event=f"legal_baseline_seeded:created={created}:updated={updated}:unchanged={unchanged}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()
    return {
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "total": len(LEGAL_INSTRUMENTS),
    }


@router.get("/monitor-plan")
def monitor_plan(current_user: CurrentUser):
    require_permission(current_user, "regulatory.read")
    return {
        "source_priority": [
            "official consolidated law / official journal",
            "competent authority technical rule",
            "accident-insurance rule subject to rights governance",
            "official EU legal source",
            "official standard metadata / customer-licensed standard content",
            "secondary guidance only as supporting context",
        ],
        "change_pipeline": [
            "discover source change",
            "verify official source and current version",
            "compare version/hash/status/effective dates",
            "create immutable regulatory change event",
            "classify applicability by jurisdiction, industry, site, activity, asset and management system",
            "generate evidence gaps and human-review task",
            "after approval create controlled downstream revisions/tasks",
            "never silently overwrite approved documents",
        ],
        "downstream_targets": [
            "legal register",
            "industry/activity library",
            "risk assessments",
            "operating instructions",
            "training and presentations",
            "inspection/testing plans",
            "environmental aspects/obligations",
            "energy management and data-center obligations",
            "sustainability due-diligence/reporting workflows",
            "audits/CAPA/management review",
        ],
    }
