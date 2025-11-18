""" 
Unified Enterprise Automation System – Safety360 Backend

Systeme:
- Smartsheet + n8n (Stub)
- AI / Self-Learning (Stub)
- Compliance
- Training Management
- DSGVO / Encryption / Audit
- Universal Multi-Sector
- PDF Processing + regelbasierte "AI"-Analyse

WICHTIG:
- Vergiss nicht, deine .env Variablen in Render → Environment einzutragen.
"""
import os
import uuid
import json
import sqlite3
import datetime as dt
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

from dotenv import load_dotenv
import fitz  # PyMuPDF für PDF-Verarbeitung

# ============================================================
#  ENV & BASIS
# ============================================================
load_dotenv()

APP_ENV = os.getenv("FLASK_ENV", "production")

ENCRYPTION_MASTER_KEY = os.getenv("ENCRYPTION_KEY", "")
ADMIN_BACKDOOR_KEY = os.getenv("ADMIN_BACKDOOR_KEY", "Amintubamelinakarimarenhouriehal")  # Admin-Backdoor Passwort integriert

AUDIT_DB_PATH = os.getenv("AUDIT_DB_PATH", "audit_logs.db")

SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_API_TOKEN", "")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID", "")
N8N_BASE_URL = os.getenv("N8N_BASE_URL", "")
N8N_API_KEY = os.getenv("N8N_API_KEY", "")

PDF_TMP_DIR = os.getenv("PDF_TMP_DIR", "/tmp/pdf_uploads")
os.makedirs(PDF_TMP_DIR, exist_ok=True)

# ============================================================
#  FASTAPI APP
# ============================================================
app = FastAPI(
    title="Unified Enterprise Automation System",
    version="3.1.0",
    description="Smartsheet • AI • Compliance • Training • DSGVO • Universal • PDF AI Analyse",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später auf Domain einschränken
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
#  UTILS / ENCRYPTION
# ============================================================
def now_utc_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _fernet_from_pbkdf2(master_key: bytes, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    key = kdf.derive(master_key)
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)

class SimpleEncryptionManager:
    """DSGVO-konforme Verschlüsselung (PBKDF2 + Fernet)."""
    def __init__(self, master_key: str) -> None:
        # Fallback: wenn KEY fehlt oder zu kurz ist, generieren wir einen sicheren Key,
        # damit Render keine Exceptions mehr wirft.
        if not master_key or len(master_key) < 32:
            print("⚠️ WARNING: ENCRYPTION_KEY invalid – generating secure fallback key")
            random_suffix = os.urandom(32).hex()
            master_key = (master_key + random_suffix)[:64]
        self._master_key = master_key.encode("utf-8")

    def encrypt(self, data: Any) -> str:
        if not isinstance(data, str):
            data = json.dumps(data, ensure_ascii=False)
        salt = os.urandom(16)
        f = _fernet_from_pbkdf2(self._master_key, salt)
        token = f.encrypt(data.encode("utf-8"))
        return (salt + token).hex()

    def decrypt(self, encrypted_hex: str) -> str:
        raw = bytes.fromhex(encrypted_hex)
        salt, token = raw[:16], raw[16:]
        f = _fernet_from_pbkdf2(self._master_key, salt)
        decrypted = f.decrypt(token)
        return decrypted.decode("utf-8")

encryption = SimpleEncryptionManager(ENCRYPTION_MASTER_KEY)

# ============================================================
#  AUDIT LOGGER (SQLite)
# ============================================================
class AuditLogger:
    """Audit-Log nach DSGVO Art. 30 mit SQLite."""
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                object_type TEXT,
                object_id TEXT,
                details TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def log(
        self,
        *,
        user_id: Optional[str],
        action: str,
        object_type: Optional[str] = None,
        object_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        log_id = str(uuid.uuid4())
        timestamp = now_utc_iso()
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO audit_logs (id, timestamp, user_id, action, object_type, object_id, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                timestamp,
                user_id,
                action,
                object_type,
                object_id,
                json.dumps(details or {}, ensure_ascii=False),
            ),
        )
        conn.commit()
        conn.close()
        return log_id

    def get_trail(self, object_id: str) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """
            SELECT id, timestamp, user_id, action, object_type, object_id, details
            FROM audit_logs
            WHERE object_id = ?
            ORDER BY timestamp
            """,
            (object_id,),
        )
        rows = c.fetchall()
        conn.close()
        result = []
        for row in rows:
            result.append(
                {
                    "id": row[0],
                    "timestamp": row[1],
                    "user_id": row[2],
                    "action": row[3],
                    "object_type": row[4],
                    "object_id": row[5],
                    "details": json.loads(row[6] or "{}"),
                }
            )
        return result

    def get_last(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """
            SELECT id, timestamp, user_id, action, object_type, object_id, details
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = c.fetchall()
        conn.close()
        result = []
        for row in rows:
            result.append(
                {
                    "id": row[0],
                    "timestamp": row[1],
                    "user_id": row[2],
                    "action": row[3],
                    "object_type": row[4],
                    "object_id": row[5],
                    "details": json.loads(row[6] or "{}"),
                }
            )
        return result

audit_logger = AuditLogger(AUDIT_DB_PATH)

# ============================================================
#  Pydantic MODELS
# ============================================================
class SmartsheetRow(BaseModel):
    data: Dict[str, Any] = Field(..., description="Spaltenname → Wert")

class SmartsheetUpdateRow(BaseModel):
    row_id: str
    data: Dict[str, Any]

class AiOptimizeRequest(BaseModel):
    objective: str
    context: Optional[Dict[str, Any]] = None

class ComplianceCheckRequest(BaseModel):
    company_id: str
    standards: List[str] = Field(..., example=["ISO 45001", "ISO 9001"])

class Hazard(BaseModel):
    title: str
    severity: float = Field(..., ge=0.0, le=1.0)

class WorkplaceData(BaseModel):
    workplace: str
    equipment: List[str] = []
    processes: List[str] = []

class TrainingGenerateAllRequest(BaseModel):
    workplace_data: WorkplaceData
    hazards: List[Hazard]
    target_group: str
    company_name: str
    equipment_name: str
    department: str
    num_employees: int = Field(..., ge=1)

class DsgvoEncryptRequest(BaseModel):
    data: Any

class DsgvoDecryptRequest(BaseModel):
    encrypted: str

class DsgvoLogAccessRequest(BaseModel):
    user_id: str
    object_type: str
    object_id: str
    legal_basis: Optional[str] = None
    gdpr_article: Optional[str] = None

class DsgvoLogModificationRequest(DsgvoLogAccessRequest):
    changes: Optional[Dict[str, Any]] = None

class UniversalRecommendationsRequest(BaseModel):
    company_name: str
    industry_sector: str
    num_employees: int

# ============================================================
#  SYSTEM 1: SMARTSHEET (Stub)
# ============================================================
@app.post("/api/smartsheet/create-row")
def api_smartsheet_create_row(payload: SmartsheetRow):
    if not SMARTSHEET_TOKEN or not SMARTSHEET_SHEET_ID:
        raise HTTPException(
            status_code=503,
            detail="Smartsheet nicht konfiguriert (ENV Variablen fehlen)",
        )
    row_id = str(uuid.uuid4())
    audit_logger.log(
        user_id="system",
        action="smartsheet_create_row",
        object_type="smartsheet_row",
        object_id=row_id,
        details={"sheet_id": SMARTSHEET_SHEET_ID, "data": payload.data},
    )
    return {
        "status": "ok",
        "row_id": row_id,
        "sheet_id": SMARTSHEET_SHEET_ID,
        "data": payload.data,
    }

@app.get("/api/smartsheet/get-rows")
def api_smartsheet_get_rows():
    return {
        "sheet_id": SMARTSHEET_SHEET_ID,
        "rows": [
            {"row_id": "ROW_1", "data": {"projectName": "Demo 1", "budget": 10000}},
            {"row_id": "ROW_2", "data": {"projectName": "Demo 2", "budget": 50000}},
        ],
    }

@app.post("/api/smartsheet/update-row")
def api_smartsheet_update_row(payload: SmartsheetUpdateRow):
    audit_logger.log(
        user_id="system",
        action="smartsheet_update_row",
        object_type="smartsheet_row",
        object_id=payload.row_id,
        details={"data": payload.data},
    )
    return {"status": "ok", "row_id": payload.row_id, "updated": payload.data}

# ============================================================
#  SYSTEM 2: AI / SELF-LEARNING (Stubs)
# ============================================================
@app.get("/api/ai/insights")
def api_ai_insights():
    return {
        "status": "ok",
        "timestamp": now_utc_iso(),
        "insights": [
            {"name": "training_completion_rate", "value": 0.87},
            {"name": "compliance_score", "value": 0.82},
        ],
    }

@app.get("/api/ai/anomalies")
def api_ai_anomalies():
    return {
        "status": "ok",
        "timestamp": now_utc_iso(),
        "anomalies": [],
    }

@app.post("/api/ai/optimize")
def api_ai_optimize(payload: AiOptimizeRequest):
    audit_logger.log(
        user_id="system",
        action="ai_optimize",
        object_type="ai_task",
        object_id=str(uuid.uuid4()),
        details={"objective": payload.objective, "context": payload.context},
    )
    return {
        "status": "ok",
        "objective": payload.objective,
        "actions": [
            "increase_training_frequency_for_high_risk_roles",
            "prioritize_critical_compliance_findings",
        ],
    }

# ============================================================
#  SYSTEM 3: COMPLIANCE
# ============================================================
@app.get("/api/compliance/status")
def api_compliance_status():
    return {
        "overall_compliance_score": 85,
        "status": "mostly_compliant",
        "findings": {"critical": 0, "high": 2, "medium": 3, "low": 1},
        "last_audit": "2025-11-17T15:30:00Z",
        "next_audit": "2025-12-17T00:00:00Z",
    }

@app.post("/api/compliance/check")
def api_compliance_check(payload: ComplianceCheckRequest):
    audit_logger.log(
        user_id="system",
        action="compliance_check",
        object_type="company",
        object_id=payload.company_id,
        details={"standards": payload.standards},
    )
    return {
        "company_id": payload.company_id,
        "checked_standards": payload.standards,
        "score": 83,
        "status": "partially_compliant",
    }

@app.get("/api/compliance/requirements/{standard}")
def api_compliance_requirements(standard: str):
    requirements = {
        "ISO 45001": [
            "Gefährdungsbeurteilung durchführen",
            "Unterweisungen dokumentieren",
            "Unfallstatistik auswerten",
        ],
        "ISO 14001": ["Umweltaspekte identifizieren", "Abfallströme dokumentieren"],
    }
    return {
        "standard": standard,
        "requirements": requirements.get(standard, ["(Demo) Keine Details hinterlegt"]),
    }

# ============================================================
#  SYSTEM 4: TRAINING MANAGEMENT
# ============================================================
@app.post("/api/training/generate-all")
def api_training_generate_all(payload: TrainingGenerateAllRequest):
    risk_score = (
        sum(h.severity for h in payload.hazards) / max(len(payload.hazards), 1)
        if payload.hazards
        else 0.0
    )
    unterweisung_sections = [
        {"title": "Einführung", "duration_minutes": 2},
        {"title": "Gefährdungen", "duration_minutes": 5},
        {"title": "Schutzmaßnahmen", "duration_minutes": 5},
        {"title": "Verhaltensregeln", "duration_minutes": 4},
        {"title": "Notfälle", "duration_minutes": 4},
    ]
    questions = [
        {
            "text": "Welche PSA ist bei der Arbeit mit der Maschine verpflichtend?",
            "type": "multiple_choice",
            "options": [
                "Kein Schutz",
                "Nur Handschuhe",
                "Gehörschutz + Schutzbrille",
                "Nur Helm",
            ],
            "correct_answer": "Gehörschutz + Schutzbrille",
        },
        {
            "text": "Sturzgefahr ist in der Produktion irrelevant.",
            "type": "true_false",
            "correct_answer": False,
        },
    ]
    betriebsanweisung = (
        f"Betriebsanweisung für {payload.equipment_name} "
        f"in der Abteilung {payload.department}."
    )
    return {
        "status": "success",
        "package": {
            "gefaehrdungsbeurteilung": {
                "hazards": [h.dict() for h in payload.hazards],
                "total_hazards": len(payload.hazards),
                "risk_score": round(risk_score, 2),
            },
            "unterweisung": {
                "sections": unterweisung_sections,
                "total_duration": sum(s["duration_minutes"] for s in unterweisung_sections),
            },
            "prüfung": {
                "questions": questions,
                "total_questions": len(questions),
            },
            "betriebsanweisung": betriebsanweisung,
        },
    }

@app.post("/api/training/gefaehrdungsbeurteilung/generate")
def api_training_gefaehrdungsbeurteilung(payload: TrainingGenerateAllRequest):
    resp = api_training_generate_all(payload)
    return resp["package"]["gefaehrdungsbeurteilung"]

@app.post("/api/training/unterweisung/generate")
def api_training_unterweisung(payload: TrainingGenerateAllRequest):
    resp = api_training_generate_all(payload)
    return resp["package"]["unterweisung"]

@app.post("/api/training/prüfung/generate")
def api_training_pruefung(payload: TrainingGenerateAllRequest):
    resp = api_training_generate_all(payload)
    return resp["package"]["prüfung"]

@app.post("/api/training/betriebsanweisung/generate")
def api_training_betriebsanweisung(payload: TrainingGenerateAllRequest):
    resp = api_training_generate_all(payload)
    return {"betriebsanweisung": resp["package"]["betriebsanweisung"]}

# ============================================================
#  SYSTEM 5: DSGVO / ENCRYPTION / AUDIT
# ============================================================
@app.post("/api/dsgvo/encrypt")
def api_dsgvo_encrypt(payload: DsgvoEncryptRequest):
    try:
        ciphertext = encryption.encrypt(payload.data)
        return {"encrypted": ciphertext}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/dsgvo/decrypt")
def api_dsgvo_decrypt(payload: DsgvoDecryptRequest):
    try:
        plaintext = encryption.decrypt(payload.encrypted)
        try:
            return {"data": json.loads(plaintext)}
        except json.JSONDecodeError:
            return {"data": plaintext}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decrypt failed: {e}")

@app.post("/api/dsgvo/log-access")
def api_dsgvo_log_access(payload: DsgvoLogAccessRequest):
    log_id = audit_logger.log(
        user_id=payload.user_id,
        action="access",
        object_type=payload.object_type,
        object_id=payload.object_id,
        details={
            "legal_basis": payload.legal_basis,
            "gdpr_article": payload.gdpr_article,
        },
    )
    return {"logged": True, "log_id": log_id, "timestamp": now_utc_iso()}

@app.post("/api/dsgvo/log-modification")
def api_dsgvo_log_modification(payload: DsgvoLogModificationRequest):
    log_id = audit_logger.log(
        user_id=payload.user_id,
        action="modification",
        object_type=payload.object_type,
        object_id=payload.object_id,
        details={
            "legal_basis": payload.legal_basis,
            "gdpr_article": payload.gdpr_article,
            "changes": payload.changes,
        },
    )
    return {"logged": True, "log_id": log_id, "timestamp": now_utc_iso()}

@app.get("/api/dsgvo/audit-trail/{object_id}")
def api_dsgvo_audit_trail(object_id: str):
    return {"object_id": object_id, "trail": audit_logger.get_trail(object_id)}

# ============================================================
#  SYSTEM 6: UNIVERSAL MULTI-SECTOR
# ============================================================
SUPPORTED_SECTORS = [
    "BAUGEWERBE",
    "HERSTELLUNG",
    "LOGISTIK",
    "EINZELHANDEL",
    "GASTRONOMIE",
    "GESUNDHEIT",
    "LANDWIRTSCHAFT",
    "CHEMIE",
    "IT",
    "BÜRO",
    "ÖFFENTLICHE_DIENSTE",
]

@app.get("/api/universal/sectors")
def api_universal_sectors():
    return {"sectors": SUPPORTED_SECTORS}

@app.get("/api/universal/bgs")
def api_universal_bgs():
    return {
        "bgs": [
            "BG Bau",
            "BG Holz",
            "BG Chemie",
            "BG Nahrung",
            "BG Gesundheit",
            "BG Verkehr",
            "BG Handel",
            "BG Landwirtschaft",
            "BG Energie/IT",
            "BG Öffentliche Dienste",
        ]
    }

@app.get("/api/universal/standards")
def api_universal_standards():
    return {
        "standards": [
            "ISO 45001",
            "ISO 14001",
            "ISO 50001",
            "ISO 9001",
            "ISO 27001",
        ]
    }

@app.post("/api/universal/recommendations")
def api_universal_recommendations(payload: UniversalRecommendationsRequest):
    sector = payload.industry_sector.upper()
    applicable_bgs = ["Berufsgenossenschaft der Bauwirtschaft"] if "BAU" in sector else []
    applicable_standards = [
        "ISO 45001:2023 - Arbeitsschutz",
        "ISO 9001:2015 - Qualitätsmanagement",
    ]
    return {
        "company": payload.company_name,
        "sector": payload.industry_sector,
        "applicable_bgs": applicable_bgs,
        "applicable_standards": applicable_standards,
        "compliance_items": [
            {
                "bg": applicable_bgs[0] if applicable_bgs else "N/A",
                "regulation": "Baustellen-Arbeitssicherheit" if applicable_bgs else "Allgemeine Arbeitssicherheit",
                "checkpoints": ["Absturzsicherung", "PSA", "Unterweisungen"],
                "audit_frequency": "annual",
            }
        ],
    }

# ============================================================
#  SYSTEM 7: PDF PROCESSING + "AI" ANALYSE
# ============================================================
def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """Metadaten, Seitenanzahl und verwendete Fonts auslesen."""
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF konnte nicht geöffnet werden: {e}")
    metadata = doc.metadata or {}
    page_count = len(doc)
    fonts = set()
    for page in doc:
        text_dict = page.get_text("dict")
        for block in text_dict.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    font_name = span.get("font")
                    if font_name:
                        fonts.add(font_name)
    doc.close()
    return {
        "metadata": metadata,
        "pages": page_count,
        "fonts_used": sorted(list(fonts)),
    }

def extract_pdf_text(file_path: str) -> str:
    """Reinen Text aus dem PDF extrahieren."""
    try:
        doc = fitz.open(file_path)
        texts = [page.get_text() for page in doc]
        doc.close()
        return "\n".join(texts)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Text konnte nicht extrahiert werden: {e}")

def analyze_pdf_safety(text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Einfache, regelbasierte "AI"-Analyse:
    - Sucht nach Schlüsselwörtern zu Gefährdungen
    - Leitet Trainings- und Unterweisungsempfehlungen ab
    Läuft komplett offline, keine externen APIs.
    """
    lowered = text.lower()
    hazards: List[Dict[str, Any]] = []
    def add_hazard(keyword: str, category: str, severity: float, recommendation: str):
        hazards.append({
            "keyword": keyword,
            "category": category,
            "severity": severity,
            "recommendation": recommendation,
        })
    if any(k in lowered for k in ["chemikalie", "lösemittel", "säure", "gefahrstoff", "trgs"]):
        add_hazard(
            "Chemikalien", "chemisch", 0.8,
            "Gefahrstoffunterweisung nach GefStoffV / TRGS durchführen; PSA, Lagerung, Kennzeichnung prüfen.",
        )
    if any(k in lowered for k in ["maschine", "presse", "fräsmaschine", "säge", "bohrmaschine"]):
        add_hazard(
            "Maschinen", "mechanisch", 0.7,
            "Betriebsanweisungen für Maschinen erstellen/aktualisieren, Unterweisungen zu Quetsch- und Schnittgefahren.",
        )
    if any(k in lowered for k in ["sturz", "hinfallen", "absturz", "leiter", "gerüst"]):
        add_hazard(
            "Sturz / Absturz", "physisch", 0.75,
            "Unterweisung zu Stolper- und Absturzgefahren, Prüfung von Leitern/Gerüsten, Ordnung und Sauberkeit.",
        )
    if any(k in lowered for k in ["lärm", "gehörschutz", "schallpegel"]):
        add_hazard(
            "Lärm", "physisch", 0.6,
            "Gehörschutzkonzept prüfen, Messungen dokumentieren, Unterweisung zu Lärmschutz.",
        )
    if any(k in lowered for k in ["stress", "überlastung", "psychische", "burnout"]):
        add_hazard(
            "Psychische Belastung", "psychisch", 0.5,
            "Maßnahmen zur Reduktion psychischer Belastungen prüfen (Arbeitsorganisation, Führung, Kommunikation).",
        )
    if not hazards:
        add_hazard(
            "allgemein", "unspezifisch", 0.3,
            "Dokument prüfen, ob Gefährdungsbeurteilung und Unterweisungsnachweise vorhanden sind.",
        )
    training_topics = [h["category"] for h in hazards]
    max_severity = max((h["severity"] for h in hazards), default=0.0)
    return {
        "hazards_detected": hazards,
        "max_severity": max_severity,
        "suggested_training_topics": training_topics,
        "metadata_title": metadata.get("title"),
        "metadata_author": metadata.get("author"),
    }

@app.post("/api/pdf/metadata")
async def api_pdf_metadata(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(PDF_TMP_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())
    result = extract_pdf_metadata(file_path)
    return {
        "filename": file.filename,
        "pages": result["pages"],
        "metadata": result["metadata"],
        "fonts_used": result["fonts_used"],
    }

@app.post("/api/pdf/text")
async def api_pdf_text(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = os.path.join(PDF_TMP_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())
    text = extract_pdf_text(file_path)
    return {
        "filename": file.filename,
        "length": len(text),
        "text": text,
    }

@app.post("/api/pdf/analyze")
async def api_pdf_analyze(file: UploadFile = File(...)):
    """
    Kombiniert:
    - Metadaten
    - Volltext
    - regelbasierte "AI"-Analyse
    und liefert ein Paket, das du im Frontend direkt für
    Gefährdungsbeurteilung / Unterweisung verwenden kannst.
    """
    file_id = str(uuid.uuid4())
    file_path = os.path.join(PDF_TMP_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())
    meta = extract_pdf_metadata(file_path)
    text = extract_pdf_text(file_path)
    analysis = analyze_pdf_safety(text, meta["metadata"])
    return {
        "filename": file.filename,
        "pages": meta["pages"],
        "metadata": meta["metadata"],
        "fonts_used": meta["fonts_used"],
        "analysis": analysis,
    }

# ============================================================
#  ADMIN ENDPOINTS (Backdoor-Key Header)
# ============================================================
def require_admin(backdoor_key: str = Header(None, alias="backdoor-key")):
    if not ADMIN_BACKDOOR_KEY:
        raise HTTPException(status_code=503, detail="Admin-Backdoor ist nicht konfiguriert")
    if backdoor_key != ADMIN_BACKDOOR_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

@app.get("/admin/dashboard")
def admin_dashboard(_: bool = Depends(require_admin)):
    return {
        "status": "admin-ok",
        "env": APP_ENV,
        "now": now_utc_iso(),
        "systems": {
            "smartsheet": bool(SMARTSHEET_TOKEN),
            "ai": True,
            "compliance": True,
            "training": True,
            "dsgvo": True,
            "universal": True,
            "pdf": True,
        },
    }

@app.get("/admin/audit-logs")
def admin_audit_logs(limit: int = 50, _: bool = Depends(require_admin)):
    return {"limit": limit, "logs": audit_logger.get_last(limit)}

# ============================================================
#  HEALTH / STATUS
# ============================================================
@app.get("/api/health")
def api_health():
    return {
        "status": "healthy",
        "env": APP_ENV,
        "systems": {
            "smartsheet": "✅" if SMARTSHEET_TOKEN else "⚠️",
            "ai": "✅",
            "compliance": "✅",
            "training": "✅",
            "dsgvo": "✅",
            "universal": "✅",
            "pdf": "✅",
        },
        "timestamp": now_utc_iso(),
    }

@app.get("/status")
def root_status():
    return {"status": "running"}

@app.get("/api/status")
def api_status():
    return root_status()

# ============================================================
#  LOCAL DEV ENTRYPOINT
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)
