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
import fitz  # PyMuPDF


# ============================================================
#  ENV & BASIS
# ============================================================
load_dotenv()

APP_ENV = os.getenv("FLASK_ENV", "production")

ENCRYPTION_MASTER_KEY = os.getenv("ENCRYPTION_KEY", "")
ADMIN_BACKDOOR_KEY = os.getenv("ADMIN_BACKDOOR_KEY", "")

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
    allow_origins=["*"],
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

    def log(self, *, user_id, action, object_type=None, object_id=None, details=None) -> str:
        log_id = str(uuid.uuid4())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO audit_logs (id, timestamp, user_id, action, object_type, object_id, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_id,
                now_utc_iso(),
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

    def get_trail(self, object_id: str):
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
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "user_id": r[2],
                "action": r[3],
                "object_type": r[4],
                "object_id": r[5],
                "details": json.loads(r[6] or "{}"),
            }
            for r in rows
        ]

    def get_last(self, limit: int = 50):
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
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "user_id": r[2],
                "action": r[3],
                "object_type": r[4],
                "object_id": r[5],
                "details": json.loads(r[6] or "{}"),
            }
            for r in rows
        ]


audit_logger = AuditLogger(AUDIT_DB_PATH)


# ============================================================
#  PYDANTIC MODELS
# ============================================================
class SmartsheetRow(BaseModel):
    data: Dict[str, Any]


class SmartsheetUpdateRow(BaseModel):
    row_id: str
    data: Dict[str, Any]


class AiOptimizeRequest(BaseModel):
    objective: str
    context: Optional[Dict[str, Any]] = None


class ComplianceCheckRequest(BaseModel):
    company_id: str
    standards: List[str]


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
    num_employees: int


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
#  SYSTEM 1: SMARTSHEET
# ============================================================
@app.post("/api/smartsheet/create-row")
def api_smartsheet_create_row(payload: SmartsheetRow):
    if not SMARTSHEET_TOKEN or not SMARTSHEET_SHEET_ID:
        raise HTTPException(status_code=503, detail="Smartsheet ENV fehlen")

    row_id = str(uuid.uuid4())
    audit_logger.log(
        user_id="system",
        action="smartsheet_create_row",
        object_type="smartsheet_row",
        object_id=row_id,
        details={"data": payload.data},
    )
    return {"status": "ok", "row_id": row_id, "data": payload.data}


@app.get("/api/smartsheet/get-rows")
def api_smartsheet_get_rows():
    return {
        "rows": [
            {"row_id": "ROW_1", "data": {"projectName": "Demo", "budget": 1000}}
        ]
    }


@app.post("/api/smartsheet/update-row")
def api_smartsheet_update_row(payload: SmartsheetUpdateRow):
    audit_logger.log(
        user_id="system",
        action="smartsheet_update_row",
        object_id=payload.row_id,
        details={"data": payload.data},
    )
    return {"status": "ok", "updated": payload.data}


# ============================================================
#  SYSTEM 2: AI / SELF-LEARNING
# ============================================================
@app.get("/api/ai/insights")
def api_ai_insights():
    return {
        "timestamp": now_utc_iso(),
        "insights": [
            {"metric": "training_completion_rate", "value": 0.87},
            {"metric": "compliance_score", "value": 0.82},
        ],
    }


@app.post("/api/ai/optimize")
def api_ai_optimize(payload: AiOptimizeRequest):
    audit_logger.log(
        user_id="system",
        action="ai_optimize",
        object_id=str(uuid.uuid4()),
        details={"objective": payload.objective, "context": payload.context},
    )
    return {"objective": payload.objective, "actions": ["increase_training", "review_hazards"]}


# ============================================================
#  SYSTEM 3: COMPLIANCE
# ============================================================
@app.get("/api/compliance/status")
def api_compliance_status():
    return {
        "overall_compliance_score": 85,
        "status": "mostly_compliant",
        "findings": {"critical": 0, "high": 2, "medium": 3, "low": 1},
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
    return {"company_id": payload.company_id, "score": 83, "checked": payload.standards}


# ============================================================
#  SYSTEM 4: TRAINING MANAGEMENT
# ============================================================
@app.post("/api/training/generate-all")
def api_training_generate_all(payload: TrainingGenerateAllRequest):
    risk_score = (
        sum(h.severity for h in payload.hazards) / max(len(payload.hazards), 1)
        if payload.hazards else 0.0
    )

    unterweisung = [
        {"title": "Einführung", "duration": 2},
        {"title": "Gefährdungen", "duration": 5},
        {"title": "Schutzmaßnahmen", "duration": 5},
        {"title": "Verhaltensregeln", "duration": 4},
        {"title": "Notfälle", "duration": 4},
    ]

    return {
        "risk_score": round(risk_score, 2),
        "total_hazards": len(payload.hazards),
        "unterweisung": unterweisung,
    }


# ============================================================
#  SYSTEM 5: DSGVO / ENCRYPTION / AUDIT LOGS
# ============================================================
@app.post("/api/dsgvo/encrypt")
def api_dsgvo_encrypt(req: DsgvoEncryptRequest):
    return {"encrypted": encryption.encrypt(req.data)}


@app.post("/api/dsgvo/decrypt")
def api_dsgvo_decrypt(req: DsgvoDecryptRequest):
    try:
        text = encryption.decrypt(req.encrypted)
        try:
            return {"data": json.loads(text)}
        except:
            return {"data": text}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decrypt failed: {e}")


@app.post("/api/dsgvo/log-access")
def api_dsgvo_log_access(req: DsgvoLogAccessRequest):
    log_id = audit_logger.log(
        user_id=req.user_id,
        action="access",
        object_type=req.object_type,
        object_id=req.object_id,
        details={"legal_basis": req.legal_basis, "gdpr_article": req.gdpr_article},
    )
    return {"log_id": log_id}


@app.get("/api/dsgvo/audit-trail/{object_id}")
def api_dsgvo_audit_trail(object_id: str):
    return {"trail": audit_logger.get_trail(object_id)}


# ============================================================
#  SYSTEM 6: UNIVERSAL MULTI-SECTOR
# ============================================================
SUPPORTED_SECTORS = [
    "BAUGEWERBE", "HERSTELLUNG", "LOGISTIK", "EINZELHANDEL", "GASTRONOMIE",
    "GESUNDHEIT", "LANDWIRTSCHAFT", "CHEMIE", "IT", "BÜRO", "ÖFFENTLICHE_DIENSTE",
]

@app.get("/api/universal/sectors")
def api_universal_sectors():
    return {"sectors": SUPPORTED_SECTORS}


@app.post("/api/universal/recommendations")
def api_universal_recommendations(req: UniversalRecommendationsRequest):
    sector = req.industry_sector.upper()
    bgs = ["BG Bau"] if "BAU" in sector else []
    return {
        "company": req.company_name,
        "sector": req.industry_sector,
        "bgs": bgs,
        "standards": ["ISO 45001", "ISO 9001"],
    }


# ============================================================
#  SYSTEM 7: PDF PROCESSING + RULE-BASED "AI"
# ============================================================
def extract_pdf_metadata(file_path: str):
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        raise HTTPException(500, f"PDF open error: {e}")

    metadata = doc.metadata or {}
    pages = len(doc)

    fonts = set()
    for page in doc:
        text = page.get_text("dict")
        for block in text.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    font = span.get("font")
                    if font:
                        fonts.add(font)

    doc.close()
    return {"metadata": metadata, "pages": pages, "fonts": list(fonts)}


def extract_pdf_text(file_path: str):
    try:
        doc = fitz.open(file_path)
        text = "\n".join(page.get_text() for page in doc)
        doc.close()
        return text
    except Exception as e:
        raise HTTPException(500, f"PDF text error: {e}")


def analyze_pdf_safety(text: str, metadata: dict):
    lowered = text.lower()
    hazards = []

    def add(keyword, category, severity, rec):
        hazards.append({
            "keyword": keyword, "category": category,
            "severity": severity, "recommendation": rec
        })

    if any(w in lowered for w in ["chemikalie", "säure", "lösemittel"]):
        add("Chemikalien", "chemisch", 0.8, "Gefahrstoffunterweisung durchführen")

    if any(w in lowered for w in ["maschine", "presse", "säge"]):
        add("Maschinen", "mechanisch", 0.7, "Maschinenschutz prüfen")

    if not hazards:
        add("allgemein", "unspezifisch", 0.3, "Dokument prüfen")

    return {"hazards": hazards, "metadata": metadata}


@app.post("/api/pdf/analyze")
async def api_pdf_analyze(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    path = os.path.join(PDF_TMP_DIR, f"{file_id}_{file.filename}")

    with open(path, "wb") as f:
        f.write(await file.read())

    meta = extract_pdf_metadata(path)
    text = extract_pdf_text(path)
    analysis = analyze_pdf_safety(text, meta["metadata"])

    return {"filename": file.filename, "metadata": meta, "analysis": analysis}


# ============================================================
#  ADMIN ENDPOINTS
# ============================================================
def require_admin(backdoor_key: str = Header(None, alias="backdoor-key")):
    if not ADMIN_BACKDOOR_KEY:
        raise HTTPException(503, "Admin-Backdoor-Key fehlt")
    if backdoor_key != ADMIN_BACKDOOR_KEY:
        raise HTTPException(401, "Unauthorized")
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
            "smartsheet": "OK" if SMARTSHEET_TOKEN else "NOT_CONFIGURED",
            "ai": "OK",
            "compliance": "OK",
            "training": "OK",
            "dsgvo": "OK",
            "universal": "OK",
            "pdf": "OK",
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
