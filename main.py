"""
Unified Enterprise Automation System – Version 3
7+ Systeme in einer FastAPI-App.

Integriert:
- Smartsheet + n8n (Stub)
- AI / Self-Learning (Stub)
- Compliance
- Training Management
- DSGVO / Encryption / Audit
- Universal Multi-Sector
- PDF Processing + Offline-"AI"-Analyse
- Admin Backdoor Endpoint (Header-Key)
"""

import os
import uuid
import json
import sqlite3
import datetime as dt
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from dotenv import load_dotenv
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import fitz  # PyMuPDF


# ============================================================
# ENV VARS
# ============================================================
load_dotenv()

APP_ENV = os.getenv("FLASK_ENV", "production")

ENCRYPTION_MASTER_KEY = os.getenv("ENCRYPTION_KEY", "")
ADMIN_BACKDOOR_KEY = os.getenv("ADMIN_BACKDOOR_KEY", "")

SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_API_TOKEN", "")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID", "")
N8N_BASE_URL = os.getenv("N8N_BASE_URL", "")
N8N_API_KEY = os.getenv("N8N_API_KEY", "")

PDF_TMP_DIR = "/tmp/pdf_uploads"
os.makedirs(PDF_TMP_DIR, exist_ok=True)

AUDIT_DB_PATH = os.getenv("AUDIT_DB_PATH", "audit_logs.db")


# ============================================================
# FASTAPI INIT
# ============================================================
app = FastAPI(
    title="Unified Enterprise Automation System – V3",
    version="3.0.0",
    description="All-in-One Enterprise Architecture: AI • DSGVO • PDF Analyse • Compliance • Training • Smartsheet • Universal",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# ============================================================
# UTILS
# ============================================================
def now_utc_iso():
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


# ============================================================
# ENCRYPTION (DSGVO)
# ============================================================
def _fernet_from_pbkdf2(master_key: bytes, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=120_000,
        backend=default_backend(),
    )
    key = kdf.derive(master_key)
    return Fernet(base64.urlsafe_b64encode(key))


class SimpleEncryptionManager:
    def __init__(self, master_key: str):
        if len(master_key) < 32:
            raise ValueError("ENCRYPTION_KEY must be at least 32 chars for security")
        self.master_key = master_key.encode()

    def encrypt(self, data: Any) -> str:
        if not isinstance(data, str):
            data = json.dumps(data, ensure_ascii=False)

        salt = os.urandom(16)
        fernet = _fernet_from_pbkdf2(self.master_key, salt)
        token = fernet.encrypt(data.encode())
        return (salt + token).hex()

    def decrypt(self, hex_data: str) -> str:
        raw = bytes.fromhex(hex_data)
        salt, token = raw[:16], raw[16:]
        fernet = _fernet_from_pbkdf2(self.master_key, salt)
        return fernet.decrypt(token).decode()


encryption = SimpleEncryptionManager(ENCRYPTION_MASTER_KEY)


# ============================================================
# AUDIT LOGGER (SQLite)
# ============================================================
class AuditLogger:
    def __init__(self, path):
        self.path = path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs(
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                user_id TEXT,
                action TEXT,
                object_type TEXT,
                object_id TEXT,
                details TEXT
            )
        """
        )
        conn.commit()
        conn.close()

    def log(self, *, user_id, action, object_type=None, object_id=None, details=None):
        log_id = str(uuid.uuid4())
        conn = sqlite3.connect(self.path)
        conn.execute(
            "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
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

    def get(self, object_id):
        conn = sqlite3.connect(self.path)
        rows = conn.execute(
            "SELECT id, timestamp, user_id, action, object_type, object_id, details "
            "FROM audit_logs WHERE object_id=? ORDER BY timestamp",
            (object_id,),
        ).fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "user_id": r[2],
                "action": r[3],
                "object_type": r[4],
                "object_id": r[5],
                "details": json.loads(r[6]),
            }
            for r in rows
        ]


audit_logger = AuditLogger(AUDIT_DB_PATH)


# ============================================================
# MODELS
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
    severity: float = Field(..., ge=0, le=1)


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


class DsgvoLogModificationRequest(DsgvoLogAccessRequest):
    changes: Dict[str, Any]


class UniversalRecommendationsRequest(BaseModel):
    company_name: str
    industry_sector: str
    num_employees: int


# ============================================================
# SYSTEM 0: ADMIN BACKDOOR (Header)
# ============================================================
@app.get("/admin/dashboard")
def admin_dashboard(backdoor_key: str = Header(None)):
    if backdoor_key != ADMIN_BACKDOOR_KEY:
        raise HTTPException(401, "Unauthorized – invalid admin key")

    return {
        "status": "ADMIN ACCESS GRANTED",
        "timestamp": now_utc_iso(),
        "environment": APP_ENV,
        "audit_entries": len(audit_logger.get("ALL")),
    }


# ============================================================
# SYSTEM 1: SMARTSHEET (Stub)
# ============================================================
@app.post("/api/smartsheet/create-row")
def create_row(payload: SmartsheetRow):
    if not SMARTSHEET_TOKEN:
        raise HTTPException(503, "Smartsheet not configured")

    row_id = str(uuid.uuid4())
    audit_logger.log(
        user_id="system",
        action="smartsheet_create_row",
        object_type="smartsheet_row",
        object_id=row_id,
        details=payload.data,
    )
    return {"row_id": row_id, "data": payload.data}


# ============================================================
# SYSTEM 2: AI
# ============================================================
@app.post("/api/ai/optimize")
def ai_optimize(payload: AiOptimizeRequest):
    audit_logger.log(
        user_id="system",
        action="ai_optimize",
        details=payload.dict(),
    )
    return {
        "objective": payload.objective,
        "suggested_actions": [
            "increase_training_quality",
            "improve_documentation",
        ],
    }


# ============================================================
# SYSTEM 3: COMPLIANCE
# ============================================================
@app.post("/api/compliance/check")
def compliance_check(payload: ComplianceCheckRequest):
    audit_logger.log(
        user_id="system",
        action="compliance_check",
        object_type="company",
        object_id=payload.company_id,
        details={"standards": payload.standards},
    )
    return {"company_id": payload.company_id, "score": 82, "status": "in_progress"}


# ============================================================
# SYSTEM 4: TRAINING
# ============================================================
@app.post("/api/training/generate-all")
def training(payload: TrainingGenerateAllRequest):
    hazard_score = (
        sum(h.severity for h in payload.hazards) / len(payload.hazards)
        if payload.hazards
        else 0
    )
    return {
        "risk_score": hazard_score,
        "unterweisung": ["Einführung", "Gefahren", "Notfälle"],
        "prüfung": [{"q": "PSA Pflicht?", "correct": "Ja"}],
        "betriebsanweisung": f"BA für {payload.equipment_name}",
    }


# ============================================================
# SYSTEM 5: DSGVO
# ============================================================
@app.post("/api/dsgvo/encrypt")
def dsgvo_encrypt(payload: DsgvoEncryptRequest):
    return {"encrypted": encryption.encrypt(payload.data)}


@app.post("/api/dsgvo/decrypt")
def dsgvo_decrypt(payload: DsgvoDecryptRequest):
    decrypted = encryption.decrypt(payload.encrypted)
    try:
        return {"data": json.loads(decrypted)}
    except:
        return {"data": decrypted}


@app.get("/api/dsgvo/audit/{object_id}")
def audit(object_id: str):
    return {"object_id": object_id, "entries": audit_logger.get(object_id)}


# ============================================================
# SYSTEM 6: UNIVERSAL MULTI-SECTOR
# ============================================================
@app.post("/api/universal/recommendations")
def universal(payload: UniversalRecommendationsRequest):
    return {
        "company": payload.company_name,
        "sector": payload.industry_sector,
        "recommended_standards": ["ISO 45001", "ISO 9001"],
        "recommended_bg": "BG Bau" if "bau" in payload.industry_sector.lower() else "BG Allgemein",
    }


# ============================================================
# SYSTEM 7: PDF (Metadata + Text + offline AI Analyse)
# ============================================================
def extract_pdf_metadata(path: str):
    doc = fitz.open(path)
    metadata = doc.metadata
    pages = len(doc)
    fonts = set()

    for page in doc:
        blocks = page.get_text("dict").get("blocks", [])
        for b in blocks:
            for line in b.get("lines", []):
                for span in line.get("spans", []):
                    if "font" in span:
                        fonts.add(span["font"])

    doc.close()
    return {"metadata": metadata, "pages": pages, "fonts": sorted(list(fonts))}


def extract_pdf_text(path: str):
    doc = fitz.open(path)
    text = "\n".join([p.get_text() for p in doc])
    doc.close()
    return text


def analyze_pdf(text: str, metadata: dict):
    text_low = text.lower()
    hazards = []

    def add(key, cat, sev, rec):
        hazards.append({"keyword": key, "category": cat, "severity": sev, "recommendation": rec})

    if "chem" in text_low:
        add("Chemikalien", "chemisch", 0.8, "Gefahrstoffunterweisung benötigt")

    if "maschine" in text_low:
        add("Maschine", "mechanisch", 0.7, "Schutzmaßnahmen prüfen")

    if not hazards:
        add("Allgemein", "basic", 0.3, "Prüfung der Dokumente empfohlen")

    return {"hazards": hazards, "max_severity": max(h["severity"] for h in hazards)}


@app.post("/api/pdf/analyze")
async def pdf_upload(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    path = os.path.join(PDF_TMP_DIR, f"{file_id}_{file.filename}")

    with open(path, "wb") as f:
        f.write(await file.read())

    meta = extract_pdf_metadata(path)
    text = extract_pdf_text(path)
    analysis = analyze_pdf(text, meta["metadata"])

    return {
        "file": file.filename,
        "metadata": meta["metadata"],
        "pages": meta["pages"],
        "fonts": meta["fonts"],
        "analysis": analysis,
        "text_length": len(text),
    }


# ============================================================
# STATUS
# ============================================================
@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "environment": APP_ENV,
        "timestamp": now_utc_iso(),
        "systems": ["smartsheet", "ai", "training", "compliance", "dsgvo", "pdf", "universal"],
    }


# ============================================================
# LOCAL DEV
# ============================================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
