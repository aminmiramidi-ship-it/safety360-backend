import os
import sqlite3
from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet
import bcrypt
import jwt

# -------------------------------------------------------
# .env laden
# -------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# -------------------------------------------------------
# FastAPI App
# -------------------------------------------------------
app = FastAPI(title="Safety360 API", version="1.0")


@app.get("/")
def root():
    return {"status": "ok", "message": "Safety360 Backend läuft"}


# -------------------------------------------------------
# ENV Variablen
# -------------------------------------------------------
DB_URL = os.getenv("DATABASE_URL", "safety360.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_TOKEN")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID")

JWT_SECRET = os.getenv("JWT_SECRET", "supersecret123")
JWT_ALGO = "HS256"

# -------------------------------------------------------
# Verschlüsselung
# -------------------------------------------------------
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY or len(str(ENCRYPTION_KEY)) < 10:
    new_key = Fernet.generate_key()
    ENCRYPTION_KEY = new_key
    print("NEW ENCRYPTION KEY GENERATED:", new_key.decode())
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)


def encrypt(x: str) -> str:
    return fernet.encrypt(x.encode()).decode()


def decrypt(x: str) -> str:
    return fernet.decrypt(x.encode()).decode()


# -------------------------------------------------------
# CORS
# -------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# -------------------------------------------------------
# SQLite DB Init
# -------------------------------------------------------
conn = sqlite3.connect(DB_URL, check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    description TEXT,
    status TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    event TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()

# -------------------------------------------------------
# PSA + HealthChecks
# -------------------------------------------------------
PSA_DATA = {
    "construction": {
        "working at heights": {
            "equipment": ["Safety harness", "Hard hat", "Lanyard"],
            "regulations": ["DGUV Regel 112-198", "ArbSchG §5"]
        },
        "noise intensive work": {
            "equipment": ["Ear protection", "Noise-cancelling helmet"],
            "regulations": ["LärmVibrationsArbSchV", "DGUV Vorschrift 3"]
        }
    },
    "laboratory": {
        "chemical handling": {
            "equipment": ["Chemical-resistant gloves", "Safety goggles", "Lab coat"],
            "regulations": ["GefStoffV", "TRGS 526"]
        }
    }
}

HEALTH_CHECKS = {
    "construction": ["G41 (Working at Heights exam)", "G20 (Noise exposure exam)"],
    "laboratory": ["G42 (Chemical exposure exam)", "G37 (Screen work exam)"]
}

translations = {
    "en": {"certificate_text": lambda hazard, num: f"Certificate for '{hazard}' – {num} measures."},
    "de": {"certificate_text": lambda hazard, num: f"Zertifikat für '{hazard}' – {num} Maßnahmen."},
}

# -------------------------------------------------------
# Models
# -------------------------------------------------------
class TicketCreate(BaseModel):
    description: str
    status: Optional[str] = "open"


class ExportData(BaseModel):
    lines: List[str]


class AuthRegister(BaseModel):
    email: str
    password: str


class AuthLogin(BaseModel):
    email: str
    password: str


# -------------------------------------------------------
# JWT
# -------------------------------------------------------
def create_jwt(user_id: int):
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except:
        return None


# -------------------------------------------------------
# AUTH - REGISTER
# -------------------------------------------------------
@app.post("/auth/register")
def register_user(data: AuthRegister):
    cursor.execute("SELECT id FROM users WHERE email=?", (data.email,))
    if cursor.fetchone():
        raise HTTPException(400, "User already exists")

    pw_hash = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

    cursor.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (data.email, pw_hash)
    )
    conn.commit()

    return {"status": "ok", "message": "user created"}


# -------------------------------------------------------
# AUTH - LOGIN
# -------------------------------------------------------
@app.post("/auth/login")
def login(data: AuthLogin):
    cursor.execute("SELECT id, password_hash FROM users WHERE email=?", (data.email,))
    u = cursor.fetchone()
    if not u:
        raise HTTPException(401, "Invalid credentials")

    user_id, pw_hash = u

    if not bcrypt.checkpw(data.password.encode(), pw_hash.encode()):
        raise HTTPException(401, "Invalid credentials")

    token = create_jwt(user_id)

    return {"access_token": token, "token_type": "bearer"}


# -------------------------------------------------------
# AUTH - ME
# -------------------------------------------------------
@app.get("/auth/me")
def auth_me(token: str):
    payload = decode_jwt(token)
    if not payload:
        raise HTTPException(401, "Invalid token")

    user_id = payload["sub"]

    cursor.execute("SELECT id, email, created_at FROM users WHERE id=?", (user_id,))
    u = cursor.fetchone()

    return {"id": u[0], "email": u[1], "created_at": u[2]}


# -------------------------------------------------------
# PSA Endpoint
# -------------------------------------------------------
@app.get("/psa")
def get_psa(industry: str, activity: str):
    ind = industry.lower()
    act = activity.lower()
    if ind in PSA_DATA and act in PSA_DATA[ind]:
        return PSA_DATA[ind][act]
    raise HTTPException(404, "No PSA data")


# -------------------------------------------------------
# Healthchecks
# -------------------------------------------------------
@app.get("/health-checks")
def get_health_checks(industry: str):
    ind = industry.lower()
    if ind in HEALTH_CHECKS:
        return {"industry": ind, "required_examinations": HEALTH_CHECKS[ind]}
    raise HTTPException(404, "No health check data")


# -------------------------------------------------------
# Risk Assessment
# -------------------------------------------------------
@app.post("/riskassessment")
def create_risk_assessment(hazard: str, lang: str = "de"):
    measures = []

    for ind, acts in PSA_DATA.items():
        for act, data in acts.items():
            if act in hazard.lower():
                measures.extend([f"Use {x}" for x in data["equipment"]])

    if lang not in translations:
        lang = "de"

    cert = translations[lang]["certificate_text"](hazard, len(measures))

    return {"hazard": hazard, "measures": measures, "certificate_text": cert}


# -------------------------------------------------------
# Tickets
# -------------------------------------------------------
@app.post("/tickets")
def create_ticket(ticket: TicketCreate):
    desc_enc = encrypt(ticket.description)
    cursor.execute("INSERT INTO tickets (description, status) VALUES (?, ?)", (desc_enc, ticket.status))
    conn.commit()
    tid = cursor.lastrowid

    cursor.execute("INSERT INTO audit_log (event) VALUES (?)", (f"Ticket {tid} created",))
    conn.commit()

    return {"ticket_id": tid}


@app.get("/tickets")
def list_tickets():
    cursor.execute("SELECT id, description, status FROM tickets")
    rows = cursor.fetchall()

    out = []
    for tid, enc, st in rows:
        try:
            desc = decrypt(enc)
        except:
            desc = "(unencrypted) " + enc
        out.append({"id": tid, "description": desc, "status": st})

    return {"tickets": out}


# -------------------------------------------------------
# Export PDF
# -------------------------------------------------------
@app.post("/export/pdf")
def export_pdf(data: ExportData):
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    for line in data.lines:
        pdf.cell(200, 10, txt=line, ln=True)

    fname = "export.pdf"
    pdf.output(fname)
    return FileResponse(fname)


# -------------------------------------------------------
# Export Word
# -------------------------------------------------------
@app.post("/export/word")
def export_word(data: ExportData):
    from docx import Document

    doc = Document()
    for line in data.lines:
        doc.add_paragraph(line)

    fname = "export.docx"
    doc.save(fname)
    return FileResponse(fname)


# -------------------------------------------------------
# PDF Import
# -------------------------------------------------------
@app.post("/import")
async def import_data(file: UploadFile = File(...)):
    import pdfplumber
    import io

    data = await file.read()

    text = ""
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page in pdf.pages:
            text += page.extract_text() or ""

    return {"extracted_text": text}


# -------------------------------------------------------
# Admin
# -------------------------------------------------------
@app.get("/admin/inspect-db")
def admin_db(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(403, "Forbidden")

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {"tables": [x[0] for x in cursor.fetchall()]}


@app.get("/admin/audit-log")
def admin_logs(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(403, "Forbidden")

    cursor.execute("SELECT timestamp, event FROM audit_log ORDER BY timestamp DESC")
    return {"audit": [{"timestamp": ts, "event": ev} for ts, ev in cursor.fetchall()]}


# -------------------------------------------------------
# WebSocket
# -------------------------------------------------------
@app.websocket("/ws/collaborate")
async def ws(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("WebSocket OK")


# -------------------------------------------------------
# Local run
# -------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
