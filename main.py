import os
import sqlite3
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet

# -------------------------------------------------------
# .env laden (lokal)
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

# Root Endpoint für Render Health Checks
@app.get("/")
def root():
    return {"status": "ok", "message": "Safety360 Backend läuft"}

# -------------------------------------------------------
# Umgebungsvariablen
# -------------------------------------------------------
DB_URL = os.getenv("DATABASE_URL", "safety360.db")
STRIPE_SECRET = os.getenv("STRIPE_SECRET_KEY")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_TOKEN")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# -------------------------------------------------------
# Verschlüsselung
# -------------------------------------------------------
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    new_key = Fernet.generate_key()
    ENCRYPTION_KEY = new_key
    print(f"Generated ENCRYPTION_KEY: {new_key.decode()} (store securely)")
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# -------------------------------------------------------
# PSA + Vorsorge
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
    "en": {
        "certificate_text": lambda hazard, num:
            f"Certificate: Risk assessment for hazard '{hazard}' completed. {num} measures recommended."
    },
    "de": {
        "certificate_text": lambda hazard, num:
            f"Zertifikat: Gefährdungsbeurteilung für Gefahr '{hazard}' abgeschlossen. {num} Maßnahmen vorgeschlagen."
    }
}

# -------------------------------------------------------
# Models
# -------------------------------------------------------
class TicketCreate(BaseModel):
    description: str
    status: Optional[str] = "open"

class ExportData(BaseModel):
    lines: List[str]

# -------------------------------------------------------
# CORS
# -------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------
# SQLite DB initialisieren
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

conn.commit()

# -------------------------------------------------------
# ENDPOINTS
# -------------------------------------------------------

@app.get("/psa")
def get_psa(industry: str, activity: str):
    ind = industry.lower()
    act = activity.lower()
    if ind in PSA_DATA and act in PSA_DATA[ind]:
        return {
            "industry": ind,
            "activity": act,
            "equipment": PSA_DATA[ind][act]["equipment"],
            "regulations": PSA_DATA[ind][act]["regulations"]
        }
    raise HTTPException(status_code=404, detail="No PSA data found.")

@app.get("/health-checks")
def get_health_checks(industry: str):
    ind = industry.lower()
    if ind in HEALTH_CHECKS:
        return {"industry": ind, "required_examinations": HEALTH_CHECKS[ind]}
    raise HTTPException(status_code=404, detail="No health check data found.")

@app.post("/riskassessment")
def create_risk_assessment(hazard: str, use_ai: bool = True, lang: str = "de"):
    measures: List[str] = []

    if use_ai and OPENAI_KEY:
        import openai
        openai.api_key = OPENAI_KEY
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": f"Suggest safety measures for: {hazard}"}]
        )
        suggestion_text = response.choices[0].message.content
        measures = [m.strip() for m in suggestion_text.split("\n") if m.strip()]
    else:
        for ind, acts in PSA_DATA.items():
            for act, data in acts.items():
                if act in hazard.lower():
                    measures.extend([f"Use {eq}" for eq in data["equipment"]])

    if lang not in translations:
        lang = "de"

    cert_text = translations[lang]["certificate_text"](hazard, len(measures))

    return {"hazard": hazard, "measures": measures, "certificate_text": cert_text}

@app.post("/tickets")
def create_ticket(ticket: TicketCreate):
    desc_enc = encrypt(ticket.description)
    status = ticket.status or "open"
    cursor.execute("INSERT INTO tickets (description, status) VALUES (?, ?)", (desc_enc, status))
    conn.commit()
    ticket_id = cursor.lastrowid
    cursor.execute("INSERT INTO audit_log (event) VALUES (?)", (f"Ticket {ticket_id} created",))
    conn.commit()
    return {"ticket_id": ticket_id, "status": status}

@app.get("/tickets")
def list_tickets():
    cursor.execute("SELECT id, description, status FROM tickets")
    rows = cursor.fetchall()
    result = []
    for tid, desc_enc, status in rows:
        try:
            desc = decrypt(desc_enc)
        except:
            desc = "(unencrypted) " + desc_enc
        result.append({"id": tid, "description": desc, "status": status})
    return {"tickets": result}

@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, status: str):
    cursor.execute("UPDATE tickets SET status=? WHERE id=?", (status, ticket_id))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Ticket not found")
    conn.commit()
    cursor.execute("INSERT INTO audit_log (event) VALUES (?)", (f"Ticket {ticket_id} status changed to {status}",))
    conn.commit()
    return {"ticket_id": ticket_id, "new_status": status}

@app.post("/export/pdf")
def export_to_pdf(data: ExportData):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in data.lines:
        pdf.cell(200, 10, txt=line, ln=True)
    filename = "export.pdf"
    pdf.output(filename)
    return FileResponse(filename, media_type="application/pdf", filename=filename)

@app.post("/export/word")
def export_to_word(data: ExportData):
    from docx import Document
    doc = Document()
    for line in data.lines:
        doc.add_paragraph(line)
    filename = "export.docx"
    doc.save(filename)
    return FileResponse(filename, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename=filename)

@app.post("/export/smartsheet")
def export_to_smartsheet(sheet_data: dict):
    if not SMARTSHEET_TOKEN or not SMARTSHEET_SHEET_ID:
        raise HTTPException(status_code=500, detail="Smartsheet integration not configured.")

    import requests
    url = f"https://api.smartsheet.com/2.0/sheets/{SMARTSHEET_SHEET_ID}/rows"
    headers = {"Authorization": f"Bearer {SMARTSHEET_TOKEN}"}
    response = requests.post(url, headers=headers, json=sheet_data)

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return {"status": "success"}

# -------------------------------------------------------
# WICHTIG: OCR komplett entfernt (Render-kompatible Version)
# -------------------------------------------------------
@app.post("/import")
async def import_data(file: UploadFile = File(...)):
    """Nur Text-PDFs werden unterstützt. OCR nicht verfügbar."""
    import io
    data = await file.read()

    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Bitte eine PDF-Datei hochladen.")

    try:
        import pdfplumber
        text = ""
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""
        return {"extracted_text": text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF extraction failed: {e}")

# -------------------------------------------------------
# Admin
# -------------------------------------------------------
@app.get("/admin/inspect-db")
def admin_inspect_db(token: str):
    if token != ADMIN_TOKEN or not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {"tables": [row[0] for row in cursor.fetchall()]}

@app.get("/admin/audit-log")
def get_audit_log(token: str):
    if token != ADMIN_TOKEN or not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    cursor.execute("SELECT timestamp, event FROM audit_log ORDER BY timestamp DESC")
    return {"audit_log": [{"timestamp": ts, "event": ev} for ts, ev in cursor.fetchall()]}

# -------------------------------------------------------
# WebSocket
# -------------------------------------------------------
@app.websocket("/ws/collaborate")
async def collaborate_ws(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Collaboration session established.")

# -------------------------------------------------------
# Lokaler Start
# -------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
