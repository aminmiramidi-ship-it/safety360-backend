import os
import sqlite3
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet

# .env laden (falls lokal vorhanden)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# -------------------------------------------------------
# FastAPI App erstellen
# -------------------------------------------------------
app = FastAPI(title="Safety360 API", version="1.0")

# Root Endpoint für Health-Check / Render
@app.get("/")
def root():
    return {"status": "ok", "message": "Safety360 Backend läuft"}

# -------------------------------------------------------
# Konfiguration aus Umgebungsvariablen
# -------------------------------------------------------
DB_URL = os.getenv("DATABASE_URL", "safety360.db")
STRIPE_SECRET = os.getenv("STRIPE_SECRET_KEY")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_TOKEN")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# -------------------------------------------------------
# Verschlüsselung vorbereiten
# -------------------------------------------------------
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    new_key = Fernet.generate_key()
    ENCRYPTION_KEY = new_key
    print(f"Generated ENCRYPTION_KEY: {new_key.decode()} (please store this securely)")
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# -------------------------------------------------------
# Internationalisierung
# -------------------------------------------------------
translations = {
    "en": {
        "certificate_text": lambda hazard, num: (
            f"Certificate: Risk assessment for hazard '{hazard}' completed. "
            f"{num} measures recommended."
        )
    },
    "de": {
        "certificate_text": lambda hazard, num: (
            f"Zertifikat: Gefährdungsbeurteilung für Gefahr '{hazard}' abgeschlossen. "
            f"{num} Maßnahmen vorgeschlagen."
        )
    }
}

# -------------------------------------------------------
# PSA Daten
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

# -------------------------------------------------------
# Pydantic Models
# -------------------------------------------------------
class TicketCreate(BaseModel):
    description: str
    status: Optional[str] = "open"

class ExportData(BaseModel):
    lines: List[str]

# -------------------------------------------------------
# CORS Einstellungen
# -------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------
# Datenbank initialisieren
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
# API ENDPOINTS
# -------------------------------------------------------

# PSA
@app.get("/psa")
def get_psa(industry: str, activity: str):
    ind = industry.lower()
    act = activity.lower()
    if ind in PSA_DATA and act in PSA_DATA[ind]:
        data = PSA_DATA[ind][act]
        return {
            "industry": ind,
            "activity": act,
            "equipment": data["equipment"],
            "regulations": data["regulations"]
        }
    raise HTTPException(status_code=404, detail="No PSA data found.")

# Health Checks
@app.get("/health-checks")
def get_health_checks(industry: str):
    ind = industry.lower()
    checks = HEALTH_CHECKS.get(ind)
    if checks:
        return {"industry": ind, "required_examinations": checks}
    raise HTTPException(status_code=404, detail="No health check data found.")

# Risk Assessment
@app.post("/riskassessment")
def create_risk_assessment(hazard: str, use_ai: bool = True, lang: str = "de"):
    measures: List[str] = []

    # Optional: KI Nutzung
    if use_ai and OPENAI_KEY:
        import openai
        openai.api_key = OPENAI_KEY
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": f"Suggest safety measures for hazard: {hazard}"}
            ]
        )
        suggestion_text = response.choices[0].message.content
        measures = [m.strip() for m in suggestion_text.split("\n") if m.strip()]
    else:
        # Fallback
        for ind, acts in PSA_DATA.items():
            for act, data in acts.items():
                if act in hazard.lower():
                    measures.extend([f"Use {eq}" for eq in data["equipment"]])

    # Zertifikatstext
    if lang not in translations:
        lang = "de"
    cert_text = translations[lang]["certificate_text"](hazard, len(measures))

    return {
        "hazard": hazard,
        "measures": measures,
        "certificate_text": cert_text
    }

# Tickets
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
    tickets = []
    for tid, desc_enc, status in rows:
        try:
            desc = decrypt(desc_enc)
        except Exception:
            desc = "(unencrypted) " + desc_enc
        tickets.append({"id": tid, "description": desc, "status": status})
    return {"tickets": tickets}

@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, status: str):
    cursor.execute("UPDATE tickets SET status=? WHERE id=?", (status, ticket_id))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Ticket not found")
    conn.commit()
    cursor.execute("INSERT INTO audit_log (event) VALUES (?)", (f"Ticket {ticket_id} status changed to {status}",))
    conn.commit()
    return {"ticket_id": ticket_id, "new_status": status}

# PDF Export
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

# Word Export
@app.post("/export/word")
def export_to_word(data: ExportData):
    from docx import Document
    doc = Document()
    for line in data.lines:
        doc.add_paragraph(line)

    filename = "export.docx"
    doc.save(filename)
    return FileResponse(filename, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename=filename)

# Smartsheet
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

# Import / OCR
@app.post("/import")
async def import_data(file: UploadFile = File(...)):
    import io
    data = await file.read()
    text_content = ""

    if file.content_type == "application/pdf":
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(data)) as pdf:
                for page in pdf.pages:
                    text = page.extract_text() or ""
                    text_content += text
        except Exception:
            try:
                from pdf2image import convert_from_bytes
                import pytesseract
                images = convert_from_bytes(data)
                for img in images:
                    text_content += pytesseract.image_to_string(img)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"PDF text extraction failed: {e}")
    else:
        try:
            from PIL import Image
            import pytesseract
            image = Image.open(io.BytesIO(data))
            text_content = pytesseract.image_to_string(image)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OCR failed: {e}")

    return {"extracted_text": text_content}

# Admin Endpoints
@app.get("/admin/inspect-db")
def admin_inspect_db(token: str):
    if token != ADMIN_TOKEN or not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    return {"tables": tables}

@app.get("/admin/audit-log")
def get_audit_log(token: str):
    if token != ADMIN_TOKEN or not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    cursor.execute("SELECT timestamp, event FROM audit_log ORDER BY timestamp DESC")
    return {"audit_log": [{"timestamp": ts, "event": ev} for ts, ev in cursor.fetchall()]}

# WebSocket
@app.websocket("/ws/collaborate")
async def collaborate_ws(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Collaboration session established.")

# Lokaler Start (optional)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
