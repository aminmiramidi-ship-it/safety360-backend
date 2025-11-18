import os
import sqlite3
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, Query
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

# Konfiguration aus Umgebungsvariablen
DB_URL = os.getenv("DATABASE_URL", "safety360.db")  # Pfad/URL der Datenbank
STRIPE_SECRET = os.getenv("STRIPE_SECRET_KEY")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_TOKEN")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

# Verschlüsselungsschlüssel einlesen oder generieren
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    # Neuen Key erzeugen, wenn keiner vorhanden oder Default ungültig
    new_key = Fernet.generate_key()
    ENCRYPTION_KEY = new_key  # bytes-Wert
    print(f"Generated ENCRYPTION_KEY: {new_key.decode()} (please store this securely)")
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()  # in bytes umwandeln, falls String

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(data: str) -> str:
    """Verschlüsselt einen Textstring und gibt Base64-Text zurück."""
    return fernet.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    """Entschlüsselt einen verschlüsselten Base64-String zurück zu Klartext."""
    return fernet.decrypt(token.encode()).decode()

# Internationalisierung: statische Texte in mehreren Sprachen
translations = {
    "en": {
        "certificate_text": lambda hazard, num: f"Certificate: Risk assessment for hazard '{hazard}' completed. {num} measures recommended."
    },
    "de": {
        "certificate_text": lambda hazard, num: f"Zertifikat: Gefährdungsbeurteilung für Gefahr '{hazard}' abgeschlossen. {num} Maßnahmen vorgeschlagen."
    }
}

# PSA-Datenbank (Beispiele) nach Branche und Tätigkeit
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

# Arbeitsmedizinische Vorsorgeuntersuchungen nach Branche (Beispiele)
HEALTH_CHECKS = {
    "construction": ["G41 (Working at Heights exam)", "G20 (Noise exposure exam)"],
    "laboratory": ["G42 (Chemical exposure exam)", "G37 (Screen work exam)"]
}

# Pydantic Models für Request-Bodies
class TicketCreate(BaseModel):
    description: str
    status: Optional[str] = "open"

class ExportData(BaseModel):
    lines: List[str]

# FastAPI-App initialisieren
app = FastAPI(title="Safety360 API", version="1.0")

# CORS freischalten (für alle Origins - in Produktion ggf. einschränken)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Datenbankverbindung herstellen (SQLite genutzt als Beispiel)
conn = sqlite3.connect(DB_URL, check_same_thread=False)
cursor = conn.cursor()
# Wichtige Tabellen erzeugen (Tickets, Audit-Log etc.)
cursor.execute("""CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    description TEXT,
    status TEXT
)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    event TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
conn.commit()

# Endpoints Definitionen:

@app.get("/psa")
def get_psa(industry: str, activity: str):
    """Empfiehlt PSA und Vorschriften für eine gegebene Branche und Tätigkeit."""
    ind = industry.lower()
    act = activity.lower()
    if ind in PSA_DATA and act in PSA_DATA[ind]:
        data = PSA_DATA[ind][act]
        return {"industry": ind, "activity": act, 
                "equipment": data["equipment"], "regulations": data["regulations"]}
    else:
        raise HTTPException(status_code=404, detail="No PSA data for this industry/activity combination.")

@app.get("/health-checks")
def get_health_checks(industry: str):
    """Listet erforderliche Vorsorgeuntersuchungen für eine Branche auf."""
    ind = industry.lower()
    checks = HEALTH_CHECKS.get(ind)
    if checks:
        return {"industry": ind, "required_examinations": checks}
    else:
        raise HTTPException(status_code=404, detail="No health check data for this industry.")

@app.post("/riskassessment")
def create_risk_assessment(hazard: str, use_ai: bool = True, lang: str = "de"):
    """
    Erstellt eine Gefährdungsbeurteilung für die angegebene Gefahr:
    - optional mit KI-Vorschlägen für Schutzmaßnahmen,
    - generiert einen Zertifikatstext (mehrsprachig) als Ergebnis.
    """
    measures: List[str] = []
    # KI-Vorschläge einholen (OpenAI), falls gewünscht und Key vorhanden
    if use_ai and OPENAI_KEY:
        import openai  # OpenAI-Paket muss installiert sein
        openai.api_key = OPENAI_KEY
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": f"Suggest safety measures for the hazard: {hazard}"}]
        )
        suggestion_text = response.choices[0].message.content if response.choices else ""
        # Auftrennen der KI-Antwort in einzelne Maßnahmen (nach Zeilenumbrüchen)
        measures = [m.strip() for m in suggestion_text.split("\n") if m.strip()]
    else:
        # Fallback: einfache regelbasierte Vorschläge aus PSA_DATA
        for ind, activities in PSA_DATA.items():
            for act, data in activities.items():
                if act in hazard.lower() or hazard.lower() in act:
                    measures.extend([f"Use {eq}" for eq in data["equipment"]])

    # Zertifikatstext je nach Sprache generieren
    if lang not in translations:
        lang = "de"
    cert_text = translations[lang]["certificate_text"](hazard, len(measures))
    # **Hier** könnte die PDF-Erzeugung des Zertifikats erfolgen (siehe /export/pdf)
    # und das Ergebnis gespeichert oder zurückgegeben werden. 
    # Fürs Erste geben wir den Text und die Maßnahmen zurück:
    return {"hazard": hazard, "measures": measures, "certificate_text": cert_text}

@app.post("/tickets")
def create_ticket(ticket: TicketCreate):
    """Erstellt ein neues Ticket und protokolliert es im Audit-Trail."""
    # Beschreibung verschlüsseln bevor sie in die DB kommt
    desc_enc = encrypt(ticket.description)
    status = ticket.status or "open"
    cursor.execute("INSERT INTO tickets (description, status) VALUES (?, ?)", (desc_enc, status))
    conn.commit()
    ticket_id = cursor.lastrowid
    # Audit-Log Eintrag
    cursor.execute("INSERT INTO audit_log (event) VALUES (?)", (f"Ticket {ticket_id} created",))
    conn.commit()
    return {"ticket_id": ticket_id, "status": status}

@app.get("/tickets")
def list_tickets():
    """Listet alle Tickets (Admin-Sicht) mit Entschlüsselung der Beschreibung."""
    cursor.execute("SELECT id, description, status FROM tickets")
    rows = cursor.fetchall()
    tickets = []
    for tid, desc_enc, status in rows:
        try:
            desc = decrypt(desc_enc)
        except Exception:
            desc = "(unencrypted) " + desc_enc  # Falls ältere Einträge noch Klartext enthalten
        tickets.append({"id": tid, "description": desc, "status": status})
    return {"tickets": tickets}

@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, status: str):
    """Aktualisiert den Status eines Tickets und loggt die Änderung."""
    cursor.execute("UPDATE tickets SET status=? WHERE id=?", (status, ticket_id))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Ticket not found")
    conn.commit()
    # Änderung im Audit-Trail festhalten
    cursor.execute("INSERT INTO audit_log (event) VALUES (?)", (f"Ticket {ticket_id} status changed to {status}",))
    conn.commit()
    return {"ticket_id": ticket_id, "new_status": status}

@app.post("/export/pdf")
def export_to_pdf(data: ExportData):
    """Erstellt eine PDF-Datei aus den gelieferten Zeilen und gibt sie als Download zurück."""
    from fpdf import FPDF  # fpdf Bibliothek zur PDF-Erstellung
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
    """Erstellt ein Word-Dokument aus den gelieferten Zeilen und gibt es zurück."""
    from docx import Document  # python-docx Bibliothek zur Word-Datei-Erstellung
    doc = Document()
    for line in data.lines:
        doc.add_paragraph(line)
    filename = "export.docx"
    doc.save(filename)
    return FileResponse(filename, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename=filename)

@app.post("/export/smartsheet")
def export_to_smartsheet(sheet_data: dict):
    """Überträgt Daten via API an ein konfiguriertes Smartsheet."""
    if not SMARTSHEET_TOKEN or not SMARTSHEET_SHEET_ID:
        raise HTTPException(status_code=500, detail="Smartsheet integration not configured.")
    import requests
    url = f"https://api.smartsheet.com/2.0/sheets/{SMARTSHEET_SHEET_ID}/rows"
    headers = {"Authorization": f"Bearer {SMARTSHEET_TOKEN}"}
    response = requests.post(url, headers=headers, json=sheet_data)
    if response.status_code >= 400:
        # Fehlerdetails zurückgeben, falls API-Call fehlschlägt
        raise HTTPException(status_code=response.status_code, detail=response.text)
    return {"status": "success"}

@app.post("/import")
async def import_data(file: UploadFile = File(...)):
    """Liest eine hochgeladene PDF- oder Bilddatei aus und gibt den extrahierten Text zurück."""
    import io
    data = await file.read()
    text_content = ""
    if file.content_type == "application/pdf":
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(data)) as pdf:
                for page in pdf.pages:
                    text_content += page.extract_text() or ""
        except Exception as e:
            # Wenn reiner Scan-PDF: OCR als Fallback
            try:
                from pdf2image import convert_from_bytes
                import pytesseract
                images = convert_from_bytes(data)
                for img in images:
                    text_content += pytesseract.image_to_string(img)
            except Exception as e2:
                raise HTTPException(status_code=500, detail=f"PDF text extraction failed: {e2}")
    else:
        try:
            from PIL import Image
            import pytesseract
            image = Image.open(io.BytesIO(data))
            text_content = pytesseract.image_to_string(image)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OCR failed: {e}")
    return {"extracted_text": text_content}

@app.get("/admin/inspect-db")
def admin_inspect_db(token: str):
    """Admin-Endpoint: Listet vorhandene Tabellen der Datenbank (Backdoor/Diagnose)."""
    if token != ADMIN_TOKEN or not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    return {"tables": tables}

@app.get("/admin/audit-log")
def get_audit_log(token: str):
    """Admin-Endpoint: Gibt die Audit-Trail-Ereignisse zurück."""
    if token != ADMIN_TOKEN or not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")
    cursor.execute("SELECT timestamp, event FROM audit_log ORDER BY timestamp DESC")
    logs = [{"timestamp": ts, "event": ev} for (ts, ev) in cursor.fetchall()]
    return {"audit_log": logs}

@app.websocket("/ws/collaborate")
async def collaborate_ws(websocket: WebSocket):
    """WebSocket für Live-Zusammenarbeit (Platzhalter-Implementierung)."""
    await websocket.accept()
    await websocket.send_text("Collaboration session established.")
    # Weitere Nachrichtenbehandlung und Broadcast an andere Clients würde hier erfolgen.

# Optional: Uvicorn Start (falls nicht über Render automatisch gestartet)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
