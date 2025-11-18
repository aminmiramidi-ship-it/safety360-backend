import os
import sqlite3
import uuid
from typing import List, Optional, Dict
from enum import Enum

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet

# === .env laden ===
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DB_URL = os.getenv("DATABASE_URL", "safety360.db")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"Generated ENCRYPTION_KEY: {ENCRYPTION_KEY.decode()} (please store securely)")
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()
fernet = Fernet(ENCRYPTION_KEY)

def encrypt(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()
def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# === FastAPI & CORS ===
app = FastAPI(title="Safety360 API", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# === Datenbank ===
conn = sqlite3.connect(DB_URL, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY, description TEXT, status TEXT
)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY, event TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
conn.commit()

# === Internationalisierung ===
translations = {
    "en": {
        "certificate_text": lambda hazard, num: f"Certificate: Risk assessment for hazard '{hazard}' completed. {num} measures recommended."
    },
    "de": {
        "certificate_text": lambda hazard, num: f"Zertifikat: Gefährdungsbeurteilung für Gefahr '{hazard}' abgeschlossen. {num} Maßnahmen vorgeschlagen."
    }
}

# --- KI-basierte NOHL Risikoampel ---
class RiskColor(str, Enum):
    RED = "ROT"
    YELLOW = "GELB"
    GREEN = "GRUEN"
def nohl_risikoampel(E: int, S: int, H: int = 1):
    risiko = E * S * H
    if risiko >= 5: return {"score": risiko, "ampel": RiskColor.RED, "hinweis": "Hohes Risiko: Sofort handeln!"}
    elif risiko >= 3: return {"score": risiko, "ampel": RiskColor.YELLOW, "hinweis": "Mittleres Risiko: Maßnahmen zeitnah umsetzen."}
    else: return {"score": risiko, "ampel": RiskColor.GREEN, "hinweis": "Akzeptabel, weiter überwachen."}

@app.post("/api/risk/ampel")
def api_nohl(E: int, S: int, H: int = 1):
    return nohl_risikoampel(E, S, H)

# --- PSA/Branchen/Checklisten ---
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

# --- Branchen/Normen-Baukasten ---
BRANCHEN_KATALOG = {
    "Bau": {
        "Tätigkeiten": ["Gerüstbau", "Hochbau", "Abbruch"],
        "Risiken": [
            {"hazard": "Absturz", "gesetz": "DGUV, BetrSichV", "psa": ["Auffanggurt", "Helm"], "ki": "Gerüstkontrolle, Absturzsicherung"},
            {"hazard": "Staub/Asbest", "gesetz": "GefStoffV, TRGS 519", "psa": ["FFP3"], "ki": "Staubarme Verfahren, Schutzkleidung"}
        ]
    },
    "Elektro": {
        "Tätigkeiten": ["Installation", "Wartung", "Prüfung"],
        "Risiken": [
            {"hazard": "Elektrischer Schlag", "gesetz": "DGUV V3, VDE 0105-100", "psa": ["Isolierhandschuhe", "Arc-Flash-Schutz"], "ki": "5 Sicherheitsregeln, nur Elektrofachkräfte"},
            {"hazard": "Lichtbogen", "gesetz": "DGUV 203-077", "psa": ["Schutzhelm mit Visier"], "ki": "Arbeiten freischalten, PSA, Distanz"}
        ]
    }
}
NORMEN_MAP = {
    "Bau": ["ISO 45001", "ISO 14001", "BaustellenVO", "DGUV 38", "Landesbauordnung"],
    "Elektro": ["DGUV V3", "VDE 0105-100", "TRBS 2131", "ISO 50001", "VDI 2050", "ISO 45001"]
}

def muster_betriebsanweisung(branch, risiko):
    score = {"E": 2, "S": 3, "H": 1}
    risk = nohl_risikoampel(score["E"], score["S"], score["H"])
    return {
        "titel": f"BA für {branch}: {risiko['hazard']}",
        "gesetz": risiko["gesetz"],
        "psa": risiko.get("psa", []),
        "risikoampel": risk,
        "schritte": [
            {"abschnitt": "Gefahr", "inhalt": risiko["hazard"]},
            {"abschnitt": "PSA", "inhalt": ', '.join(risiko.get("psa", []))},
            {"abschnitt": "Maßnahmen", "inhalt": risiko["ki"]},
            {"abschnitt": "Risikoampel", "inhalt": str(risk)},
        ]
    }
def muster_unterweisung(branch, risiko):
    return {
        "thema": f"Unterweisung {risiko['hazard']}",
        "ziele": f"Schutz vor {risiko['hazard']}, Verständnis: {risiko['ki']}",
        "quiz": [
            {"frage": f"Wie wird {risiko['hazard']} vermieden?", "antwort": risiko["ki"]},
            {"frage": f"Passende PSA?", "antwort": ', '.join(risiko["psa"])}
        ]
    }

# --- API-Endpunkte ---
@app.get("/psa")
def get_psa(industry: str, activity: str):
    ind = industry.lower()
    act = activity.lower()
    if ind in PSA_DATA and act in PSA_DATA[ind]:
        data = PSA_DATA[ind][act]
        return {"industry": ind, "activity": act, "equipment": data["equipment"], "regulations": data["regulations"]}
    raise HTTPException(status_code=404, detail="No PSA data for this industry/activity combination.")

@app.get("/health-checks")
def get_health_checks(industry: str):
    ind = industry.lower()
    checks = HEALTH_CHECKS.get(ind)
    if checks:
        return {"industry": ind, "required_examinations": checks}
    else:
        raise HTTPException(status_code=404, detail="No health check data for this industry.")

@app.post("/api/job/checkliste")
def get_branch_checklist(branch: str):
    if branch not in BRANCHEN_KATALOG:
        raise HTTPException(404, "Branche nicht vorhanden")
    entry = BRANCHEN_KATALOG[branch]
    vorschlag = []
    for risiko in entry["Risiken"]:
        betriebsanweisung = muster_betriebsanweisung(branch, risiko)
        unterweisung = muster_unterweisung(branch, risiko)
        vorschlag.append({
            "risiko": risiko["hazard"],
            "gesetz": risiko["gesetz"],
            "psa": risiko.get("psa", []),
            "ki_risikoeinschätzung": risiko["ki"],
            "normen": NORMEN_MAP.get(branch, []),
            "betriebsanweisung_muster": betriebsanweisung,
            "unterweisung_muster": unterweisung
        })
    return {
        "branche": branch,
        "taetigkeiten": entry["Tätigkeiten"],
        "normen_und_gesetze": NORMEN_MAP.get(branch, []),
        "punkte": vorschlag
    }

# == Admin, Tickets, Import, Export, Audit-Log, WebSocket etc. ==
class TicketCreate(BaseModel):
    description: str
    status: Optional[str] = "open"
class ExportData(BaseModel):
    lines: List[str]

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

# VDI-Checklisten, Elektro, Baustelle...
VDI_CHECKLISTEN = [
    {"nr": "VDI6022-01", "thema": "Lüftungsanlagen Hygiene", "check": "Wurde Hygieneprüfung/nach VDI 6022 & ArbStättV durchgeführt?", "gesetz": "VDI 6022, ArbStättV", "ki_help": "KI prüft Termine, erinnert an Schulungen"},
    {"nr": "VDI3819-01", "thema": "Brandschutz Gebäudetechnik", "check": "Brandschutzklappen geprüft?", "gesetz": "VDI 3819, LandesbauO", "ki_help": "Prüfprotokoll automatisch anfordern"},
]

@app.get("/api/vdi/checklisten")
def get_vdi_checklisten():
    return {"vdi_checklisten": VDI_CHECKLISTEN}

# Externer Import/Upload/Integration
EXTERNAL_UPLOAD_DIR = "/tmp/external_uploads"
os.makedirs(EXTERNAL_UPLOAD_DIR, exist_ok=True)

@app.post("/api/integration/upload")
async def import_external_file(
    source_system: str = Form(...),
    doc_type: str = Form(...),
    file: UploadFile = File(...)
):
    filename = f"{source_system}_{uuid.uuid4().hex[:8]}_{file.filename}"
    save_path = os.path.join(EXTERNAL_UPLOAD_DIR, filename)
    with open(save_path, "wb") as f:
        f.write(await file.read())
    auto_recognized = {"doc_type": doc_type, "system": source_system, "content": "[Platzhalter für Parser-Output]"}
    return {
        "status": "imported",
        "filename": filename,
        "system": source_system,
        "doc_type": doc_type,
        "auto_recognized": auto_recognized
    }

@app.post("/api/integration/webhook")
async def external_webhook(system: str, event: str, data: dict):
    return {"status": "received", "system": system, "event": event, "data": data}

@app.websocket("/ws/collaborate")
async def collaborate_ws(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Collaboration session established.")
    # Weiterer Ausbau für Live-Kollaboration möglich.

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
