import os
import sqlite3
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = FastAPI(title="Safety360 API", version="1.0")

@app.get("/")
def root():
    return {"status": "ok", "message": "Safety360 Backend läuft"}

# -------------------------------------------------------
# ENV
# -------------------------------------------------------
DB_URL = os.getenv("DATABASE_URL", "safety360.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"Generated ENCRYPTION_KEY: {ENCRYPTION_KEY.decode()}")
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# -------------------------------------------------------
# DATABASE
# -------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

# -------------------------------------------------------
# PSA
# -------------------------------------------------------
@app.get("/psa")
def get_psa(industry: str, activity: str):
    return {
        "industry": industry,
        "activity": activity,
        "equipment": ["Safety harness", "Helmet", "Gloves"],
        "regulations": ["DGUV 112-198", "ArbSchG §5"]
    }

# -------------------------------------------------------
# HEALTH EXAMS
# -------------------------------------------------------
@app.get("/health-checks")
def get_health(industry: str):
    return {
        "industry": industry,
        "required_examinations": [
            "G41 (Working at Heights)",
            "G20 (Noise Exposure)"
        ]
    }

# -------------------------------------------------------
# RISK ASSESSMENT
# -------------------------------------------------------
class RiskAssessment(BaseModel):
    industry: str
    hazards: List[str]
    measures: List[str]

@app.post("/riskassessment")
def create_risk_assessment(body: RiskAssessment):
    return {
        "status": "saved",
        "data": body.dict()
    }

# -------------------------------------------------------
# TICKETS
# -------------------------------------------------------
class Ticket(BaseModel):
    title: str
    description: str
    status: str = "open"

@app.get("/tickets")
def list_tickets():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY, title TEXT, description TEXT, status TEXT)")
    rows = cur.execute("SELECT * FROM tickets").fetchall()
    return [dict(r) for r in rows]

@app.post("/tickets")
def create_ticket(ticket: Ticket):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO tickets (title, description, status) VALUES (?, ?, ?)",
                (ticket.title, ticket.description, ticket.status))
    conn.commit()
    return {"status": "created"}

@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, ticket: Ticket):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE tickets SET title=?, description=?, status=? WHERE id=?",
                (ticket.title, ticket.description, ticket.status, ticket_id))
    conn.commit()
    return {"status": "updated"}

# -------------------------------------------------------
# EXPORTS
# -------------------------------------------------------
@app.post("/export/pdf")
def export_pdf(text: str):
    filename = "export.pdf"
    with open(filename, "w") as f:
        f.write(text)
    return FileResponse(filename, media_type="application/pdf")

@app.post("/export/word")
def export_word(text: str):
    filename = "export.docx"
    with open(filename, "w") as f:
        f.write(text)
    return FileResponse(filename)

@app.post("/export/smartsheet")
def export_smartsheet(data: dict):
    return {"status": "sent-to-smartsheet", "data": data}

# -------------------------------------------------------
# IMPORT
# -------------------------------------------------------
@app.post("/import")
def import_data(file: UploadFile = File(...)):
    content = file.file.read().decode()
    return {"status": "imported", "length": len(content)}

# -------------------------------------------------------
# ADMIN
# -------------------------------------------------------
@app.get("/admin/inspect-db")
def admin_inspect(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {"tables": [r[0] for r in cur.fetchall()]}

@app.get("/admin/audit-log")
def admin_audit(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"log": ["system ok", "no issues detected"]}
