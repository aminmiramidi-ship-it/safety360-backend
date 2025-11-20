import os
import sqlite3
import hashlib
import secrets
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.fernet import Fernet

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

# FastAPI instance
app = FastAPI(
    title="Safety360 API",
    version="1.0",
    description="Backend für Safety360 – PSA, Tickets, KI-Gefährdungsbeurteilung"
)

@app.get("/")
def root():
    return {"status": "ok", "message": "Safety360 Backend läuft"}

# Environment variables
DB_URL = os.getenv("DATABASE_URL", "safety360.db")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "changeme123")
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
SMARTSHEET_TOKEN = os.getenv("SMARTSHEET_TOKEN", "")
SMARTSHEET_SHEET_ID = os.getenv("SMARTSHEET_SHEET_ID", "")

# Encryption handler
if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    new_key = Fernet.generate_key()
    ENCRYPTION_KEY = new_key
    print(f"[INFO] Generated new ENCRYPTION_KEY: {new_key.decode()}")

if isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()

def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# Models
class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class TicketCreate(BaseModel):
    description: str
    status: Optional[str] = "open"

class ExportData(BaseModel):
    lines: List[str]

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database
conn = sqlite3.connect(DB_URL, check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    description TEXT,
    status TEXT
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    event TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()

# Password hashing
def hash_password(pw: str, salt: str):
    h = hashlib.sha256()
    h.update(salt.encode() + pw.encode())
    return h.hexdigest()

# ---------------- AUTH -----------------------
@app.post("/register")
def register(user: UserRegister):
    cur.execute("SELECT 1 FROM users WHERE email=?", (user.email,))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="User exists")

    salt = secrets.token_hex(16)
    pw_hash = hash_password(user.password, salt)

    cur.execute("INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
                (user.email, pw_hash, salt))
    conn.commit()

    return {"status": "ok", "message": "User registered"}

@app.post("/login")
def login(user: UserLogin):
    cur.execute("SELECT id, password_hash, salt FROM users WHERE email=?", (user.email,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")

    uid, pw_hash, salt = row
    if hash_password(user.password, salt) != pw_hash:
        raise HTTPException(401, "Invalid credentials")

    token = encrypt(f"{uid}:{user.email}")

    return {
        "status": "ok",
        "token": token,
        "email": user.email,
        "user_id": uid
    }

# ---------------- PSA ------------------------
PSA_DATA = {
    "construction": {
        "working at heights": {
            "equipment": ["Safety harness", "Helmet", "Lanyard"],
            "regulations": ["DGUV 112-198", "ArbSchG §5"]
        }
    }
}

@app.get("/psa")
def get_psa(industry: str, activity: str):
    i = industry.lower()
    a = activity.lower()
    if i in PSA_DATA and a in PSA_DATA[i]:
        return PSA_DATA[i][a]
    raise HTTPException(404, "No PSA found")

# ---------------- Tickets --------------------
@app.post("/tickets")
def create_ticket(ticket: TicketCreate):
    enc = encrypt(ticket.description)
    cur.execute("INSERT INTO tickets (description, status) VALUES (?, ?)",
                (enc, ticket.status))
    conn.commit()
    return {"ticket_id": cur.lastrowid}

@app.get("/tickets")
def list_tickets():
    cur.execute("SELECT id, description, status FROM tickets")
    rows = cur.fetchall()
    out = []
    for tid, enc, status in rows:
        try:
            dec = decrypt(enc)
        except:
            dec = "(error decrypting)"
        out.append({"id": tid, "description": dec, "status": status})
    return {"tickets": out}

# ---------------- Export ---------------------
@app.post("/export/pdf")
def export_pdf(data: ExportData):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in data.lines:
        pdf.cell(200, 10, txt=line, ln=True)
    pdf.output("export.pdf")
    return FileResponse("export.pdf")

# ---------------- Import PDF -----------------
@app.post("/import")
async def import_pdf(file: UploadFile):
    import pdfplumber
    import io

    content = await file.read()
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        text = "\n".join([page.extract_text() or "" for page in pdf.pages])

    return {"text": text}

# ---------------- Admin ----------------------
@app.get("/admin/db")
def admin_db(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(403, "Forbidden")
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {"tables": [r[0] for r in cur.fetchall()]}

# ---------------- WebSocket ------------------
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Connected to Safety360 WebSocket")

# ---------------- Start ----------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
