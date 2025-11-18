import os
import sqlite3
from typing import List
from datetime import datetime, timedelta
import hashlib
import base64
import jwt

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from cryptography.fernet import Fernet

# -----------------------------------------------------------
# ENV laden
# -----------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

JWT_SECRET = os.getenv("JWT_SECRET", "change_me")
JWT_ALG = "HS256"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")
DB_URL = os.getenv("DATABASE_URL", "safety360.db")

# -----------------------------------------------------------
# App
# -----------------------------------------------------------
app = FastAPI(title="Safety360 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "ok", "message": "Safety360 Backend läuft"}

# -----------------------------------------------------------
# Encryption
# -----------------------------------------------------------
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    ENCRYPTION_KEY = Fernet.generate_key()
    print("Generated ENCRYPTION_KEY:", ENCRYPTION_KEY.decode())
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(text: str) -> str:
    return fernet.encrypt(text.encode()).decode()

def decrypt(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# -----------------------------------------------------------
# DB
# -----------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            salt TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY,
            title TEXT,
            description TEXT,
            status TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# -----------------------------------------------------------
# JWT / Passwort
# -----------------------------------------------------------
security = HTTPBearer()

def hash_pw(password: str, salt: str) -> str:
    h = hashlib.sha256()
    h.update(salt.encode() + password.encode())
    return h.hexdigest()

def verify_pw(password: str, salt: str, pw_hash: str) -> bool:
    return hash_pw(password, salt) == pw_hash

def create_token(user_id: int) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# -----------------------------------------------------------
# Models
# -----------------------------------------------------------
class RegisterBody(BaseModel):
    email: str
    password: str

class LoginBody(BaseModel):
    email: str
    password: str

class Ticket(BaseModel):
    title: str
    description: str
    status: str = "open"

class RiskAssessment(BaseModel):
    industry: str
    hazards: List[str]
    measures: List[str]

# -----------------------------------------------------------
# AUTH
# -----------------------------------------------------------
@app.post("/auth/register")
def register(body: RegisterBody):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=?", (body.email,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(400, "User exists")

    salt = base64.b64encode(os.urandom(16)).decode()
    pw_hash = hash_pw(body.password, salt)

    cur.execute(
        "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
        (body.email, pw_hash, salt)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.post("/auth/login")
def login(body: LoginBody):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash, salt FROM users WHERE email=?", (body.email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(401, "Invalid credentials")

    if not verify_pw(body.password, row["salt"], row["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    return {"access_token": create_token(row["id"]), "token_type": "bearer"}

@app.get("/auth/me")
def me(user_id: int = Depends(require_user)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, created_at FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    return dict(row)

# -----------------------------------------------------------
# PSA (öffentlich)
# -----------------------------------------------------------
@app.get("/psa")
def psa(industry: str, activity: str):
    return {
        "industry": industry,
        "activity": activity,
        "equipment": ["Safety harness", "Helmet", "Gloves"],
        "regulations": ["DGUV 112-198", "ArbSchG §5"]
    }

# -----------------------------------------------------------
# Health Checks (öffentlich)
# -----------------------------------------------------------
@app.get("/health-checks")
def health(industry: str):
    return {
        "industry": industry,
        "required_examinations": ["G41 (Working at Heights)", "G20 (Noise Exposure)"]
    }

# -----------------------------------------------------------
# Risk Assessment (geschützt)
# -----------------------------------------------------------
@app.post("/riskassessment")
def risk_create(body: RiskAssessment, user_id: int = Depends(require_user)):
    return {"saved": True, "user_id": user_id, "data": body.dict()}

# -----------------------------------------------------------
# Tickets (geschützt)
# -----------------------------------------------------------
@app.get("/tickets")
def ticket_list(user_id: int = Depends(require_user)):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tickets")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

@app.post("/tickets")
def ticket_create(ticket: Ticket, user_id: int = Depends(require_user)):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tickets (title, description, status) VALUES (?, ?, ?)",
        (ticket.title, ticket.description, ticket.status)
    )
    conn.commit()
    conn.close()
    return {"status": "created"}

@app.put("/tickets/{ticket_id}")
def ticket_update(ticket_id: int, ticket: Ticket, user_id: int = Depends(require_user)):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE tickets SET title=?, description=?, status=? WHERE id=?",
        (ticket.title, ticket.description, ticket.status, ticket_id)
    )
    conn.commit()
    conn.close()
    return {"status": "updated"}

# -----------------------------------------------------------
# Export (geschützt)
# -----------------------------------------------------------
@app.post("/export/pdf")
def export_pdf(text: str, user_id: int = Depends(require_user)):
    filename = "export.pdf"
    with open(filename, "w") as f:
        f.write(text)
    return FileResponse(filename, media_type="application/pdf")

@app.post("/export/word")
def export_word(text: str, user_id: int = Depends(require_user)):
    filename = "export.docx"
    with open(filename, "w") as f:
        f.write(text)
    return FileResponse(filename)

# -----------------------------------------------------------
# Import (geschützt)
# -----------------------------------------------------------
@app.post("/import")
def import_data(file: UploadFile = File(...), user_id: int = Depends(require_user)):
    content = file.file.read().decode()
    return {"imported": True, "length": len(content)}

# -----------------------------------------------------------
# Admin
# -----------------------------------------------------------
@app.get("/admin/inspect-db")
def admin_db(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(401, "Unauthorized")

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

@app.get("/admin/audit-log")
def admin_log(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(401, "Unauthorized")
    return ["system ok", "no issues"]
