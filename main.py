import os
import sqlite3
from typing import Optional, List

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

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

DB_URL = os.getenv("DATABASE_URL", "safety360.db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretjwtkey")
JWT_ALG = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY or len(ENCRYPTION_KEY) < 10:
    new_key = Fernet.generate_key()
    ENCRYPTION_KEY = new_key
    print(f"Generated ENCRYPTION_KEY: {new_key.decode()} (store securely)")
elif isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

fernet = Fernet(ENCRYPTION_KEY)

def encrypt(x: str) -> str:
    return fernet.encrypt(x.encode()).decode()

def decrypt(x: str) -> str:
    return fernet.decrypt(x.encode()).decode()

def db():
    conn = sqlite3.connect(DB_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS tickets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        status TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

def create_token(user_id: int):
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(hours=10)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str):
    payload = decode_token(token)
    return payload["sub"]

class RegisterBody(BaseModel):
    email: str
    password: str

class LoginBody(BaseModel):
    email: str
    password: str

@app.post("/auth/register")
def register(body: RegisterBody):
    conn = db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users(email, password) VALUES (?, ?)", (
            body.email,
            pwd_context.hash(body.password)
        ))
        conn.commit()
    except:
        raise HTTPException(400, "Email already exists")
    finally:
        conn.close()

    return {"status": "ok"}

@app.post("/auth/login")
def login(body: LoginBody):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE email=?", (body.email,))
    row = c.fetchone()
    conn.close()

    if not row or not pwd_context.verify(body.password, row["password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(row["id"])
    return {"token": token}

@app.get("/psa")
def get_psa(industry: str, activity: str):
    data = {
        "industry": industry,
        "activity": activity,
        "equipment": ["Safety harness", "Hard hat", "Lanyard"],
        "regulations": ["DGUV Regel 112-198", "ArbSchG §5"]
    }
    return data

@app.get("/health-checks")
def get_health(industry: str):
    data = {
        "industry": industry,
        "required_examinations": [
            "G41 (Working at Heights exam)",
            "G20 (Noise exposure exam)"
        ]
    }
    return data

class RiskBody(BaseModel):
    hazard: str
    probability: int
    impact: int

@app.post("/riskassessment")
def risk_assessment(body: RiskBody):
    score = body.probability * body.impact
    return {"hazard": body.hazard, "risk_score": score}

@app.get("/tickets")
def list_tickets():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM tickets")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

class TicketBody(BaseModel):
    title: str
    description: str

@app.post("/tickets")
def create_ticket(body: TicketBody):
    conn = db()
    c = conn.cursor()
    c.execute("INSERT INTO tickets(title, description, status) VALUES (?, ?, ?)", (
        body.title, body.description, "open"
    ))
    conn.commit()
    conn.close()
    return {"status": "created"}

class TicketUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None

@app.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, body: TicketUpdate):
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,))
    row = c.fetchone()
    if not row:
        raise HTTPException(404, "Not found")

    new_title = body.title or row["title"]
    new_desc = body.description or row["description"]
    new_status = body.status or row["status"]

    c.execute("UPDATE tickets SET title=?, description=?, status=? WHERE id=?",
              (new_title, new_desc, new_status, ticket_id))
    conn.commit()
    conn.close()

    return {"status": "updated"}

@app.post("/import")
def import_data(file: UploadFile = File(...)):
    return {"status": "imported", "filename": file.filename}

@app.get("/admin/inspect-db")
def inspect():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in c.fetchall()]
    conn.close()
    return tables

@app.get("/admin/audit-log")
def audit():
    return {"status": "empty"}
