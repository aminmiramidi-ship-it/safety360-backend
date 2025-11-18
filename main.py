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
# ------------------------------------------
