from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import fitz  # PyMuPDF

app = FastAPI()

# ---------------------------------------
# CORS EINSTELLUNGEN
# ---------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------
# STATUS ROUTE
# ---------------------------------------
@app.get("/status")
def status():
    return {"message": "Safety360 Backend läuft!"}

# ---------------------------------------
# DATEI-UPLOAD (OHNE VERARBEITUNG)
# ---------------------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    file_size = len(content)

    return {
        "filename": file.filename,
        "size": file_size,
        "message": "Datei erfolgreich empfangen!"
    }

# ---------------------------------------
# PDF TEXT EXTRAKTION
# ---------------------------------------
@app.post("/extract/pdf")
async def extract_pdf(file: UploadFile = File(...)):
    # Datei einlesen
    pdf_bytes = await file.read()

    # PDF öffnen
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    # Text extrahieren
    extracted_text = ""
    for page in doc:
        extracted_text += page.get_text()

    return {
        "filename": file.filename,
        "text": extracted_text,
        "message": "PDF Text erfolgreich extrahiert!"
    }
