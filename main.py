from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pdfminer.high_level import extract_text
import os
import uuid

app = FastAPI()

# -----------------------------------
# CORS Einstellungen
# -----------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # erlaubt alle Frontends
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------
# STATUS-Test
# -----------------------------------
@app.get("/status")
def status():
    return {"message": "Safety360 Backend läuft!"}

# -----------------------------------
# Datei-Upload
# -----------------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    file_size = len(content)

    return {
        "filename": file.filename,
        "size": file_size,
        "message": "Datei erfolgreich empfangen!"
    }

# -----------------------------------
# PDF Text Extraktion
# -----------------------------------
@app.post("/extract/pdf")
async def extract_pdf_text(file: UploadFile = File(...)):
    # temporäre Datei speichern
    temp_filename = f"/tmp/{uuid.uuid4()}.pdf"

    with open(temp_filename, "wb") as tmp:
        tmp.write(await file.read())

    # Text extrahieren
    try:
        text = extract_text(temp_filename)
    except Exception as e:
        return {"error": "PDF konnte nicht gelesen werden", "details": str(e)}

    # Datei löschen
    os.remove(temp_filename)

    return {
        "filename": file.filename,
        "extracted_text": text
    }
