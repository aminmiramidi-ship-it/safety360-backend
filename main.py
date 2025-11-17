from fastapi import FastAPI, UploadFile, File
import fitz  # PyMuPDF
import pdfplumber
import uuid
import os

app = FastAPI()

UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------
# STATUS ENDPOINT
# ---------------------------------------------------------
@app.get("/status")
def status():
    return {"status": "running"}

# ---------------------------------------------------------
# FILE UPLOAD ENDPOINT
# ---------------------------------------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as f:
        f.write(await file.read())

    return {
        "message": "Datei erfolgreich empfangen",
        "filename": file.filename,
        "file_id": file_id,
        "size": os.path.getsize(file_path)
    }

# ---------------------------------------------------------
# PDF TEXT EXTRACTOR (PyMuPDF)
# ---------------------------------------------------------
@app.post("/extract/text")
async def extract_pdf_text(file: UploadFile = File(...)):
    # Datei speichern
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as f:
        f.write(await file.read())

    # PDF öffnen
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    full_text = ""

    for page_number in range(len(doc)):
        page = doc.load_page(page_number)
        text = page.get_text("text")
        full_text += f"\n\n--- Seite {page_number+1} ---\n{text}"

    doc.close()

    return {
        "filename": file.filename,
        "pages": len(doc),
        "extracted_text": full_text
    }

# ---------------------------------------------------------
# PDF TABLE EXTRACTOR (pdfplumber)
# ---------------------------------------------------------
@app.post("/extract/tables")
async def extract_tables(file: UploadFile = File(...)):
    # Datei speichern
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as f:
        f.write(await file.read())

    tables_output = []

    try:
        with pdfplumber.open(file_path) as pdf:
            for page_num, page in enumerate(pdf.pages):
                try:
                    tables = page.extract_tables()
                    for t in tables:
                        tables_output.append({
                            "page": page_num + 1,
                            "table": t
                        })
                except Exception as e:
                    tables_output.append({
                        "page": page_num + 1,
                        "error": str(e)
                    })

    except Exception as e:
        return {"error": f"PDF konnte nicht verarbeitet werden: {str(e)}"}

    return {
        "filename": file.filename,
        "tables_found": len(tables_output),
        "tables": tables_output
    }
