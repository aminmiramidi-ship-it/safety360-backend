from fastapi import FastAPI, UploadFile, File
import fitz  # PyMuPDF
import pdfplumber
import uuid
import os

app = FastAPI()

UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------
# STATUS CHECK
# ---------------------------
@app.get("/status")
def status():
    return {"status": "running"}


# ---------------------------
# FILE UPLOAD
# ---------------------------
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


# ---------------------------
# PDF TEXT EXTRACTION (PyMuPDF)
# ---------------------------
@app.post("/extract/text")
async def extract_pdf_text(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as f:
        f.write(await file.read())

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


# ---------------------------
# PDF TABLE EXTRACTION (pdfplumber)
# ---------------------------
@app.post("/extract/tables")
async def extract_tables(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as f:
        f.write(await file.read())

    tables_output = []

    try:
        with pdfplumber.open(file_path) as pdf:
            for page_num, page in enumerate(pdf.pages):
                tables = page.extract_tables()
                if tables:
                    tables_output.append({
                        "page": page_num + 1,
                        "tables": tables
                    })
    except Exception as e:
        return {"error": f"Tabellen konnten nicht extrahiert werden: {str(e)}"}

    return {
        "filename": file.filename,
        "table_count": len(tables_output),
        "tables": tables_output
    }
