from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import fitz  # PyMuPDF
import pdfplumber
import uuid
import os

app = FastAPI()

# ---------------------------
# CORS
# ---------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # bei Bedarf auf deine Domain einschränken
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Upload Directory
# ---------------------------
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
        "size": os.path.getsize(file_path),
        "stored_path": file_path,
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
        full_text += f"\n\n--- Seite {page_number + 1} ---\n{text or ''}"

    page_count = len(doc)
    doc.close()

    return {
        "filename": file.filename,
        "pages": page_count,
        "extracted_text": full_text,
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
                        "tables": tables,
                    })
    except Exception as e:
        return {"error": f"Tabellen konnten nicht extrahiert werden: {str(e)}"}

    return {
        "filename": file.filename,
        "table_count": len(tables_output),
        "tables": tables_output,   # kann leer sein
    }

# ---------------------------
# PDF IMAGE EXTRACTION (PyMuPDF)
# ---------------------------
@app.post("/extract/images")
async def extract_pdf_images(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"
    with open(file_path, "wb") as f:
        f.write(await file.read())

    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    image_results = []
    image_dir = f"{UPLOAD_DIR}/{file_id}_images"
    os.makedirs(image_dir, exist_ok=True)

    for page_index in range(len(doc)):
        page = doc.load_page(page_index)
        images = page.get_images(full=True)
        for img_index, img in enumerate(images):
            xref = img[0]
            pix = fitz.Pixmap(doc, xref)
            img_path = f"{image_dir}/page{page_index+1}_img{img_index+1}.png"
            if pix.n < 5:
                pix.save(img_path)
            else:
                rgb_pix = fitz.Pixmap(fitz.csRGB, pix)
                rgb_pix.save(img_path)
                rgb_pix = None
            image_results.append(img_path)

    doc.close()

    return {
        "filename": file.filename,
        "image_count": len(image_results),
        "image_paths": image_results,
    }

# ---------------------------
# FILE DOWNLOAD ENDPOINT (serve stored files)
# ---------------------------
@app.get("/files/{file_path:path}")
async def serve_file(file_path: str):
    # Nur innerhalb UPLOAD_DIR ausliefern (Pfad-Sicherheit)
    full_path = os.path.join(UPLOAD_DIR, file_path)
    if not os.path.isfile(full_path):
        return JSONResponse(status_code=404, content={"error": f"Datei nicht gefunden: {file_path}"})
    return FileResponse(full_path)
