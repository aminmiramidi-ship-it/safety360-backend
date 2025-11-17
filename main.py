from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import fitz  # PyMuPDF
import pdfplumber
import uuid
import os


# -------------------------------------------------
# APP & CORS
# -------------------------------------------------
app = FastAPI(title="Safety360 Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später auf deine Domain einschränken
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------
# UPLOAD-ORDNER
# -------------------------------------------------
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)
UPLOAD_DIR_ABS = os.path.abspath(UPLOAD_DIR)


# -------------------------------------------------
# HILFSFUNKTION: Datei speichern
# -------------------------------------------------
async def save_upload(file: UploadFile) -> dict:
    """Speichert eine hochgeladene Datei im UPLOAD_DIR und gibt Infos zurück."""
    file_id = str(uuid.uuid4())
    stored_name = f"{file_id}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, stored_name)

    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    return {
        "file_id": file_id,
        "filename": file.filename,
        "stored_filename": stored_name,
        "stored_path": file_path,
        "size": len(content),
    }


# -------------------------------------------------
# STATUS-CHECK
# -------------------------------------------------
@app.get("/status")
def status():
    return {"status": "running"}


# -------------------------------------------------
# ROHER DATEI-UPLOAD (ohne Analyse)
# -------------------------------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    info = await save_upload(file)
    return {
        "message": "Datei erfolgreich empfangen",
        **info,
    }


# -------------------------------------------------
# PDF TEXT EXTRAKTION (PyMuPDF)
# -------------------------------------------------
@app.post("/extract/text")
async def extract_pdf_text(file: UploadFile = File(...)):
    info = await save_upload(file)
    file_path = info["stored_path"]

    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    full_text = ""
    for page_number in range(len(doc)):
        page = doc.load_page(page_number)
        text = page.get_text("text") or ""
        full_text += f"\n\n--- Seite {page_number + 1} ---\n{text}"

    page_count = len(doc)
    doc.close()

    return {
        "filename": info["filename"],
        "stored_filename": info["stored_filename"],
        "pages": page_count,
        "extracted_text": full_text,
    }


# -------------------------------------------------
# PDF TABELLEN EXTRAKTION (pdfplumber)
# -------------------------------------------------
@app.post("/extract/tables")
async def extract_tables(file: UploadFile = File(...)):
    info = await save_upload(file)
    file_path = info["stored_path"]

    tables_output = []

    try:
        with pdfplumber.open(file_path) as pdf:
            for page_num, page in enumerate(pdf.pages):
                tables = page.extract_tables()
                if tables:
                    tables_output.append(
                        {
                            "page": page_num + 1,
                            "tables": tables,
                        }
                    )
    except Exception as e:
        return {"error": f"Tabellen konnten nicht extrahiert werden: {str(e)}"}

    return {
        "filename": info["filename"],
        "stored_filename": info["stored_filename"],
        "table_count": len(tables_output),
        "tables": tables_output,  # kann leer sein
    }


# -------------------------------------------------
# PDF BILD-EXTRAKTION (PyMuPDF)
# -------------------------------------------------
@app.post("/extract/images")
async def extract_pdf_images(file: UploadFile = File(...)):
    info = await save_upload(file)
    file_path = info["stored_path"]

    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    image_results = []
    image_dir_name = f"{info['file_id']}_images"
    image_dir = os.path.join(UPLOAD_DIR, image_dir_name)
    os.makedirs(image_dir, exist_ok=True)

    for page_index in range(len(doc)):
        page = doc.load_page(page_index)
        images = page.get_images(full=True)

        for img_index, img in enumerate(images):
            xref = img[0]
            pix = fitz.Pixmap(doc, xref)

            img_filename = f"page{page_index + 1}_img{img_index + 1}.png"
            img_path = os.path.join(image_dir, img_filename)

            if pix.n < 5:
                pix.save(img_path)
            else:
                rgb_pix = fitz.Pixmap(fitz.csRGB, pix)
                rgb_pix.save(img_path)
                rgb_pix = None

            image_results.append(
                {
                    "page": page_index + 1,
                    "image_index": img_index + 1,
                    "stored_path": os.path.relpath(img_path, UPLOAD_DIR),
                }
            )

    doc.close()

    return {
        "filename": info["filename"],
        "stored_filename": info["stored_filename"],
        "image_count": len(image_results),
        "images": image_results,
    }


# -------------------------------------------------
# PDF METADATA EXTRAKTION (Titel, Autor, Schriftarten usw.)
# -------------------------------------------------
@app.post("/extract/meta")
async def extract_pdf_metadata(file: UploadFile = File(...)):
    info = await save_upload(file)
    file_path = info["stored_path"]

    # PDF öffnen
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    # Metadaten
    metadata = doc.metadata or {}

    # Seitenanzahl
    page_count = len(doc)

    # Schriftarten erkennen
    fonts = set()
    for page in doc:
        text_dict = page.get_text("dict") or {}
        for block in text_dict.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    font_name = span.get("font")
                    if font_name:
                        fonts.add(font_name)

    doc.close()

    return {
        "filename": info["filename"],
        "stored_filename": info["stored_filename"],
        "pages": page_count,
        "metadata": metadata,
        "fonts_used": sorted(list(fonts)),
    }


# -------------------------------------------------
# DATEI-SERVING (für gespeicherte Dateien/Bilder)
# -------------------------------------------------
@app.get("/files/{file_path:path}")
async def serve_file(file_path: str):
    """
    Liefert eine zuvor gespeicherte Datei zurück.
    Erwartet einen Pfad relativ zu UPLOAD_DIR, z.B.:
    GET /files/<stored_filename>
    GET /files/<file_id>_images/page1_img1.png
    """
    # Sicheren absoluten Pfad bauen
    full_path = os.path.abspath(os.path.join(UPLOAD_DIR, file_path))

    # Path-Traversal verhindern
    if not full_path.startswith(UPLOAD_DIR_ABS + os.sep) and full_path != UPLOAD_DIR_ABS:
        return JSONResponse(
            status_code=400,
            content={"error": "Ungültiger Dateipfad."},
        )

    if not os.path.isfile(full_path):
        return JSONResponse(
            status_code=404,
            content={"error": f"Datei nicht gefunden: {file_path}"},
        )

    return FileResponse(full_path)
