from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import fitz  # PyMuPDF
import pdfplumber
import uuid
import os
import shutil

app = FastAPI()

# ----------------------------------
# CORS
# ----------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # später Domain anpassen
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------
# WORK DIR
# ----------------------------------
UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ----------------------------------
# STATUS CHECK
# ----------------------------------
@app.get("/status")
def status():
    return {"status": "running"}


# ----------------------------------
# FILE UPLOAD
# ----------------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(file_path, "wb") as f:
        f.write(await file.read())

    return {
        "message": "Datei erfolgreich hochgeladen",
        "filename": file.filename,
        "file_id": file_id,
        "stored_path": file_path,
        "size": os.path.getsize(file_path),
    }


# ----------------------------------
# EXTRACT TEXT
# ----------------------------------
@app.post("/extract/text")
async def extract_text(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(path, "wb") as f:
        f.write(await file.read())

    try:
        doc = fitz.open(path)
    except Exception as e:
        return {"error": str(e)}

    result = ""
    for i in range(len(doc)):
        page = doc.load_page(i)
        text = page.get_text("text")
        result += f"\n--- Seite {i+1} ---\n{text}"

    doc.close()

    return {
        "filename": file.filename,
        "pages": len(result.split("--- Seite")),
        "extracted_text": result,
    }


# ----------------------------------
# EXTRACT TABLES
# ----------------------------------
@app.post("/extract/tables")
async def extract_tables(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"
    with open(path, "wb") as f:
        f.write(await file.read())

    tables_out = []

    try:
        with pdfplumber.open(path) as pdf:
            for p, page in enumerate(pdf.pages):
                tables = page.extract_tables()
                if tables:
                    tables_out.append({"page": p + 1, "tables": tables})
    except Exception as e:
        return {"error": str(e)}

    return {
        "filename": file.filename,
        "table_count": len(tables_out),
        "tables": tables_out,
    }


# ----------------------------------
# EXTRACT IMAGES
# ----------------------------------
@app.post("/extract/images")
async def extract_images(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"
    with open(path, "wb") as f:
        f.write(await file.read())

    try:
        doc = fitz.open(path)
    except Exception as e:
        return {"error": str(e)}

    img_dir = f"{UPLOAD_DIR}/{file_id}_images"
    os.makedirs(img_dir, exist_ok=True)
    results = []

    for i in range(len(doc)):
        page = doc.load_page(i)
        imgs = page.get_images(full=True)

        for idx, img in enumerate(imgs):
            xref = img[0]
            pix = fitz.Pixmap(doc, xref)

            img_path = f"{img_dir}/p{i+1}_img{idx+1}.png"

            if pix.n < 5:
                pix.save(img_path)
            else:
                rgb = fitz.Pixmap(fitz.csRGB, pix)
                rgb.save(img_path)
                rgb = None

            results.append(img_path)

    doc.close()

    return {
        "filename": file.filename,
        "image_count": len(results),
        "image_paths": results,
    }


# ----------------------------------
# EXTRACT METADATA
# ----------------------------------
@app.post("/extract/meta")
async def extract_meta(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    with open(path, "wb") as f:
        f.write(await file.read())

    try:
        doc = fitz.open(path)
    except Exception as e:
        return {"error": str(e)}

    metadata = doc.metadata or {}
    pages = len(doc)

    fonts = set()
    for page in doc:
        content = page.get_text("dict")
        for block in content.get("blocks", []):
            for l in block.get("lines", []):
                for s in l.get("spans", []):
                    font = s.get("font")
                    if font:
                        fonts.add(font)

    doc.close()

    return {
        "filename": file.filename,
        "pages": pages,
        "metadata": metadata,
        "fonts_used": list(fonts),
    }


# ----------------------------------
# FILE DOWNLOAD
# ----------------------------------
@app.get("/files/{file_path:path}")
async def serve_file(file_path: str):
    full = os.path.join(UPLOAD_DIR, file_path)
    if not os.path.isfile(full):
        return JSONResponse(
            status_code=404,
            content={"error": f"Datei {file_path} nicht gefunden"},
        )
    return FileResponse(full)
