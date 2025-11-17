# ---------------------------
# PDF METADATA EXTRACTION
# ---------------------------
@app.post("/extract/meta")
async def extract_pdf_metadata(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = f"{UPLOAD_DIR}/{file_id}_{file.filename}"

    # Datei speichern
    with open(file_path, "wb") as f:
        f.write(await file.read())

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
        text_blocks = page.get_text("dict")
        for block in text_blocks.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    if "font" in span:
                        fonts.add(span["font"])

    doc.close()

    return {
        "filename": file.filename,
        "pages": page_count,
        "metadata": metadata,
        "fonts_used": list(fonts)
    }
