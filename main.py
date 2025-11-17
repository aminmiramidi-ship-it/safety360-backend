from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field as PydField, validator
from typing import List, Optional, Dict, Any
from pathlib import Path
import fitz  # PyMuPDF
import pdfplumber
import uuid
import os
import json
import re

# ---------------------------
# App & CORS
# ---------------------------
app = FastAPI(title="Safety360 Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # bei Bedarf auf deine Domain einschränken
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------
# Pfade
# ---------------------------
BASE_DIR = Path(".").resolve()
UPLOAD_DIR = BASE_DIR / "uploaded_files"
IMAGE_DIR = BASE_DIR / "generated_images"
TEMPLATE_DIR = BASE_DIR / "templates"
SUBMISSIONS_DIR = BASE_DIR / "submissions"

for d in (UPLOAD_DIR, IMAGE_DIR, TEMPLATE_DIR, SUBMISSIONS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ---------------------------
# Hilfen
# ---------------------------
def secure_join(base: Path, *parts: str) -> Path:
    p = (base / Path(*parts)).resolve()
    if base not in p.parents and p != base:
        raise HTTPException(status_code=400, detail="Unsicherer Pfad")
    return p

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return path.read_text(errors="ignore")

# ---------------------------
# Template-Modelle
# ---------------------------
class Section(BaseModel):
    id: str
    title: Dict[str, str] = PydField(default_factory=dict)  # {"de":"…","en":"…"}
    description: Dict[str, str] = PydField(default_factory=dict)

class FormField(BaseModel):
    id: str
    label: Dict[str, str] = PydField(default_factory=dict)
    type: str = PydField(regex=r"^(text|textarea|number|date|checkbox|choice)$")
    required: bool = False
    section_id: str
    choices: Optional[List[str]] = None
    default: Optional[Any] = None
    extraction_hint: Optional[Dict[str, Any]] = None  # {"keywords":["…"], "regex":"…", "page":1}

class Template(BaseModel):
    id: str
    name: str
    version: str = "1.0"
    language: str = "de"
    sections: List[Section]
    fields: List[FormField]
    metadata: Dict[str, Any] = PydField(default_factory=dict)

    @validator("fields")
    def section_refs_exist(cls, fields, values):
        section_ids = {s.id for s in values.get("sections", [])}
        for f in fields:
            if f.section_id not in section_ids:
                raise ValueError(f"Field.section_id '{f.section_id}' existiert nicht")
        return fields

# ---------------------------
# Template-Persistenz
# ---------------------------
def template_path(tpl_id: str) -> Path:
    return secure_join(TEMPLATE_DIR, f"{tpl_id}.json")

def load_template(tpl_id: str) -> Template:
    p = template_path(tpl_id)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"Template '{tpl_id}' nicht gefunden")
    return Template.parse_raw(read_text(p))

def save_template(tpl: Template) -> None:
    p = template_path(tpl.id)
    p.write_text(tpl.json(indent=2, ensure_ascii=False), encoding="utf-8")

def list_templates() -> List[Template]:
    templates: List[Template] = []
    for fp in TEMPLATE_DIR.glob("*.json"):
        try:
            templates.append(Template.parse_raw(read_text(fp)))
        except Exception:
            continue
    return templates

# ---------------------------
# Default-Template bei Erststart
# ---------------------------
if not any(TEMPLATE_DIR.glob("*.json")):
    default = Template(
        id="safety360_default",
        name="Safety360 Muster-Checkliste",
        sections=[
            Section(id="A", title={"de": "A. Allgemeines"}),
            Section(id="B", title={"de": "B. Gefährdungsbeurteilung"}),
        ],
        fields=[
            FormField(
                id="op_name",
                label={"de": "Betriebs-/Projektname"},
                type="text",
                required=True,
                section_id="A",
                extraction_hint={"keywords": ["Betrieb", "Projekt", "Auftrag"], "regex": None}
            ),
            FormField(
                id="responsible",
                label={"de": "Verantwortliche Person"},
                type="text",
                required=False,
                section_id="A",
                extraction_hint={"keywords": ["Verantwortlich", "Ansprechpartner"], "regex": None}
            ),
            FormField(
                id="risk_assessment_done",
                label={"de": "Gefährdungsbeurteilung durchgeführt"},
                type="checkbox",
                required=False,
                section_id="B",
                extraction_hint={"keywords": ["Gefährdungsbeurteilung"], "regex": r"(durchgeführt|vorhanden|erfolgt)"}
            ),
        ],
        metadata={"domain": "safety", "i18n": ["de", "en"]}
    )
    save_template(default)

# ---------------------------
# Status
# ---------------------------
@app.get("/status")
def status():
    return {"status": "running"}

# ---------------------------
# Datei-Upload
# ---------------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = secure_join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())
    return {
        "message": "Datei erfolgreich empfangen",
        "filename": file.filename,
        "file_id": file_id,
        "size": os.path.getsize(file_path),
        "stored_path": str(file_path.relative_to(BASE_DIR)),
    }

# ---------------------------
# PDF Text-Extraktion (PyMuPDF)
# ---------------------------
@app.post("/extract/text")
async def extract_pdf_text(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = secure_join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    full_text = []
    for page_number in range(len(doc)):
        page = doc.load_page(page_number)
        text = page.get_text("text") or ""
        full_text.append({"page": page_number + 1, "text": text})
    page_count = len(doc)
    doc.close()
    return {"filename": file.filename, "pages": page_count, "content": full_text}

# ---------------------------
# PDF Tabellen (pdfplumber)
# ---------------------------
@app.post("/extract/tables")
async def extract_tables(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = secure_join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())

    tables_output = []
    try:
        with pdfplumber.open(file_path) as pdf:
            for page_num, page in enumerate(pdf.pages):
                tables = page.extract_tables() or []
                if tables:
                    tables_output.append({"page": page_num + 1, "tables": tables})
    except Exception as e:
        return {"error": f"Tabellen konnten nicht extrahiert werden: {str(e)}"}

    return {"filename": file.filename, "table_count": len(tables_output), "tables": tables_output}

# ---------------------------
# PDF Bilder (PyMuPDF)
# ---------------------------
@app.post("/extract/images")
async def extract_pdf_images(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = secure_join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())

    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    out_dir = secure_join(IMAGE_DIR, file_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    image_paths = []
    for page_index in range(len(doc)):
        page = doc.load_page(page_index)
        images = page.get_images(full=True)
        for img_index, img in enumerate(images):
            xref = img[0]
            pix = fitz.Pixmap(doc, xref)
            out_path = out_dir / f"page{page_index+1}_img{img_index+1}.png"
            if pix.n < 5:
                pix.save(out_path)
            else:
                rgb_pix = fitz.Pixmap(fitz.csRGB, pix)
                rgb_pix.save(out_path)
            image_paths.append(str(out_path.relative_to(BASE_DIR)))
    doc.close()
    return {"filename": file.filename, "image_count": len(image_paths), "image_paths": image_paths}

# ---------------------------
# PDF Metadaten & Fonts
# ---------------------------
@app.post("/extract/meta")
async def extract_pdf_metadata(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_path = secure_join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())

    try:
        doc = fitz.open(file_path)
    except Exception as e:
        return {"error": f"PDF konnte nicht geöffnet werden: {str(e)}"}

    metadata = doc.metadata or {}
    page_count = len(doc)

    fonts = set()
    for page in doc:
        data = page.get_text("dict") or {}
        for block in data.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    fname = span.get("font")
                    if fname:
                        fonts.add(fname)
    doc.close()
    return {"filename": file.filename, "pages": page_count, "metadata": metadata, "fonts_used": sorted(fonts)}

# ---------------------------
# Dateien ausliefern
# ---------------------------
@app.get("/files/{file_path:path}")
async def serve_file(file_path: str):
    full_path = secure_join(BASE_DIR, file_path) if not file_path.startswith("uploaded_files") else secure_join(BASE_DIR, file_path)
    if not Path(full_path).is_file():
        return JSONResponse(status_code=404, content={"error": f"Datei nicht gefunden: {file_path}"})
    return FileResponse(full_path)

# ---------------------------
# Template-API (Individualisierung)
# ---------------------------
@app.get("/templates")
def get_templates() -> List[Template]:
    return list_templates()

@app.get("/templates/{tpl_id}")
def get_template(tpl_id: str) -> Template:
    return load_template(tpl_id)

@app.post("/templates")
def upsert_template(template: Template):
    save_template(template)
    return {"status": "ok", "template_id": template.id}

@app.delete("/templates/{tpl_id}")
def delete_template(tpl_id: str):
    p = template_path(tpl_id)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Template nicht gefunden")
    p.unlink()
    return {"status": "deleted", "template_id": tpl_id}

# ---------------------------
# Formular fürs Frontend
# ---------------------------
@app.get("/form")
def get_form(
    template_id: str = Query(...),
    lang: str = Query("de"),
    user_id: Optional[str] = Header(None),
    org_id: Optional[str] = Header(None),
):
    tpl = load_template(template_id)
    # Labels entsprechend gewünschter Sprache ausliefern
    def tr(d: Dict[str, str]) -> str:
        if not d:
            return ""
        return d.get(lang) or d.get(tpl.language) or next(iter(d.values()))
    sections = [{"id": s.id, "title": tr(s.title), "description": tr(s.description)} for s in tpl.sections]
    fields = []
    for f in tpl.fields:
        fields.append({
            "id": f.id,
            "label": tr(f.label),
            "type": f.type,
            "required": f.required,
            "section_id": f.section_id,
            "choices": f.choices,
            "default": f.default
        })
    return {
        "template": {"id": tpl.id, "name": tpl.name, "version": tpl.version},
        "context": {"user_id": user_id, "org_id": org_id},
        "sections": sections,
        "fields": fields
    }

# ---------------------------
# Submission speichern
# ---------------------------
class Submission(BaseModel):
    data: Dict[str, Any]

@app.post("/submit")
def submit_form(
    submission: Submission,
    template_id: str = Query(...),
    user_id: Optional[str] = Header(None),
    org_id: Optional[str] = Header(None),
):
    tpl = load_template(template_id)  # validiert Existenz
    sub_id = str(uuid.uuid4())
    out = {
        "submission_id": sub_id,
        "template_id": tpl.id,
        "user_id": user_id,
        "org_id": org_id,
        "data": submission.data,
    }
    out_path = secure_join(SUBMISSIONS_DIR, f"{tpl.id}__{sub_id}.json")
    Path(out_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"status": "stored", "submission_id": sub_id}

# ---------------------------
# Strukturierte Extraktion basierend auf Template
# (einfaches Mapping via Keywords/Regex)
# ---------------------------
@app.post("/extract/structured")
async def extract_structured(
    file: UploadFile = File(...),
    template_id: str = Query(...),
    lang: str = Query("de")
):
    tpl = load_template(template_id)
    # PDF speichern
    file_id = str(uuid.uuid4())
    file_path = secure_join(UPLOAD_DIR, f"{file_id}_{file.filename}")
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Volltext holen
    try:
        doc = fitz.open(file_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"PDF konnte nicht geöffnet werden: {str(e)}")

    pages_text = []
    for i in range(len(doc)):
        t = doc.load_page(i).get_text("text") or ""
        pages_text.append(t)
    all_text = "\n".join(pages_text)
    doc.close()

    def find_value(hint: Optional[Dict[str, Any]]) -> Optional[str]:
        if not hint:
            return None
        scope = all_text
        if "page" in hint and isinstance(hint["page"], int):
            p = hint["page"] - 1
            if 0 <= p < len(pages_text):
                scope = pages_text[p]
        # Regex bevorzugen
        rx = hint.get("regex")
        if rx:
            m = re.search(rx, scope, flags=re.IGNORECASE)
            if m:
                return m.group(0)
        # Keywords -> nächste Zeile/Nachbarwort
        kws = hint.get("keywords") or []
        for kw in kws:
            pat = re.compile(rf"{re.escape(kw)}[^\n\r]*[:\-]?\s*(.+)", re.IGNORECASE)
            m = pat.search(scope)
            if m:
                return m.group(1).strip()
        return None

    structured = {}
    for f in tpl.fields:
        val = find_value(f.extraction_hint)
        if f.type == "checkbox":
            # simple Heuristik: Treffer => True
            structured[f.id] = bool(val)
        else:
            structured[f.id] = val

    return {
        "template": {"id": tpl.id, "name": tpl.name, "version": tpl.version},
        "extraction": structured,
        "raw_preview": all_text[:2000]  # kurzer Preview für Debug
    }
