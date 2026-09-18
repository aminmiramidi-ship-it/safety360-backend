import io
import os
import tempfile
from pathlib import Path
from typing import Dict

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, status
from fastapi.background import BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from auth import get_current_user, router as auth_router
from database import Base, engine, get_db
from models import AuditLog, Ticket, User
from schemas import (
    DashboardResponse,
    ExportData,
    TicketCreate,
    TicketListResponse,
    TicketResponse,
    UserResponse,
)
from tenants import router as tenant_router

APP_VERSION = "1.2.0"
ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").lower()
MAX_IMPORT_BYTES = int(os.getenv("MAX_IMPORT_BYTES", str(20 * 1024 * 1024)))


def build_fernet() -> Fernet:
    configured_key = os.getenv("ENCRYPTION_KEY")

    if configured_key:
        try:
            return Fernet(configured_key.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise RuntimeError("ENCRYPTION_KEY ist kein gültiger Fernet-Schlüssel.") from exc

    if ENVIRONMENT == "production":
        raise RuntimeError("ENCRYPTION_KEY muss in Produktion gesetzt sein.")

    print(
        "[WARNING] ENCRYPTION_KEY ist nicht gesetzt. "
        "Für diese Development-Session wird ein temporärer Schlüssel verwendet."
    )
    return Fernet(Fernet.generate_key())


fernet = build_fernet()
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Safety360 API",
    version=APP_VERSION,
    description="Safety360 Backend für HSE, IMS, Tickets, Dokumente und KI-Workflows.",
)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:5174,http://localhost:5174",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(tenant_router, prefix="/tenants", tags=["Tenants"])


@app.get("/", tags=["System"])
def root() -> Dict[str, str]:
    return {
        "status": "ok",
        "message": "Safety360 Backend läuft",
        "version": APP_VERSION,
    }


@app.get("/status", tags=["System"])
def api_status() -> Dict[str, str]:
    return {
        "status": "ok",
        "service": "Safety360 Backend",
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
    }


@app.get("/dashboard", response_model=DashboardResponse, tags=["Dashboard"])
def dashboard(current_user: User = Depends(get_current_user)) -> DashboardResponse:
    return DashboardResponse(
        message=f"Willkommen bei Safety360, {current_user.full_name or current_user.email}.",
        user=UserResponse.model_validate(current_user),
    )


PSA_DATA = {
    "construction": {
        "working at heights": {
            "equipment": ["Safety harness", "Helmet", "Lanyard"],
            "regulations": ["DGUV 112-198", "ArbSchG §5"],
        }
    }
}


@app.get("/psa", tags=["HSE"])
def get_psa(
    industry: str,
    activity: str,
    current_user: User = Depends(get_current_user),
):
    del current_user
    industry_key = industry.strip().lower()
    activity_key = activity.strip().lower()

    if industry_key in PSA_DATA and activity_key in PSA_DATA[industry_key]:
        return PSA_DATA[industry_key][activity_key]

    raise HTTPException(status_code=404, detail="Keine passende PSA-Empfehlung gefunden.")


def encrypt_text(text: str) -> str:
    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str) -> str:
    try:
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Gespeicherte Ticketdaten konnten nicht entschlüsselt werden.",
        ) from exc


def ticket_to_response(ticket: Ticket) -> TicketResponse:
    return TicketResponse(
        id=ticket.id,
        description=decrypt_text(ticket.description_encrypted),
        status=ticket.status,
        created_by_id=ticket.created_by_id,
        tenant_id=ticket.tenant_id,
        created_at=ticket.created_at,
    )


@app.post(
    "/tickets",
    response_model=TicketResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Tickets"],
)
def create_ticket(
    ticket_data: TicketCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TicketResponse:
    ticket = Ticket(
        description_encrypted=encrypt_text(ticket_data.description.strip()),
        status=ticket_data.status.strip().lower(),
        created_by_id=current_user.id,
        tenant_id=current_user.tenant_id,
    )

    db.add(ticket)
    db.flush()

    db.add(
        AuditLog(
            event=f"ticket_created:{ticket.id}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )

    db.commit()
    db.refresh(ticket)
    return ticket_to_response(ticket)


@app.get("/tickets", response_model=TicketListResponse, tags=["Tickets"])
def list_tickets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TicketListResponse:
    query = db.query(Ticket)

    if current_user.tenant_id is not None:
        query = query.filter(Ticket.tenant_id == current_user.tenant_id)
    else:
        query = query.filter(Ticket.created_by_id == current_user.id)

    tickets = query.order_by(Ticket.created_at.desc()).all()
    return TicketListResponse(tickets=[ticket_to_response(ticket) for ticket in tickets])


def remove_temp_file(path: str) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


@app.post("/export/pdf", tags=["Documents"])
def export_pdf(
    data: ExportData,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    del current_user
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)

    for line in data.lines:
        pdf.multi_cell(0, 8, text=str(line))

    temp_file = tempfile.NamedTemporaryFile(
        suffix=".pdf",
        delete=False,
    )
    temp_path = temp_file.name
    temp_file.close()
    pdf.output(temp_path)

    background_tasks.add_task(remove_temp_file, temp_path)
    return FileResponse(
        temp_path,
        media_type="application/pdf",
        filename="safety360-export.pdf",
    )


@app.post("/import", tags=["Documents"])
async def import_pdf(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    del current_user
    import pdfplumber

    if file.content_type not in {"application/pdf", "application/octet-stream"}:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Aktuell werden nur PDF-Dateien unterstützt.",
        )

    content = await file.read(MAX_IMPORT_BYTES + 1)
    if len(content) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Die hochgeladene Datei ist zu groß.",
        )

    try:
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Die PDF-Datei konnte nicht verarbeitet werden.",
        ) from exc

    return {
        "filename": file.filename,
        "characters": len(text),
        "text": text,
    }


@app.get("/admin/db", tags=["Admin"])
def admin_db(
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administratorrechte erforderlich.",
        )

    return {"tables": inspect(engine).get_table_names()}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Connected to Safety360 WebSocket")
    await websocket.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
    )
