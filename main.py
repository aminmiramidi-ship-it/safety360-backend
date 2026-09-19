import io
import os
import tempfile
from pathlib import Path
from typing import Annotated

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.background import BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from agent_api import router as agent_router
from assistant_api import router as assistant_router
from audit_api import router as audit_router
from audit_integrity import append_audit_event
from auth import get_current_user
from auth import router as auth_router
from billing_api import router as billing_router
from content_impact_api import router as content_impact_router
from database import Base, engine, get_db
from dguv_catalog_api import router as dguv_catalog_router
from dguv_v2_api import router as dguv_v2_router
from documents import router as document_router
from files_api import router as file_router
from ims_api import router as ims_router
from industry_api import router as industry_router
from integration_catalog_api import router as integration_router
from learning_content_api import router as learning_content_router
from legal_baseline_api import router as legal_baseline_router
from legal_graph_api import router as legal_graph_router
from models import AuditLog, Ticket, User
from occupational_health_api import router as occupational_health_router
from permissions import require_permission
from platform_api import router as platform_router
from privacy_api import router as privacy_router
from realtime_api import router as realtime_router
from regulatory_api import router as regulatory_router
from schemas import (
    DashboardResponse,
    ExportData,
    TicketCreate,
    TicketListResponse,
    TicketResponse,
    UserResponse,
)
from sso_api import router as sso_router
from tenants import router as tenant_router
from translation_api import router as translation_router

APP_VERSION = "3.0.0"
ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").lower()
MAX_IMPORT_BYTES = int(os.getenv("MAX_IMPORT_BYTES", str(20 * 1024 * 1024)))

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
PDFUpload = Annotated[UploadFile, File()]


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

if ENVIRONMENT != "production":
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Safety360 API",
    version=APP_VERSION,
    description=(
        "Safety360 Backend für HSE, IMS, Datenschutz-Governance, Regulatory Intelligence, "
        "Legal Knowledge Graph und Anwendbarkeitsmatrix, Arbeitsmedizin-Autopilot, Enterprise-Integrationen, "
        "Arbeitsschutz-, Umwelt-, Energie- und Nachhaltigkeitsrecht, branchenbezogene Tätigkeits- und "
        "Prozessintelligenz, integrierte Content-/Training-Factory mit Impact-/Revisionssteuerung, "
        "DGUV-basierte deutsche Arbeitsschutzgrundlagen mit lizenz-/rechtebewusster Quellen-Governance, "
        "Dokumente, Ablage, Tickets, KI, Übersetzung, adaptive Agent-Orchestrierung, Enterprise-SSO, "
        "ticket-gesicherte Realtime-Verbindungen, HMAC-verkettete Audit-Ereignisse und Plattformdienste."
    ),
)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:5174,http://localhost:5174",
    ).split(",")
    if origin.strip()
]
if ENVIRONMENT == "production" and "*" in cors_origins:
    raise RuntimeError("Wildcard-CORS ist in Produktion nicht zulässig.")

trusted_hosts = [
    host.strip()
    for host in os.getenv(
        "TRUSTED_HOSTS",
        "127.0.0.1,localhost,testserver",
    ).split(",")
    if host.strip()
]
if ENVIRONMENT == "production" and "*" in trusted_hosts:
    raise RuntimeError("Wildcard-Trusted-Hosts sind in Produktion nicht zulässig.")

app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
        "X-CSRF-Token",
    ],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    if ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(sso_router, prefix="/auth/sso", tags=["Enterprise SSO"])
app.include_router(tenant_router, prefix="/tenants", tags=["Tenants"])
app.include_router(document_router, prefix="/documents", tags=["Document Control"])
app.include_router(file_router, prefix="/files", tags=["File Storage"])
app.include_router(assistant_router, prefix="/assistant", tags=["Assistant"])
app.include_router(translation_router, prefix="/translation", tags=["Translation"])
app.include_router(agent_router, prefix="/agents", tags=["AI Agent Autopilot"])
app.include_router(ims_router, prefix="/ims", tags=["IMS Orchestration"])
app.include_router(industry_router, prefix="/industry", tags=["Industry Intelligence"])
app.include_router(learning_content_router, prefix="/content-factory", tags=["Content & Training Factory"])
app.include_router(content_impact_router, prefix="/content-impact", tags=["Content Impact & Revision Engine"])
app.include_router(integration_router, prefix="/integrations", tags=["Enterprise Integrations"])
app.include_router(occupational_health_router, prefix="/occupational-health", tags=["Occupational Health Autopilot"])
app.include_router(privacy_router, prefix="/privacy", tags=["Privacy & GDPR Governance"])
app.include_router(realtime_router, prefix="/realtime", tags=["Secure Realtime"])
app.include_router(audit_router, prefix="/audit", tags=["Audit Integrity"])
app.include_router(regulatory_router, prefix="/regulatory", tags=["Regulatory Intelligence"])
app.include_router(
    legal_graph_router,
    prefix="/regulatory/legal-graph",
    tags=["Legal Knowledge Graph & Applicability"],
)
app.include_router(
    legal_baseline_router,
    prefix="/regulatory/de-eu/baseline",
    tags=["DE/EU Legal, Environment, Energy & Sustainability Baseline"],
)
app.include_router(
    dguv_catalog_router,
    prefix="/regulatory/de/dguv-catalog",
    tags=["DE Regulatory - DGUV Catalog Governance"],
)
app.include_router(
    dguv_v2_router,
    prefix="/regulatory/de/dguv-v2-2024",
    tags=["DE Regulatory Baseline - DGUV Vorschrift 2"],
)
app.include_router(billing_router, prefix="/billing", tags=["Billing"])
app.include_router(platform_router, prefix="/platform", tags=["Platform"])


@app.get("/", tags=["System"])
def root() -> dict[str, str]:
    return {
        "status": "ok",
        "message": "Safety360 Backend läuft",
        "version": APP_VERSION,
    }


@app.get("/status", tags=["System"])
def api_status() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "Safety360 Backend",
        "version": APP_VERSION,
        "environment": ENVIRONMENT,
    }


@app.get("/dashboard", response_model=DashboardResponse, tags=["Dashboard"])
def dashboard(current_user: CurrentUser) -> DashboardResponse:
    require_permission(current_user, "dashboard.read")
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
    current_user: CurrentUser,
):
    require_permission(current_user, "dashboard.read")
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
    current_user: CurrentUser,
    db: DBSession,
) -> TicketResponse:
    require_permission(current_user, "tickets.create")
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
    append_audit_event(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="ticket.created",
        object_type="ticket",
        object_id=ticket.id,
        source="tickets",
        details={"status": ticket.status},
    )

    db.commit()
    db.refresh(ticket)
    return ticket_to_response(ticket)


@app.get("/tickets", response_model=TicketListResponse, tags=["Tickets"])
def list_tickets(
    current_user: CurrentUser,
    db: DBSession,
) -> TicketListResponse:
    require_permission(current_user, "tickets.read")
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
    current_user: CurrentUser,
):
    require_permission(current_user, "documents.read")
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)

    for line in data.lines:
        pdf.multi_cell(0, 8, text=str(line))

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_file:
        temp_path = temp_file.name

    pdf.output(temp_path)

    background_tasks.add_task(remove_temp_file, temp_path)
    return FileResponse(
        temp_path,
        media_type="application/pdf",
        filename="safety360-export.pdf",
        headers={"Cache-Control": "private, no-store"},
    )


@app.post("/import", tags=["Documents"])
async def import_pdf(
    file: PDFUpload,
    current_user: CurrentUser,
):
    require_permission(current_user, "documents.create")
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
def admin_db(current_user: CurrentUser):
    require_permission(current_user, "*")
    return {"tables": inspect(engine).get_table_names()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
    )
