import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import SessionLocal, get_db
from models import AuditLog, User
from permissions import require_permission
from realtime_models import RealtimeAccessTicket

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

TICKET_TTL_SECONDS = max(15, min(int(os.getenv("REALTIME_TICKET_TTL_SECONDS", "60")), 300))
MAX_MESSAGES_PER_CONNECTION = max(1, min(int(os.getenv("REALTIME_MAX_MESSAGES", "32")), 256))
MAX_MESSAGE_BYTES = max(32, min(int(os.getenv("REALTIME_MAX_MESSAGE_BYTES", "1024")), 65536))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@router.post("/tickets", status_code=status.HTTP_201_CREATED)
def create_realtime_ticket(current_user: CurrentUser, db: DBSession):
    require_permission(current_user, "realtime.connect")
    token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(seconds=TICKET_TTL_SECONDS)
    ticket = RealtimeAccessTicket(
        token_hash=_token_hash(token),
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        purpose="websocket",
        expires_at=expires_at,
    )
    db.add(ticket)
    db.flush()
    db.add(
        AuditLog(
            event=f"realtime_ticket_created:{ticket.id}",
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()
    return {
        "ticket": token,
        "expires_at": expires_at,
        "websocket_path": "/realtime/ws",
        "single_use": True,
    }


@router.websocket("/ws")
async def realtime_websocket(websocket: WebSocket):
    raw_ticket = websocket.query_params.get("ticket")
    if not raw_ticket or len(raw_ticket) > 256:
        await websocket.close(code=4401, reason="Realtime access ticket required")
        return

    db = SessionLocal()
    user_id: int | None = None
    tenant_id: int | None = None
    ticket_id: int | None = None
    try:
        now = _now()
        ticket = db.query(RealtimeAccessTicket).filter(
            RealtimeAccessTicket.token_hash == _token_hash(raw_ticket),
            RealtimeAccessTicket.purpose == "websocket",
        ).first()
        if ticket is None or ticket.used_at is not None:
            await websocket.close(code=4401, reason="Invalid or already used realtime ticket")
            return
        expires_at = _as_utc(ticket.expires_at)
        if expires_at is None or expires_at <= now:
            await websocket.close(code=4401, reason="Realtime ticket expired")
            return

        user = db.query(User).filter(
            User.id == ticket.user_id,
            User.is_active.is_(True),
        ).first()
        if user is None or user.tenant_id != ticket.tenant_id:
            await websocket.close(code=4403, reason="Realtime identity is no longer valid")
            return

        ticket.used_at = now
        user_id = int(user.id)
        tenant_id = int(user.tenant_id) if user.tenant_id is not None else None
        ticket_id = int(ticket.id)
        db.add(
            AuditLog(
                event=f"realtime_ticket_consumed:{ticket.id}",
                user_id=user.id,
                tenant_id=user.tenant_id,
            )
        )
        db.commit()
    finally:
        db.close()

    await websocket.accept()
    await websocket.send_json(
        {
            "type": "connected",
            "authenticated": True,
            "tenant_scoped": tenant_id is not None,
            "ticket_id": ticket_id,
        }
    )

    messages = 0
    try:
        while messages < MAX_MESSAGES_PER_CONNECTION:
            text = await websocket.receive_text()
            messages += 1
            if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
                await websocket.close(code=1009, reason="Message too large")
                return
            if text == "ping":
                await websocket.send_json({"type": "pong"})
                continue
            await websocket.send_json(
                {
                    "type": "error",
                    "code": "unsupported_message",
                    "message": "This secure realtime foundation currently accepts only ping keepalive messages.",
                }
            )
        await websocket.close(code=1008, reason="Realtime message limit reached")
    except WebSocketDisconnect:
        return
    finally:
        if user_id is not None:
            audit_db = SessionLocal()
            try:
                audit_db.add(
                    AuditLog(
                        event=f"realtime_connection_closed:{messages}",
                        user_id=user_id,
                        tenant_id=tenant_id,
                    )
                )
                audit_db.commit()
            finally:
                audit_db.close()
