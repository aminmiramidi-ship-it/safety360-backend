import os
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import (
    AssistantMessage,
    AssistantThread,
    AuditLog,
    Document,
    StoredFile,
    User,
)
from permissions import require_permission
from schemas import (
    AssistantMessageCreate,
    AssistantMessageResponse,
    AssistantThreadCreate,
    AssistantThreadListResponse,
    AssistantThreadResponse,
    AssistantTurnResponse,
)

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

AI_PROVIDER = os.getenv("AI_PROVIDER", "rules").strip().lower()
AI_BASE_URL = os.getenv("AI_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
AI_MODEL = os.getenv("AI_MODEL", "").strip()
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
AI_TIMEOUT_SECONDS = float(os.getenv("AI_TIMEOUT_SECONDS", "45"))
AI_ALLOW_DOCUMENT_SUMMARIES = os.getenv("AI_ALLOW_DOCUMENT_SUMMARIES", "false").lower() == "true"

SYSTEM_PROMPT = (
    "Du bist der Safety360 Assistent für ein integriertes Managementsystem. "
    "Arbeite sachlich, risikoorientiert und nachvollziehbar. Erfinde keine gesetzlichen Pflichten, "
    "Normforderungen oder Freigaben. Kennzeichne Unsicherheit. Bei sicherheits-, rechts- oder "
    "compliancekritischen Entscheidungen sollst du eine menschliche Prüfung empfehlen. "
    "Nutze nur den bereitgestellten Mandantenkontext und vermische niemals Daten verschiedener Mandanten."
)


def _require_tenant(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für den Assistenten muss ein Mandant zugeordnet sein.",
        )
    return current_user.tenant_id


def _tenant_thread(db: Session, thread_id: int, tenant_id: int) -> AssistantThread:
    thread = (
        db.query(AssistantThread)
        .filter(
            AssistantThread.id == thread_id,
            AssistantThread.tenant_id == tenant_id,
        )
        .first()
    )
    if thread is None:
        raise HTTPException(status_code=404, detail="Assistenten-Thread wurde nicht gefunden.")
    return thread


def _tenant_context(db: Session, tenant_id: int) -> str:
    documents = (
        db.query(Document)
        .filter(Document.tenant_id == tenant_id)
        .order_by(Document.updated_at.desc())
        .limit(20)
        .all()
    )
    file_count = (
        db.query(StoredFile)
        .filter(
            StoredFile.tenant_id == tenant_id,
            StoredFile.archived_at.is_(None),
        )
        .count()
    )

    document_lines: list[str] = []
    for document in documents:
        line = f"- {document.title} | Typ={document.document_type} | Status={document.status} | Version={document.version}"
        if AI_ALLOW_DOCUMENT_SUMMARIES and document.content_summary:
            line += f" | Kurzinhalt={document.content_summary[:1000]}"
        document_lines.append(line)

    documents_text = "\n".join(document_lines) if document_lines else "- Keine Dokumente vorhanden"
    return (
        f"Mandantenkontext:\nAktive Dateien: {file_count}\n"
        f"Letzte kontrollierte Dokumente:\n{documents_text}"
    )


def _recent_messages(db: Session, thread_id: int, tenant_id: int) -> list[dict[str, str]]:
    messages = (
        db.query(AssistantMessage)
        .filter(
            AssistantMessage.thread_id == thread_id,
            AssistantMessage.tenant_id == tenant_id,
        )
        .order_by(AssistantMessage.created_at.desc())
        .limit(12)
        .all()
    )
    messages.reverse()
    return [{"role": message.role, "content": message.content} for message in messages]


def _rules_reply(user_text: str, context: str) -> str:
    lowered = user_text.lower()
    if any(term in lowered for term in ("audit", "finding", "abweich", "maßnahme", "massnahme")):
        guidance = (
            "Für einen belastbaren Audit-/Maßnahmenprozess würde ich zuerst Nachweis, Verantwortlichen, "
            "Fälligkeit, Ursache, Maßnahme und Wirksamkeitsprüfung strukturiert erfassen."
        )
    elif any(term in lowered for term in ("gefahr", "risiko", "gbu", "gefährdungsbeurteilung")):
        guidance = (
            "Für die Risikobeurteilung sollten Tätigkeit, Gefährdungen, bestehende Schutzmaßnahmen, "
            "Restrisiko, zusätzliche Maßnahmen, Verantwortliche und Prüftermin miteinander verknüpft werden."
        )
    elif any(term in lowered for term in ("dokument", "betriebsanweisung", "unterweisung")):
        guidance = (
            "Ich würde den kontrollierten Dokumentenprozess nutzen: Entwurf, Review, Freigabe, Versionierung, "
            "Verteilung, Unterweisungsbezug und spätere Revision mit Audit-Trail."
        )
    else:
        guidance = (
            "Ich kann den Vorgang in einen nachvollziehbaren Safety360-Workflow zerlegen und die benötigten "
            "Nachweise, Rollen und Folgeschritte strukturieren."
        )

    return (
        f"{guidance}\n\n{context}\n\n"
        "Hinweis: Rechts-, Norm- und Sicherheitsentscheidungen müssen bei kritischen Fällen anhand der "
        "aktuellen Primärquelle und durch eine verantwortliche Person geprüft werden."
    )


def _call_ollama(messages: list[dict[str, str]]) -> tuple[str, str | None]:
    if not AI_MODEL:
        raise RuntimeError("AI_MODEL ist für AI_PROVIDER=ollama nicht gesetzt.")
    response = httpx.post(
        f"{AI_BASE_URL}/api/chat",
        json={"model": AI_MODEL, "messages": messages, "stream": False},
        timeout=AI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    return str(payload["message"]["content"]), AI_MODEL


def _call_openai_compatible(messages: list[dict[str, str]]) -> tuple[str, str | None]:
    if not AI_MODEL or not AI_API_KEY:
        raise RuntimeError("AI_MODEL und AI_API_KEY müssen für AI_PROVIDER=openai_compatible gesetzt sein.")
    response = httpx.post(
        f"{AI_BASE_URL}/chat/completions",
        headers={"Authorization": f"Bearer {AI_API_KEY}"},
        json={"model": AI_MODEL, "messages": messages, "temperature": 0.1},
        timeout=AI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    return str(payload["choices"][0]["message"]["content"]), AI_MODEL


def _assistant_reply(db: Session, thread: AssistantThread, user_text: str) -> tuple[str, str, str | None]:
    context = _tenant_context(db, thread.tenant_id)
    if AI_PROVIDER == "disabled":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Der KI-Assistent ist in dieser Umgebung deaktiviert.",
        )
    if AI_PROVIDER == "rules":
        return _rules_reply(user_text, context), "rules", None

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": context},
        *_recent_messages(db, thread.id, thread.tenant_id),
        {"role": "user", "content": user_text},
    ]
    try:
        if AI_PROVIDER == "ollama":
            content, model = _call_ollama(messages)
            return content, "ollama", model
        if AI_PROVIDER == "openai_compatible":
            content, model = _call_openai_compatible(messages)
            return content, "openai_compatible", model
    except (httpx.HTTPError, KeyError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Der konfigurierte KI-Dienst ist momentan nicht verfügbar.",
        ) from exc

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="AI_PROVIDER ist nicht unterstützt.",
    )


@router.post("/threads", response_model=AssistantThreadResponse, status_code=status.HTTP_201_CREATED)
def create_thread(
    data: AssistantThreadCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> AssistantThread:
    require_permission(current_user, "assistant.use")
    tenant_id = _require_tenant(current_user)
    thread = AssistantThread(
        tenant_id=tenant_id,
        title=data.title.strip(),
        created_by_id=current_user.id,
    )
    db.add(thread)
    db.flush()
    db.add(
        AuditLog(
            event=f"assistant_thread_created:{thread.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(thread)
    return thread


@router.get("/threads", response_model=AssistantThreadListResponse)
def list_threads(
    current_user: CurrentUser,
    db: DBSession,
) -> AssistantThreadListResponse:
    require_permission(current_user, "assistant.use")
    tenant_id = _require_tenant(current_user)
    threads = (
        db.query(AssistantThread)
        .filter(AssistantThread.tenant_id == tenant_id)
        .order_by(AssistantThread.updated_at.desc())
        .limit(100)
        .all()
    )
    return AssistantThreadListResponse(threads=threads)


@router.post("/threads/{thread_id}/messages", response_model=AssistantTurnResponse)
def create_message(
    thread_id: int,
    data: AssistantMessageCreate,
    current_user: CurrentUser,
    db: DBSession,
) -> AssistantTurnResponse:
    require_permission(current_user, "assistant.use")
    tenant_id = _require_tenant(current_user)
    thread = _tenant_thread(db, thread_id, tenant_id)
    user_text = data.content.strip()

    user_message = AssistantMessage(
        thread_id=thread.id,
        tenant_id=tenant_id,
        role="user",
        content=user_text,
        provider="user",
        model=None,
        created_by_id=current_user.id,
    )
    db.add(user_message)
    db.flush()

    reply_text, provider, model = _assistant_reply(db, thread, user_text)
    assistant_message = AssistantMessage(
        thread_id=thread.id,
        tenant_id=tenant_id,
        role="assistant",
        content=reply_text,
        provider=provider,
        model=model,
        created_by_id=None,
    )
    db.add(assistant_message)
    db.add(
        AuditLog(
            event=f"assistant_turn:{thread.id}:{provider}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(user_message)
    db.refresh(assistant_message)
    return AssistantTurnResponse(
        user_message=AssistantMessageResponse.model_validate(user_message),
        assistant_message=AssistantMessageResponse.model_validate(assistant_message),
    )
