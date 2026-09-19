import os
import re
from typing import Annotated, Literal
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, User
from permissions import require_permission
from schemas import PlatformCapabilitiesResponse

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

BCP47_RE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")
TRANSLATION_CRITICALITIES = {"normal", "hse_critical", "legal", "security", "quality"}


class TranslationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=30000)
    source_language: str = Field(default="auto", min_length=2, max_length=35)
    target_language: str = Field(min_length=2, max_length=35)
    criticality: Literal["normal", "hse_critical", "legal", "security", "quality"] = "normal"


class TranslationResponse(BaseModel):
    source_language: str
    target_language: str
    translated_text: str
    provider: str
    model: str | None = None
    machine_translated: bool
    requires_human_review: bool


class TranslationLanguage(BaseModel):
    code: str
    name: str
    targets: list[str] = Field(default_factory=list)


class TranslationLanguageListResponse(BaseModel):
    provider: str
    languages: list[TranslationLanguage]
    accepts_bcp47: bool = True


def _translation_provider() -> str:
    return os.getenv("TRANSLATION_PROVIDER", "disabled").strip().lower()


def _translation_base_url() -> str:
    return os.getenv("TRANSLATION_BASE_URL", "http://127.0.0.1:5000").rstrip("/")


def _translation_timeout() -> float:
    return float(os.getenv("TRANSLATION_TIMEOUT_SECONDS", "45"))


def _external_allowed() -> bool:
    return os.getenv("TRANSLATION_ALLOW_EXTERNAL", "false").strip().lower() == "true"


def _is_local_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _validate_language(code: str, *, allow_auto: bool = False) -> str:
    normalized = code.strip()
    if allow_auto and normalized.lower() == "auto":
        return "auto"
    if not BCP47_RE.fullmatch(normalized):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Ungültiger Sprachcode. Safety360 erwartet einen BCP-47-Sprachcode, z. B. de, en, de-DE oder ar-SA.",
        )
    return normalized


def _require_external_approval(base_url: str) -> None:
    if not _is_local_url(base_url) and not _external_allowed():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Externe Übersetzungsverarbeitung ist für diese Umgebung nicht freigegeben. "
                "Für sensible Mandantendaten muss ein genehmigter lokaler Dienst verwendet oder "
                "TRANSLATION_ALLOW_EXTERNAL ausdrücklich aktiviert werden."
            ),
        )


def _libretranslate(
    text: str,
    source_language: str,
    target_language: str,
) -> tuple[str, str | None]:
    base_url = _translation_base_url()
    _require_external_approval(base_url)
    api_key = os.getenv("TRANSLATION_API_KEY", "").strip()
    payload: dict[str, object] = {
        "q": text,
        "source": source_language,
        "target": target_language,
        "format": "text",
    }
    if api_key:
        payload["api_key"] = api_key

    response = httpx.post(
        f"{base_url}/translate",
        json=payload,
        timeout=_translation_timeout(),
    )
    response.raise_for_status()
    data = response.json()
    translated_text = data.get("translatedText")
    if not isinstance(translated_text, str) or not translated_text.strip():
        raise ValueError("Übersetzungsdienst lieferte keinen Text.")
    return translated_text, None


def _openai_compatible(
    text: str,
    source_language: str,
    target_language: str,
) -> tuple[str, str | None]:
    base_url = _translation_base_url()
    _require_external_approval(base_url)
    model = os.getenv("TRANSLATION_MODEL", "").strip()
    api_key = os.getenv("TRANSLATION_API_KEY", "").strip()
    if not model:
        raise RuntimeError("TRANSLATION_MODEL ist nicht gesetzt.")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    source_instruction = "automatisch erkennen" if source_language == "auto" else source_language
    system_prompt = (
        "Du bist die Safety360 Übersetzungsengine. Übersetze fachlich präzise und vollständig. "
        "Erhalte Struktur, Nummerierungen, Tabellenmarker, technische Begriffe, Produktnamen, "
        "ISO-/EN-/IEC-Kennzeichnungen, Paragraphen- und Quellenangaben. Erfinde nichts, ergänze nichts "
        "und gib ausschließlich die Übersetzung zurück."
    )
    user_prompt = (
        f"Ausgangssprache: {source_instruction}\nZielsprache: {target_language}\n\n{text}"
    )

    response = httpx.post(
        f"{base_url}/chat/completions",
        headers=headers,
        json={
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
        timeout=_translation_timeout(),
    )
    response.raise_for_status()
    data = response.json()
    translated_text = data["choices"][0]["message"]["content"]
    if not isinstance(translated_text, str) or not translated_text.strip():
        raise ValueError("Übersetzungsdienst lieferte keinen Text.")
    return translated_text, model


def _provider_languages() -> list[TranslationLanguage]:
    provider = _translation_provider()
    if provider != "libretranslate":
        return []

    base_url = _translation_base_url()
    _require_external_approval(base_url)
    response = httpx.get(f"{base_url}/languages", timeout=_translation_timeout())
    response.raise_for_status()
    data = response.json()
    languages: list[TranslationLanguage] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code", "")).strip()
        name = str(item.get("name", code)).strip()
        targets = [str(value) for value in item.get("targets", []) if value]
        if code:
            languages.append(TranslationLanguage(code=code, name=name or code, targets=targets))
    return languages


@router.get("/capabilities", response_model=PlatformCapabilitiesResponse)
def capabilities() -> PlatformCapabilitiesResponse:
    environment = os.getenv("SAFETY360_ENV", "development").lower()
    storage_provider = os.getenv("STORAGE_PROVIDER", "local").lower()
    assistant_provider = os.getenv("AI_PROVIDER", "rules").lower()
    billing_provider = os.getenv("BILLING_PROVIDER", "manual").lower()
    translation_provider = _translation_provider()

    return PlatformCapabilitiesResponse(
        environment=environment,
        storage_provider=storage_provider,
        assistant_provider=assistant_provider,
        billing_provider=billing_provider,
        features={
            "multi_tenant": True,
            "rbac": True,
            "document_control": True,
            "file_storage": True,
            "assistant": assistant_provider != "disabled",
            "translation": translation_provider != "disabled",
            "ims_orchestration": True,
            "agent_orchestration": True,
            "adaptive_feedback": True,
            "human_in_the_loop": True,
            "billing_foundation": True,
            "external_payment_processing": billing_provider not in {"manual", "disabled"},
            "production_migrations": True,
        },
    )


@router.get("/translation/languages", response_model=TranslationLanguageListResponse)
def translation_languages(
    current_user: CurrentUser,
) -> TranslationLanguageListResponse:
    require_permission(current_user, "translation.use")
    provider = _translation_provider()
    if provider == "disabled":
        return TranslationLanguageListResponse(provider=provider, languages=[])

    try:
        languages = _provider_languages()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Die Sprachliste des konfigurierten Übersetzungsdienstes ist momentan nicht verfügbar.",
        ) from exc

    return TranslationLanguageListResponse(provider=provider, languages=languages)


@router.post("/translation/translate", response_model=TranslationResponse)
def translate(
    data: TranslationRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> TranslationResponse:
    require_permission(current_user, "translation.use")

    source_language = _validate_language(data.source_language, allow_auto=True)
    target_language = _validate_language(data.target_language)
    criticality = data.criticality.strip().lower()
    if criticality not in TRANSLATION_CRITICALITIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unbekannte Kritikalitätsstufe.",
        )

    if source_language.lower() == target_language.lower():
        translated_text = data.text
        provider = "identity"
        model = None
        machine_translated = False
    else:
        provider = _translation_provider()
        try:
            if provider == "libretranslate":
                translated_text, model = _libretranslate(
                    data.text,
                    source_language,
                    target_language,
                )
            elif provider == "openai_compatible":
                translated_text, model = _openai_compatible(
                    data.text,
                    source_language,
                    target_language,
                )
            elif provider == "disabled":
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Die Übersetzungsfunktion ist in dieser Umgebung deaktiviert.",
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Der konfigurierte Übersetzungsanbieter wird nicht unterstützt.",
                )
        except HTTPException:
            raise
        except (httpx.HTTPError, KeyError, RuntimeError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Der konfigurierte Übersetzungsdienst ist momentan nicht verfügbar.",
            ) from exc
        machine_translated = True

    requires_human_review = machine_translated and criticality != "normal"

    db.add(
        AuditLog(
            event=(
                "translation_requested:"
                f"{provider}:{source_language}:{target_language}:{criticality}:"
                f"review={str(requires_human_review).lower()}"
            ),
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
        )
    )
    db.commit()

    return TranslationResponse(
        source_language=source_language,
        target_language=target_language,
        translated_text=translated_text,
        provider=provider,
        model=model,
        machine_translated=machine_translated,
        requires_human_review=requires_human_review,
    )
