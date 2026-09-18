import os
import re
from typing import Annotated
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from auth import get_current_user
from models import User
from permissions import require_permission

router = APIRouter()

CurrentUser = Annotated[User, Depends(get_current_user)]

TRANSLATION_PROVIDER = os.getenv("TRANSLATION_PROVIDER", "disabled").strip().lower()
TRANSLATION_BASE_URL = os.getenv("TRANSLATION_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
TRANSLATION_API_KEY = os.getenv("TRANSLATION_API_KEY", "").strip()
TRANSLATION_MODEL = os.getenv("TRANSLATION_MODEL", "").strip()
TRANSLATION_TIMEOUT_SECONDS = float(os.getenv("TRANSLATION_TIMEOUT_SECONDS", "45"))
TRANSLATION_ALLOW_EXTERNAL = os.getenv("TRANSLATION_ALLOW_EXTERNAL", "false").lower() == "true"

LANGUAGE_TAG_PATTERN = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")
CRITICAL_CONTENT_CLASSES = {"hse", "legal", "standard", "security", "banking", "authority"}


class TranslationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=50000)
    source_language: str = Field(default="auto", max_length=35)
    target_language: str = Field(min_length=2, max_length=35)
    content_class: str = Field(default="general", min_length=2, max_length=40)


class TranslationResponse(BaseModel):
    translated_text: str
    source_language: str
    target_language: str
    provider: str
    model: str | None = None
    machine_translated: bool
    human_review_required: bool
    external_processing: bool


class TranslationCapabilitiesResponse(BaseModel):
    provider: str
    enabled: bool
    arbitrary_bcp47_languages: bool
    external_processing_allowed: bool
    critical_content_human_review_required: bool


def _normalize_language_tag(value: str, *, allow_auto: bool = False) -> str:
    cleaned = value.strip()
    if allow_auto and cleaned.lower() == "auto":
        return "auto"
    if not LANGUAGE_TAG_PATTERN.fullmatch(cleaned):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Ungültiger Sprachcode. Bitte einen BCP-47-Sprachcode wie de, en, fr, ar oder pt-BR verwenden.",
        )
    parts = cleaned.split("-")
    normalized = [parts[0].lower()]
    for part in parts[1:]:
        if len(part) == 2 and part.isalpha():
            normalized.append(part.upper())
        elif len(part) == 4 and part.isalpha():
            normalized.append(part.title())
        else:
            normalized.append(part.lower())
    return "-".join(normalized)


def _is_local_endpoint(url: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower()
    return hostname in {"127.0.0.1", "localhost", "::1"}


def _external_processing_required() -> bool:
    return not _is_local_endpoint(TRANSLATION_BASE_URL)


def _enforce_processing_policy() -> bool:
    external = _external_processing_required()
    if external and not TRANSLATION_ALLOW_EXTERNAL:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Externe Übersetzungsverarbeitung ist deaktiviert. Für sensible Mandantendaten muss entweder "
                "ein lokaler Übersetzungsdienst verwendet oder TRANSLATION_ALLOW_EXTERNAL ausdrücklich freigegeben werden."
            ),
        )
    return external


def _translate_libretranslate(text: str, source: str, target: str) -> tuple[str, str | None]:
    payload: dict[str, str] = {
        "q": text,
        "source": source,
        "target": target,
        "format": "text",
    }
    if TRANSLATION_API_KEY:
        payload["api_key"] = TRANSLATION_API_KEY
    response = httpx.post(
        f"{TRANSLATION_BASE_URL}/translate",
        json=payload,
        timeout=TRANSLATION_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    translated = str(response.json()["translatedText"])
    return translated, None


def _translate_openai_compatible(text: str, source: str, target: str) -> tuple[str, str | None]:
    if not TRANSLATION_MODEL:
        raise RuntimeError("TRANSLATION_MODEL ist nicht gesetzt.")
    headers = {"Content-Type": "application/json"}
    if TRANSLATION_API_KEY:
        headers["Authorization"] = f"Bearer {TRANSLATION_API_KEY}"
    system_prompt = (
        "Translate the provided content faithfully into the requested target language. Preserve structure, numbers, "
        "technical terms, identifiers and warnings. Do not invent legal, ISO, safety or compliance requirements. "
        "Return only the translated content."
    )
    response = httpx.post(
        f"{TRANSLATION_BASE_URL}/chat/completions",
        headers=headers,
        json={
            "model": TRANSLATION_MODEL,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"Source language: {source}\nTarget language: {target}\n\n{text}",
                },
            ],
        },
        timeout=TRANSLATION_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    translated = str(response.json()["choices"][0]["message"]["content"])
    return translated, TRANSLATION_MODEL


@router.get("/capabilities", response_model=TranslationCapabilitiesResponse)
def translation_capabilities(current_user: CurrentUser) -> TranslationCapabilitiesResponse:
    require_permission(current_user, "translation.use")
    return TranslationCapabilitiesResponse(
        provider=TRANSLATION_PROVIDER,
        enabled=TRANSLATION_PROVIDER != "disabled",
        arbitrary_bcp47_languages=True,
        external_processing_allowed=TRANSLATION_ALLOW_EXTERNAL,
        critical_content_human_review_required=True,
    )


@router.post("", response_model=TranslationResponse)
def translate(
    data: TranslationRequest,
    current_user: CurrentUser,
) -> TranslationResponse:
    require_permission(current_user, "translation.use")
    source = _normalize_language_tag(data.source_language, allow_auto=True)
    target = _normalize_language_tag(data.target_language)
    content_class = data.content_class.strip().lower()

    if source != "auto" and source.lower() == target.lower():
        return TranslationResponse(
            translated_text=data.text,
            source_language=source,
            target_language=target,
            provider="identity",
            model=None,
            machine_translated=False,
            human_review_required=content_class in CRITICAL_CONTENT_CLASSES,
            external_processing=False,
        )

    if TRANSLATION_PROVIDER == "disabled":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Der Übersetzungsdienst ist in dieser Umgebung deaktiviert.",
        )

    external_processing = _enforce_processing_policy()
    try:
        if TRANSLATION_PROVIDER == "libretranslate":
            translated, model = _translate_libretranslate(data.text, source, target)
        elif TRANSLATION_PROVIDER == "openai_compatible":
            translated, model = _translate_openai_compatible(data.text, source, target)
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

    return TranslationResponse(
        translated_text=translated,
        source_language=source,
        target_language=target,
        provider=TRANSLATION_PROVIDER,
        model=model,
        machine_translated=True,
        human_review_required=content_class in CRITICAL_CONTENT_CLASSES,
        external_processing=external_processing,
    )
