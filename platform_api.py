import os

from fastapi import APIRouter

from schemas import PlatformCapabilitiesResponse

router = APIRouter()


@router.get("/capabilities", response_model=PlatformCapabilitiesResponse)
def capabilities() -> PlatformCapabilitiesResponse:
    environment = os.getenv("SAFETY360_ENV", "development").lower()
    storage_provider = os.getenv("STORAGE_PROVIDER", "local").lower()
    assistant_provider = os.getenv("AI_PROVIDER", "rules").lower()
    billing_provider = os.getenv("BILLING_PROVIDER", "manual").lower()
    translation_provider = os.getenv("TRANSLATION_PROVIDER", "disabled").lower()

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
            "billing_foundation": True,
            "external_payment_processing": billing_provider not in {"manual", "disabled"},
            "production_migrations": True,
        },
    )
