from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=200)
    language: str = Field(default="de", min_length=2, max_length=10)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: str | None = None
    role: str
    language: str
    tenant_id: int | None = None
    is_active: bool
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class DashboardResponse(BaseModel):
    message: str
    user: UserResponse


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str | None = Field(default=None, min_length=2, max_length=100)


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    is_active: bool
    created_at: datetime


class TenantInvitationCreate(BaseModel):
    email: EmailStr
    role: str = Field(default="user", min_length=2, max_length=50)
    expires_in_hours: int = Field(default=72, ge=1, le=168)


class TenantInvitationAccept(BaseModel):
    invitation_token: str = Field(min_length=32, max_length=512)


class TenantInvitationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    email: EmailStr
    role: str
    created_by_id: int
    expires_at: datetime
    accepted_at: datetime | None = None
    created_at: datetime


class TenantInvitationCreated(TenantInvitationResponse):
    invitation_token: str


class TenantInvitationListResponse(BaseModel):
    invitations: list[TenantInvitationResponse]


class TicketCreate(BaseModel):
    description: str = Field(min_length=1, max_length=10000)
    status: str = Field(default="open", min_length=1, max_length=50)


class TicketResponse(BaseModel):
    id: int
    description: str
    status: str
    created_by_id: int
    tenant_id: int | None = None
    created_at: datetime


class TicketListResponse(BaseModel):
    tickets: list[TicketResponse]


class DocumentCreate(BaseModel):
    title: str = Field(min_length=2, max_length=250)
    document_type: str = Field(min_length=2, max_length=80)
    content_summary: str | None = Field(default=None, max_length=20000)


class DocumentRevisionCreate(BaseModel):
    title: str | None = Field(default=None, min_length=2, max_length=250)
    content_summary: str | None = Field(default=None, max_length=20000)


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    logical_id: str
    title: str
    document_type: str
    status: str
    version: int
    content_summary: str | None = None
    tenant_id: int
    created_by_id: int
    approved_by_id: int | None = None
    approved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class DocumentListResponse(BaseModel):
    documents: list[DocumentResponse]


class IMSActivityCreate(BaseModel):
    title: str = Field(min_length=2, max_length=250)
    description: str = Field(min_length=5, max_length=30000)
    industry: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=250)
    equipment: str | None = Field(default=None, max_length=12000)
    substances: str | None = Field(default=None, max_length=12000)
    environmental_context: str | None = Field(default=None, max_length=12000)
    energy_context: str | None = Field(default=None, max_length=12000)
    quality_context: str | None = Field(default=None, max_length=12000)
    information_security_context: str | None = Field(default=None, max_length=12000)


class IMSActivityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    title: str
    description: str
    industry: str | None = None
    location: str | None = None
    equipment: str | None = None
    substances: str | None = None
    environmental_context: str | None = None
    energy_context: str | None = None
    quality_context: str | None = None
    information_security_context: str | None = None
    status: str
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class IMSActivityListResponse(BaseModel):
    activities: list[IMSActivityResponse]


class IMSGenerationRequest(BaseModel):
    standards: list[str] = Field(
        default_factory=lambda: [
            "ISO 45001",
            "ISO 14001",
            "ISO 50001",
            "ISO 9001",
            "ISO/IEC 27001",
            "EN 50600",
        ],
        min_length=1,
        max_length=30,
    )
    artifact_types: list[str] = Field(
        default_factory=lambda: [
            "risk_assessment",
            "operating_instruction",
            "training_plan",
            "ims_requirements_map",
        ],
        min_length=1,
        max_length=20,
    )


class IMSArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    activity_id: int
    logical_id: str
    artifact_type: str
    title: str
    version: int
    status: str
    content: dict[str, Any]
    standards: list[str]
    generation_mode: str
    created_by_id: int
    approved_by_id: int | None = None
    approved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class IMSArtifactListResponse(BaseModel):
    artifacts: list[IMSArtifactResponse]


class IMSGenerationResponse(BaseModel):
    activity: IMSActivityResponse
    artifacts: list[IMSArtifactResponse]
    warnings: list[str]


class StandardRegistryItem(BaseModel):
    identifier: str
    domain: str
    purpose: str
    implementation_note: str


class StandardRegistryResponse(BaseModel):
    standards: list[StandardRegistryItem]


class StoredFileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    logical_id: str
    tenant_id: int
    original_name: str
    media_type: str | None = None
    size_bytes: int
    sha256: str
    category: str
    folder: str
    created_by_id: int
    archived_at: datetime | None = None
    created_at: datetime


class StoredFileListResponse(BaseModel):
    files: list[StoredFileResponse]


class AssistantThreadCreate(BaseModel):
    title: str = Field(default="Safety360 Assistant", min_length=2, max_length=250)


class AssistantThreadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    title: str
    created_by_id: int
    created_at: datetime
    updated_at: datetime


class AssistantThreadListResponse(BaseModel):
    threads: list[AssistantThreadResponse]


class AssistantMessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=12000)


class AssistantMessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    thread_id: int
    tenant_id: int
    role: str
    content: str
    provider: str
    model: str | None = None
    created_by_id: int | None = None
    created_at: datetime


class AssistantTurnResponse(BaseModel):
    user_message: AssistantMessageResponse
    assistant_message: AssistantMessageResponse


class SubscriptionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    plan_code: str
    status: str
    provider: str
    current_period_end: datetime | None = None
    created_at: datetime
    updated_at: datetime


class BillingPlanResponse(BaseModel):
    code: str
    name: str
    description: str
    features: list[str]
    commercial_activation_required: bool


class BillingPlanListResponse(BaseModel):
    plans: list[BillingPlanResponse]


class PlatformCapabilitiesResponse(BaseModel):
    environment: str
    storage_provider: str
    assistant_provider: str
    billing_provider: str
    features: dict[str, bool]


class ExportData(BaseModel):
    lines: list[str]
