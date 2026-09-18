from datetime import datetime

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


class ExportData(BaseModel):
    lines: list[str]
