from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: Optional[str] = Field(default=None, max_length=200)
    language: str = Field(default="de", min_length=2, max_length=10)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    language: str
    tenant_id: Optional[int] = None
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
    slug: Optional[str] = Field(default=None, min_length=2, max_length=100)


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    is_active: bool
    created_at: datetime


class TicketCreate(BaseModel):
    description: str = Field(min_length=1, max_length=10000)
    status: str = Field(default="open", min_length=1, max_length=50)


class TicketResponse(BaseModel):
    id: int
    description: str
    status: str
    created_by_id: int
    tenant_id: Optional[int] = None
    created_at: datetime


class TicketListResponse(BaseModel):
    tickets: List[TicketResponse]


class ExportData(BaseModel):
    lines: List[str]
