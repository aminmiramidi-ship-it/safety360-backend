import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import TenantSubscription, User
from permissions import require_permission
from schemas import BillingPlanListResponse, BillingPlanResponse, SubscriptionResponse

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]

BILLING_PROVIDER = os.getenv("BILLING_PROVIDER", "manual").strip().lower()
DEFAULT_TRIAL_DAYS = int(os.getenv("DEFAULT_TRIAL_DAYS", "30"))

PLANS = [
    BillingPlanResponse(
        code="trial",
        name="Trial",
        description="Evaluierung der Safety360 Kernfunktionen.",
        features=["core_ims", "documents", "tickets", "assistant_basic", "files"],
        commercial_activation_required=False,
    ),
    BillingPlanResponse(
        code="professional",
        name="Professional",
        description="Mandantenfähiger Betrieb für kleine und mittlere Organisationen.",
        features=[
            "core_ims",
            "documents",
            "tickets",
            "assistant",
            "files",
            "audit_trail",
            "rbac",
            "integrations",
        ],
        commercial_activation_required=True,
    ),
    BillingPlanResponse(
        code="enterprise",
        name="Enterprise",
        description="Erweiterte Governance-, Security-, Integrations- und Compliance-Funktionen.",
        features=[
            "core_ims",
            "documents",
            "tickets",
            "assistant",
            "files",
            "audit_trail",
            "advanced_rbac",
            "sso",
            "retention",
            "api",
            "integrations",
            "compliance_pack",
            "enterprise_support",
        ],
        commercial_activation_required=True,
    ),
]


def _require_tenant(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Für die Abrechnung muss ein Mandant zugeordnet sein.",
        )
    return current_user.tenant_id


def _subscription(db: Session, tenant_id: int) -> TenantSubscription:
    subscription = (
        db.query(TenantSubscription)
        .filter(TenantSubscription.tenant_id == tenant_id)
        .first()
    )
    if subscription is None:
        now = datetime.now(timezone.utc)
        subscription = TenantSubscription(
            tenant_id=tenant_id,
            plan_code="trial",
            status="trialing",
            provider=BILLING_PROVIDER,
            current_period_end=now + timedelta(days=DEFAULT_TRIAL_DAYS),
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
    return subscription


@router.get("/plans", response_model=BillingPlanListResponse)
def list_plans() -> BillingPlanListResponse:
    return BillingPlanListResponse(plans=PLANS)


@router.get("/subscription", response_model=SubscriptionResponse)
def current_subscription(
    current_user: CurrentUser,
    db: DBSession,
) -> TenantSubscription:
    require_permission(current_user, "billing.read")
    tenant_id = _require_tenant(current_user)
    return _subscription(db, tenant_id)


@router.post("/checkout", status_code=status.HTTP_501_NOT_IMPLEMENTED)
def create_checkout(current_user: CurrentUser):
    require_permission(current_user, "billing.read")
    _require_tenant(current_user)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Die kommerzielle Zahlungsabwicklung ist bewusst noch nicht an einen Zahlungsdienstleister gebunden. "
            "Safety360 verarbeitet keine Karten- oder Bankdaten selbst. Für Produktion wird ein PCI-konformer "
            "Payment Service Provider über einen separaten Adapter angebunden."
        ),
    )
