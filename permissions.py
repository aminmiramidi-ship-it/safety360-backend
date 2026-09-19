from fastapi import HTTPException, status

from models import User

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "user": {
        "dashboard.read",
        "tickets.read",
        "tickets.create",
        "documents.read",
        "documents.create",
        "files.read",
        "files.upload",
        "assistant.use",
        "translation.use",
        "agents.use",
        "agents.feedback",
        "ims.read",
    },
    "viewer": {
        "dashboard.read",
        "tickets.read",
        "documents.read",
        "files.read",
        "assistant.use",
        "translation.use",
        "agents.use",
        "ims.read",
    },
    "manager": {
        "dashboard.read",
        "tickets.read",
        "tickets.create",
        "documents.read",
        "documents.create",
        "files.read",
        "files.upload",
        "assistant.use",
        "translation.use",
        "agents.use",
        "agents.feedback",
        "ims.read",
        "ims.create",
        "ims.generate",
    },
    "hse_manager": {
        "dashboard.read",
        "tickets.read",
        "tickets.create",
        "documents.read",
        "documents.create",
        "documents.approve",
        "files.read",
        "files.upload",
        "files.archive",
        "assistant.use",
        "translation.use",
        "agents.use",
        "agents.feedback",
        "ims.read",
        "ims.create",
        "ims.generate",
        "ims.approve",
    },
    "document_controller": {
        "dashboard.read",
        "tickets.read",
        "documents.read",
        "documents.create",
        "documents.approve",
        "files.read",
        "files.upload",
        "files.archive",
        "assistant.use",
        "translation.use",
        "agents.use",
        "agents.feedback",
        "ims.read",
        "ims.approve",
    },
    "tenant_admin": {
        "dashboard.read",
        "tickets.read",
        "tickets.create",
        "documents.read",
        "documents.create",
        "documents.approve",
        "files.read",
        "files.upload",
        "files.archive",
        "assistant.use",
        "translation.use",
        "agents.use",
        "agents.feedback",
        "tenant.invite",
        "tenant.manage",
        "sso.manage",
        "billing.read",
        "ims.read",
        "ims.create",
        "ims.generate",
        "ims.approve",
    },
    "admin": {"*"},
}


def has_permission(user: User, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(user.role, set())
    return "*" in permissions or permission in permissions


def require_permission(user: User, permission: str) -> None:
    if not has_permission(user, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Für diese Aktion fehlen die erforderlichen Berechtigungen.",
        )
