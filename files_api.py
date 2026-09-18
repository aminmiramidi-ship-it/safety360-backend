import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import AuditLog, StoredFile, User
from permissions import require_permission
from schemas import StoredFileListResponse, StoredFileResponse

router = APIRouter()

DBSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
Upload = Annotated[UploadFile, File()]

MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(100 * 1024 * 1024)))
STORAGE_PROVIDER = os.getenv("STORAGE_PROVIDER", "local").strip().lower()
STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", "./storage_data")).resolve()

BLOCKED_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".jar",
    ".msi",
    ".ps1",
    ".scr",
    ".sh",
}


def _require_tenant(current_user: User) -> int:
    if current_user.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vor der Dateiablage muss ein Mandant angelegt oder zugeordnet werden.",
        )
    return current_user.tenant_id


def _validate_local_provider() -> None:
    if STORAGE_PROVIDER != "local":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Der konfigurierte Storage-Provider ist in diesem Build noch nicht aktiviert. "
                "Für Entwicklung und Self-Hosting steht STORAGE_PROVIDER=local zur Verfügung."
            ),
        )


def _safe_suffix(filename: str | None) -> str:
    suffix = Path(filename or "file").suffix.lower()
    if suffix in BLOCKED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Dieser Dateityp ist aus Sicherheitsgründen nicht zulässig.",
        )
    return suffix[:20]


def _normalize_folder(value: str) -> str:
    parts = [part for part in value.replace("\\", "/").split("/") if part and part not in {".", ".."}]
    normalized = "/" + "/".join(parts)
    return normalized[:250] or "/"


def _tenant_file(db: Session, file_id: int, tenant_id: int, include_archived: bool = False) -> StoredFile:
    query = db.query(StoredFile).filter(
        StoredFile.id == file_id,
        StoredFile.tenant_id == tenant_id,
    )
    if not include_archived:
        query = query.filter(StoredFile.archived_at.is_(None))
    stored_file = query.first()
    if stored_file is None:
        raise HTTPException(status_code=404, detail="Datei wurde nicht gefunden.")
    return stored_file


def _physical_path(storage_key: str) -> Path:
    root = STORAGE_ROOT.resolve()
    candidate = (root / storage_key).resolve()
    if root not in candidate.parents and candidate != root:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ungültiger Speicherpfad.",
        )
    return candidate


@router.post("", response_model=StoredFileResponse, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: Upload,
    current_user: CurrentUser,
    db: DBSession,
    category: Annotated[str, Form(max_length=80)] = "general",
    folder: Annotated[str, Form(max_length=250)] = "/",
) -> StoredFile:
    require_permission(current_user, "files.upload")
    tenant_id = _require_tenant(current_user)
    _validate_local_provider()

    original_name = (file.filename or "file").strip()[:255]
    suffix = _safe_suffix(original_name)
    logical_id = str(uuid4())
    storage_key = f"tenant-{tenant_id}/{logical_id}{suffix}"
    target = _physical_path(storage_key)
    target.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    size = 0

    try:
        with target.open("wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Die hochgeladene Datei überschreitet das konfigurierte Größenlimit.",
                    )
                hasher.update(chunk)
                handle.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    stored_file = StoredFile(
        logical_id=logical_id,
        tenant_id=tenant_id,
        original_name=original_name,
        storage_key=storage_key,
        media_type=(file.content_type or "application/octet-stream")[:160],
        size_bytes=size,
        sha256=hasher.hexdigest(),
        category=(category.strip().lower() or "general")[:80],
        folder=_normalize_folder(folder),
        created_by_id=current_user.id,
    )
    db.add(stored_file)
    db.flush()
    db.add(
        AuditLog(
            event=f"file_uploaded:{stored_file.id}:{stored_file.sha256}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(stored_file)
    return stored_file


@router.get("", response_model=StoredFileListResponse)
def list_files(
    current_user: CurrentUser,
    db: DBSession,
    include_archived: bool = False,
) -> StoredFileListResponse:
    require_permission(current_user, "files.read")
    tenant_id = _require_tenant(current_user)
    query = db.query(StoredFile).filter(StoredFile.tenant_id == tenant_id)
    if not include_archived:
        query = query.filter(StoredFile.archived_at.is_(None))
    files = query.order_by(StoredFile.created_at.desc()).all()
    return StoredFileListResponse(files=files)


@router.get("/{file_id}/download")
def download_file(
    file_id: int,
    current_user: CurrentUser,
    db: DBSession,
):
    require_permission(current_user, "files.read")
    tenant_id = _require_tenant(current_user)
    _validate_local_provider()
    stored_file = _tenant_file(db, file_id, tenant_id)
    path = _physical_path(stored_file.storage_key)
    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Dateiinhalt ist im Speicher nicht verfügbar.",
        )

    db.add(
        AuditLog(
            event=f"file_downloaded:{stored_file.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()

    return FileResponse(
        path,
        media_type=stored_file.media_type or "application/octet-stream",
        filename=stored_file.original_name,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, no-store",
        },
    )


@router.post("/{file_id}/archive", response_model=StoredFileResponse)
def archive_file(
    file_id: int,
    current_user: CurrentUser,
    db: DBSession,
) -> StoredFile:
    require_permission(current_user, "files.archive")
    tenant_id = _require_tenant(current_user)
    stored_file = _tenant_file(db, file_id, tenant_id)
    stored_file.archived_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            event=f"file_archived:{stored_file.id}",
            user_id=current_user.id,
            tenant_id=tenant_id,
        )
    )
    db.commit()
    db.refresh(stored_file)
    return stored_file
