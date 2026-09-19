import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from audit_models import AuditChainHead, AuditEvent

ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").lower()
AUDIT_ACTIVE_KEY_ID = os.getenv("AUDIT_ACTIVE_KEY_ID", "v1").strip() or "v1"
AUDIT_MAX_DETAILS_BYTES = max(1024, min(int(os.getenv("AUDIT_MAX_DETAILS_BYTES", "16384")), 262144))
SENSITIVE_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "csrf",
    "session",
    "credential",
    "api_key",
    "apikey",
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _scope_key(tenant_id: int | None) -> str:
    return f"tenant:{tenant_id}" if tenant_id is not None else "global"


def _key_env_name(key_id: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", key_id).strip("_").upper()
    return f"AUDIT_INTEGRITY_KEY_{normalized or 'V1'}"


def _get_integrity_key(key_id: str) -> bytes:
    configured = os.getenv(_key_env_name(key_id))
    if configured:
        return configured.encode("utf-8")
    if ENVIRONMENT == "production":
        raise RuntimeError(
            f"{_key_env_name(key_id)} muss in Produktion für die Audit-Integritätsprüfung gesetzt sein."
        )
    return f"safety360-development-audit-key::{key_id}".encode("utf-8")


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "[depth-limit]"
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if any(marker in lowered for marker in SENSITIVE_MARKERS):
                sanitized[key] = "[redacted]"
            else:
                sanitized[key] = _sanitize_value(raw_value, depth + 1)
        return sanitized
    if isinstance(value, (list, tuple, set)):
        return [_sanitize_value(item, depth + 1) for item in list(value)[:100]]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, datetime):
        return _as_utc(value).isoformat(timespec="microseconds")
    return str(value)


def canonicalize_details(details: dict[str, Any] | None) -> str:
    sanitized = _sanitize_value(details or {})
    encoded = json.dumps(sanitized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    encoded_bytes = encoded.encode("utf-8")
    if len(encoded_bytes) <= AUDIT_MAX_DETAILS_BYTES:
        return encoded
    digest = hashlib.sha256(encoded_bytes).hexdigest()
    return json.dumps(
        {
            "details_truncated": True,
            "original_bytes": len(encoded_bytes),
            "sha256": digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _record_payload(
    *,
    event_id: str,
    scope_key: str,
    sequence: int,
    tenant_id: int | None,
    actor_user_id: int | None,
    action: str,
    object_type: str,
    object_id: str | None,
    outcome: str,
    source: str,
    request_id: str | None,
    details_json: str,
    previous_hash: str | None,
    key_id: str,
    created_at: datetime,
) -> bytes:
    payload = {
        "event_id": event_id,
        "scope_key": scope_key,
        "sequence": sequence,
        "tenant_id": tenant_id,
        "actor_user_id": actor_user_id,
        "action": action,
        "object_type": object_type,
        "object_id": object_id,
        "outcome": outcome,
        "source": source,
        "request_id": request_id,
        "details_json": details_json,
        "previous_hash": previous_hash,
        "key_id": key_id,
        "created_at": _as_utc(created_at).isoformat(timespec="microseconds"),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_payload(payload: bytes, key_id: str) -> str:
    return hmac.new(_get_integrity_key(key_id), payload, hashlib.sha256).hexdigest()


def append_audit_event(
    db: Session,
    *,
    tenant_id: int | None,
    actor_user_id: int | None,
    action: str,
    object_type: str,
    object_id: str | int | None = None,
    outcome: str = "success",
    source: str = "application",
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    scope_key = _scope_key(tenant_id)
    head = (
        db.query(AuditChainHead)
        .filter(AuditChainHead.scope_key == scope_key)
        .with_for_update()
        .first()
    )
    if head is None:
        head = AuditChainHead(
            scope_key=scope_key,
            tenant_id=tenant_id,
            last_sequence=0,
            head_hash=None,
        )
        db.add(head)
        db.flush()

    event_id = str(uuid.uuid4())
    sequence = int(head.last_sequence) + 1
    created_at = _now()
    previous_hash = head.head_hash
    key_id = AUDIT_ACTIVE_KEY_ID
    details_json = canonicalize_details(details)
    normalized_object_id = str(object_id) if object_id is not None else None
    normalized_action = action.strip().lower()[:120]
    normalized_type = object_type.strip().lower()[:120]
    normalized_outcome = outcome.strip().lower()[:30]
    normalized_source = source.strip().lower()[:80]

    record_hash = _sign_payload(
        _record_payload(
            event_id=event_id,
            scope_key=scope_key,
            sequence=sequence,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            action=normalized_action,
            object_type=normalized_type,
            object_id=normalized_object_id,
            outcome=normalized_outcome,
            source=normalized_source,
            request_id=request_id,
            details_json=details_json,
            previous_hash=previous_hash,
            key_id=key_id,
            created_at=created_at,
        ),
        key_id,
    )

    audit_event = AuditEvent(
        event_id=event_id,
        scope_key=scope_key,
        sequence=sequence,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=normalized_action,
        object_type=normalized_type,
        object_id=normalized_object_id,
        outcome=normalized_outcome,
        source=normalized_source,
        request_id=request_id,
        details_json=details_json,
        previous_hash=previous_hash,
        record_hash=record_hash,
        key_id=key_id,
        created_at=created_at,
    )
    db.add(audit_event)
    head.last_sequence = sequence
    head.head_hash = record_hash
    head.updated_at = created_at
    db.flush()
    return audit_event


def audit_event_to_dict(event: AuditEvent) -> dict[str, Any]:
    try:
        details = json.loads(event.details_json or "{}")
    except json.JSONDecodeError:
        details = {"invalid_details_json": True}
    return {
        "id": event.id,
        "event_id": event.event_id,
        "sequence": event.sequence,
        "tenant_id": event.tenant_id,
        "actor_user_id": event.actor_user_id,
        "action": event.action,
        "object_type": event.object_type,
        "object_id": event.object_id,
        "outcome": event.outcome,
        "source": event.source,
        "request_id": event.request_id,
        "details": details,
        "previous_hash": event.previous_hash,
        "record_hash": event.record_hash,
        "key_id": event.key_id,
        "created_at": _as_utc(event.created_at).isoformat(timespec="microseconds"),
    }


def verify_audit_chain(db: Session, *, tenant_id: int | None) -> dict[str, Any]:
    scope_key = _scope_key(tenant_id)
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.scope_key == scope_key)
        .order_by(AuditEvent.sequence.asc())
        .all()
    )
    head = db.query(AuditChainHead).filter(AuditChainHead.scope_key == scope_key).first()

    expected_sequence = 1
    previous_hash: str | None = None
    for event in events:
        if event.sequence != expected_sequence:
            return {
                "valid": False,
                "scope_key": scope_key,
                "checked_events": expected_sequence - 1,
                "error": f"sequence_gap_at:{event.sequence}",
            }
        if event.previous_hash != previous_hash:
            return {
                "valid": False,
                "scope_key": scope_key,
                "checked_events": expected_sequence - 1,
                "error": f"previous_hash_mismatch_at:{event.sequence}",
            }

        try:
            expected_hash = _sign_payload(
                _record_payload(
                    event_id=event.event_id,
                    scope_key=event.scope_key,
                    sequence=event.sequence,
                    tenant_id=event.tenant_id,
                    actor_user_id=event.actor_user_id,
                    action=event.action,
                    object_type=event.object_type,
                    object_id=event.object_id,
                    outcome=event.outcome,
                    source=event.source,
                    request_id=event.request_id,
                    details_json=event.details_json or "{}",
                    previous_hash=event.previous_hash,
                    key_id=event.key_id,
                    created_at=event.created_at,
                ),
                event.key_id,
            )
        except RuntimeError as exc:
            return {
                "valid": False,
                "scope_key": scope_key,
                "checked_events": expected_sequence - 1,
                "error": f"key_unavailable:{event.key_id}",
                "detail": str(exc),
            }

        if not hmac.compare_digest(event.record_hash, expected_hash):
            return {
                "valid": False,
                "scope_key": scope_key,
                "checked_events": expected_sequence - 1,
                "error": f"record_hash_mismatch_at:{event.sequence}",
            }
        previous_hash = event.record_hash
        expected_sequence += 1

    expected_last_sequence = len(events)
    if head is None:
        if events:
            return {
                "valid": False,
                "scope_key": scope_key,
                "checked_events": len(events),
                "error": "missing_chain_head",
            }
        return {
            "valid": True,
            "scope_key": scope_key,
            "checked_events": 0,
            "head_sequence": 0,
            "head_hash": None,
        }

    if head.last_sequence != expected_last_sequence or head.head_hash != previous_hash:
        return {
            "valid": False,
            "scope_key": scope_key,
            "checked_events": len(events),
            "error": "chain_head_mismatch",
            "head_sequence": head.last_sequence,
            "head_hash": head.head_hash,
        }

    return {
        "valid": True,
        "scope_key": scope_key,
        "checked_events": len(events),
        "head_sequence": head.last_sequence,
        "head_hash": head.head_hash,
    }
