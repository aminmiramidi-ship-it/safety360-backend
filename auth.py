import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from models import AuditLog, User
from schemas import LoginRequest, TokenResponse, UserCreate, UserResponse
from session_models import BrowserSession

router = APIRouter()
security = HTTPBearer(auto_error=False)

ALGORITHM = "HS256"
TOKEN_TYPE = "bearer"  # nosec B105
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ENVIRONMENT = os.getenv("SAFETY360_ENV", "development").lower()
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "safety360_session")
CSRF_COOKIE_NAME = os.getenv("CSRF_COOKIE_NAME", "safety360_csrf")
SESSION_TTL_MINUTES = max(15, min(int(os.getenv("BROWSER_SESSION_TTL_MINUTES", "480")), 10080))
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "lax").strip().lower()
SESSION_COOKIE_SECURE = ENVIRONMENT == "production" or os.getenv(
    "SESSION_COOKIE_SECURE",
    "false",
).strip().lower() in {"1", "true", "yes", "on"}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

if SESSION_COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    raise RuntimeError("SESSION_COOKIE_SAMESITE muss lax, strict oder none sein.")
if SESSION_COOKIE_SAMESITE == "none" and not SESSION_COOKIE_SECURE:
    raise RuntimeError("SameSite=None ist nur mit sicheren Cookies zulässig.")

SECRET_KEY = os.getenv("SAFETY360_SECRET_KEY")
if not SECRET_KEY:
    if ENVIRONMENT == "production":
        raise RuntimeError(
            "SAFETY360_SECRET_KEY muss in der Produktionsumgebung gesetzt sein."
        )
    SECRET_KEY = secrets.token_urlsafe(64)
    print(
        "[WARNING] SAFETY360_SECRET_KEY ist nicht gesetzt. "
        "Für diese Development-Session wurde ein temporärer Schlüssel erzeugt."
    )

DBSession = Annotated[Session, Depends(get_db)]
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(security),
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _auth_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Ungültige oder abgelaufene Anmeldung.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _password_bytes(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) > 72:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Das Passwort darf in UTF-8 höchstens 72 Bytes lang sein.",
        )
    return encoded


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            _password_bytes(plain_password),
            password_hash.encode("utf-8"),
        )
    except (ValueError, HTTPException):
        return False


def _authenticate_password(login_data: LoginRequest, db: Session) -> User:
    normalized_email = str(login_data.email).strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if user is None or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-Mail-Adresse oder Passwort ist ungültig.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dieses Benutzerkonto ist deaktiviert.",
        )

    return user


def create_access_token(user: User) -> str:
    now = _now()
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "language": user.language,
        "tenant_id": user.tenant_id,
        "iat": now,
        "exp": expires_at,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _user_from_bearer(credentials: HTTPAuthorizationCredentials, db: Session) -> User:
    if credentials.scheme.lower() != TOKEN_TYPE:
        raise _auth_error()

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
        user_id = int(payload.get("sub"))
    except (InvalidTokenError, TypeError, ValueError):
        raise _auth_error()

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if user is None:
        raise _auth_error()
    return user


def _user_from_browser_session(request: Request, db: Session) -> User | None:
    raw_session = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_session or len(raw_session) > 512:
        return None

    browser_session = db.query(BrowserSession).filter(
        BrowserSession.session_hash == _hash_secret(raw_session)
    ).first()
    if browser_session is None or browser_session.revoked_at is not None:
        return None

    expires_at = _as_utc(browser_session.expires_at)
    if expires_at is None or expires_at <= _now():
        return None

    user = db.query(User).filter(
        User.id == browser_session.user_id,
        User.is_active.is_(True),
    ).first()
    if user is None:
        return None

    if request.method.upper() in UNSAFE_METHODS:
        csrf_header = request.headers.get("X-CSRF-Token")
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        if (
            not csrf_header
            or not csrf_cookie
            or not secrets.compare_digest(csrf_header, csrf_cookie)
            or not secrets.compare_digest(
                _hash_secret(csrf_header),
                browser_session.csrf_hash,
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF-Prüfung fehlgeschlagen.",
            )

    return user


def get_current_user(
    request: Request,
    credentials: BearerCredentials,
    db: DBSession,
) -> User:
    if credentials is not None:
        return _user_from_bearer(credentials, db)

    user = _user_from_browser_session(request, db)
    if user is None:
        raise _auth_error()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def _set_browser_session_cookies(
    response: Response,
    session_token: str,
    csrf_token: str,
    expires_at: datetime,
) -> None:
    max_age = SESSION_TTL_MINUTES * 60
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=max_age,
        expires=expires_at,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age,
        expires=expires_at,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=False,
        samesite=SESSION_COOKIE_SAMESITE,
    )


def _clear_browser_session_cookies(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
    )
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        path="/",
        secure=SESSION_COOKIE_SECURE,
        httponly=False,
        samesite=SESSION_COOKIE_SAMESITE,
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(user_data: UserCreate, db: DBSession) -> User:
    normalized_email = str(user_data.email).strip().lower()

    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Diese E-Mail-Adresse ist bereits registriert.",
        )

    new_user = User(
        email=normalized_email,
        password_hash=hash_password(user_data.password),
        full_name=user_data.full_name,
        role="user",
        language=user_data.language.lower(),
        tenant_id=None,
        is_active=True,
    )

    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Diese E-Mail-Adresse ist bereits registriert.",
        )

    db.refresh(new_user)
    return new_user


@router.post("/login", response_model=TokenResponse)
def login(login_data: LoginRequest, db: DBSession) -> TokenResponse:
    user = _authenticate_password(login_data, db)
    token = create_access_token(user)
    return TokenResponse(
        access_token=token,
        token_type=TOKEN_TYPE,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/session/login", response_model=UserResponse)
def browser_session_login(
    login_data: LoginRequest,
    response: Response,
    db: DBSession,
) -> User:
    user = _authenticate_password(login_data, db)
    session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(minutes=SESSION_TTL_MINUTES)

    browser_session = BrowserSession(
        session_hash=_hash_secret(session_token),
        csrf_hash=_hash_secret(csrf_token),
        user_id=user.id,
        tenant_id=user.tenant_id,
        expires_at=expires_at,
    )
    db.add(browser_session)
    db.flush()
    db.add(
        AuditLog(
            event=f"browser_session_created:{browser_session.id}",
            user_id=user.id,
            tenant_id=user.tenant_id,
        )
    )
    db.commit()

    _set_browser_session_cookies(response, session_token, csrf_token, expires_at)
    return user


@router.post("/session/logout")
def browser_session_logout(
    request: Request,
    response: Response,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    raw_session = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_session:
        browser_session = db.query(BrowserSession).filter(
            BrowserSession.session_hash == _hash_secret(raw_session),
            BrowserSession.user_id == current_user.id,
        ).first()
        if browser_session is not None and browser_session.revoked_at is None:
            browser_session.revoked_at = _now()
            db.add(
                AuditLog(
                    event=f"browser_session_revoked:{browser_session.id}",
                    user_id=current_user.id,
                    tenant_id=current_user.tenant_id,
                )
            )
            db.commit()

    _clear_browser_session_cookies(response)
    return {"status": "logged_out"}


@router.get("/me", response_model=UserResponse)
def me(current_user: CurrentUser) -> User:
    return current_user
