# Safety360 Backend Deployment

## Target

The backend is prepared for deployment as a FastAPI application with a persistent PostgreSQL database.

## Required production environment variables

Set these for Production and Preview as appropriate:

- `SAFETY360_ENV=production`
- `SAFETY360_SECRET_KEY=<strong random secret>`
- `ENCRYPTION_KEY=<valid Fernet key>`
- `DATABASE_URL=<persistent PostgreSQL connection URL>`
- `CORS_ORIGINS=<comma-separated allowed frontend origins>`
- `ACCESS_TOKEN_EXPIRE_MINUTES=60`
- `MAX_IMPORT_BYTES=20971520`

## Database rule

Do not use SQLite in production. Serverless and ephemeral compute cannot safely persist the local SQLite file. Production must use a persistent PostgreSQL service.

The production application intentionally does not call `Base.metadata.create_all()`. Database changes must be explicit and auditable through Alembic migrations.

Before the first production start and after every approved schema change, run:

```cmd
alembic upgrade head
```

For a future schema change:

```cmd
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Always back up production data before destructive migrations.

## Generate secrets locally

JWT secret:

```cmd
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Fernet encryption key:

```cmd
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Never commit generated secrets to GitHub.

## Local start

```cmd
cd C:\Safety360-New\backend
venv\Scripts\activate
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

## Health checks

After deployment verify:

- `GET /`
- `GET /status`
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me` with Bearer token
- `POST /tenants` with Bearer token
- `GET /tenants/current` with Bearer token
- `GET /dashboard` with Bearer token
- `POST /tickets` with Bearer token
- `GET /tickets` with Bearer token

## CI gates

The GitHub Actions workflow checks:

- Python compilation
- Ruff linting
- Alembic migration creation of the expected schema
- authentication flow
- tenant onboarding
- tenant ticket isolation

A production merge should only happen after these checks and a local smoke test pass.
