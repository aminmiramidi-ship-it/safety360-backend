# Safety360 Backend Deployment

## Target

The backend is prepared for deployment as a FastAPI application on Vercel.

## Required production environment variables

Set these in Vercel for Production and Preview as appropriate:

- `SAFETY360_ENV=production`
- `SAFETY360_SECRET_KEY=<strong random secret>`
- `ENCRYPTION_KEY=<valid Fernet key>`
- `DATABASE_URL=<persistent PostgreSQL connection URL>`
- `CORS_ORIGINS=<comma-separated allowed frontend origins>`
- `ACCESS_TOKEN_EXPIRE_MINUTES=60`
- `MAX_IMPORT_BYTES=20971520`

## Important database rule

Do not use the local SQLite fallback in production. Vercel Functions use ephemeral/serverless compute, so application data must be stored in a persistent external database. The current production target is PostgreSQL through SQLAlchemy and psycopg.

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
- `GET /dashboard` with Bearer token
- `POST /tickets` with Bearer token
- `GET /tickets` with Bearer token

## Migration note

The current prototype creates missing tables automatically. Before production data is introduced, database schema changes should be moved to Alembic migrations so upgrades are explicit, reversible and auditable.
