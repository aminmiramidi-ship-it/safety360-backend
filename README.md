# Safety360 Backend

FastAPI backend for Safety360 with modular authentication, database access, tickets, PDF import/export and protected application routes.

## Current development branch

`Safety360-phase1-auth` introduces the first consolidated authentication foundation:

- SQLAlchemy database layer
- user model with role, language, tenant reference and active state
- bcrypt password hashing
- JWT bearer authentication
- `/auth/register`, `/auth/login`, `/auth/me`
- protected `/dashboard`
- authenticated ticket routes with encrypted ticket descriptions
- restricted CORS configuration for local frontend development
- environment-based secrets

## Local development

From the repository root on Windows CMD:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Generate a JWT secret:

```cmd
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Generate a Fernet encryption key:

```cmd
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Insert both generated values into `.env`, then start the backend:

```cmd
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

## Authentication test flow

Register:

```json
{
  "email": "test@safety360.de",
  "password": "Secret123!",
  "full_name": "Amin Test",
  "language": "de"
}
```

Login:

```json
{
  "email": "test@safety360.de",
  "password": "Secret123!"
}
```

Use the returned JWT in Swagger's **Authorize** dialog, then test:

- `GET /auth/me`
- `GET /dashboard`
- `GET /tickets`

## Important database note

The older prototype used a different SQLite `users` table schema. During development, an old local `safety360.db` must either be migrated or removed before starting this branch. Do not delete production data. Formal migrations with Alembic should be added before production rollout.

## Production requirements

Before production:

- set `SAFETY360_ENV=production`
- configure a persistent production database instead of local SQLite
- configure `SAFETY360_SECRET_KEY`
- configure `ENCRYPTION_KEY`
- set production `CORS_ORIGINS`
- add database migrations
- add automated tests and CI
- use a managed secrets store and never commit `.env`
