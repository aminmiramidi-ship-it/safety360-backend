# Safety360 Backend

FastAPI backend foundation for the Safety360 multi-tenant HSE/IMS platform.

## Current scope

- SQLAlchemy database layer
- SQLite for local development
- PostgreSQL-ready production configuration
- Alembic migrations
- bcrypt password hashing
- JWT Bearer authentication
- tenant onboarding and tenant isolation foundation
- protected user and dashboard endpoints
- encrypted ticket descriptions
- audit-log foundation
- controlled-document workflow with revision history and approvals
- PDF import/export
- local CORS allowlist
- GitHub Actions CI with compile, lint, migration, API and security tests
- Vercel deployment configuration

## Main endpoints

- `GET /`
- `GET /status`
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /tenants`
- `GET /tenants/current`
- `GET /dashboard`
- `GET /psa`
- `POST /tickets`
- `GET /tickets`
- `POST /documents`
- `GET /documents`
- `GET /documents/{id}`
- `POST /documents/{id}/submit-review`
- `POST /documents/{id}/approve`
- `POST /documents/{id}/revisions`
- `POST /import`
- `POST /export/pdf`
- `GET /admin/db`

## Controlled documents

Document control is tenant-scoped. Each document receives a stable `logical_id` and an integer revision number. The current workflow is:

`draft -> review -> approved -> obsolete`

A new revision keeps the logical document ID, increments the version and starts again as `draft`. Creating a revision from an approved document marks the previous approved version as `obsolete`. Approval stores the approving user and timestamp, and significant actions are written to the audit log.

Current approval roles are `tenant_admin`, `hse_manager` and `document_controller`. More granular RBAC is planned for later phases.

`GET /documents` returns only the newest revision of each logical document by default. Use `GET /documents?latest_only=false` to retrieve the full revision history.

## Local development

```cmd
cd C:\Safety360-New\backend
venv\Scripts\activate
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Swagger:

`http://127.0.0.1:8000/docs`

## Database migrations

For a new database:

```cmd
alembic upgrade head
```

For future schema changes:

```cmd
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Production schema changes must be applied with Alembic. The application does not automatically create production tables.

## Tests and security

```cmd
pip install -r requirements-dev.txt
ruff check .
pytest -q
bandit -q -r . -x ./tests,./migrations,./venv,./.venv
pip-audit -r requirements.txt
```

## Production

See `DEPLOYMENT.md` before deploying. Production requires persistent PostgreSQL plus explicit JWT and encryption secrets. Do not use the local SQLite fallback as the production data store.
