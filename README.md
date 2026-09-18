# Safety360 Backend

FastAPI backend foundation for Safety360.

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
- PDF import/export
- local CORS allowlist
- GitHub Actions CI with compile, lint, migration and API tests
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
- `POST /import`
- `POST /export/pdf`
- `GET /admin/db`

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

## Tests

```cmd
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

## Production

See `DEPLOYMENT.md` before deploying. Production requires persistent PostgreSQL plus explicit JWT and encryption secrets. Do not use the local SQLite fallback as the production data store.
