# Safety360 Backend

FastAPI backend foundation for Safety360.

## Current Phase 1 scope

- SQLAlchemy database layer
- SQLite for local development
- PostgreSQL-ready production database configuration
- bcrypt password hashing
- JWT Bearer authentication
- protected user and dashboard endpoints
- encrypted ticket descriptions
- audit-log foundation
- PDF import/export
- local CORS allowlist
- GitHub Actions smoke test
- Vercel deployment configuration

## Main endpoints

- `GET /`
- `GET /status`
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
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

## Tests

```cmd
pip install -r requirements-dev.txt
pytest -q
```

## Production

See `DEPLOYMENT.md` before deploying. Production requires persistent PostgreSQL plus explicit JWT and encryption secrets. Do not deploy the local SQLite fallback as the production data store.
