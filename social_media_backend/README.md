# Social Media Backend (FastAPI)

FastAPI backend providing Users, Profiles, Posts, Analytics, and Admin endpoints.

## Run locally

1. Create env file:
   cp .env.example .env
   # Optionally adjust SQLITE_DB path and CORS_ALLOW_ORIGINS

2. Install dependencies:
   pip install -r requirements.txt

3. Start server:
   uvicorn src.api.main:app --host 0.0.0.0 --port 3001

Open http://localhost:3001/docs

## Environment variables

- SQLITE_DB: Path to SQLite DB file. Example: ./data/social_media.db
- CORS_ALLOW_ORIGINS: Comma separated origins for CORS (e.g., http://localhost:3000)
- SESSION_TTL_MINUTES: Session TTL in minutes

## Tests

Run smoke tests:

   pytest -q
