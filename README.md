# user-approval-system-747-756

Backend (social_media_backend) provides FastAPI services for users, profiles, posts, analytics, and admin.

How to run locally:
1. cd social_media_backend
2. Create .env from example and set SQLITE_DB path if needed:
   cp .env.example .env
3. Install deps:
   pip install -r requirements.txt
4. Start server:
   uvicorn src.api.main:app --host 0.0.0.0 --port 3001

Generating OpenAPI:
- python -m src.api.generate_openapi

Environment variables:
- SQLITE_DB: Path to SQLite DB file
- CORS_ALLOW_ORIGINS: Allowed origins for CORS (comma separated)
- SESSION_TTL_MINUTES: Session TTL in minutes