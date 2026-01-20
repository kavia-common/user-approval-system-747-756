import os
from typing import List, Optional

from fastapi import Cookie, FastAPI, HTTPException, Path, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import sqlite3

# Load env via python-dotenv if present
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# Environment variables
SQLITE_DB = os.getenv("SQLITE_DB", os.path.join(os.path.dirname(__file__), "..", "..", "social_media.db"))
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000")
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60"))

def get_db_conn():
    """
    Create a SQLite connection using the env-configured path.
    Ensures foreign keys are enabled.
    """
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# PUBLIC_INTERFACE
def create_app() -> FastAPI:
    """Create and configure the FastAPI app with CORS and basic routes."""
    app = FastAPI(
        title="Social Media Backend",
        description="Backend REST API for social media dashboard providing users, profiles, posts, analytics, and admin endpoints.",
        version="1.0.0",
        openapi_tags=[
            {"name": "health", "description": "Service health and metadata"},
            {"name": "auth", "description": "Authentication and session management"},
            {"name": "users", "description": "User management"},
            {"name": "profiles", "description": "Profile management"},
            {"name": "posts", "description": "Posts CRUD and interactions"},
            {"name": "analytics", "description": "Analytics summaries and aggregations"},
            {"name": "admin", "description": "Administrative operations"},
        ],
    )

    # CORS
    origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Schemas (minimal to support smoke tests)
    class PageMeta(BaseModel):
        page: int = Field(..., description="Current page number (1-indexed)")
        page_size: int = Field(..., description="Number of items per page")
        total: int = Field(..., description="Total number of records available")

    class PaginatedResponse(BaseModel):
        meta: PageMeta
        items: list

    class UserCreate(BaseModel):
        email: str = Field(..., description="Unique email address for the user")
        name: str = Field(..., description="Display name", min_length=1, max_length=100)
        password: str = Field(..., description="Plain password to be hashed by backend", min_length=6, max_length=128)

    class UserUpdate(BaseModel):
        email: Optional[str] = Field(None, description="Updated email")
        name: Optional[str] = Field(None, description="Updated name")
        password: Optional[str] = Field(None, description="Updated password")

    class UserOut(BaseModel):
        id: int
        email: str
        name: str
        created_at: Optional[str] = None

    class ProfileCreate(BaseModel):
        bio: Optional[str] = Field(None, description="Short biography", max_length=280)
        website: Optional[str] = Field(None, description="Website URL", max_length=255)
        avatar_url: Optional[str] = Field(None, description="Avatar URL", max_length=255)
        user_id: int = Field(..., description="Associated user id")

    class ProfileUpdate(BaseModel):
        bio: Optional[str] = Field(None, description="Short biography", max_length=280)
        website: Optional[str] = Field(None, description="Website URL", max_length=255)
        avatar_url: Optional[str] = Field(None, description="Avatar URL", max_length=255)

    class ProfileOut(BaseModel):
        id: int
        user_id: int
        bio: Optional[str] = None
        website: Optional[str] = None
        avatar_url: Optional[str] = None

    class PostCreate(BaseModel):
        user_id: int = Field(..., description="Author user id")
        content: str = Field(..., description="Post text content", min_length=1, max_length=500)

    class PostUpdate(BaseModel):
        content: Optional[str] = Field(None, description="Updated content", min_length=1, max_length=500)

    class PostOut(BaseModel):
        id: int
        user_id: int
        content: str
        created_at: Optional[str] = None
        likes: int = 0
        comments: int = 0
        shares: int = 0

    class AnalyticsSummary(BaseModel):
        total_users: int
        total_posts: int
        avg_engagement_per_post: float
        top_users_by_posts: List[dict]

    # Ensure basic tables exist for smoke tests
    def ensure_schema():
        conn = get_db_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    is_admin INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE NOT NULL,
                    bio TEXT,
                    website TEXT,
                    avatar_url TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    likes INTEGER NOT NULL DEFAULT 0,
                    comments INTEGER NOT NULL DEFAULT 0,
                    shares INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            conn.commit()
        finally:
            conn.close()

    ensure_schema()

    @app.get("/", tags=["health"], summary="Health Check", description="Health check endpoint.\n\nReturns:\n    JSON message confirming service health.")
    def health_check():
        return {"status": "ok", "db": SQLITE_DB}

    # USERS
    @app.get("/users/", tags=["users"], summary="List users", response_model=PaginatedResponse)
    def list_users(
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(10, ge=1, le=100, description="Items per page"),
        q: Optional[str] = Query(None, description="Search query for email or name"),
        session_id: Optional[str] = Cookie(default=None),
    ):
        conn = get_db_conn()
        try:
            params = []
            cond = ""
            if q:
                cond = "WHERE email LIKE ? OR name LIKE ?"
                like = f"%{q}%"
                params.extend([like, like])

            total = conn.execute(f"SELECT COUNT(*) AS c FROM users {cond}", params).fetchone()["c"]
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"SELECT id, email, name, created_at FROM users {cond} ORDER BY id LIMIT ? OFFSET ?",
                params + [page_size, offset]
            ).fetchall()
            items = [dict(r) for r in rows]
            return {"meta": {"page": page, "page_size": page_size, "total": total}, "items": items}
        finally:
            conn.close()

    @app.post("/users/", tags=["users"], summary="Create user", status_code=status.HTTP_201_CREATED, response_model=UserOut)
    def create_user(payload: UserCreate, session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            # NOTE: for demo smoke tests, store password hash as plain (do NOT do this in production).
            cur = conn.execute(
                "INSERT INTO users(email, name, password_hash) VALUES(?,?,?)",
                (payload.email, payload.name, payload.password)
            )
            conn.commit()
            user_id = cur.lastrowid
            row = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Email already exists")
        finally:
            conn.close()

    @app.get("/users/{user_id}", tags=["users"], summary="Get user by id", response_model=UserOut)
    def get_user_by_id(user_id: int = Path(...), session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            return dict(row)
        finally:
            conn.close()

    @app.patch("/users/{user_id}", tags=["users"], summary="Update user by id", response_model=UserOut)
    def update_user(user_id: int = Path(...), payload: UserUpdate = None, session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            sets = []
            vals = []
            if payload.email is not None:
                sets.append("email = ?")
                vals.append(payload.email)
            if payload.name is not None:
                sets.append("name = ?")
                vals.append(payload.name)
            if payload.password is not None:
                sets.append("password_hash = ?")
                vals.append(payload.password)
            if not sets:
                row = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="User not found")
                return dict(row)

            vals.append(user_id)
            conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
            conn.commit()
            row = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            return dict(row)
        finally:
            conn.close()

    @app.delete("/users/{user_id}", tags=["users"], summary="Delete user by id", status_code=status.HTTP_204_NO_CONTENT)
    def delete_user(user_id: int = Path(...), session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()
        return

    # PROFILES
    @app.get("/profiles/", tags=["profiles"], summary="List profiles", response_model=PaginatedResponse)
    def list_profiles(
        page: int = Query(1, ge=1),
        page_size: int = Query(10, ge=1, le=100),
        user_id: Optional[int] = Query(None, description="Filter by user id"),
        session_id: Optional[str] = Cookie(default=None),
    ):
        conn = get_db_conn()
        try:
            cond = ""
            params = []
            if user_id is not None:
                cond = "WHERE user_id = ?"
                params.append(user_id)

            total = conn.execute(f"SELECT COUNT(*) AS c FROM profiles {cond}", params).fetchone()["c"]
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"SELECT id, user_id, bio, website, avatar_url FROM profiles {cond} ORDER BY id LIMIT ? OFFSET ?",
                params + [page_size, offset]
            ).fetchall()
            items = [dict(r) for r in rows]
            return {"meta": {"page": page, "page_size": page_size, "total": total}, "items": items}
        finally:
            conn.close()

    @app.post("/profiles/", tags=["profiles"], summary="Create profile", status_code=status.HTTP_201_CREATED, response_model=ProfileOut)
    def create_profile(payload: ProfileCreate, session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            # ensure user exists
            u = conn.execute("SELECT id FROM users WHERE id = ?", (payload.user_id,)).fetchone()
            if not u:
                raise HTTPException(status_code=400, detail="User does not exist")
            cur = conn.execute(
                "INSERT INTO profiles(user_id, bio, website, avatar_url) VALUES(?,?,?,?)",
                (payload.user_id, payload.bio, payload.website, payload.avatar_url)
            )
            conn.commit()
            pid = cur.lastrowid
            row = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE id = ?", (pid,)).fetchone()
            return dict(row)
        except sqlite3.IntegrityError:
            # unique on user_id
            row = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE user_id = ?", (payload.user_id,)).fetchone()
            if row:
                return dict(row)
            raise
        finally:
            conn.close()

    @app.get("/profiles/{profile_id}", tags=["profiles"], summary="Get profile", response_model=ProfileOut)
    def get_profile(profile_id: int = Path(...), session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            row = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE id = ?", (profile_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Profile not found")
            return dict(row)
        finally:
            conn.close()

    @app.patch("/profiles/{profile_id}", tags=["profiles"], summary="Update profile", response_model=ProfileOut)
    def update_profile(profile_id: int = Path(...), payload: ProfileUpdate = None, session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            sets = []
            vals = []
            if payload.bio is not None:
                sets.append("bio = ?")
                vals.append(payload.bio)
            if payload.website is not None:
                sets.append("website = ?")
                vals.append(payload.website)
            if payload.avatar_url is not None:
                sets.append("avatar_url = ?")
                vals.append(payload.avatar_url)
            if sets:
                vals.append(profile_id)
                conn.execute(f"UPDATE profiles SET {', '.join(sets)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", vals)
                conn.commit()
            row = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE id = ?", (profile_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Profile not found")
            return dict(row)
        finally:
            conn.close()

    @app.delete("/profiles/{profile_id}", tags=["profiles"], summary="Delete profile", status_code=status.HTTP_204_NO_CONTENT)
    def delete_profile(profile_id: int = Path(...), session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
            conn.commit()
        finally:
            conn.close()
        return

    # POSTS (minimal list/create to support analytics)
    @app.get("/posts/", tags=["posts"], summary="List posts", response_model=PaginatedResponse)
    def list_posts(
        page: int = Query(1, ge=1),
        page_size: int = Query(10, ge=1, le=100),
        user_id: Optional[int] = Query(None, description="Filter by author user id"),
        session_id: Optional[str] = Cookie(default=None),
    ):
        conn = get_db_conn()
        try:
            cond = ""
            params = []
            if user_id is not None:
                cond = "WHERE user_id = ?"
                params.append(user_id)

            total = conn.execute(f"SELECT COUNT(*) AS c FROM posts {cond}", params).fetchone()["c"]
            offset = (page - 1) * page_size
            rows = conn.execute(
                f"SELECT id, user_id, content, created_at, likes, comments, shares FROM posts {cond} ORDER BY id LIMIT ? OFFSET ?",
                params + [page_size, offset]
            ).fetchall()
            items = [dict(r) for r in rows]
            return {"meta": {"page": page, "page_size": page_size, "total": total}, "items": items}
        finally:
            conn.close()

    @app.post("/posts/", tags=["posts"], summary="Create post", status_code=status.HTTP_201_CREATED, response_model=PostOut)
    def create_post(payload: PostCreate, session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            u = conn.execute("SELECT id FROM users WHERE id = ?", (payload.user_id,)).fetchone()
            if not u:
                raise HTTPException(status_code=400, detail="User does not exist")
            cur = conn.execute(
                "INSERT INTO posts(user_id, content) VALUES(?,?)",
                (payload.user_id, payload.content)
            )
            conn.commit()
            pid = cur.lastrowid
            row = conn.execute("SELECT id, user_id, content, created_at, likes, comments, shares FROM posts WHERE id = ?", (pid,)).fetchone()
            return dict(row)
        finally:
            conn.close()

    # ANALYTICS
    @app.get("/analytics/", tags=["analytics"], summary="Analytics summary", response_model=AnalyticsSummary)
    def analytics_summary(session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            total_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            total_posts = conn.execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"]
            # Simple engagement metric
            row = conn.execute("SELECT AVG(likes + comments + shares) AS avg_eng FROM posts").fetchone()
            avg = float(row["avg_eng"] or 0.0)
            top_rows = conn.execute("""
                SELECT u.id as user_id, u.name, COUNT(p.id) as posts_count
                FROM users u LEFT JOIN posts p ON p.user_id = u.id
                GROUP BY u.id, u.name
                ORDER BY posts_count DESC, u.id ASC
                LIMIT 5
            """).fetchall()
            top_users = [dict(r) for r in top_rows]
            return {
                "total_users": total_users,
                "total_posts": total_posts,
                "avg_engagement_per_post": round(avg, 2),
                "top_users_by_posts": top_users,
            }
        finally:
            conn.close()

    # ADMIN
    @app.get("/admin/summary", tags=["admin"], summary="Admin summary")
    def admin_summary(session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            active_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            posts = conn.execute("SELECT COUNT(*) AS c FROM posts").fetchone()["c"]
            admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE is_admin = 1").fetchone()["c"]
            return {"active_users": active_users, "posts": posts, "admins": admins}
        finally:
            conn.close()

    @app.post("/admin/grant-admin/{user_id}", tags=["admin"], summary="Grant admin")
    def grant_admin(user_id: int = Path(...), session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            res = conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
            conn.commit()
            if res.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
            return {"user_id": user_id, "is_admin": True}
        finally:
            conn.close()

    @app.post("/admin/revoke-admin/{user_id}", tags=["admin"], summary="Revoke admin")
    def revoke_admin(user_id: int = Path(...), session_id: Optional[str] = Cookie(default=None)):
        conn = get_db_conn()
        try:
            res = conn.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
            conn.commit()
            if res.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
            return {"user_id": user_id, "is_admin": False}
        finally:
            conn.close()

    # Docs misc
    @app.get("/docs/websocket-usage", tags=["health"], summary="WebSocket usage note")
    def websocket_usage_note():
        return {
            "note": "No WebSocket endpoints currently. Use REST endpoints documented in OpenAPI.",
            "websocket": None,
        }

    return app

app = create_app()
