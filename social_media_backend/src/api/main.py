import os
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, APIRouter, Response, Cookie, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr, constr
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

# Constants and configuration
DEFAULT_DB_PATH = os.path.join(os.getcwd(), "social_media.db")
SQLITE_DB = os.getenv("SQLITE_DB", DEFAULT_DB_PATH)
SESSION_COOKIE_NAME = "session_id"
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "120"))

# In-memory session store (simple demo; for production use a persistent cache or JWT)
_SESSIONS: Dict[str, Dict[str, Any]] = {}

def _now_utc() -> datetime:
    return datetime.utcnow()

def _prune_sessions() -> None:
    """Remove expired sessions."""
    expired = []
    for sid, s in _SESSIONS.items():
        if s.get("expires_at") and s["expires_at"] < _now_utc():
            expired.append(sid)
    for sid in expired:
        _SESSIONS.pop(sid, None)

def _new_session(user_id: int) -> str:
    sid = f"{user_id}-{int(datetime.utcnow().timestamp()*1000)}"
    _SESSIONS[sid] = {
        "user_id": user_id,
        "created_at": _now_utc(),
        "expires_at": _now_utc() + timedelta(minutes=SESSION_TTL_MINUTES),
    }
    return sid

def _get_session(session_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not session_id:
        return None
    _prune_sessions()
    sess = _SESSIONS.get(session_id)
    if not sess:
        return None
    # sliding expiration
    sess["expires_at"] = _now_utc() + timedelta(minutes=SESSION_TTL_MINUTES)
    return sess

def get_db() -> sqlite3.Connection:
    """
    Returns a SQLite connection using the SQLITE_DB environment variable.
    Ensures foreign keys are enabled.
    """
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# Pydantic models

class PageMeta(BaseModel):
    page: int = Field(..., description="Current page number (1-indexed)")
    page_size: int = Field(..., description="Number of items per page")
    total: int = Field(..., description="Total number of records available")

class PaginatedResponse(BaseModel):
    meta: PageMeta
    items: List[Dict[str, Any]]

# Users

class UserBase(BaseModel):
    email: EmailStr = Field(..., description="Unique email address for the user")
    name: constr(min_length=1, max_length=100) = Field(..., description="Display name")

class UserCreate(UserBase):
    password: constr(min_length=6, max_length=128) = Field(..., description="Plain password to be hashed by backend")

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = Field(None, description="Updated email")
    name: Optional[constr(min_length=1, max_length=100)] = Field(None, description="Updated name")
    password: Optional[constr(min_length=6, max_length=128)] = Field(None, description="Updated password")

class UserOut(BaseModel):
    id: int
    email: EmailStr
    name: str
    created_at: Optional[str] = None

# Profiles

class ProfileBase(BaseModel):
    bio: Optional[constr(max_length=280)] = Field(None, description="Short biography")
    website: Optional[constr(max_length=255)] = Field(None, description="Website URL")
    avatar_url: Optional[constr(max_length=255)] = Field(None, description="Avatar URL")

class ProfileCreate(ProfileBase):
    user_id: int = Field(..., description="Associated user id")

class ProfileUpdate(ProfileBase):
    pass

class ProfileOut(ProfileBase):
    id: int
    user_id: int

# Posts

class PostBase(BaseModel):
    user_id: int = Field(..., description="Author user id")
    content: constr(min_length=1, max_length=500) = Field(..., description="Post text content")

class PostCreate(PostBase):
    pass

class PostUpdate(BaseModel):
    content: Optional[constr(min_length=1, max_length=500)] = Field(None, description="Updated content")

class PostOut(PostBase):
    id: int
    created_at: Optional[str] = None
    likes: int = 0
    comments: int = 0
    shares: int = 0

# Auth

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="User password")

class LoginResponse(BaseModel):
    user: UserOut
    session_id: str

# Analytics

class AnalyticsSummary(BaseModel):
    total_users: int
    total_posts: int
    avg_engagement_per_post: float
    top_users_by_posts: List[Dict[str, Any]]

# Admin

class AdminUserOut(UserOut):
    is_admin: bool = False

# App initialization

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

# CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities
def _hash_password(pw: str) -> str:
    # Simple hash for demo; replace with passlib/bcrypt for production
    import hashlib
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def _paginate(q: str, params: tuple, page: int, page_size: int, conn: sqlite3.Connection) -> PaginatedResponse:
    count_q = f"SELECT COUNT(*) as cnt FROM ({q}) as sub"
    cur = conn.execute(count_q, params)
    total = int(cur.fetchone()["cnt"])
    offset = (page - 1) * page_size
    data_q = f"{q} LIMIT ? OFFSET ?"
    cur = conn.execute(data_q, params + (page_size, offset))
    rows = [dict(r) for r in cur.fetchall()]
    return PaginatedResponse(meta=PageMeta(page=page, page_size=page_size, total=total), items=rows)

# Dependencies
def get_current_session(session_id: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)) -> Dict[str, Any]:
    sess = _get_session(session_id)
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return sess

def get_current_user(conn: sqlite3.Connection = Depends(get_db), sess: Dict[str, Any] = Depends(get_current_session)) -> Dict[str, Any]:
    uid = sess["user_id"]
    cur = conn.execute("SELECT id, email, name, created_at, is_admin FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)

def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

# Routers
health_router = APIRouter()

@health_router.get("/", summary="Health Check", tags=["health"])
def health_check():
    """
    Health check endpoint.

    Returns:
        JSON message confirming service health.
    """
    return {"message": "Healthy", "database": SQLITE_DB}

auth_router = APIRouter(prefix="/auth", tags=["auth"])

# PUBLIC_INTERFACE
@auth_router.post("/login", response_model=LoginResponse, summary="Login", description="Authenticate user and create a session.")
def login(payload: LoginRequest, response: Response, conn: sqlite3.Connection = Depends(get_db)):
    """Authenticate using email and password and set a session cookie."""
    cur = conn.execute("SELECT id, email, name, created_at, is_admin, password_hash FROM users WHERE email = ?", (payload.email,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if row["password_hash"] != _hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    sid = _new_session(row["id"])
    response.set_cookie(key=SESSION_COOKIE_NAME, value=sid, httponly=True, samesite="lax", max_age=SESSION_TTL_MINUTES * 60)
    user = UserOut(id=row["id"], email=row["email"], name=row["name"], created_at=row["created_at"])
    return LoginResponse(user=user, session_id=sid)

# PUBLIC_INTERFACE
@auth_router.post("/logout", summary="Logout", description="Destroy current session.")
def logout(response: Response, session_id: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME)):
    """Destroy session and clear cookie."""
    if session_id:
        _SESSIONS.pop(session_id, None)
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return {"message": "Logged out"}

# PUBLIC_INTERFACE
@auth_router.get("/me", response_model=UserOut, summary="Current user", description="Return the currently authenticated user.")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    return UserOut(id=user["id"], email=user["email"], name=user["name"], created_at=user.get("created_at"))

users_router = APIRouter(prefix="/users", tags=["users"])

# PUBLIC_INTERFACE
@users_router.get("/", response_model=PaginatedResponse, summary="List users", description="List users with pagination and optional email/name filtering.")
def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    q: Optional[str] = Query(None, description="Search query for email or name"),
    conn: sqlite3.Connection = Depends(get_db),
    _u: Dict[str, Any] = Depends(get_current_user),
):
    params: tuple = ()
    base = "SELECT id, email, name, created_at, COALESCE(is_admin, 0) as is_admin FROM users"
    if q:
        base += " WHERE email LIKE ? OR name LIKE ?"
        like = f"%{q}%"
        params = (like, like)
    base += " ORDER BY id DESC"
    return _paginate(base, params, page, page_size, conn)

# PUBLIC_INTERFACE
@users_router.post("/", response_model=UserOut, status_code=201, summary="Create user")
def create_user(payload: UserCreate, conn: sqlite3.Connection = Depends(get_db), _admin: Dict[str, Any] = Depends(require_admin)):
    try:
        cur = conn.execute(
            "INSERT INTO users (email, name, password_hash, created_at, is_admin) VALUES (?, ?, ?, datetime('now'), 0)",
            (payload.email, payload.name, _hash_password(payload.password)),
        )
        uid = cur.lastrowid
        conn.commit()
        cur = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
        return UserOut(**dict(row))
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail=f"Integrity error: {e}")

# PUBLIC_INTERFACE
@users_router.get("/{user_id}", response_model=UserOut, summary="Get user by id")
def get_user_by_id(user_id: int, conn: sqlite3.Connection = Depends(get_db), _u: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut(**dict(row))

# PUBLIC_INTERFACE
@users_router.patch("/{user_id}", response_model=UserOut, summary="Update user by id")
def update_user(user_id: int, payload: UserUpdate, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    if (not current.get("is_admin")) and (current["id"] != user_id):
        raise HTTPException(status_code=403, detail="Forbidden")
    sets = []
    params: List[Any] = []
    if payload.email is not None:
        sets.append("email = ?")
        params.append(payload.email)
    if payload.name is not None:
        sets.append("name = ?")
        params.append(payload.name)
    if payload.password is not None:
        sets.append("password_hash = ?")
        params.append(_hash_password(payload.password))
    if not sets:
        cur = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return UserOut(**dict(row))
    params.append(user_id)
    conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", tuple(params))
    conn.commit()
    cur = conn.execute("SELECT id, email, name, created_at FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut(**dict(row))

# PUBLIC_INTERFACE
@users_router.delete("/{user_id}", status_code=204, summary="Delete user by id")
def delete_user(user_id: int, conn: sqlite3.Connection = Depends(get_db), _admin: Dict[str, Any] = Depends(require_admin)):
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return Response(status_code=204)

profiles_router = APIRouter(prefix="/profiles", tags=["profiles"])

# PUBLIC_INTERFACE
@profiles_router.get("/", response_model=PaginatedResponse, summary="List profiles")
def list_profiles(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    user_id: Optional[int] = Query(None, description="Filter by user id"),
    conn: sqlite3.Connection = Depends(get_db),
    _u: Dict[str, Any] = Depends(get_current_user),
):
    params: List[Any] = []
    base = "SELECT id, user_id, bio, website, avatar_url FROM profiles"
    if user_id is not None:
        base += " WHERE user_id = ?"
        params.append(user_id)
    base += " ORDER BY id DESC"
    return _paginate(base, tuple(params), page, page_size, conn)

# PUBLIC_INTERFACE
@profiles_router.post("/", response_model=ProfileOut, status_code=201, summary="Create profile")
def create_profile(payload: ProfileCreate, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    if (not current.get("is_admin")) and (current["id"] != payload.user_id):
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        cur = conn.execute(
            "INSERT INTO profiles (user_id, bio, website, avatar_url) VALUES (?, ?, ?, ?)",
            (payload.user_id, payload.bio, payload.website, payload.avatar_url),
        )
        pid = cur.lastrowid
        conn.commit()
        cur = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE id = ?", (pid,))
        row = cur.fetchone()
        return ProfileOut(**dict(row))
    except sqlite3.IntegrityError as e:
        raise HTTPException(status_code=400, detail=f"Integrity error: {e}")

# PUBLIC_INTERFACE
@profiles_router.get("/{profile_id}", response_model=ProfileOut, summary="Get profile")
def get_profile(profile_id: int, conn: sqlite3.Connection = Depends(get_db), _u: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE id = ?", (profile_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileOut(**dict(row))

# PUBLIC_INTERFACE
@profiles_router.patch("/{profile_id}", response_model=ProfileOut, summary="Update profile")
def update_profile(profile_id: int, payload: ProfileUpdate, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, user_id FROM profiles WHERE id = ?", (profile_id,))
    prof = cur.fetchone()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    if (not current.get("is_admin")) and (current["id"] != prof["user_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    sets = []
    params: List[Any] = []
    for field in ["bio", "website", "avatar_url"]:
        val = getattr(payload, field)
        if val is not None:
            sets.append(f"{field} = ?")
            params.append(val)
    if sets:
        params.append(profile_id)
        conn.execute(f"UPDATE profiles SET {', '.join(sets)} WHERE id = ?", tuple(params))
        conn.commit()
    cur = conn.execute("SELECT id, user_id, bio, website, avatar_url FROM profiles WHERE id = ?", (profile_id,))
    row = cur.fetchone()
    return ProfileOut(**dict(row))

# PUBLIC_INTERFACE
@profiles_router.delete("/{profile_id}", status_code=204, summary="Delete profile")
def delete_profile(profile_id: int, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, user_id FROM profiles WHERE id = ?", (profile_id,))
    prof = cur.fetchone()
    if not prof:
        return Response(status_code=204)
    if (not current.get("is_admin")) and (current["id"] != prof["user_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
    conn.commit()
    return Response(status_code=204)

posts_router = APIRouter(prefix="/posts", tags=["posts"])

# PUBLIC_INTERFACE
@posts_router.get("/", response_model=PaginatedResponse, summary="List posts")
def list_posts(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    user_id: Optional[int] = Query(None, description="Filter by author user id"),
    conn: sqlite3.Connection = Depends(get_db),
    _u: Dict[str, Any] = Depends(get_current_user),
):
    params: List[Any] = []
    base = """
        SELECT p.id, p.user_id, p.content, p.created_at,
               COALESCE(p.likes, 0) as likes,
               COALESCE(p.comments, 0) as comments,
               COALESCE(p.shares, 0) as shares
        FROM posts p
    """
    conds = []
    if user_id is not None:
        conds.append("p.user_id = ?")
        params.append(user_id)
    if conds:
        base += " WHERE " + " AND ".join(conds)
    base += " ORDER BY p.id DESC"
    return _paginate(base, tuple(params), page, page_size, conn)

# PUBLIC_INTERFACE
@posts_router.post("/", response_model=PostOut, status_code=201, summary="Create post")
def create_post(payload: PostCreate, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    if (not current.get("is_admin")) and (current["id"] != payload.user_id):
        raise HTTPException(status_code=403, detail="Forbidden")
    cur = conn.execute(
        "INSERT INTO posts (user_id, content, created_at, likes, comments, shares) VALUES (?, ?, datetime('now'), 0, 0, 0)",
        (payload.user_id, payload.content),
    )
    pid = cur.lastrowid
    conn.commit()
    cur = conn.execute("SELECT id, user_id, content, created_at, COALESCE(likes,0) as likes, COALESCE(comments,0) as comments, COALESCE(shares,0) as shares FROM posts WHERE id = ?", (pid,))
    row = cur.fetchone()
    return PostOut(**dict(row))

# PUBLIC_INTERFACE
@posts_router.get("/{post_id}", response_model=PostOut, summary="Get post")
def get_post(post_id: int, conn: sqlite3.Connection = Depends(get_db), _u: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, user_id, content, created_at, COALESCE(likes,0) as likes, COALESCE(comments,0) as comments, COALESCE(shares,0) as shares FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Post not found")
    return PostOut(**dict(row))

# PUBLIC_INTERFACE
@posts_router.patch("/{post_id}", response_model=PostOut, summary="Update post")
def update_post(post_id: int, payload: PostUpdate, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, user_id FROM posts WHERE id = ?", (post_id,))
    post = cur.fetchone()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if (not current.get("is_admin")) and (current["id"] != post["user_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    sets = []
    params: List[Any] = []
    if payload.content is not None:
        sets.append("content = ?")
        params.append(payload.content)
    if sets:
        params.append(post_id)
        conn.execute(f"UPDATE posts SET {', '.join(sets)} WHERE id = ?", tuple(params))
        conn.commit()
    cur = conn.execute("SELECT id, user_id, content, created_at, COALESCE(likes,0) as likes, COALESCE(comments,0) as comments, COALESCE(shares,0) as shares FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    return PostOut(**dict(row))

# PUBLIC_INTERFACE
@posts_router.delete("/{post_id}", status_code=204, summary="Delete post")
def delete_post(post_id: int, conn: sqlite3.Connection = Depends(get_db), current: Dict[str, Any] = Depends(get_current_user)):
    cur = conn.execute("SELECT id, user_id FROM posts WHERE id = ?", (post_id,))
    post = cur.fetchone()
    if not post:
        return Response(status_code=204)
    if (not current.get("is_admin")) and (current["id"] != post["user_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    return Response(status_code=204)

analytics_router = APIRouter(prefix="/analytics", tags=["analytics"])

# PUBLIC_INTERFACE
@analytics_router.get("/", response_model=AnalyticsSummary, summary="Analytics summary", description="Compute summary metrics across the platform.")
def analytics_summary(conn: sqlite3.Connection = Depends(get_db), _u: Dict[str, Any] = Depends(get_current_user)):
    # total users
    cur = conn.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = int(cur.fetchone()["cnt"])
    # total posts
    cur = conn.execute("SELECT COUNT(*) as cnt FROM posts")
    total_posts = int(cur.fetchone()["cnt"])
    # engagement per post
    cur = conn.execute("SELECT AVG(COALESCE(likes,0) + COALESCE(comments,0) + COALESCE(shares,0)) as avg_eng FROM posts")
    row = cur.fetchone()
    avg_eng = float(row["avg_eng"] if row["avg_eng"] is not None else 0.0)
    # top users by posts
    cur = conn.execute("""
        SELECT u.id as user_id, u.name, u.email, COUNT(p.id) as post_count
        FROM users u
        LEFT JOIN posts p ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY post_count DESC, u.id ASC
        LIMIT 5
    """)
    top_users = [dict(r) for r in cur.fetchall()]
    return AnalyticsSummary(
        total_users=total_users,
        total_posts=total_posts,
        avg_engagement_per_post=round(avg_eng, 2),
        top_users_by_posts=top_users,
    )

admin_router = APIRouter(prefix="/admin", tags=["admin"])

# PUBLIC_INTERFACE
@admin_router.get("/summary", summary="Admin summary", description="Admin view across users and posts with additional metrics.")
def admin_summary(conn: sqlite3.Connection = Depends(get_db), _admin: Dict[str, Any] = Depends(require_admin)):
    cur = conn.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = int(cur.fetchone()["cnt"])
    cur = conn.execute("SELECT COUNT(*) as cnt FROM posts")
    total_posts = int(cur.fetchone()["cnt"])
    cur = conn.execute("SELECT SUM(COALESCE(likes,0)) as likes, SUM(COALESCE(comments,0)) as comments, SUM(COALESCE(shares,0)) as shares FROM posts")
    agg = cur.fetchone()
    totals = {
        "likes": int(agg["likes"] or 0),
        "comments": int(agg["comments"] or 0),
        "shares": int(agg["shares"] or 0),
    }
    return {"total_users": total_users, "total_posts": total_posts, "engagement_totals": totals}

# PUBLIC_INTERFACE
@admin_router.post("/grant-admin/{user_id}", summary="Grant admin", description="Grant admin privileges to a user.")
def grant_admin(user_id: int, conn: sqlite3.Connection = Depends(get_db), _admin: Dict[str, Any] = Depends(require_admin)):
    conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    conn.commit()
    return {"message": "Granted admin", "user_id": user_id}

# PUBLIC_INTERFACE
@admin_router.post("/revoke-admin/{user_id}", summary="Revoke admin", description="Revoke admin privileges from a user.")
def revoke_admin(user_id: int, conn: sqlite3.Connection = Depends(get_db), _admin: Dict[str, Any] = Depends(require_admin)):
    conn.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
    conn.commit()
    return {"message": "Revoked admin", "user_id": user_id}

# Register routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(profiles_router)
app.include_router(posts_router)
app.include_router(analytics_router)
app.include_router(admin_router)

# PUBLIC_INTERFACE
@app.get("/docs/websocket-usage", tags=["health"], summary="WebSocket usage note")
def websocket_usage_note():
    """Informational endpoint about WebSocket usage (none currently)."""
    return {
        "note": "This API currently uses HTTP endpoints only. No WebSocket connections are required.",
        "openapi": "/openapi.json",
    }
