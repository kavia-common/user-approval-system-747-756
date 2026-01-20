import os
import tempfile
import shutil
import pytest
from fastapi.testclient import TestClient

# Ensure we import the app from our main entrypoint
from src.api.main import create_app

@pytest.fixture(scope="session")
def temp_db_env(tmp_path_factory):
    tmpdir = tmp_path_factory.mktemp("db")
    db_path = os.path.join(tmpdir, "test.db")
    os.environ["SQLITE_DB"] = db_path
    os.environ["CORS_ALLOW_ORIGINS"] = "http://localhost:3000"
    yield db_path
    # cleanup not strictly necessary; tmp_path_factory handles it

@pytest.fixture()
def client(temp_db_env):
    app = create_app()
    return TestClient(app)

def test_health(client, temp_db_env):
    res = client.get("/")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "db" in body

def test_user_profile_admin_analytics_flow(client):
    # Create user
    create_res = client.post("/users/", json={"email": "a@example.com", "name": "Alice", "password": "secret123"})
    assert create_res.status_code in (200, 201)
    user = create_res.json()
    user_id = user["id"]

    # Create profile
    prof_res = client.post("/profiles/", json={"user_id": user_id, "bio": "Hello", "website": None, "avatar_url": None})
    assert prof_res.status_code in (200, 201)
    profile = prof_res.json()
    assert profile["user_id"] == user_id

    # Create posts for analytics
    for i in range(3):
        r = client.post("/posts/", json={"user_id": user_id, "content": f"Post {i}"})
        assert r.status_code in (200, 201)

    # Admin grant
    g = client.post(f"/admin/grant-admin/{user_id}")
    assert g.status_code == 200
    assert g.json()["is_admin"] is True

    # Admin summary
    a = client.get("/admin/summary")
    assert a.status_code == 200
    adm = a.json()
    assert adm["admins"] >= 1
    assert adm["active_users"] >= 1
    assert adm["posts"] >= 3

    # Analytics summary
    an = client.get("/analytics/")
    assert an.status_code == 200
    analytics = an.json()
    assert analytics["total_users"] >= 1
    assert analytics["total_posts"] >= 3
