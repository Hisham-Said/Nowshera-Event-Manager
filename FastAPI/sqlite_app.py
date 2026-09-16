import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SQLITE_DB_PATH", BASE_DIR / "events.db"))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "local-development-secret-change-me").encode()
ACCESS_TOKEN_TTL = timedelta(hours=12)

app = FastAPI(title="Event Registration & Management System")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
security = HTTPBearer(auto_error=False)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def init_db():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Attendee'
                    CHECK (role IN ('Attendee', 'Admin')),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                event_date TEXT NOT NULL,
                event_time TEXT NOT NULL,
                location TEXT NOT NULL,
                capacity INTEGER NOT NULL CHECK (capacity > 0),
                status TEXT NOT NULL DEFAULT 'Draft'
                    CHECK (status IN ('Draft', 'Published', 'Completed', 'Cancelled')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registrations (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'Registered'
                    CHECK (status IN ('Registered', 'Cancelled')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS active_registration
                ON registrations(user_id, event_id) WHERE status = 'Registered';
            CREATE INDEX IF NOT EXISTS event_date_status
                ON events(status, event_date);
            CREATE INDEX IF NOT EXISTS registration_event_status
                ON registrations(event_id, status);
            CREATE INDEX IF NOT EXISTS registration_user_status
                ON registrations(user_id, status);
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "")
        if admin_email and admin_password:
            existing = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?, 'Admin', ?)",
                    (str(uuid.uuid4()), os.getenv("ADMIN_NAME", "Administrator"), admin_email,
                     hash_password(admin_password), now_iso()),
                )


init_db()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def make_access_token(user_id):
    payload = {"sub": user_id, "exp": int((datetime.now(timezone.utc) + ACCESS_TOKEN_TTL).timestamp())}
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def read_access_token(token):
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(TOKEN_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if payload["exp"] < int(datetime.now(timezone.utc).timestamp()):
            return None
        return payload["sub"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def user_response(row):
    return {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}


def event_response(row):
    result = dict(row)
    result["available_capacity"] = max(0, result["capacity"] - result.pop("registered_count", 0))
    return result


def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    user_id = read_access_token(credentials.credentials)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def get_event(db, event_id):
    return db.execute(
        """
        SELECT e.*, COUNT(CASE WHEN r.status = 'Registered' THEN 1 END) AS registered_count
        FROM events e LEFT JOIN registrations r ON r.event_id = e.id
        WHERE e.id = ? GROUP BY e.id
        """, (event_id,)
    ).fetchone()


@app.get("/")
def health():
    return {"message": "FastAPI + SQLite connected successfully", "database": str(DB_PATH)}


@app.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(data: dict):
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).lower().strip()
    password = str(data.get("password", ""))
    if not name or not email or len(password) < 6:
        raise HTTPException(status_code=400, detail="Name, email, and a password of at least 6 characters are required")
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, 'Attendee', ?)",
                (str(uuid.uuid4()), name, email, hash_password(password), now_iso()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="An account with this email already exists")
    return {"message": "Account created successfully"}


@app.post("/login")
def login(data: dict):
    email = str(data.get("email", "")).lower().strip()
    requested_role = data.get("role", "")
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not verify_password(str(data.get("password", "")), user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if requested_role and requested_role != user["role"]:
        raise HTTPException(status_code=403, detail=f"This account is registered as {user['role']}")
    access_token = make_access_token(user["id"])
    refresh_token = secrets.token_urlsafe(48)
    with get_db() as db:
        db.execute("INSERT INTO refresh_tokens VALUES (?, ?, ?, ?)",
                   (refresh_token, user["id"], (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(), now_iso()))
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer", "user": user_response(user)}


@app.post("/refresh-token")
def refresh_token(data: dict):
    token = str(data.get("refresh_token", ""))
    with get_db() as db:
        row = db.execute(
            "SELECT u.* FROM refresh_tokens r JOIN users u ON u.id = r.user_id WHERE r.token = ? AND r.expires_at > ?",
            (token, now_iso()),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        new_refresh = secrets.token_urlsafe(48)
        db.execute("INSERT INTO refresh_tokens VALUES (?, ?, ?, ?)",
                   (new_refresh, row["id"], (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(), now_iso()))
    return {"access_token": make_access_token(row["id"]), "refresh_token": new_refresh, "token_type": "bearer"}


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user_response(user)


@app.get("/admin/test")
def admin_test(user=Depends(require_admin)):
    return {"message": "Admin access verified"}


@app.post("/events", status_code=status.HTTP_201_CREATED)
def create_event(data: dict, user=Depends(require_admin)):
    required = ["title", "event_date", "event_time", "location", "capacity"]
    if any(not str(data.get(field, "")).strip() for field in required):
        raise HTTPException(status_code=400, detail="All event fields are required")
    try:
        capacity = int(data["capacity"])
        if capacity <= 0:
            raise ValueError
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Capacity must be a positive number")
    event_id = str(uuid.uuid4())
    timestamp = now_iso()
    with get_db() as db:
        db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (event_id, str(data["title"]).strip(), str(data.get("description", "")).strip(),
                    str(data["event_date"]), str(data["event_time"]), str(data["location"]).strip(),
                    capacity, data.get("status", "Draft"), timestamp, timestamp))
        return event_response(get_event(db, event_id))


@app.get("/events")
def list_events():
    with get_db() as db:
        rows = db.execute(
            """SELECT e.*, COUNT(CASE WHEN r.status = 'Registered' THEN 1 END) AS registered_count
               FROM events e LEFT JOIN registrations r ON r.event_id = e.id
               WHERE e.status = 'Published' AND e.event_date >= ? GROUP BY e.id ORDER BY e.event_date, e.event_time""",
            (datetime.now().date().isoformat(),),
        ).fetchall()
    return [event_response(row) for row in rows]


@app.get("/events/{event_id}")
def event_details(event_id: str):
    with get_db() as db:
        row = get_event(db, event_id)
    if not row or row["status"] != "Published":
        raise HTTPException(status_code=404, detail="Event not found")
    return event_response(row)


@app.get("/admin/events")
def admin_events(user=Depends(require_admin)):
    with get_db() as db:
        rows = db.execute(
            """SELECT e.*, COUNT(CASE WHEN r.status = 'Registered' THEN 1 END) AS registered_count
               FROM events e LEFT JOIN registrations r ON r.event_id = e.id
               GROUP BY e.id ORDER BY e.event_date DESC, e.created_at DESC"""
        ).fetchall()
    return [event_response(row) for row in rows]


@app.put("/events/{event_id}")
def update_event(event_id: str, data: dict, user=Depends(require_admin)):
    fields = ["title", "description", "event_date", "event_time", "location", "capacity"]
    values = [data.get(field) for field in fields]
    if any(value is None for value in values):
        raise HTTPException(status_code=400, detail="All event fields are required")
    with get_db() as db:
        if not get_event(db, event_id):
            raise HTTPException(status_code=404, detail="Event not found")
        db.execute("""UPDATE events SET title=?, description=?, event_date=?, event_time=?, location=?, capacity=?, updated_at=? WHERE id=?""",
                   (*values, now_iso(), event_id))
        return event_response(get_event(db, event_id))


@app.patch("/events/{event_id}/status")
def update_status(event_id: str, data: dict, user=Depends(require_admin)):
    new_status = data.get("status")
    if new_status not in {"Draft", "Published", "Completed", "Cancelled"}:
        raise HTTPException(status_code=400, detail="Invalid event status")
    with get_db() as db:
        if not get_event(db, event_id):
            raise HTTPException(status_code=404, detail="Event not found")
        db.execute("UPDATE events SET status=?, updated_at=? WHERE id=?", (new_status, now_iso(), event_id))
        return event_response(get_event(db, event_id))


@app.post("/events/{event_id}/register", status_code=status.HTTP_201_CREATED)
def register(event_id: str, user=Depends(get_current_user)):
    if user["role"] != "Attendee":
        raise HTTPException(status_code=403, detail="Only attendees can register")
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        event = get_event(db, event_id)
        if not event or event["status"] != "Published" or event["event_date"] < datetime.now().date().isoformat():
            raise HTTPException(status_code=400, detail="Event is not open for registration")
        if event["registered_count"] >= event["capacity"]:
            raise HTTPException(status_code=400, detail="Event is full")
        try:
            registration_id = str(uuid.uuid4())
            timestamp = now_iso()
            db.execute("INSERT INTO registrations VALUES (?, ?, ?, 'Registered', ?, ?)",
                       (registration_id, user["id"], event_id, timestamp, timestamp))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="You are already registered for this event")
    return {"message": "Registration successful", "registration_id": registration_id}


@app.get("/my-registrations")
def my_registrations(user=Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            """SELECT r.id AS registration_id, r.status, r.created_at, r.updated_at,
                      e.id AS event_id, e.title, e.description, e.event_date, e.event_time, e.location, e.capacity, e.status AS event_status
               FROM registrations r JOIN events e ON e.id = r.event_id
               WHERE r.user_id = ? ORDER BY r.created_at DESC""", (user["id"],)
        ).fetchall()
    registrations = []
    for row in rows:
        registration = dict(row)
        registration["id"] = registration["registration_id"]
        registration["events"] = {
            "id": registration["event_id"],
            "title": registration["title"],
            "description": registration["description"],
            "event_date": registration["event_date"],
            "event_time": registration["event_time"],
            "location": registration["location"],
            "capacity": registration["capacity"],
            "status": registration["event_status"],
        }
        registrations.append(registration)
    return registrations


@app.patch("/registrations/{registration_id}/cancel")
def cancel_registration(registration_id: str, user=Depends(get_current_user)):
    with get_db() as db:
        row = db.execute("SELECT * FROM registrations WHERE id=? AND user_id=?", (registration_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Registration not found")
        if row["status"] != "Registered":
            raise HTTPException(status_code=400, detail="Registration is already cancelled")
        db.execute("UPDATE registrations SET status='Cancelled', updated_at=? WHERE id=?", (now_iso(), registration_id))
    return {"message": "Registration cancelled successfully"}


@app.get("/admin/events/{event_id}/attendees")
def attendees(event_id: str, search: str = "", user=Depends(require_admin)):
    pattern = f"%{search.strip()}%"
    with get_db() as db:
        event = get_event(db, event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        rows = db.execute(
            """SELECT r.id AS registration_id, u.id AS user_id, u.name, u.email,
                      r.created_at AS registered_at, r.status
               FROM registrations r JOIN users u ON u.id = r.user_id
               WHERE r.event_id=? AND r.status='Registered' AND (u.name LIKE ? OR u.email LIKE ?)
               ORDER BY r.created_at""", (event_id, pattern, pattern)
        ).fetchall()
    return {
        "event": event_response(event),
        "attendees": [dict(row) for row in rows],
    }


@app.get("/admin/dashboard")
def dashboard(user=Depends(require_admin)):
    with get_db() as db:
        events = db.execute("SELECT status, COUNT(*) AS count FROM events GROUP BY status").fetchall()
        registration = db.execute("SELECT status, COUNT(*) AS count FROM registrations GROUP BY status").fetchall()
        capacity = db.execute("SELECT COALESCE(SUM(capacity), 0) AS total, COALESCE(SUM(registered_count), 0) AS used FROM (SELECT e.capacity, COUNT(CASE WHEN r.status='Registered' THEN 1 END) AS registered_count FROM events e LEFT JOIN registrations r ON r.event_id=e.id AND r.status='Registered' GROUP BY e.id)").fetchone()
    event_counts = {row["status"].lower(): row["count"] for row in events}
    registration_counts = {row["status"].lower(): row["count"] for row in registration}
    total_events = sum(event_counts.values())
    total_registrations = sum(registration_counts.values())
    return {
        "events": {"total": total_events, "draft": event_counts.get("draft", 0), "published": event_counts.get("published", 0), "completed": event_counts.get("completed", 0), "cancelled": event_counts.get("cancelled", 0)},
        "registrations": {"total": total_registrations, "active": registration_counts.get("registered", 0), "cancelled": registration_counts.get("cancelled", 0)},
        "capacity": {"total": capacity["total"], "used": capacity["used"], "available": max(0, capacity["total"] - capacity["used"])},
    }


@app.get("/admin/reports/events/{event_id}")
def report(event_id: str, user=Depends(require_admin)):
    with get_db() as db:
        event = get_event(db, event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        rows = db.execute(
            """SELECT r.id AS registration_id, u.name, u.email, r.created_at AS registered_at, r.status
               FROM registrations r JOIN users u ON u.id=r.user_id WHERE r.event_id=? ORDER BY r.created_at""", (event_id,)
        ).fetchall()
    attendees = [dict(row) for row in rows if row["status"] == "Registered"]
    all_registrations = [dict(row) for row in rows]
    active = attendees
    result = event_response(event)
    cancelled_count = sum(
        row["status"] == "Cancelled" for row in all_registrations
    )
    return {
        "event": result,
        "summary": {
            "capacity": result["capacity"],
            "active_registrations": len(active),
            "cancelled_registrations": cancelled_count,
            "available_capacity": result["available_capacity"],
        },
        "attendees": attendees,
        "active_attendees": active,
        "total_registrations": len(all_registrations),
        "active_registrations": len(active),
        "available_capacity": result["available_capacity"],
    }
