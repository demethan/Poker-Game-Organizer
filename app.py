from __future__ import annotations

import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "poker.db"

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", secrets.token_hex(32)),
    same_site="strict",
    https_only=os.getenv("SESSION_SECURE", "true").lower() == "true",
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def format_ts(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value


templates.env.filters["fmt_ts"] = format_ts

def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token

templates.env.globals["csrf_token"] = get_csrf_token


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.hits = {}
        self.limits = {
            "/login": (10, 60),
            "/register": (5, 60),
            "/g/": (30, 60),  # RSVP/standby
        }

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            path = request.url.path
            key = None
            for prefix in self.limits:
                if path == prefix or path.startswith(prefix):
                    key = prefix
                    break
            if key:
                limit, window = self.limits[key]
                now = time.time()
                ip = (request.headers.get("x-forwarded-for") or request.client.host or "unknown").split(",")[0].strip()
                bucket_key = f"{ip}:{key}"
                bucket = self.hits.get(bucket_key, [])
                bucket = [t for t in bucket if now - t < window]
                if len(bucket) >= limit:
                    return PlainTextResponse("Too many requests", status_code=429)
                bucket.append(now)
                self.hits[bucket_key] = bucket
        return await call_next(request)


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)


# ------------------------
# Database helpers
# ------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    # Ensure optional admin fields exist
    cur.execute("PRAGMA table_info(users)")
    existing_cols = {row["name"] for row in cur.fetchall()}
    if "username" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN username TEXT")
    if "is_admin" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    if "is_disabled" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_disabled INTEGER DEFAULT 0")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organizer_id INTEGER NOT NULL,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            location TEXT NOT NULL,
            game_date TEXT NOT NULL,
            game_time TEXT NOT NULL,
            total_players INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (organizer_id) REFERENCES users(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            late_eta TEXT,
            FOREIGN KEY (game_id) REFERENCES games(id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS standby (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (game_id) REFERENCES games(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_name ON rsvps(game_id, lower(name))")
    conn.commit()
    conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ------------------------
# Auth helpers
# ------------------------

def current_user_id(request: Request) -> Optional[int]:
    return request.session.get("user_id")

def current_user_is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))

def require_login(request: Request) -> Optional[int]:
    user_id = current_user_id(request)
    return user_id


def require_admin(request: Request) -> bool:
    return current_user_is_admin(request)


# ------------------------
# Utility
# ------------------------

def generate_code(length: int = 8) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM games WHERE code = ?", (code,))
        exists = cur.fetchone()
        conn.close()
        if not exists:
            return code


def count_in(conn: sqlite3.Connection, game_id: int) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM rsvps WHERE game_id = ? AND status IN ('IN', 'LATE', 'HOST')", (game_id,))
    row = cur.fetchone()
    return int(row["c"]) if row else 0


def verify_csrf(request: Request, token: str) -> bool:
    return token and token == request.session.get("csrf_token")


def clean_text(value: str, max_len: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_len:
        raise ValueError("Invalid input")
    return cleaned


def cleanup_old_games(conn: sqlite3.Connection, organizer_id: int) -> None:
    cutoff = (datetime.utcnow() - timedelta(days=365)).isoformat()
    cur = conn.cursor()
    cur.execute("SELECT id FROM games WHERE organizer_id = ? AND created_at < ?", (organizer_id, cutoff))
    old_ids = [row["id"] for row in cur.fetchall()]
    if not old_ids:
        return
    cur.execute("DELETE FROM rsvps WHERE game_id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)
    cur.execute("DELETE FROM standby WHERE game_id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)
    cur.execute("DELETE FROM games WHERE id IN (%s)" % ",".join("?" * len(old_ids)), old_ids)


# ------------------------
# Routes
# ------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user_id = current_user_id(request)
    if user_id:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    if len(password) < 8 or len(password) > 128:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Password must be at least 8 characters."},
            status_code=400,
        )

    try:
        cleaned_name = clean_text(name, 50)
        cleaned_email = clean_text(email.lower().strip(), 254)
    except ValueError:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Invalid name or email."},
            status_code=400,
        )

    password_hash = pwd_context.hash(password)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, name, created_at, is_admin, is_disabled) VALUES (?, ?, ?, ?, 0, 0)",
            (cleaned_email, password_hash, cleaned_name, datetime.utcnow().isoformat()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Email already registered."},
            status_code=400,
        )
    conn.close()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    identifier = email.strip()
    cur.execute(
        "SELECT id, password_hash, is_admin, is_disabled FROM users WHERE email = ? OR username = ?",
        (identifier.lower(), identifier),
    )
    row = cur.fetchone()
    conn.close()
    if not row or not pwd_context.verify(password, row["password_hash"]):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password."},
            status_code=401,
        )
    if row["is_disabled"]:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Account disabled. Contact admin."},
            status_code=403,
        )
    request.session["user_id"] = row["id"]
    request.session["is_admin"] = int(row["is_admin"] or 0)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    cur.execute("SELECT * FROM games WHERE organizer_id = ? ORDER BY created_at DESC", (user_id,))
    games = cur.fetchall()
    conn.close()

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "games": games},
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.email, u.name, u.username, u.is_admin, u.is_disabled,
               (SELECT COUNT(*) FROM games g WHERE g.organizer_id = u.id) AS game_count
        FROM users u
        ORDER BY u.created_at DESC
        """
    )
    users = cur.fetchall()
    conn.close()
    return templates.TemplateResponse("admin.html", {"request": request, "users": users, "error": None, "success": None})


@app.post("/admin/users/{user_id}/disable")
def admin_disable_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_disabled = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/users/{user_id}/enable")
def admin_enable_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_disabled = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/users/{user_id}/reset")
def admin_reset_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    new_password = secrets.token_urlsafe(10)
    password_hash = pwd_context.hash(new_password)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    # Re-render admin page with temp password
    cur.execute(
        """
        SELECT u.id, u.email, u.name, u.username, u.is_admin, u.is_disabled,
               (SELECT COUNT(*) FROM games g WHERE g.organizer_id = u.id) AS game_count
        FROM users u
        ORDER BY u.created_at DESC
        """
    )
    users = cur.fetchall()
    conn.close()
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "users": users, "error": None, "success": f\"Temporary password: {new_password}\"},
    )


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int, csrf_token: str = Form(...)):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    if user_id == current_user_id(request):
        return RedirectResponse(url="/admin", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    # Delete games + related records
    cur.execute("SELECT id FROM games WHERE organizer_id = ?", (user_id,))
    game_ids = [row["id"] for row in cur.fetchall()]
    if game_ids:
        cur.execute("DELETE FROM rsvps WHERE game_id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
        cur.execute("DELETE FROM standby WHERE game_id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
        cur.execute("DELETE FROM games WHERE id IN (%s)" % ",".join("?" * len(game_ids)), game_ids)
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/games/new", response_class=HTMLResponse)
def new_game_form(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM games WHERE organizer_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    last_game = cur.fetchone()
    last_organizer_name = None
    if last_game:
        cur.execute(
            "SELECT name FROM rsvps WHERE game_id = ? AND status IN ('IN','LATE') ORDER BY created_at ASC LIMIT 1",
            (last_game["id"],),
        )
        row = cur.fetchone()
        if row:
            last_organizer_name = row["name"]
    conn.close()

    return templates.TemplateResponse(
        "create_game.html",
        {
            "request": request,
            "error": None,
            "last_game": last_game,
            "last_organizer_name": last_organizer_name,
        },
    )


@app.post("/games/new", response_class=HTMLResponse)
def new_game(
    request: Request,
    title: str = Form(...),
    location: str = Form(...),
    game_date: str = Form(...),
    game_time: str = Form(...),
    total_players: int = Form(...),
    organizer_name: str = Form(...),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    if total_players < 1 or total_players > 100:
        return templates.TemplateResponse(
            "create_game.html",
            {"request": request, "error": "Total players must be at least 1."},
            status_code=400,
        )

    code = generate_code()
    now = datetime.utcnow().isoformat()

    try:
        cleaned_title = clean_text(title, 100)
        cleaned_location = clean_text(location, 120)
        cleaned_organizer = clean_text(organizer_name, 50)
    except ValueError:
        return templates.TemplateResponse(
            "create_game.html",
            {"request": request, "error": "Invalid title, location, or organizer name."},
            status_code=400,
        )

    conn = get_db()
    cur = conn.cursor()
    cleanup_old_games(conn, user_id)
    cur.execute(
        """
        INSERT INTO games (organizer_id, code, title, location, game_date, game_time, total_players, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, code, cleaned_title, cleaned_location, game_date, game_time, total_players, now),
    )
    game_id = cur.lastrowid

    # Organizer counts as IN (HOST)
    cur.execute(
        "INSERT INTO rsvps (game_id, name, phone, status, created_at) VALUES (?, ?, ?, ?, ?)",
        (game_id, cleaned_organizer, None, "HOST", now),
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/games/{game_id}", status_code=302)


@app.get("/games/{game_id}", response_class=HTMLResponse)
def view_game(request: Request, game_id: int):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur.execute("SELECT * FROM rsvps WHERE game_id = ? ORDER BY created_at ASC", (game_id,))
    rsvps = cur.fetchall()

    cur.execute("SELECT * FROM standby WHERE game_id = ? ORDER BY created_at ASC", (game_id,))
    standby = cur.fetchall()

    in_count = count_in(conn, game_id)
    conn.close()

    return templates.TemplateResponse(
        "game_view.html",
        {
            "request": request,
            "game": game,
            "rsvps": rsvps,
            "standby": standby,
            "in_count": in_count,
        },
    )


@app.post("/games/{game_id}/delete")
def delete_game(request: Request, game_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur.execute("DELETE FROM rsvps WHERE game_id = ?", (game_id,))
    cur.execute("DELETE FROM standby WHERE game_id = ?", (game_id,))
    cur.execute("DELETE FROM games WHERE id = ?", (game_id,))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/game", response_class=HTMLResponse)
def game_by_query(request: Request, g: Optional[str] = None):
    if not g:
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Missing game code."},
            status_code=404,
        )
    return RedirectResponse(url=f"/g/{g}", status_code=302)


@app.get("/g/{code}", response_class=HTMLResponse)
def game_by_code(request: Request, code: str):
    user_id = current_user_id(request)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Game not found."},
            status_code=404,
        )

    # If organizer opens invite link while logged in, send to organizer view
    if user_id and game["organizer_id"] == user_id:
        conn.close()
        return RedirectResponse(url=f"/games/{game['id']}", status_code=302)

    in_count = count_in(conn, game["id"])
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'IN' ORDER BY created_at ASC", (game["id"],))
    in_players = [row["name"] for row in cur.fetchall()]
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'LATE' ORDER BY created_at ASC", (game["id"],))
    late_players = [row["name"] for row in cur.fetchall()]
    conn.close()

    if in_count >= game["total_players"]:
        return templates.TemplateResponse(
            "game_full.html",
            {"request": request, "game": game},
        )

    return templates.TemplateResponse(
        "game.html",
        {"request": request, "game": game, "in_count": in_count, "in_players": in_players, "late_players": late_players},
    )


@app.post("/g/{code}/rsvp", response_class=HTMLResponse)
def rsvp_game(
    request: Request,
    code: str,
    name: str = Form(...),
    phone: str = Form(None),
    status: str = Form(...),
    late_eta: str = Form(None),
    csrf_token: str = Form(...),
):
    status = status.upper().strip()
    if status not in {"IN", "OUT", "LATE"}:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Game not found."},
            status_code=404,
        )

    # If IN and full, show full page
    if status == "IN":
        if count_in(conn, game["id"]) >= game["total_players"]:
            conn.close()
            return templates.TemplateResponse(
                "game_full.html",
                {"request": request, "game": game},
            )

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    cleaned_phone = (phone or "").strip() or None
    cleaned_eta = (late_eta or "").strip() or None
    now = datetime.utcnow().isoformat()

    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game["id"], cleaned_name),
    )
    existing = cur.fetchone()
    if existing:
        cur.execute(
            "UPDATE rsvps SET phone = ?, status = ?, late_eta = ?, created_at = ? WHERE id = ?",
            (cleaned_phone, status, cleaned_eta, now, existing["id"]),
        )
    else:
        cur.execute(
            "INSERT INTO rsvps (game_id, name, phone, status, late_eta, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (game["id"], cleaned_name, cleaned_phone, status, cleaned_eta, now),
        )
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "rsvp_thanks.html",
        {"request": request, "game": game, "status": status, "late_eta": late_eta},
    )


@app.post("/g/{code}/standby", response_class=HTMLResponse)
def standby_game(
    request: Request,
    code: str,
    name: str = Form(...),
    phone: str = Form(None),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Game not found."},
            status_code=404,
        )

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    cur.execute(
        "INSERT INTO standby (game_id, name, phone, created_at) VALUES (?, ?, ?, ?)",
        (game["id"], cleaned_name, (phone or "").strip() or None, datetime.utcnow().isoformat()),
    )
    cur.execute("SELECT COUNT(*) AS c FROM standby WHERE game_id = ?", (game["id"],))
    position = int(cur.fetchone()["c"])
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "standby_thanks.html",
        {"request": request, "game": game, "position": position},
    )
