from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
import base64
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse
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

# Python 3.8 environment: implement America/Thunder_Bay (EST/EDT) without zoneinfo.
def _thunder_bay_dst_bounds(year: int):
    # DST starts 2nd Sunday in March at 2:00, ends 1st Sunday in November at 2:00.
    march = datetime(year, 3, 1)
    march_weekday = march.weekday()  # Mon=0..Sun=6
    first_sunday_march = march + timedelta(days=(6 - march_weekday) % 7)
    second_sunday_march = first_sunday_march + timedelta(days=7)
    dst_start = datetime(year, 3, second_sunday_march.day, 2, 0, 0)

    november = datetime(year, 11, 1)
    nov_weekday = november.weekday()
    first_sunday_nov = november + timedelta(days=(6 - nov_weekday) % 7)
    dst_end = datetime(year, 11, first_sunday_nov.day, 2, 0, 0)
    return dst_start, dst_end


def _is_thunder_bay_dst(local_dt: datetime) -> bool:
    dst_start, dst_end = _thunder_bay_dst_bounds(local_dt.year)
    return dst_start <= local_dt < dst_end


def thunder_bay_now() -> datetime:
    now_utc = datetime.utcnow()
    local_guess = now_utc + timedelta(hours=-5)
    if _is_thunder_bay_dst(local_guess):
        local = now_utc + timedelta(hours=-4)
        return local.replace(tzinfo=timezone(timedelta(hours=-4)))
    return local_guess.replace(tzinfo=timezone(timedelta(hours=-5)))


def thunder_bay_localize(local_dt: datetime) -> datetime:
    offset_hours = -4 if _is_thunder_bay_dst(local_dt) else -5
    return local_dt.replace(tzinfo=timezone(timedelta(hours=offset_hours)))


def format_ts(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return value


def format_phone(value: Optional[str]) -> str:
    if not value:
        return "-"
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return value
    return f"+1 ({digits[0:3]}) {digits[3:6]}-{digits[6:10]}"


templates.env.filters["fmt_ts"] = format_ts
templates.env.filters["fmt_phone"] = format_phone

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
    cur.execute("PRAGMA table_info(games)")
    game_cols = {row["name"] for row in cur.fetchall()}
    if "is_cancelled" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN is_cancelled INTEGER DEFAULT 0")
    if "cancelled_at" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN cancelled_at TEXT")
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
    cur.execute("PRAGMA table_info(rsvps)")
    rsvp_cols = {row["name"] for row in cur.fetchall()}
    if "seat_number" not in rsvp_cols:
        cur.execute("ALTER TABLE rsvps ADD COLUMN seat_number INTEGER")
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_seat ON rsvps(game_id, seat_number) WHERE seat_number IS NOT NULL"
    )
    conn.commit()
    backfill_seats(conn)
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


def table_sizes(total_players: int) -> list:
    if total_players <= 0:
        return []
    if total_players <= 9:
        return [total_players]
    table_count = (total_players + 8) // 9
    base = total_players // table_count
    remainder = total_players % table_count
    return [base + 1 if idx < remainder else base for idx in range(table_count)]


def table_labels(count: int) -> list:
    labels = []
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for idx in range(count):
        n = idx
        label = ""
        while True:
            label = alphabet[n % 26] + label
            n = n // 26 - 1
            if n < 0:
                break
        labels.append(label)
    return labels


def seat_assignment(seat_number: Optional[int], total_players: int) -> tuple[Optional[str], Optional[int]]:
    if not seat_number or total_players <= 0:
        return None, None
    sizes = table_sizes(total_players)
    labels = table_labels(len(sizes))
    idx = seat_number - 1
    for label, size in zip(labels, sizes):
        if idx < size:
            return label, idx + 1
        idx -= size
    return None, None


def seat_display(seat_number: Optional[int], total_players: int) -> Optional[str]:
    label, seat_in_table = seat_assignment(seat_number, total_players)
    if not label or not seat_in_table:
        return None
    return f"{label}{seat_in_table}"


def seat_threshold_reached(conn: sqlite3.Connection, game_id: int, total_players: int) -> bool:
    if total_players <= 0:
        return False
    return (count_in(conn, game_id) / total_players) >= 0.8


def assign_seats_if_ready(conn: sqlite3.Connection, game_id: int, total_players: int) -> None:
    if not seat_threshold_reached(conn, game_id, total_players):
        return
    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND status IN ('IN','LATE','HOST') AND seat_number IS NULL ORDER BY datetime(created_at) ASC, id ASC",
        (game_id,),
    )
    rows = cur.fetchall()
    if not rows:
        return
    seats = available_seats(conn, game_id, total_players)
    for row in rows:
        if not seats:
            break
        seat = secrets.choice(seats)
        seats.remove(seat)
        cur.execute("UPDATE rsvps SET seat_number = ? WHERE id = ?", (seat, row["id"]))


def available_seats(conn: sqlite3.Connection, game_id: int, total_players: int) -> list:
    cur = conn.cursor()
    cur.execute(
        "SELECT seat_number FROM rsvps WHERE game_id = ? AND seat_number IS NOT NULL",
        (game_id,),
    )
    taken = {row["seat_number"] for row in cur.fetchall()}
    return [n for n in range(1, total_players + 1) if n not in taken]


def assign_random_seat(conn: sqlite3.Connection, game_id: int, total_players: int) -> Optional[int]:
    seats = available_seats(conn, game_id, total_players)
    if not seats:
        return None
    return secrets.choice(seats)


def backfill_seats(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("SELECT id, total_players FROM games")
    games = cur.fetchall()
    for game in games:
        if not seat_threshold_reached(conn, game["id"], game["total_players"]):
            continue
        cur.execute(
            "SELECT id FROM rsvps WHERE game_id = ? AND status IN ('IN','LATE','HOST') AND seat_number IS NULL ORDER BY datetime(created_at) ASC, id ASC",
            (game["id"],),
        )
        rows = cur.fetchall()
        if not rows:
            continue
        seats = available_seats(conn, game["id"], game["total_players"])
        for row in rows:
            if not seats:
                break
            seat = secrets.choice(seats)
            seats.remove(seat)
            cur.execute("UPDATE rsvps SET seat_number = ? WHERE id = ?", (seat, row["id"]))
    conn.commit()


def verify_csrf(request: Request, token: str) -> bool:
    return token and token == request.session.get("csrf_token")


def clean_text(value: str, max_len: int) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > max_len:
        raise ValueError("Invalid input")
    return cleaned


def normalize_phone_10(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        raise ValueError("Invalid phone")
    return digits


def twilio_config() -> dict:
    return {
        "account_sid": (os.getenv("TWILIO_ACCOUNT_SID") or "").strip(),
        "auth_token": (os.getenv("TWILIO_AUTH_TOKEN") or "").strip(),
        "from_number": (os.getenv("TWILIO_FROM_NUMBER") or "").strip(),
        "messaging_service_sid": (os.getenv("TWILIO_MESSAGING_SERVICE_SID") or "").strip(),
    }


def twilio_enabled() -> bool:
    cfg = twilio_config()
    has_sender = bool(cfg["messaging_service_sid"] or cfg["from_number"])
    return bool(cfg["account_sid"] and cfg["auth_token"] and has_sender)


def invite_link(request: Request, code: str) -> str:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip() or "https"
    host = (
        (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
        or (request.headers.get("host") or "").strip()
        or request.url.netloc
    )
    return f"{proto}://{host}/game?g={code}"


def build_invite_sms_text(request: Request, game_row, seat_label: Optional[str]) -> str:
    lines = [
        str(game_row["title"]),
        f"When: {game_row['game_date']} at {game_row['game_time']}",
        f"Where: {game_row['location']}",
    ]
    if seat_label:
        lines.append(f"Seat: {seat_label}")
    lines.append(invite_link(request, game_row["code"]))
    return "\n".join(lines)


def send_twilio_sms(to_phone_10: str, body: str) -> tuple[bool, str]:
    cfg = twilio_config()
    if not twilio_enabled():
        return False, "Twilio is not configured"
    if len(to_phone_10) != 10 or not to_phone_10.isdigit():
        return False, "Invalid destination phone"

    to_number = f"+1{to_phone_10}"
    form_data = {
        "To": to_number,
        "Body": body,
    }
    if cfg["messaging_service_sid"]:
        form_data["MessagingServiceSid"] = cfg["messaging_service_sid"]
    else:
        form_data["From"] = cfg["from_number"]
    payload = urllib.parse.urlencode(form_data).encode("utf-8")
    auth_value = f"{cfg['account_sid']}:{cfg['auth_token']}".encode("utf-8")
    auth_header = "Basic " + base64.b64encode(auth_value).decode("ascii")
    url = f"https://api.twilio.com/2010-04-01/Accounts/{cfg['account_sid']}/Messages.json"
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            sid = data.get("sid") if isinstance(data, dict) else None
            return True, sid or "unknown"
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            message = data.get("message") if isinstance(data, dict) else None
        except Exception:
            message = None
        return False, message or str(e)
    except Exception as e:
        return False, str(e)


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


def is_game_expired(game_row) -> bool:
    try:
        dt = datetime.fromisoformat(f"{game_row['game_date']}T{game_row['game_time']}")
        local_dt = thunder_bay_localize(dt)
        return thunder_bay_now() > (local_dt + timedelta(hours=6))
    except Exception:
        return False


def is_game_cancelled(game_row) -> bool:
    return bool(game_row and int(game_row["is_cancelled"] or 0) == 1)


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
        "SELECT id, password_hash, is_admin, is_disabled, name FROM users WHERE email = ? OR username = ?",
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
    request.session["user_name"] = row["name"]
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
        {"request": request, "users": users, "error": None, "success": f"Temporary password: {new_password}"},
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

    # Organizer counts as IN (HOST) with seat
    seat_number = None

    cur.execute(
        "INSERT INTO rsvps (game_id, name, phone, status, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (game_id, cleaned_organizer, None, "HOST", seat_number, now),
    )
    assign_seats_if_ready(conn, game_id, total_players)
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
    rsvp_rows = cur.fetchall()
    rsvps = []
    for row in rsvp_rows:
        rsvp = dict(row)
        rsvp["seat_label"] = seat_display(row["seat_number"], game["total_players"])
        rsvps.append(rsvp)

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
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@app.post("/games/{game_id}/rsvp/{rsvp_id}/text")
def organizer_send_text(request: Request, game_id: int, rsvp_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)
    if not verify_csrf(request, csrf_token):
        return JSONResponse({"ok": False, "error": "Bad CSRF token"}, status_code=400)

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
        game = cur.fetchone()
        if not game:
            return JSONResponse({"ok": False, "error": "Game not found"}, status_code=404)

        cur.execute("SELECT * FROM rsvps WHERE id = ? AND game_id = ?", (rsvp_id, game_id))
        rsvp = cur.fetchone()
        if not rsvp:
            return JSONResponse({"ok": False, "error": "RSVP not found"}, status_code=404)
        if not rsvp["phone"]:
            return JSONResponse({"ok": False, "error": "No phone number"}, status_code=400)

        seat_label = seat_display(rsvp["seat_number"], game["total_players"])
        message = build_invite_sms_text(request, game, seat_label)
        sent, result = send_twilio_sms(rsvp["phone"], message)
        if not sent:
            return JSONResponse(
                {"ok": False, "provider": "twilio", "error": result},
                status_code=503,
            )
        return JSONResponse({"ok": True, "provider": "twilio", "message_sid": result})
    finally:
        conn.close()


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


@app.post("/games/{game_id}/cancel")
def cancel_game(request: Request, game_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, is_cancelled FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    if int(game["is_cancelled"] or 0) == 0:
        cur.execute(
            "UPDATE games SET is_cancelled = 1, cancelled_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), game_id),
        )
        conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Game%20cancelled", status_code=302)


@app.post("/games/{game_id}/rsvp/{rsvp_id}/update")
def update_rsvp(
    request: Request,
    game_id: int,
    rsvp_id: int,
    name: str = Form(...),
    status: str = Form(...),
    late_eta: str = Form(None),
    phone: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    status = status.upper().strip()
    if status not in {"IN", "LATE", "OUT", "HOST"}:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20status", status_code=302)

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20name", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur.execute("SELECT * FROM rsvps WHERE id = ? AND game_id = ?", (rsvp_id, game_id))
    rsvp = cur.fetchone()
    if not rsvp:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=RSVP%20not%20found", status_code=302)

    # Prevent duplicate names in same game
    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?) AND id != ?",
        (game_id, cleaned_name, rsvp_id),
    )
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Name%20already%20exists", status_code=302)

    new_seat = rsvp["seat_number"]
    if status == "OUT":
        new_seat = None

    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20phone%20number", status_code=302)
    cur.execute(
        "UPDATE rsvps SET name = ?, phone = ?, status = ?, late_eta = ?, seat_number = ? WHERE id = ?",
        (cleaned_name, cleaned_phone, status, (late_eta or "").strip() or None, new_seat, rsvp_id),
    )
    assign_seats_if_ready(conn, game_id, game["total_players"])
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Updated", status_code=302)


@app.post("/games/{game_id}/rsvp/add")
def add_rsvp(
    request: Request,
    game_id: int,
    name: str = Form(...),
    phone: str = Form(None),
    status: str = Form(...),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    status = status.upper().strip()
    if status not in {"IN", "LATE", "OUT"}:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20status", status_code=302)

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20name", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game_id, cleaned_name),
    )
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Name%20already%20exists", status_code=302)

    total_players = int(game["total_players"])
    if status in {"IN", "LATE"} and count_in(conn, game_id) >= total_players:
        total_players += 1
        cur.execute("UPDATE games SET total_players = ? WHERE id = ?", (total_players, game_id))

    seat_number = None

    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20phone%20number", status_code=302)
    now = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO rsvps (game_id, name, phone, status, late_eta, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (game_id, cleaned_name, cleaned_phone, status, None, seat_number, now),
    )
    assign_seats_if_ready(conn, game_id, total_players)
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Added", status_code=302)


@app.post("/games/{game_id}/standby/{standby_id}/promote")
def promote_standby(
    request: Request,
    game_id: int,
    standby_id: int,
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur.execute("SELECT * FROM standby WHERE id = ? AND game_id = ?", (standby_id, game_id))
    standby_row = cur.fetchone()
    if not standby_row:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Standby%20not%20found", status_code=302)

    try:
        cleaned_name = clean_text(standby_row["name"], 50)
    except ValueError:
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20name", status_code=302)

    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game_id, cleaned_name),
    )
    if cur.fetchone():
        conn.close()
        return RedirectResponse(url=f"/games/{game_id}?error=Name%20already%20exists", status_code=302)

    total_players = int(game["total_players"])
    if count_in(conn, game_id) >= total_players:
        total_players += 1
        cur.execute("UPDATE games SET total_players = ? WHERE id = ?", (total_players, game_id))

    seat_number = None

    now = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO rsvps (game_id, name, phone, status, late_eta, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (game_id, cleaned_name, standby_row["phone"], "IN", None, seat_number, now),
    )
    assign_seats_if_ready(conn, game_id, total_players)
    cur.execute("DELETE FROM standby WHERE id = ?", (standby_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Moved%20to%20IN", status_code=302)


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

    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )

    if is_game_expired(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has expired."},
            status_code=404,
        )

    # If organizer opens invite link while logged in, send to organizer view
    if user_id and game["organizer_id"] == user_id:
        conn.close()
        return RedirectResponse(url=f"/games/{game['id']}", status_code=302)

    in_count = count_in(conn, game["id"])
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'HOST' ORDER BY created_at ASC LIMIT 1", (game["id"],))
    host_row = cur.fetchone()
    host_name = host_row["name"] if host_row else None
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'IN' ORDER BY created_at ASC", (game["id"],))
    in_players = [row["name"] for row in cur.fetchall()]
    cur.execute("SELECT name FROM rsvps WHERE game_id = ? AND status = 'LATE' ORDER BY created_at ASC", (game["id"],))
    late_players = [row["name"] for row in cur.fetchall()]
    cur.execute("SELECT COUNT(*) AS c FROM rsvps WHERE game_id = ? AND status = 'OUT'", (game["id"],))
    out_count = int(cur.fetchone()["c"])
    conn.close()

    if in_count >= game["total_players"]:
        return templates.TemplateResponse(
            "game_full.html",
            {"request": request, "game": game},
        )

    return templates.TemplateResponse(
        "game.html",
        {
            "request": request,
            "game": game,
            "in_count": in_count,
            "in_players": in_players,
            "late_players": late_players,
            "host_name": host_name,
            "out_count": out_count,
        },
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
    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )

    # If IN/LATE and full, show full page
    if status in {"IN", "LATE"}:
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
    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}?error=Invalid%20phone%20number", status_code=302)
    cleaned_eta = (late_eta or "").strip() or None
    now = datetime.utcnow().isoformat()

    cur.execute(
        "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game["id"], cleaned_name),
    )
    existing = cur.fetchone()
    current_seat = None
    if existing:
        cur.execute("SELECT seat_number FROM rsvps WHERE id = ?", (existing["id"],))
        seat_row = cur.fetchone()
        current_seat = seat_row["seat_number"] if seat_row else None
        new_seat = current_seat
        if status == "OUT":
            new_seat = None
        cur.execute(
            "UPDATE rsvps SET phone = ?, status = ?, late_eta = ?, seat_number = ?, created_at = ? WHERE id = ?",
            (cleaned_phone, status, cleaned_eta, new_seat, now, existing["id"]),
        )
    else:
        new_seat = None
        cur.execute(
            "INSERT INTO rsvps (game_id, name, phone, status, late_eta, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (game["id"], cleaned_name, cleaned_phone, status, cleaned_eta, new_seat, now),
        )
    assign_seats_if_ready(conn, game["id"], game["total_players"])
    cur.execute(
        "SELECT seat_number FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
        (game["id"], cleaned_name),
    )
    seat_row = cur.fetchone()
    seat_to_show = seat_row["seat_number"] if seat_row else None
    table_label, seat_in_table = seat_assignment(seat_to_show, game["total_players"])
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "rsvp_thanks.html",
        {
            "request": request,
            "game": game,
            "status": status,
            "late_eta": late_eta,
            "seat_number": seat_to_show,
            "table_label": table_label,
            "seat_in_table": seat_in_table,
            "seat_label": seat_display(seat_to_show, game["total_players"]),
        },
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
    if is_game_cancelled(game):
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "This game has been cancelled."},
            status_code=404,
        )

    try:
        cleaned_name = clean_text(name, 50)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}", status_code=302)
    try:
        cleaned_phone = normalize_phone_10(phone)
    except ValueError:
        return RedirectResponse(url=f"/g/{code}?error=Invalid%20phone%20number", status_code=302)
    cur.execute(
        "INSERT INTO standby (game_id, name, phone, created_at) VALUES (?, ?, ?, ?)",
        (game["id"], cleaned_name, cleaned_phone, datetime.utcnow().isoformat()),
    )
    cur.execute("SELECT COUNT(*) AS c FROM standby WHERE game_id = ?", (game["id"],))
    position = int(cur.fetchone()["c"])
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "standby_thanks.html",
        {"request": request, "game": game, "position": position},
    )
