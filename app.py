from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, StreamingResponse, JSONResponse
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
cancel_sms_worker_task = None

SMS_WINDOW_MINUTES = 10
SMS_PER_PHONE_WINDOW_LIMIT = 4
SMS_PER_GAME_WINDOW_LIMIT = 120
SMS_GLOBAL_WINDOW_LIMIT = 400
SMS_DUPLICATE_COOLDOWN_SECONDS = 90
SMS_PER_ORGANIZER_HOUR_LIMIT = 180
SMS_PER_ORGANIZER_DAY_LIMIT = 700
CANCELLATION_SMS_COOLDOWN_HOURS = 6
TRUSTED_DEVICE_DAYS = 30
TRUSTED_DEVICE_COOKIE = "poker_trusted_device"

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


def format_game_time(value: str) -> str:
    if not value:
        return ""
    raw = str(value).strip()
    for fmt in ("%H:%M", "%H:%M:%S", "%I:%M %p", "%I:%M%p"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.strftime("%I:%M %p").lstrip("0")
        except Exception:
            pass
    return raw


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
templates.env.filters["fmt_game_time"] = format_game_time
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
    if "phone" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "phone_verified_at" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN phone_verified_at TEXT")
    if "mfa_enabled" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
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
            multiple_tables INTEGER DEFAULT 0,
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
    if "host_code" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN host_code TEXT")
    if "multiple_tables" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN multiple_tables INTEGER DEFAULT 0")
    if "sms_enabled" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN sms_enabled INTEGER DEFAULT 1")
    if "cancellation_sms_due_at" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN cancellation_sms_due_at TEXT")
    if "cancellation_sms_sent_at" not in game_cols:
        cur.execute("ALTER TABLE games ADD COLUMN cancellation_sms_sent_at TEXT")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_games_host_code ON games(host_code)")
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
    if "rsvp_token" not in rsvp_cols:
        cur.execute("ALTER TABLE rsvps ADD COLUMN rsvp_token TEXT")
    if "seat_full_sms_sent_at" not in rsvp_cols:
        cur.execute("ALTER TABLE rsvps ADD COLUMN seat_full_sms_sent_at TEXT")
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_seat ON rsvps(game_id, seat_number) WHERE seat_number IS NOT NULL"
    )
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rsvps_game_token ON rsvps(game_id, rsvp_token) WHERE rsvp_token IS NOT NULL"
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_mfa_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_mfa_codes_user_created_at ON user_mfa_codes(user_id, created_at)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_trusted_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            ua_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user_trusted_devices_user ON user_trusted_devices(user_id)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_phone_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            phone TEXT NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            verified_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_phone_verifications_user ON user_phone_verifications(user_id)")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS phone_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER NOT NULL,
            phone TEXT NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            verified_at TEXT,
            FOREIGN KEY (game_id) REFERENCES games(id)
        )
        """
    )
    cur.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_phone_verifications_game_phone ON phone_verifications(game_id, phone)"
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sms_outbound (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER,
            phone TEXT NOT NULL,
            kind TEXT NOT NULL,
            body_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            sent_ok INTEGER NOT NULL DEFAULT 0,
            detail TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sms_outbound_created_at ON sms_outbound(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sms_outbound_phone_created_at ON sms_outbound(phone, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sms_outbound_game_created_at ON sms_outbound(game_id, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sms_outbound_phone_body_created_at ON sms_outbound(phone, body_hash, created_at)")
    cur.execute("SELECT id FROM games WHERE host_code IS NULL OR host_code = ''")
    for row in cur.fetchall():
        cur.execute("UPDATE games SET host_code = ? WHERE id = ?", (generate_host_code(conn), row["id"]))
    conn.commit()
    backfill_seats(conn)
    conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


@app.on_event("startup")
async def start_cancel_sms_worker():
    global cancel_sms_worker_task
    if cancel_sms_worker_task is None or cancel_sms_worker_task.done():
        cancel_sms_worker_task = asyncio.create_task(cancel_sms_worker_loop())


@app.on_event("shutdown")
async def stop_cancel_sms_worker():
    global cancel_sms_worker_task
    if cancel_sms_worker_task:
        cancel_sms_worker_task.cancel()
        try:
            await cancel_sms_worker_task
        except asyncio.CancelledError:
            pass
        cancel_sms_worker_task = None


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

def _generate_unique_game_value(conn: sqlite3.Connection, column: str, length: int) -> str:
    if column not in {"code", "host_code"}:
        raise ValueError("Invalid games column for code generation")
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    while True:
        code = "".join(secrets.choice(alphabet) for _ in range(length))
        cur = conn.cursor()
        cur.execute(f"SELECT id FROM games WHERE {column} = ?", (code,))
        exists = cur.fetchone()
        if not exists:
            return code


def generate_code(length: int = 8, conn: Optional[sqlite3.Connection] = None) -> str:
    own_conn = conn is None
    if conn is None:
        conn = get_db()
    try:
        return _generate_unique_game_value(conn, "code", length)
    finally:
        if own_conn:
            conn.close()


def generate_host_code(conn: Optional[sqlite3.Connection] = None, length: int = 16) -> str:
    own_conn = conn is None
    if conn is None:
        conn = get_db()
    try:
        return _generate_unique_game_value(conn, "host_code", length)
    finally:
        if own_conn:
            conn.close()


def count_in(conn: sqlite3.Connection, game_id: int) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM rsvps WHERE game_id = ? AND status IN ('IN', 'LATE', 'HOST')", (game_id,))
    row = cur.fetchone()
    return int(row["c"]) if row else 0


def game_uses_multiple_tables(game_row) -> bool:
    return bool(game_row and int(game_row["multiple_tables"] or 0) == 1)


def table_sizes(total_players: int, multiple_tables: bool = False) -> list:
    if total_players <= 0:
        return []
    if not multiple_tables:
        return [total_players]
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


def seat_assignment(seat_number: Optional[int], total_players: int, multiple_tables: bool = False) -> tuple[Optional[str], Optional[int]]:
    if not seat_number or total_players <= 0:
        return None, None
    sizes = table_sizes(total_players, multiple_tables)
    labels = table_labels(len(sizes))
    idx = seat_number - 1
    for label, size in zip(labels, sizes):
        if idx < size:
            return label, idx + 1
        idx -= size
    return None, None


def seat_display(seat_number: Optional[int], total_players: int, multiple_tables: bool = False) -> Optional[str]:
    label, seat_in_table = seat_assignment(seat_number, total_players, multiple_tables)
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


def normalize_game_time(value: str) -> str:
    cleaned = clean_text(value, 32)
    normalized = " ".join(cleaned.upper().split())
    for fmt in ("%H:%M", "%H:%M:%S", "%I:%M %p", "%I:%M%p"):
        try:
            return datetime.strptime(normalized, fmt).strftime("%H:%M")
        except Exception:
            pass
    raise ValueError("Invalid game time")


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


def sms_send_enabled_globally() -> bool:
    return (os.getenv("SMS_SEND_ENABLED", "true").strip().lower() in {"1", "true", "on", "yes"})


def game_sms_enabled(game_row) -> bool:
    if not game_row:
        return True
    return int(game_row["sms_enabled"] or 1) == 1


def should_verify_phone(game_row) -> bool:
    return twilio_enabled() and sms_send_enabled_globally() and game_sms_enabled(game_row)


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
        f"When: {game_row['game_date']} at {format_game_time(game_row['game_time'])}",
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
            sid = data.get("sid") or "unknown"
            return True, sid
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            message = data.get("message") or str(e)
        except Exception:
            message = str(e)
        return False, message
    except Exception as e:
        return False, str(e)


def send_twilio_sms_guarded(
    conn: sqlite3.Connection,
    game_id: Optional[int],
    to_phone_10: str,
    body: str,
    kind: str,
) -> tuple[bool, str]:
    if not sms_send_enabled_globally():
        reason = "SMS sending disabled globally"
        log_sms_outbound(conn, game_id, to_phone_10, kind, body, False, reason)
        audit_sms_event("blocked", game_id, to_phone_10, kind, reason)
        return False, reason
    if game_id is not None:
        cur = conn.cursor()
        cur.execute("SELECT sms_enabled FROM games WHERE id = ?", (game_id,))
        game_row = cur.fetchone()
        if game_row and int(game_row["sms_enabled"] or 1) != 1:
            reason = "SMS sending disabled for this game"
            log_sms_outbound(conn, game_id, to_phone_10, kind, body, False, reason)
            audit_sms_event("blocked", game_id, to_phone_10, kind, reason)
            return False, reason
    ok, reason = sms_throttle_allows(conn, game_id, to_phone_10, body)
    if not ok:
        log_sms_outbound(conn, game_id, to_phone_10, kind, body, False, reason)
        audit_sms_event("blocked", game_id, to_phone_10, kind, reason)
        return False, reason
    sent, result = send_twilio_sms(to_phone_10, body)
    log_sms_outbound(conn, game_id, to_phone_10, kind, body, sent, result)
    if not sent:
        audit_sms_event("failed", game_id, to_phone_10, kind, result)
    return sent, result


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat()


def _utc_in_minutes_iso(minutes: int) -> str:
    return (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()


def _utc_minus_minutes_iso(minutes: int) -> str:
    return (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()


def _utc_minus_seconds_iso(seconds: int) -> str:
    return (datetime.utcnow() - timedelta(seconds=seconds)).isoformat()


def sms_body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8")).hexdigest()


def sms_throttle_allows(conn: sqlite3.Connection, game_id: Optional[int], phone_10: str, body: str) -> tuple[bool, str]:
    cur = conn.cursor()
    window_start = _utc_minus_minutes_iso(SMS_WINDOW_MINUTES)
    duplicate_since = _utc_minus_seconds_iso(SMS_DUPLICATE_COOLDOWN_SECONDS)
    body_hash = sms_body_hash(body)

    cur.execute(
        """
        SELECT COUNT(*) AS c
        FROM sms_outbound
        WHERE phone = ? AND sent_ok = 1 AND created_at >= ?
        """,
        (phone_10, window_start),
    )
    if int(cur.fetchone()["c"] or 0) >= SMS_PER_PHONE_WINDOW_LIMIT:
        return False, "Per-phone SMS rate limit hit"

    cur.execute(
        """
        SELECT COUNT(*) AS c
        FROM sms_outbound
        WHERE sent_ok = 1 AND created_at >= ?
        """,
        (window_start,),
    )
    if int(cur.fetchone()["c"] or 0) >= SMS_GLOBAL_WINDOW_LIMIT:
        return False, "Global SMS rate limit hit"

    if game_id is not None:
        cur.execute(
            """
            SELECT COUNT(*) AS c
            FROM sms_outbound
            WHERE game_id = ? AND sent_ok = 1 AND created_at >= ?
            """,
            (game_id, window_start),
        )
        if int(cur.fetchone()["c"] or 0) >= SMS_PER_GAME_WINDOW_LIMIT:
            return False, "Per-game SMS rate limit hit"
        cur.execute("SELECT organizer_id FROM games WHERE id = ?", (game_id,))
        owner_row = cur.fetchone()
        organizer_id = int(owner_row["organizer_id"]) if owner_row else None
        if organizer_id:
            cur.execute(
                """
                SELECT COUNT(*) AS c
                FROM sms_outbound s
                JOIN games g ON g.id = s.game_id
                WHERE g.organizer_id = ?
                  AND s.sent_ok = 1
                  AND s.created_at >= ?
                """,
                (organizer_id, _utc_minus_minutes_iso(60)),
            )
            if int(cur.fetchone()["c"] or 0) >= SMS_PER_ORGANIZER_HOUR_LIMIT:
                return False, "Per-organizer hourly SMS limit hit"
            cur.execute(
                """
                SELECT COUNT(*) AS c
                FROM sms_outbound s
                JOIN games g ON g.id = s.game_id
                WHERE g.organizer_id = ?
                  AND s.sent_ok = 1
                  AND s.created_at >= ?
                """,
                (organizer_id, _utc_minus_minutes_iso(1440)),
            )
            if int(cur.fetchone()["c"] or 0) >= SMS_PER_ORGANIZER_DAY_LIMIT:
                return False, "Per-organizer daily SMS limit hit"

    cur.execute(
        """
        SELECT COUNT(*) AS c
        FROM sms_outbound
        WHERE phone = ? AND body_hash = ? AND sent_ok = 1 AND created_at >= ?
        """,
        (phone_10, body_hash, duplicate_since),
    )
    if int(cur.fetchone()["c"] or 0) > 0:
        return False, "Duplicate SMS cooldown active"

    return True, ""


def log_sms_outbound(conn: sqlite3.Connection, game_id: Optional[int], phone_10: str, kind: str, body: str, sent_ok: bool, detail: str) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO sms_outbound (game_id, phone, kind, body_hash, created_at, sent_ok, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            game_id,
            phone_10,
            kind,
            sms_body_hash(body),
            _utc_now_iso(),
            1 if sent_ok else 0,
            (detail or "")[:300],
        ),
    )


def audit_sms_event(event: str, game_id: Optional[int], phone_10: str, kind: str, detail: str) -> None:
    # Keep this stdout log lightweight for operational monitoring.
    print(
        f"[sms-audit] event={event} game_id={game_id if game_id is not None else '-'} "
        f"phone={phone_10} kind={kind} detail={str(detail or '')[:160]}"
    )


def generate_phone_verification_code() -> str:
    return f"{secrets.randbelow(900000) + 100000}"


def user_phone_is_verified(user_row) -> bool:
    return bool(user_row and user_row["phone"] and user_row["phone_verified_at"])


def complete_login_session(request: Request, user_row) -> None:
    request.session["user_id"] = user_row["id"]
    request.session["is_admin"] = int(user_row["is_admin"] or 0)
    request.session["user_name"] = user_row["name"]
    request.session.pop("pending_mfa_user_id", None)
    request.session.pop("pending_mfa_name", None)


def trusted_device_ua_hash(request: Request) -> str:
    ua = (request.headers.get("user-agent") or "").strip()
    return hashlib.sha256(ua.encode("utf-8")).hexdigest()


def trusted_device_token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def has_valid_trusted_device(conn: sqlite3.Connection, request: Request, user_id: int) -> bool:
    token = request.cookies.get(TRUSTED_DEVICE_COOKIE)
    if not token:
        return False
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, expires_at
        FROM user_trusted_devices
        WHERE user_id = ?
          AND token_hash = ?
          AND ua_hash = ?
          AND revoked_at IS NULL
        LIMIT 1
        """,
        (user_id, trusted_device_token_hash(token), trusted_device_ua_hash(request)),
    )
    row = cur.fetchone()
    if not row:
        return False
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False
    if datetime.utcnow() > expires_at:
        return False
    cur.execute("UPDATE user_trusted_devices SET last_seen_at = ? WHERE id = ?", (_utc_now_iso(), row["id"]))
    return True


def create_trusted_device(conn: sqlite3.Connection, request: Request, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO user_trusted_devices (user_id, token_hash, ua_hash, created_at, last_seen_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
        """,
        (
            user_id,
            trusted_device_token_hash(token),
            trusted_device_ua_hash(request),
            _utc_now_iso(),
            _utc_now_iso(),
            _utc_in_minutes_iso(TRUSTED_DEVICE_DAYS * 24 * 60),
        ),
    )
    return token


def create_user_mfa_code(conn: sqlite3.Connection, user_id: int) -> str:
    code = generate_phone_verification_code()
    now = _utc_now_iso()
    expires_at = _utc_in_minutes_iso(10)
    cur = conn.cursor()
    cur.execute("DELETE FROM user_mfa_codes WHERE user_id = ? AND used_at IS NULL", (user_id,))
    cur.execute(
        """
        INSERT INTO user_mfa_codes (user_id, code, created_at, expires_at, used_at)
        VALUES (?, ?, ?, ?, NULL)
        """,
        (user_id, code, now, expires_at),
    )
    return code


def verify_user_mfa_code(conn: sqlite3.Connection, user_id: int, code: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, code, expires_at
        FROM user_mfa_codes
        WHERE user_id = ? AND used_at IS NULL
        ORDER BY id DESC
        LIMIT 1
        """,
        (user_id,),
    )
    row = cur.fetchone()
    if not row:
        return False
    if str(row["code"]).strip() != str(code or "").strip():
        return False
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False
    if datetime.utcnow() > expires_at:
        return False
    cur.execute("UPDATE user_mfa_codes SET used_at = ? WHERE id = ?", (_utc_now_iso(), row["id"]))
    return True


def send_user_mfa_sms(conn: sqlite3.Connection, user_row, code: str) -> tuple[bool, str]:
    phone = user_row["phone"] or ""
    body = f"Organizer login code: {code}. Expires in 10 minutes."
    return send_twilio_sms_guarded(conn, None, phone, body, "user_mfa")


def send_user_phone_verify_sms(conn: sqlite3.Connection, phone_10: str, code: str) -> tuple[bool, str]:
    body = f"Organizer phone verification code: {code}. Expires in 10 minutes."
    return send_twilio_sms_guarded(conn, None, phone_10, body, "user_phone_verify")


def create_user_phone_verification(conn: sqlite3.Connection, user_id: int, phone_10: str) -> str:
    code = generate_phone_verification_code()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO user_phone_verifications (user_id, phone, code, created_at, expires_at, verified_at)
        VALUES (?, ?, ?, ?, ?, NULL)
        ON CONFLICT(user_id) DO UPDATE SET
            phone = excluded.phone,
            code = excluded.code,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            verified_at = NULL
        """,
        (user_id, phone_10, code, _utc_now_iso(), _utc_in_minutes_iso(10)),
    )
    return code


def verify_user_phone_code(conn: sqlite3.Connection, user_id: int, phone_10: str, code: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, code, expires_at
        FROM user_phone_verifications
        WHERE user_id = ? AND phone = ?
        LIMIT 1
        """,
        (user_id, phone_10),
    )
    row = cur.fetchone()
    if not row:
        return False
    if str(row["code"]).strip() != str(code or "").strip():
        return False
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False
    if datetime.utcnow() > expires_at:
        return False
    now = _utc_now_iso()
    cur.execute("UPDATE user_phone_verifications SET verified_at = ? WHERE id = ?", (now, row["id"]))
    cur.execute("UPDATE users SET phone_verified_at = ? WHERE id = ? AND phone = ?", (now, user_id, phone_10))
    return True


def phone_is_verified(conn: sqlite3.Connection, game_id: int, phone_10: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT verified_at
        FROM phone_verifications
        WHERE phone = ?
          AND verified_at IS NOT NULL
        ORDER BY datetime(verified_at) DESC, id DESC
        LIMIT 1
        """,
        (phone_10,),
    )
    row = cur.fetchone()
    return bool(row and row["verified_at"])


def create_or_refresh_phone_code(conn: sqlite3.Connection, game_id: int, phone_10: str) -> str:
    code = generate_phone_verification_code()
    now = _utc_now_iso()
    expires_at = _utc_in_minutes_iso(10)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO phone_verifications (game_id, phone, code, created_at, expires_at, verified_at)
        VALUES (?, ?, ?, ?, ?, NULL)
        ON CONFLICT(game_id, phone) DO UPDATE SET
            code = excluded.code,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            verified_at = NULL
        """,
        (game_id, phone_10, code, now, expires_at),
    )
    return code


def confirm_phone_code(conn: sqlite3.Connection, game_id: int, phone_10: str, code: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT code, expires_at FROM phone_verifications WHERE game_id = ? AND phone = ?",
        (game_id, phone_10),
    )
    row = cur.fetchone()
    if not row:
        return False
    if str(row["code"]).strip() != str(code or "").strip():
        return False
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False
    if datetime.utcnow() > expires_at:
        return False
    cur.execute(
        "UPDATE phone_verifications SET verified_at = ? WHERE game_id = ? AND phone = ?",
        (_utc_now_iso(), game_id, phone_10),
    )
    return True


def send_phone_verification_sms(conn: sqlite3.Connection, game_row, phone_10: str, code: str) -> tuple[bool, str]:
    body = f"{game_row['title']}: verification code {code}. Expires in 10 minutes."
    return send_twilio_sms_guarded(conn, int(game_row["id"]), phone_10, body, "verify")


def maybe_send_choice_confirmation_sms(conn: sqlite3.Connection, game_row, phone_10: Optional[str], status: str, late_eta: Optional[str], seat_label: Optional[str]) -> None:
    if not phone_10:
        return
    base = f"{game_row['title']}: response confirmed as {status}."
    if status == "LATE" and late_eta:
        base += f" ETA: {late_eta}."
    if seat_label:
        base += f" Seat: {seat_label}."
    send_twilio_sms_guarded(conn, int(game_row["id"]), phone_10, base, "choice_confirm")


def maybe_send_standby_confirmation_sms(conn: sqlite3.Connection, game_row, phone_10: Optional[str], position: int) -> None:
    if not phone_10:
        return
    body = f"{game_row['title']}: you are on standby at position #{position}."
    send_twilio_sms_guarded(conn, int(game_row["id"]), phone_10, body, "standby_confirm")


def notify_game_cancelled_sms(conn: sqlite3.Connection, game_row) -> None:
    cur = conn.cursor()
    recipients = set()
    cur.execute("SELECT phone FROM rsvps WHERE game_id = ? AND phone IS NOT NULL", (game_row["id"],))
    for row in cur.fetchall():
        phone = (row["phone"] or "").strip()
        if len(phone) == 10 and phone.isdigit():
            recipients.add(phone)
    cur.execute("SELECT phone FROM standby WHERE game_id = ? AND phone IS NOT NULL", (game_row["id"],))
    for row in cur.fetchall():
        phone = (row["phone"] or "").strip()
        if len(phone) == 10 and phone.isdigit():
            recipients.add(phone)
    if not recipients:
        return
    body = f"{game_row['title']} has been cancelled. Please do not come to the game location."
    for phone in sorted(recipients):
        send_twilio_sms_guarded(conn, int(game_row["id"]), phone, body, "cancel_notice")


def process_due_cancellation_sms(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    now = _utc_now_iso()
    cur.execute(
        """
        SELECT *
        FROM games
        WHERE is_cancelled = 1
          AND cancellation_sms_sent_at IS NULL
          AND cancellation_sms_due_at IS NOT NULL
          AND cancellation_sms_due_at <= ?
        ORDER BY id ASC
        """,
        (now,),
    )
    games = cur.fetchall()
    for game in games:
        notify_game_cancelled_sms(conn, game)
        cur.execute(
            "UPDATE games SET cancellation_sms_sent_at = ? WHERE id = ?",
            (_utc_now_iso(), game["id"]),
        )


async def cancel_sms_worker_loop():
    while True:
        try:
            conn = get_db()
            try:
                process_due_cancellation_sms(conn)
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass
        await asyncio.sleep(10)


def notify_seat_sms_when_full(conn: sqlite3.Connection, game_row) -> None:
    game_id = int(game_row["id"])
    total_players = int(game_row["total_players"])
    if count_in(conn, game_id) < total_players:
        return
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, phone, seat_number
        FROM rsvps
        WHERE game_id = ?
          AND status IN ('IN', 'LATE', 'HOST')
          AND phone IS NOT NULL
          AND seat_number IS NOT NULL
          AND (seat_full_sms_sent_at IS NULL OR seat_full_sms_sent_at = '')
        ORDER BY id ASC
        """,
        (game_id,),
    )
    rows = cur.fetchall()
    if not rows:
        return
    for row in rows:
        seat_label = seat_display(
            row["seat_number"],
            total_players,
            game_uses_multiple_tables(game_row),
        ) or f"#{row['seat_number']}"
        body = f"{game_row['title']} is now full. Your seat is {seat_label}."
        sent, _ = send_twilio_sms_guarded(conn, game_id, row["phone"], body, "seat_full")
        if sent:
            cur.execute(
                "UPDATE rsvps SET seat_full_sms_sent_at = ? WHERE id = ?",
                (_utc_now_iso(), row["id"]),
            )


def normalize_rsvp_token(value: Optional[str]) -> Optional[str]:
    token = (value or "").strip()
    if not token:
        return None
    if len(token) < 8 or len(token) > 64:
        return None
    for ch in token:
        if not (ch.isalnum() or ch in {"-", "_"}):
            return None
    return token


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


def game_snapshot_payload(conn: sqlite3.Connection, game_row) -> dict:
    game_id = int(game_row["id"])
    cur = conn.cursor()
    cur.execute("SELECT * FROM rsvps WHERE game_id = ? ORDER BY created_at ASC", (game_id,))
    rsvp_rows = cur.fetchall()
    rsvps = []
    for row in rsvp_rows:
        rsvps.append(
            {
                "id": int(row["id"]),
                "name": row["name"],
                "phone": row["phone"] or "",
                "phone_fmt": format_phone(row["phone"]),
                "status": row["status"],
                "late_eta": row["late_eta"] or "",
                "created_at": row["created_at"],
                "created_at_fmt": format_ts(row["created_at"]),
                "seat_number": row["seat_number"],
                "seat_label": seat_display(row["seat_number"], game_row["total_players"], game_uses_multiple_tables(game_row)) or "-",
            }
        )
    payload = {
        "game_id": game_id,
        "is_cancelled": is_game_cancelled(game_row),
        "in_count": count_in(conn, game_id),
        "total_players": int(game_row["total_players"]),
        "rsvps": rsvps,
    }
    payload["signature"] = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return payload


def host_snapshot_payload(conn: sqlite3.Connection, game_row) -> dict:
    game_id = int(game_row["id"])
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, name, status, late_eta, seat_number, created_at
        FROM rsvps
        WHERE game_id = ? AND status IN ('IN', 'LATE')
        ORDER BY
            CASE status WHEN 'IN' THEN 0 WHEN 'LATE' THEN 1 ELSE 9 END,
            datetime(created_at) ASC, id ASC
        """,
        (game_id,),
    )
    players = []
    for row in cur.fetchall():
        players.append(
            {
                "id": int(row["id"]),
                "name": row["name"],
                "status": row["status"],
                "late_eta": row["late_eta"] or "",
                "seat_number": row["seat_number"],
                "seat_label": seat_display(row["seat_number"], game_row["total_players"], game_uses_multiple_tables(game_row)) or "-",
            }
        )
    in_count = sum(1 for p in players if p["status"] == "IN")
    late_count = sum(1 for p in players if p["status"] == "LATE")
    payload = {
        "game_id": game_id,
        "title": game_row["title"],
        "game_date": game_row["game_date"],
        "game_time": game_row["game_time"],
        "total_players": int(game_row["total_players"]),
        "is_cancelled": is_game_cancelled(game_row),
        "in_count": in_count,
        "late_count": late_count,
        "players": players,
    }
    payload["signature"] = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return payload


def twiml_message(text: str) -> str:
    safe = xml_escape(text or "")
    return f'<?xml version="1.0" encoding="UTF-8"?><Response><Message>{safe}</Message></Response>'


def active_games_for_phone(conn: sqlite3.Connection, phone_10: str) -> list:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            g.*,
            r.status AS rsvp_status,
            r.name AS rsvp_name,
            r.seat_number AS rsvp_seat_number
        FROM rsvps r
        JOIN games g ON g.id = r.game_id
        WHERE r.phone = ?
          AND r.status IN ('IN', 'LATE', 'HOST')
        ORDER BY g.game_date ASC, g.game_time ASC, g.id ASC
        """,
        (phone_10,),
    )
    rows = []
    for row in cur.fetchall():
        if is_game_cancelled(row) or is_game_expired(row):
            continue
        rows.append(row)
    return rows


def build_inbound_status_text(conn: sqlite3.Connection, phone_10: str) -> str:
    games = active_games_for_phone(conn, phone_10)
    if not games:
        return "No active game found for this number."
    if len(games) == 1:
        game = games[0]
        seat_label = seat_display(game["rsvp_seat_number"], game["total_players"], game_uses_multiple_tables(game))
        seat_part = f"Seat {seat_label}." if seat_label else "Seat pending."
        return (
            f"{game['title']} on {game['game_date']} at {format_game_time(game['game_time'])}. "
            f"Status {game['rsvp_status']}. {seat_part}"
        )
    lines = ["You are in multiple active games:"]
    for game in games[:3]:
        seat_label = seat_display(game["rsvp_seat_number"], game["total_players"], game_uses_multiple_tables(game)) or "pending"
        lines.append(
            f"- {game['title']} {game['game_date']} {format_game_time(game['game_time'])}, "
            f"{game['rsvp_status']}, seat {seat_label}"
        )
    if len(games) > 3:
        lines.append(f"...and {len(games) - 3} more.")
    return "\n".join(lines)


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


@app.get("/favicon.ico")
def favicon():
    return RedirectResponse(url="/static/favicon-app-32.png", status_code=302)


@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    return RedirectResponse(url="/static/apple-touch-icon-app.png", status_code=302)


@app.get("/apple-touch-icon-precomposed.png")
def apple_touch_icon_precomposed():
    return RedirectResponse(url="/static/apple-touch-icon-app.png", status_code=302)


@app.post("/twilio/sms/inbound")
def twilio_sms_inbound(request: Request, From: str = Form(None), Body: str = Form(None)):
    # Optional shared token guard: include ?token=... in the Twilio webhook URL.
    inbound_token = (os.getenv("TWILIO_INBOUND_TOKEN") or "").strip()
    if inbound_token:
        token = (request.query_params.get("token") or "").strip()
        if token != inbound_token:
            return PlainTextResponse("Forbidden", status_code=403)

    try:
        phone_10 = normalize_phone_10(From)
    except ValueError:
        phone_10 = None
    if not phone_10:
        return PlainTextResponse(twiml_message("Could not read your phone number."), media_type="application/xml")

    conn = get_db()
    try:
        text = build_inbound_status_text(conn, phone_10)
    finally:
        conn.close()
    return PlainTextResponse(twiml_message(text), media_type="application/xml")


@app.post("/twilio/voice/inbound")
def twilio_voice_inbound(request: Request):
    inbound_token = (os.getenv("TWILIO_INBOUND_TOKEN") or "").strip()
    if inbound_token:
        token = (request.query_params.get("token") or "").strip()
        if token != inbound_token:
            return PlainTextResponse("Forbidden", status_code=403)
    return PlainTextResponse(
        '<?xml version="1.0" encoding="UTF-8"?><Response><Reject reason="rejected"/></Response>',
        media_type="application/xml",
    )


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
        "SELECT id, password_hash, is_admin, is_disabled, name, phone, phone_verified_at, mfa_enabled FROM users WHERE email = ? OR username = ?",
        (identifier.lower(), identifier),
    )
    row = cur.fetchone()
    if not row or not pwd_context.verify(password, row["password_hash"]):
        conn.close()
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid email or password."},
            status_code=401,
        )
    if row["is_disabled"]:
        conn.close()
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Account disabled. Contact admin."},
            status_code=403,
        )
    if int(row["mfa_enabled"] or 0) == 1:
        if not user_phone_is_verified(row):
            conn.close()
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "MFA is enabled but phone is not verified. Use profile settings after admin reset if needed."},
                status_code=403,
            )
        if has_valid_trusted_device(conn, request, int(row["id"])):
            conn.commit()
            conn.close()
            complete_login_session(request, row)
            return RedirectResponse(url="/dashboard", status_code=302)
        code = create_user_mfa_code(conn, int(row["id"]))
        sent, reason = send_user_mfa_sms(conn, row, code)
        conn.commit()
        conn.close()
        if not sent:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": f"Could not send MFA code: {reason}"},
                status_code=503,
            )
        request.session["pending_mfa_user_id"] = int(row["id"])
        request.session["pending_mfa_name"] = row["name"]
        return RedirectResponse(url="/mfa", status_code=302)
    conn.close()
    complete_login_session(request, row)
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/mfa", response_class=HTMLResponse)
def mfa_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/dashboard", status_code=302)
    pending_user_id = request.session.get("pending_mfa_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "mfa.html",
        {
            "request": request,
            "error": None,
            "pending_name": request.session.get("pending_mfa_name") or "Organizer",
        },
    )


@app.post("/mfa", response_class=HTMLResponse)
def mfa_verify(request: Request, code: str = Form(...), trust_device: str = Form(None), csrf_token: str = Form(...)):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    pending_user_id = request.session.get("pending_mfa_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    if not verify_user_mfa_code(conn, int(pending_user_id), code):
        conn.commit()
        conn.close()
        return templates.TemplateResponse(
            "mfa.html",
            {
                "request": request,
                "error": "Invalid or expired MFA code.",
                "pending_name": request.session.get("pending_mfa_name") or "Organizer",
            },
            status_code=400,
        )
    cur.execute("SELECT id, is_admin, name FROM users WHERE id = ?", (int(pending_user_id),))
    row = cur.fetchone()
    conn.commit()
    trusted_token = None
    if row and str(trust_device or "").strip() in {"1", "true", "on", "yes"}:
        trusted_token = create_trusted_device(conn, request, int(row["id"]))
        conn.commit()
    conn.close()
    if not row:
        request.session.pop("pending_mfa_user_id", None)
        request.session.pop("pending_mfa_name", None)
        return RedirectResponse(url="/login", status_code=302)
    complete_login_session(request, row)
    response = RedirectResponse(url="/dashboard", status_code=302)
    if trusted_token:
        response.set_cookie(
            TRUSTED_DEVICE_COOKIE,
            trusted_token,
            max_age=TRUSTED_DEVICE_DAYS * 24 * 60 * 60,
            httponly=True,
            secure=os.getenv("SESSION_SECURE", "true").lower() == "true",
            samesite="strict",
        )
    return response


@app.post("/mfa/resend", response_class=HTMLResponse)
def mfa_resend(request: Request, csrf_token: str = Form(...)):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    pending_user_id = request.session.get("pending_mfa_user_id")
    if not pending_user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, phone, phone_verified_at FROM users WHERE id = ?", (int(pending_user_id),))
    row = cur.fetchone()
    if not row or not user_phone_is_verified(row):
        conn.close()
        return RedirectResponse(url="/login", status_code=302)
    code = create_user_mfa_code(conn, int(row["id"]))
    sent, reason = send_user_mfa_sms(conn, row, code)
    conn.commit()
    conn.close()
    if not sent:
        return templates.TemplateResponse(
            "mfa.html",
            {
                "request": request,
                "error": f"Could not resend MFA code: {reason}",
                "pending_name": request.session.get("pending_mfa_name") or "Organizer",
            },
            status_code=503,
        )
    return templates.TemplateResponse(
        "mfa.html",
        {
            "request": request,
            "error": None,
            "success": "MFA code resent.",
            "pending_name": request.session.get("pending_mfa_name") or "Organizer",
        },
    )


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


@app.get("/profile", response_class=HTMLResponse)
def profile_view(request: Request):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, name, phone, phone_verified_at, mfa_enabled FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        "profile.html",
        {"request": request, "user": user, "error": None, "success": None},
    )


@app.post("/profile", response_class=HTMLResponse)
def profile_update(
    request: Request,
    action: str = Form(...),
    current_password: str = Form(None),
    new_password: str = Form(None),
    confirm_password: str = Form(None),
    phone: str = Form(None),
    verification_code: str = Form(None),
    mfa_enabled: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, name, phone, phone_verified_at, mfa_enabled, password_hash FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        request.session.clear()
        return RedirectResponse(url="/login", status_code=302)

    error = None
    success = None

    if action == "change_password":
        if not current_password or not pwd_context.verify(current_password, user["password_hash"]):
            error = "Current password is incorrect."
        elif not new_password or len(new_password) < 8 or len(new_password) > 128:
            error = "New password must be 8-128 characters."
        elif new_password != (confirm_password or ""):
            error = "Password confirmation does not match."
        else:
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pwd_context.hash(new_password), user_id))
            success = "Password updated."

    elif action == "send_phone_code":
        try:
            cleaned_phone = normalize_phone_10(phone)
        except ValueError:
            cleaned_phone = None
            error = "Invalid phone number."
        if not error and not cleaned_phone:
            error = "Phone number is required."
        if not error:
            cur.execute("UPDATE users SET phone = ?, phone_verified_at = NULL WHERE id = ?", (cleaned_phone, user_id))
            code = create_user_phone_verification(conn, user_id, cleaned_phone)
            sent, reason = send_user_phone_verify_sms(conn, cleaned_phone, code)
            if not sent:
                error = f"Could not send verification code: {reason}"
            else:
                success = "Verification code sent."

    elif action == "verify_phone":
        current_phone = None
        try:
            cleaned_phone = normalize_phone_10(phone or user["phone"])
            current_phone = cleaned_phone
        except ValueError:
            error = "Invalid phone number."
        if not error:
            code = (verification_code or "").strip()
            if not code:
                error = "Verification code is required."
            elif verify_user_phone_code(conn, user_id, current_phone, code):
                success = "Phone verified."
            else:
                error = "Invalid or expired verification code."

    elif action == "set_mfa":
        enable = str(mfa_enabled or "").strip() == "1"
        if enable and not user_phone_is_verified(user):
            error = "Verify your phone before enabling MFA."
        else:
            cur.execute("UPDATE users SET mfa_enabled = ? WHERE id = ?", (1 if enable else 0, user_id))
            success = "MFA updated."
    else:
        error = "Unknown profile action."

    conn.commit()
    cur.execute("SELECT id, email, name, phone, phone_verified_at, mfa_enabled FROM users WHERE id = ?", (user_id,))
    fresh = cur.fetchone()
    conn.close()
    return templates.TemplateResponse(
        "profile.html",
        {"request": request, "user": fresh, "error": error, "success": success},
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    if not require_admin(request):
        return RedirectResponse(url="/login", status_code=302)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.id, u.email, u.name, u.username, u.is_admin, u.is_disabled, u.mfa_enabled,
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
        SELECT u.id, u.email, u.name, u.username, u.is_admin, u.is_disabled, u.mfa_enabled,
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

    return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id))


def build_new_game_form_context(request: Request, user_id: int, error: Optional[str] = None) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM games WHERE organizer_id = ? ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    last_game = cur.fetchone()
    last_organizer_name = None
    last_organizer_phone = None
    if last_game:
        cur.execute(
            "SELECT name, phone FROM rsvps WHERE game_id = ? AND status = 'HOST' ORDER BY created_at ASC LIMIT 1",
            (last_game["id"],),
        )
        row = cur.fetchone()
        if row:
            last_organizer_name = row["name"]
            last_organizer_phone = row["phone"]

    cur.execute(
        """
        SELECT title
        FROM games
        WHERE organizer_id = ?
        GROUP BY title
        ORDER BY MAX(datetime(created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    title_suggestions = [row["title"] for row in cur.fetchall() if row["title"]]

    cur.execute(
        """
        SELECT location
        FROM games
        WHERE organizer_id = ?
        GROUP BY location
        ORDER BY MAX(datetime(created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    location_suggestions = [row["location"] for row in cur.fetchall() if row["location"]]

    cur.execute(
        """
        SELECT total_players
        FROM games
        WHERE organizer_id = ?
        GROUP BY total_players
        ORDER BY MAX(datetime(created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    total_player_suggestions = [int(row["total_players"]) for row in cur.fetchall()]

    cur.execute(
        """
        SELECT r.name
        FROM rsvps r
        JOIN games g ON g.id = r.game_id
        WHERE g.organizer_id = ? AND r.status = 'HOST'
        GROUP BY r.name
        ORDER BY MAX(datetime(r.created_at)) DESC
        LIMIT 12
        """,
        (user_id,),
    )
    organizer_name_suggestions = [row["name"] for row in cur.fetchall() if row["name"]]
    conn.close()

    return {
        "request": request,
        "error": error,
        "last_game": last_game,
        "last_organizer_name": last_organizer_name,
        "last_organizer_phone": last_organizer_phone,
        "title_suggestions": title_suggestions,
        "location_suggestions": location_suggestions,
        "total_player_suggestions": total_player_suggestions,
        "organizer_name_suggestions": organizer_name_suggestions,
    }


@app.post("/games/new", response_class=HTMLResponse)
def new_game(
    request: Request,
    title: str = Form(...),
    location: str = Form(...),
    game_date: str = Form(...),
    game_time: str = Form(...),
    total_players: int = Form(...),
    organizer_name: str = Form(...),
    organizer_phone: str = Form(None),
    multiple_tables: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    if total_players < 1 or total_players > 100:
        return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id, "Total players must be at least 1."), status_code=400)

    now = datetime.utcnow().isoformat()

    try:
        cleaned_title = clean_text(title, 100)
        cleaned_location = clean_text(location, 120)
        cleaned_game_time = normalize_game_time(game_time)
        cleaned_organizer = clean_text(organizer_name, 50)
    except ValueError:
        return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id, "Invalid title, location, or organizer name."), status_code=400)
    try:
        cleaned_organizer_phone = normalize_phone_10(organizer_phone)
    except ValueError:
        return templates.TemplateResponse("create_game.html", build_new_game_form_context(request, user_id, "Invalid organizer phone number."), status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cleanup_old_games(conn, user_id)
    code = generate_code(conn=conn)
    host_code = generate_host_code(conn=conn)
    is_multiple_tables = 1 if str(multiple_tables or "").strip().lower() in {"1", "true", "on", "yes"} else 0
    cur.execute(
        """
        INSERT INTO games (organizer_id, code, host_code, title, location, game_date, game_time, total_players, multiple_tables, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, code, host_code, cleaned_title, cleaned_location, game_date, cleaned_game_time, total_players, is_multiple_tables, now),
    )
    game_id = cur.lastrowid

    # Organizer counts as IN (HOST) with seat
    seat_number = None

    cur.execute(
        "INSERT INTO rsvps (game_id, name, phone, status, seat_number, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (game_id, cleaned_organizer, cleaned_organizer_phone, "HOST", seat_number, now),
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
        rsvp["seat_label"] = seat_display(row["seat_number"], game["total_players"], game_uses_multiple_tables(game))
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


@app.get("/games/{game_id}/snapshot")
def game_snapshot(request: Request, game_id: int):
    user_id = require_login(request)
    if not user_id:
        return PlainTextResponse("Unauthorized", status_code=401)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return PlainTextResponse("Not found", status_code=404)
    payload = game_snapshot_payload(conn, game)
    conn.close()
    return payload


@app.get("/games/{game_id}/events")
async def game_events(request: Request, game_id: int):
    user_id = require_login(request)
    if not user_id:
        return PlainTextResponse("Unauthorized", status_code=401)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    conn.close()
    if not game:
        return PlainTextResponse("Not found", status_code=404)

    async def event_generator():
        last_sig = None
        while True:
            if await request.is_disconnected():
                break
            loop_conn = get_db()
            try:
                loop_cur = loop_conn.cursor()
                loop_cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
                game_row = loop_cur.fetchone()
                if not game_row:
                    break
                payload = game_snapshot_payload(loop_conn, game_row)
            finally:
                loop_conn.close()
            sig = payload["signature"]
            if sig != last_sig:
                yield f"id: {sig}\nevent: refresh\ndata: {json.dumps({'signature': sig})}\n\n"
                last_sig = sig
            else:
                # Keep the stream alive even when no changes occurred.
                yield "event: ping\ndata: {}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
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

        seat_label = seat_display(
            rsvp["seat_number"],
            game["total_players"],
            game_uses_multiple_tables(game),
        )
        message = build_invite_sms_text(request, game, seat_label)
        sent, result = send_twilio_sms_guarded(conn, game_id, rsvp["phone"], message, "organizer_text")
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
    cur.execute("SELECT * FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    is_cancelled = int(game["is_cancelled"] or 0) == 1
    if not is_cancelled:
        last_sent = game["cancellation_sms_sent_at"]
        if last_sent:
            try:
                last_dt = datetime.fromisoformat(last_sent)
                if datetime.utcnow() < (last_dt + timedelta(hours=CANCELLATION_SMS_COOLDOWN_HOURS)):
                    conn.close()
                    return RedirectResponse(
                        url=f"/games/{game_id}?error=Cancellation%20SMS%20cooldown%20active.%20Try%20again%20later.",
                        status_code=302,
                    )
            except Exception:
                pass
        due_at = _utc_in_minutes_iso(2)
        cur.execute(
            """
            UPDATE games
            SET is_cancelled = 1,
                cancelled_at = ?,
                cancellation_sms_due_at = ?,
                cancellation_sms_sent_at = NULL
            WHERE id = ?
            """,
            (datetime.utcnow().isoformat(), due_at, game_id),
        )
        conn.commit()
        message = "Game%20cancelled.%20Cancellation%20SMS%20will%20send%20in%202%20minutes%20unless%20you%20reopen."
    else:
        cur.execute(
            """
            UPDATE games
            SET is_cancelled = 0,
                cancelled_at = NULL,
                cancellation_sms_due_at = NULL,
                cancellation_sms_sent_at = NULL
            WHERE id = ?
            """,
            (game_id,),
        )
        conn.commit()
        message = "Game%20reopened"
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success={message}", status_code=302)


@app.post("/games/{game_id}/sms-toggle")
def toggle_game_sms(request: Request, game_id: int, csrf_token: str = Form(...)):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT sms_enabled FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)
    next_value = 0 if int(game["sms_enabled"] or 1) == 1 else 1
    cur.execute("UPDATE games SET sms_enabled = ? WHERE id = ?", (next_value, game_id))
    conn.commit()
    conn.close()
    msg = "SMS%20enabled" if next_value == 1 else "SMS%20disabled"
    return RedirectResponse(url=f"/games/{game_id}?success={msg}", status_code=302)


@app.post("/games/{game_id}/details/update")
def update_game_details(
    request: Request,
    game_id: int,
    location: str = Form(...),
    game_date: str = Form(...),
    game_time: str = Form(...),
    multiple_tables: str = Form(None),
    csrf_token: str = Form(...),
):
    user_id = require_login(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)

    try:
        cleaned_location = clean_text(location, 120)
        cleaned_game_date = clean_text(game_date, 32)
        cleaned_game_time = normalize_game_time(game_time)
    except ValueError:
        return RedirectResponse(url=f"/games/{game_id}?error=Invalid%20date,%20time,%20or%20address", status_code=302)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM games WHERE id = ? AND organizer_id = ?", (game_id, user_id))
    game = cur.fetchone()
    if not game:
        conn.close()
        return RedirectResponse(url="/dashboard", status_code=302)

    cur.execute(
        "UPDATE games SET location = ?, game_date = ?, game_time = ?, multiple_tables = ? WHERE id = ?",
        (
            cleaned_location,
            cleaned_game_date,
            cleaned_game_time,
            1 if str(multiple_tables or "").strip().lower() in {"1", "true", "on", "yes"} else 0,
            game_id,
        ),
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/games/{game_id}?success=Game%20details%20updated", status_code=302)


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
    notify_seat_sms_when_full(conn, game)
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
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    updated_game = cur.fetchone() or game
    notify_seat_sms_when_full(conn, updated_game)
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
    cur.execute("SELECT * FROM games WHERE id = ?", (game_id,))
    updated_game = cur.fetchone() or game
    notify_seat_sms_when_full(conn, updated_game)
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
            {
                "request": request,
                "game": game,
                "title": "RSVP Here",
                "verify_required": request.query_params.get("verify") == "1",
                "twilio_enabled": should_verify_phone(game),
            },
        )

    return templates.TemplateResponse(
        "game.html",
        {
            "request": request,
            "title": "RSVP Here",
            "game": game,
            "in_count": in_count,
            "in_players": in_players,
            "late_players": late_players,
            "host_name": host_name,
            "out_count": out_count,
            "verify_required": request.query_params.get("verify") == "1",
            "twilio_enabled": should_verify_phone(game),
        },
    )


@app.get("/h/{host_code}", response_class=HTMLResponse)
def host_view(request: Request, host_code: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE host_code = ?", (host_code,))
    game = cur.fetchone()
    if not game:
        conn.close()
        return templates.TemplateResponse(
            "game_not_found.html",
            {"request": request, "message": "Host link not found."},
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
    payload = host_snapshot_payload(conn, game)
    conn.close()
    return templates.TemplateResponse(
        "host_view.html",
        {
            "request": request,
            "game": game,
            "players": payload["players"],
            "in_count": payload["in_count"],
            "late_count": payload["late_count"],
        },
    )


@app.get("/h/{host_code}/snapshot")
def host_snapshot(host_code: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE host_code = ?", (host_code,))
    game = cur.fetchone()
    if not game or is_game_cancelled(game) or is_game_expired(game):
        conn.close()
        return PlainTextResponse("Not found", status_code=404)
    payload = host_snapshot_payload(conn, game)
    conn.close()
    return payload


@app.post("/g/{code}/rsvp", response_class=HTMLResponse)
def rsvp_game(
    request: Request,
    code: str,
    name: str = Form(...),
    phone: str = Form(None),
    status: str = Form(...),
    late_eta: str = Form(None),
    verification_code: str = Form(None),
    rsvp_token: str = Form(None),
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
                {"request": request, "game": game, "verify_required": False, "twilio_enabled": should_verify_phone(game)},
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
    cleaned_verification_code = (verification_code or "").strip()
    cleaned_token = normalize_rsvp_token(rsvp_token)
    now = datetime.utcnow().isoformat()

    if cleaned_phone and should_verify_phone(game) and not phone_is_verified(conn, game["id"], cleaned_phone):
        if not cleaned_verification_code:
            code_value = create_or_refresh_phone_code(conn, game["id"], cleaned_phone)
            sent, reason = send_phone_verification_sms(conn, game, cleaned_phone, code_value)
            conn.commit()
            conn.close()
            if not sent:
                return RedirectResponse(url=f"/g/{code}?error=Could%20not%20send%20verification%20code", status_code=302)
            return RedirectResponse(url=f"/g/{code}?verify=1&error=Enter%20the%206-digit%20verification%20code%20sent%20to%20your%20phone", status_code=302)
        if not confirm_phone_code(conn, game["id"], cleaned_phone, cleaned_verification_code):
            conn.commit()
            conn.close()
            return RedirectResponse(url=f"/g/{code}?verify=1&error=Invalid%20or%20expired%20verification%20code", status_code=302)

    existing = None
    if cleaned_token:
        cur.execute(
            "SELECT id, seat_number FROM rsvps WHERE game_id = ? AND rsvp_token = ?",
            (game["id"], cleaned_token),
        )
        existing = cur.fetchone()
    if not existing:
        cur.execute(
            "SELECT id, seat_number FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?)",
            (game["id"], cleaned_name),
        )
        existing = cur.fetchone()

    rsvp_id = None
    if existing:
        cur.execute(
            "SELECT id FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?) AND id != ?",
            (game["id"], cleaned_name, existing["id"]),
        )
        if cur.fetchone():
            conn.close()
            return RedirectResponse(url=f"/g/{code}?error=Name%20already%20exists", status_code=302)
        current_seat = existing["seat_number"]
        new_seat = current_seat
        if status == "OUT":
            new_seat = None
        cur.execute(
            """
            UPDATE rsvps
            SET name = ?, phone = ?, status = ?, late_eta = ?, seat_number = ?, created_at = ?, rsvp_token = COALESCE(rsvp_token, ?)
            WHERE id = ?
            """,
            (cleaned_name, cleaned_phone, status, cleaned_eta, new_seat, now, cleaned_token, existing["id"]),
        )
        rsvp_id = int(existing["id"])
    else:
        new_seat = None
        cur.execute(
            """
            INSERT INTO rsvps (game_id, name, phone, status, late_eta, seat_number, created_at, rsvp_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (game["id"], cleaned_name, cleaned_phone, status, cleaned_eta, new_seat, now, cleaned_token),
        )
        rsvp_id = int(cur.lastrowid)
    assign_seats_if_ready(conn, game["id"], game["total_players"])
    cur.execute("SELECT seat_number FROM rsvps WHERE id = ?", (rsvp_id,))
    seat_row = cur.fetchone()
    seat_to_show = seat_row["seat_number"] if seat_row else None
    table_label, seat_in_table = seat_assignment(seat_to_show, game["total_players"], game_uses_multiple_tables(game))
    seat_label = seat_display(seat_to_show, game["total_players"], game_uses_multiple_tables(game))
    maybe_send_choice_confirmation_sms(conn, game, cleaned_phone, status, cleaned_eta, seat_label)
    notify_seat_sms_when_full(conn, game)
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
            "seat_label": seat_label,
        },
    )


@app.post("/g/{code}/contact")
def lookup_contact(
    request: Request,
    code: str,
    name: str = Form(None),
    rsvp_token: str = Form(None),
    csrf_token: str = Form(...),
):
    if not verify_csrf(request, csrf_token):
        return PlainTextResponse("Bad CSRF token", status_code=400)
    cleaned_token = normalize_rsvp_token(rsvp_token)
    cleaned_name = None
    if not cleaned_token:
        try:
            cleaned_name = clean_text(name, 50)
        except ValueError:
            return {"phone": None, "name": None}

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM games WHERE code = ?", (code,))
    game = cur.fetchone()
    if not game or is_game_cancelled(game) or is_game_expired(game):
        conn.close()
        return {"phone": None, "name": None}

    if cleaned_token:
        cur.execute(
            "SELECT phone, name FROM rsvps WHERE game_id = ? AND rsvp_token = ? LIMIT 1",
            (game["id"], cleaned_token),
        )
    else:
        cur.execute(
            "SELECT phone, name FROM rsvps WHERE game_id = ? AND LOWER(name) = LOWER(?) LIMIT 1",
            (game["id"], cleaned_name),
        )
    row = cur.fetchone()
    conn.close()
    return {
        "phone": (row["phone"] if row and row["phone"] else None),
        "name": (row["name"] if row and row["name"] else None),
    }


@app.post("/g/{code}/standby", response_class=HTMLResponse)
def standby_game(
    request: Request,
    code: str,
    name: str = Form(...),
    phone: str = Form(None),
    verification_code: str = Form(None),
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
    cleaned_verification_code = (verification_code or "").strip()
    if cleaned_phone and should_verify_phone(game) and not phone_is_verified(conn, game["id"], cleaned_phone):
        if not cleaned_verification_code:
            code_value = create_or_refresh_phone_code(conn, game["id"], cleaned_phone)
            sent, _ = send_phone_verification_sms(conn, game, cleaned_phone, code_value)
            conn.commit()
            conn.close()
            if not sent:
                return RedirectResponse(url=f"/g/{code}?error=Could%20not%20send%20verification%20code", status_code=302)
            return RedirectResponse(url=f"/g/{code}?verify=1&error=Enter%20the%206-digit%20verification%20code%20sent%20to%20your%20phone", status_code=302)
        if not confirm_phone_code(conn, game["id"], cleaned_phone, cleaned_verification_code):
            conn.commit()
            conn.close()
            return RedirectResponse(url=f"/g/{code}?verify=1&error=Invalid%20or%20expired%20verification%20code", status_code=302)
    cur.execute(
        "INSERT INTO standby (game_id, name, phone, created_at) VALUES (?, ?, ?, ?)",
        (game["id"], cleaned_name, cleaned_phone, datetime.utcnow().isoformat()),
    )
    cur.execute("SELECT COUNT(*) AS c FROM standby WHERE game_id = ?", (game["id"],))
    position = int(cur.fetchone()["c"])
    maybe_send_standby_confirmation_sms(conn, game, cleaned_phone, position)
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "standby_thanks.html",
        {"request": request, "game": game, "position": position},
    )
