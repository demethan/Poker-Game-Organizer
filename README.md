# Luck's Poker Game Organizer

A mobile-first web app to organize poker games with invite links, RSVP tracking, and standby lists.

## Features
- Organizer login and game creation
- Unique invite links per game
- Invitees can RSVP (IN / LATE / OUT)
- LATE supports ETA
- Standby list when game is full
- Organizer dashboard and game view
- Admin panel for user management

## Quick Start (Local)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SESSION_SECRET="change-me"
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open: `http://localhost:8000`

## Production Notes
- Recommended: reverse proxy (Caddy/Nginx) for TLS
- Set `SESSION_SECRET` to a strong random value
- Uses SQLite file `poker.db` (not committed)

## Admin
- Admin panel at `/admin`
- Admin login uses username (not email)

## Security
- Parameterized SQL queries
- Argon2 password hashing
- CSRF protection for POSTs
- Basic rate limiting

## Repo Layout
- `app.py` — FastAPI backend
- `templates/` — Jinja2 HTML templates
- `static/` — CSS/JS/assets

## License
MIT (add your preferred license if needed)
