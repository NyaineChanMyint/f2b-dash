#!/usr/bin/env python3
"""Fail2Ban Dashboard Central: HTTPS-ready event collector and dashboard API.

Run behind a TLS reverse proxy in production.  Agents authenticate with the
shared F2B_API_TOKEN supplied to both the server and every agent.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web"
DB_PATH = Path(os.environ.get("F2B_DASHBOARD_DB", ROOT / "data" / "central.db"))
API_TOKEN = os.environ.get("F2B_API_TOKEN", "")
ADMIN_USERNAME = os.environ.get("F2B_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("F2B_ADMIN_PASSWORD", "")
SESSION_HOURS = int(os.environ.get("F2B_SESSION_HOURS", "12"))
COOKIE_SECURE = os.environ.get("F2B_COOKIE_SECURE", "false").lower() == "true"
MAX_EVENTS = 2_000


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialise():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
          name TEXT PRIMARY KEY, last_seen TEXT NOT NULL, agent_version TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
          event_id TEXT PRIMARY KEY, host TEXT NOT NULL, timestamp TEXT NOT NULL,
          kind TEXT NOT NULL, ip TEXT, jail TEXT, message TEXT,
          FOREIGN KEY(host) REFERENCES hosts(name)
        );
        CREATE INDEX IF NOT EXISTS events_host_time ON events(host, timestamp);
        CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          password_salt TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
        """)
        has_user = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if not has_user:
            if not ADMIN_PASSWORD:
                raise RuntimeError("F2B_ADMIN_PASSWORD is required when creating the first user")
            if not valid_username(ADMIN_USERNAME):
                raise RuntimeError("F2B_ADMIN_USERNAME must be 3-64 characters (letters, digits, ., _, -)")
            conn.execute("INSERT INTO users(username,password_hash,password_salt,created_at) VALUES(?,?,?,?)",
                         (ADMIN_USERNAME, *password_hash(ADMIN_PASSWORD), iso_now()))


def iso_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username))


def password_hash(password, salt=None):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600_000).hex()
    return digest, salt


def valid_password(password, stored_hash, salt):
    digest, _ = password_hash(password, salt)
    return hmac.compare_digest(digest, stored_hash)


def session_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() + SESSION_HOURS * 3600, timezone.utc)
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (iso_now(),))
        conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                     (session_token_hash(token), user_id, expires.isoformat().replace("+00:00", "Z"), iso_now()))
    return token


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def event_jail(row, selected_host):
    return row["jail"] if selected_host else row["host"] + "/" + row["jail"]


def dashboard(host=None):
    with db() as conn:
        if host:
            rows = conn.execute("SELECT * FROM events WHERE host=? ORDER BY timestamp", (host,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM events ORDER BY timestamp").fetchall()
    found = [r for r in rows if r["kind"] == "Found"]
    jails = sorted({event_jail(r, host) for r in rows if r["jail"]})
    state = {}
    for r in rows:
        if r["kind"] in ("Ban", "RestoreBan", "Unban") and r["ip"]:
            state[(r["host"], r["jail"], r["ip"])] = r
    active = [r for r in state.values() if r["kind"] in ("Ban", "RestoreBan")]
    ip_count, ip_last, ip_jail, ip_bans = Counter(), {}, {}, Counter()
    jail_attacks, jail_bans, jail_unbans = Counter(), Counter(), Counter()
    timeline, trends = defaultdict(Counter), defaultdict(Counter)
    heatmap = [[0 for _ in range(24)] for _ in range(7)]
    per_jail_ips, per_jail_banned = defaultdict(Counter), defaultdict(list)
    for r in found:
        jail, ip = event_jail(r, host), r["ip"]
        if not ip: continue
        t = parse_time(r["timestamp"])
        ip_count[ip] += 1; ip_last[ip] = r["timestamp"]; ip_jail[ip] = jail
        jail_attacks[jail] += 1; per_jail_ips[jail][ip] += 1
        timeline[t.strftime("%Y-%m-%dT%H:00:00Z")][jail] += 1
        trends[t.strftime("%Y-%m-%d")][jail] += 1
        heatmap[t.weekday()][t.hour] += 1
    for r in rows:
        jail = event_jail(r, host)
        day = r["timestamp"][:10]
        if r["kind"] in ("Ban", "RestoreBan"):
            jail_bans[jail] += 1
            if r["ip"]: ip_bans[r["ip"]] += 1
            trends[day]["__bans"] += 1
        elif r["kind"] == "Unban":
            jail_unbans[jail] += 1; trends[day]["__unbans"] += 1
    active_by_jail = Counter(event_jail(r, host) for r in active)
    for r in active:
        per_jail_banned[event_jail(r, host)].append(r)
    top_ips = [{"ip": ip, "count": count, "jail": ip_jail[ip], "country": "Unknown", "city": None,
                "lat": None, "lon": None, "lastSeen": ip_last[ip], "isBanned": any(x["ip"] == ip for x in active),
                "banCount": ip_bans[ip], "isPrivate": ip.startswith(("10.", "192.168.", "127.")), "isIPv6": ":" in ip}
               for ip, count in ip_count.most_common(20)]
    timeline_data = []
    for stamp in sorted(timeline):
        item = {"timestamp": stamp, "total": sum(timeline[stamp].values())}
        item.update(timeline[stamp]); timeline_data.append(item)
    trend_data = []
    for day in sorted(trends):
        item = {"date": day, "total": sum(v for k, v in trends[day].items() if not k.startswith("__")),
                "bans": trends[day]["__bans"], "unbans": trends[day]["__unbans"]}
        item.update({k: v for k, v in trends[day].items() if not k.startswith("__")}); trend_data.append(item)
    per_jail = {}
    for jail in jails:
        attack_trend = [day.get(jail, 0) for day in trend_data]
        banned = sorted(per_jail_banned[jail], key=lambda r: r["timestamp"], reverse=True)
        per_jail[jail] = {"banTime": 0, "findtime": 0, "maxRetry": 0, "totalAttacks": jail_attacks[jail],
            "totalBans": jail_bans[jail], "totalUnbans": jail_unbans[jail], "currentBanned": active_by_jail[jail],
            "uniqueIPs": len(per_jail_ips[jail]), "attackTrend": attack_trend, "topCountries": [],
            "hourlyDistribution": {str(h): 0 for h in range(24)},
            "topIPs": [{"ip": ip, "count": n, "country": "Unknown"} for ip, n in per_jail_ips[jail].most_common(10)],
            "bannedIPs": [{"ip": r["ip"], "lastBannedAt": r["timestamp"], "country": "Unknown"} for r in banned]}
    recent = [{"timestamp": r["timestamp"], "type": r["kind"], "ip": r["ip"] or "", "jail": event_jail(r, host),
               "message": "[{}] {}".format(r["host"], r["message"] or r["kind"])} for r in reversed(rows[-100:])]
    return {"meta": {"generatedAt": iso_now(), "lastUpdated": iso_now(), "timezone": "UTC", "jailNames": jails,
                     "timeRangeStart": rows[0]["timestamp"] if rows else "", "timeRangeEnd": rows[-1]["timestamp"] if rows else ""},
            "summary": {"totalAttacks": len(found), "totalBans": sum(jail_bans.values()), "totalUnbans": sum(jail_unbans.values()),
                        "activeBans": len(active), "uniqueIPs": len(ip_count), "activeJails": len(jails), "f2bStatus": "running",
                        "restoredBans": 0, "repeatAttacks": 0, "ignored": 0,
                        "topAttacker": {"ip": top_ips[0]["ip"] if top_ips else "", "count": top_ips[0]["count"] if top_ips else 0, "jail": top_ips[0]["jail"] if top_ips else ""}},
            "timeline": timeline_data, "trends": trend_data, "topIPs": top_ips, "jails": {j: {"attacks": jail_attacks[j], "bans": jail_bans[j], "unbans": jail_unbans[j], "uniqueIPs": len(per_jail_ips[j])} for j in jails},
            "heatmap": {"grid": heatmap, "hourly": {str(h): sum(heatmap[d][h] for d in range(7)) for h in range(24)}, "weekly": {str(d): sum(heatmap[d]) for d in range(7)}},
            "recentLogs": recent, "perJail": per_jail, "server": None}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(WEB_ROOT), **kwargs)
    def json(self, obj, status=200, headers=None):
        body = json.dumps(obj).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items(): self.send_header(key, value)
        self.end_headers(); self.wfile.write(body)
    def redirect(self, location):
        self.send_response(302); self.send_header("Location", location); self.end_headers()
    def current_user(self):
        cookie = SimpleCookie(self.headers.get("Cookie"))
        token = cookie.get("f2b_session")
        if not token: return None
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (iso_now(),))
            return conn.execute("SELECT users.id, users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?", (session_token_hash(token.value), iso_now())).fetchone()
    def require_user(self):
        user = self.current_user()
        if not user: self.json({"error": "authentication required"}, 401)
        return user
    def session_cookie(self, token):
        secure = "; Secure" if COOKIE_SECURE else ""
        return "f2b_session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}".format(token, SESSION_HOURS * 3600) + secure
    def clear_session_cookie(self):
        secure = "; Secure" if COOKIE_SECURE else ""
        return "f2b_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + secure
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health": return self.json({"ok": True})
        if parsed.path == "/api/auth/me":
            user = self.current_user()
            return self.json({"user": dict(user)} if user else {"error": "authentication required"}, 200 if user else 401)
        if parsed.path == "/":
            if not self.current_user(): return self.redirect("/login.html")
        if parsed.path in {"/api/hosts", "/api/dashboard"} and not self.require_user(): return
        if parsed.path == "/api/hosts":
            with db() as conn: hosts = [dict(r) for r in conn.execute("SELECT name, last_seen FROM hosts ORDER BY name")]
            return self.json({"hosts": hosts})
        if parsed.path == "/api/dashboard":
            host = parse_qs(parsed.query).get("host", [None])[0]
            return self.json(dashboard(host))
        return super().do_GET()
    def do_POST(self):
        if self.path == "/api/auth/login":
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size > 10_000: raise ValueError("request too large")
                payload = json.loads(self.rfile.read(size)); username = str(payload.get("username", "")); password = payload.get("password", "")
                with db() as conn: user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if not user or not valid_password(password, user["password_hash"], user["password_salt"]):
                    return self.json({"error": "invalid username or password"}, 401)
                token = create_session(user["id"])
                return self.json({"user": {"username": user["username"]}}, headers={"Set-Cookie": self.session_cookie(token)})
            except (ValueError, json.JSONDecodeError): return self.json({"error": "invalid login request"}, 400)
        if self.path == "/api/auth/logout":
            cookie = SimpleCookie(self.headers.get("Cookie")); token = cookie.get("f2b_session")
            if token:
                with db() as conn: conn.execute("DELETE FROM sessions WHERE token_hash=?", (session_token_hash(token.value),))
            return self.json({"ok": True}, headers={"Set-Cookie": self.clear_session_cookie()})
        if self.path != "/api/v1/events": return self.send_error(404)
        if not API_TOKEN or self.headers.get("X-Api-Token") != API_TOKEN: return self.json({"error": "unauthorized"}, 401)
        try:
            size = int(self.headers.get("Content-Length", "0")); payload = json.loads(self.rfile.read(size))
            host = str(payload["host"]).strip(); events = payload.get("events", [])
            if not host or len(host) > 255 or not isinstance(events, list) or len(events) > MAX_EVENTS: raise ValueError("invalid payload")
            now = iso_now()
            with db() as conn:
                conn.execute("INSERT INTO hosts(name,last_seen,agent_version) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen,agent_version=excluded.agent_version", (host, now, str(payload.get("agent_version", ""))))
                for e in events:
                    timestamp, kind, jail = str(e["timestamp"]), str(e["kind"]), str(e.get("jail", "unknown"))
                    if kind not in {"Found", "Ban", "Unban", "RestoreBan", "Ignore", "AlreadyBanned"}: continue
                    parse_time(timestamp)
                    raw = "|".join((host, timestamp, kind, str(e.get("ip", "")), jail, str(e.get("message", ""))))
                    event_id = hashlib.sha256(raw.encode()).hexdigest()
                    conn.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?)", (event_id, host, timestamp, kind, e.get("ip"), jail, e.get("message")))
            return self.json({"accepted": len(events)})
        except (ValueError, KeyError, json.JSONDecodeError) as exc: return self.json({"error": str(exc)}, 400)


if __name__ == "__main__":
    initialise()
    port = int(os.environ.get("PORT", "8080"))
    print("Serving dashboard on http://0.0.0.0:%d" % port)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

