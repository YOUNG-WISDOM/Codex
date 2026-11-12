from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
PAGE_PATH = ROOT / "fullstack.html"
DATA_PATH = ROOT / "data"
MESSAGES_PATH = DATA_PATH / "contact-messages.jsonl"
DATABASE_PATH = DATA_PATH / "wisdom-market.sqlite3"
MAX_BODY_BYTES = 8 * 1024
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
STORE_LOCK = threading.Lock()
SESSION_MAX_AGE = 30 * 24 * 60 * 60
PASSWORD_HASH_BYTES = 64
PASSWORD_SCRYPT_COST = 2 ** 14
COOKIE_SECURE = os.environ.get("WISDOM_COOKIE_SECURE") == "1"


@contextmanager
def database_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    DATA_PATH.mkdir(exist_ok=True)
    with database_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            """
        )


def hash_password(password, salt):
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_SCRYPT_COST,
        r=8,
        p=1,
        dklen=PASSWORD_HASH_BYTES,
    )


def public_user(row):
    return {"name": row["name"], "email": row["email"]}


class WisdomMarketHandler(BaseHTTPRequestHandler):
    server_version = "WisdomMarket/1.0"

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_session_cookie(self, token):
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header(
            "Set-Cookie",
            f"wisdom_session={token}; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={SESSION_MAX_AGE}{secure}",
        )

    def clear_session_cookie(self):
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header(
            "Set-Cookie",
            f"wisdom_session=; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age=0{secure}",
        )

    def request_json(self):
        if self.headers.get_content_type() != "application/json":
            self.send_json(415, {"error": "Send the request as JSON."})
            return None

        try:
            body_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(400, {"error": "A valid Content-Length header is required."})
            return None

        if body_length < 1 or body_length > MAX_BODY_BYTES:
            self.send_json(413, {"error": "The request is empty or too large."})
            return None

        try:
            payload = json.loads(self.rfile.read(body_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "The request body must be valid JSON."})
            return None

        if not isinstance(payload, dict):
            self.send_json(400, {"error": "The request body must be a JSON object."})
            return None
        return payload

    def request_user(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        session_cookie = cookies.get("wisdom_session")
        if session_cookie is None:
            return None

        token_hash = hashlib.sha256(session_cookie.value.encode("utf-8")).hexdigest()
        with database_connection() as connection:
            row = connection.execute(
                """
                SELECT users.name, users.email
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, int(time.time())),
            ).fetchone()
        return public_user(row) if row else None

    def create_session(self, connection, user_id):
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(time.time())
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, now + SESSION_MAX_AGE),
        )
        return token

    def handle_register(self):
        payload = self.request_json()
        if payload is None:
            return

        name = payload.get("name")
        email = payload.get("email")
        password = payload.get("password")
        if not all(isinstance(value, str) for value in (name, email, password)):
            self.send_json(400, {"error": "Name, email, and password are required."})
            return

        name = name.strip()
        email = email.strip().lower()
        if not name or len(name) > 100:
            self.send_json(400, {"error": "Name must be between 1 and 100 characters."})
            return
        if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
            self.send_json(400, {"error": "Enter a valid email address."})
            return
        if len(password) < 10 or len(password) > 128:
            self.send_json(400, {"error": "Password must be between 10 and 128 characters."})
            return

        salt = secrets.token_bytes(16)
        password_hash = hash_password(password, salt).hex()
        try:
            with database_connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (name, email, password_salt, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        email,
                        salt.hex(),
                        password_hash,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                user_id = cursor.lastrowid
                token = self.create_session(connection, user_id)
                user = connection.execute(
                    "SELECT name, email FROM users WHERE id = ?", (user_id,)
                ).fetchone()
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "An account with that email already exists. Try signing in."})
            return
        except sqlite3.Error:
            self.send_json(500, {"error": "Your account could not be created. Please try again."})
            return

        body = json.dumps(
            {"user": public_user(user)}, ensure_ascii=False
        ).encode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_session_cookie(token)
        self.end_headers()
        self.wfile.write(body)

    def handle_login(self):
        payload = self.request_json()
        if payload is None:
            return

        email = payload.get("email")
        password = payload.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            self.send_json(400, {"error": "Email and password are required."})
            return
        if len(email) > 254 or len(password) > 128:
            self.send_json(400, {"error": "The email or password is too long."})
            return

        try:
            with database_connection() as connection:
                user = connection.execute(
                    "SELECT id, name, email, password_salt, password_hash FROM users WHERE email = ?",
                    (email.strip(),),
                ).fetchone()
                if user is None:
                    self.send_json(401, {"error": "Email or password is incorrect."})
                    return

                candidate_hash = hash_password(
                    password, bytes.fromhex(user["password_salt"])
                ).hex()
                if not hmac.compare_digest(candidate_hash, user["password_hash"]):
                    self.send_json(401, {"error": "Email or password is incorrect."})
                    return

                token = self.create_session(connection, user["id"])
                response_user = public_user(user)
        except (sqlite3.Error, ValueError):
            self.send_json(500, {"error": "Sign in could not be completed. Please try again."})
            return

        body = json.dumps(
            {"user": response_user}, ensure_ascii=False
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_session_cookie(token)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.send_json(200, {"status": "ok"})
            return

        if path == "/api/auth/me":
            try:
                user = self.request_user()
            except sqlite3.Error:
                self.send_json(500, {"error": "Account status could not be checked."})
                return
            self.send_json(200, {"user": user})
            return

        if path not in ("/", "/fullstack.html"):
            self.send_json(404, {"error": "Not found."})
            return

        try:
            body = PAGE_PATH.read_bytes()
        except OSError:
            self.send_json(500, {"error": "The website page could not be loaded."})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path in ("/api/auth/register", "/api/auth/login", "/api/auth/logout"):
            origin = self.headers.get("Origin")
            if origin:
                try:
                    origin_url = urlsplit(origin)
                except ValueError:
                    self.send_json(403, {"error": "Cross-origin account requests are not allowed."})
                    return
                if (
                    origin_url.scheme not in ("http", "https")
                    or origin_url.netloc.lower() != self.headers.get("Host", "").lower()
                ):
                    self.send_json(403, {"error": "Cross-origin account requests are not allowed."})
                    return

            if path == "/api/auth/register":
                self.handle_register()
                return
            if path == "/api/auth/login":
                self.handle_login()
                return

            try:
                cookies = SimpleCookie()
                cookies.load(self.headers.get("Cookie", ""))
                session_cookie = cookies.get("wisdom_session")
                if session_cookie:
                    token_hash = hashlib.sha256(session_cookie.value.encode("utf-8")).hexdigest()
                    with database_connection() as connection:
                        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            except (sqlite3.Error, CookieError):
                self.send_json(500, {"error": "Sign out could not be completed. Please try again."})
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b'{"message":"Signed out."}')))
            self.send_header("Cache-Control", "no-store")
            self.clear_session_cookie()
            self.end_headers()
            self.wfile.write(b'{"message":"Signed out."}')
            return

        if path != "/api/contact":
            self.send_json(404, {"error": "Not found."})
            return

        payload = self.request_json()
        if payload is None:
            return

        name = payload.get("name")
        email = payload.get("email")
        message = payload.get("message")
        if not all(isinstance(value, str) for value in (name, email, message)):
            self.send_json(400, {"error": "Name, email, and message are required."})
            return

        name = name.strip()
        email = email.strip()
        message = message.strip()
        if not name or len(name) > 100:
            self.send_json(400, {"error": "Name must be between 1 and 100 characters."})
            return
        if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
            self.send_json(400, {"error": "Enter a valid email address."})
            return
        if not message or len(message) > 3000:
            self.send_json(400, {"error": "Message must be between 1 and 3000 characters."})
            return

        record = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "name": name,
            "email": email,
            "message": message,
        }

        try:
            DATA_PATH.mkdir(exist_ok=True)
            with STORE_LOCK, MESSAGES_PATH.open("a", encoding="utf-8") as messages_file:
                messages_file.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            self.send_json(500, {"error": "Your message could not be saved. Please try WhatsApp or email instead."})
            return

        self.send_json(201, {"message": "Your message has been received."})

    def log_message(self, format_string, *args):
        # Keep request logs free of contact-form contents.
        super().log_message(format_string, *args)


if __name__ == "__main__":
    initialize_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), WisdomMarketHandler)
    print("HEX TECH is available at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HEX TECH.")
    finally:
        server.server_close()
