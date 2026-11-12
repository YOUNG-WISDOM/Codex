from contextlib import contextmanager
from datetime import datetime, timezone
from io import BytesIO
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
from urllib.parse import parse_qs, quote, urlsplit


ROOT = Path(__file__).resolve().parent
PAGE_PATH = ROOT / "fullstack.html"
ADMIN_PAGE_PATH = ROOT / "admin.html"
DATA_PATH = Path(os.environ.get("WISDOM_DATA_DIR", ROOT / "data")).expanduser()
LEGACY_MESSAGES_PATH = ROOT / "data" / "contact-messages.jsonl"
MESSAGES_PATH = DATA_PATH / "contact-messages.jsonl"
DATABASE_PATH = DATA_PATH / "wisdom-market.sqlite3"
MAX_BODY_BYTES = 8 * 1024
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SESSION_MAX_AGE = 30 * 24 * 60 * 60
ADMIN_SESSION_MAX_AGE = 8 * 60 * 60
PASSWORD_HASH_BYTES = 64
PASSWORD_SCRYPT_COST = 2 ** 14
COOKIE_SECURE = os.environ.get("WISDOM_COOKIE_SECURE") == "1"
ADMIN_PASSWORD = os.environ.get("WISDOM_ADMIN_PASSWORD", "")
DATABASE_INITIALIZE_LOCK = threading.Lock()
DATABASE_INITIALIZED = False


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
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL,
                received_at TEXT NOT NULL,
                legacy_key TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions(expires_at);
            """
        )
    migrate_contact_messages()


def migrate_contact_messages():
    sources = [MESSAGES_PATH]
    if LEGACY_MESSAGES_PATH != MESSAGES_PATH:
        sources.append(LEGACY_MESSAGES_PATH)

    for source in sources:
        if not source.exists():
            continue

        try:
            with source.open(encoding="utf-8") as messages_file:
                with database_connection() as connection:
                    for line_number, line in enumerate(messages_file, start=1):
                        if not line.strip():
                            continue

                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as error:
                            raise RuntimeError(
                                f"Cannot import contact message on line {line_number}: invalid JSON."
                            ) from error

                        if not isinstance(record, dict) or not all(
                            isinstance(record.get(field), str)
                            for field in ("name", "email", "message", "received_at")
                        ):
                            raise RuntimeError(
                                f"Cannot import contact message on line {line_number}: "
                                "required fields are missing or invalid."
                            )

                        phone = record.get("phone", "")
                        if not isinstance(phone, str):
                            raise RuntimeError(
                                f"Cannot import contact message on line {line_number}: "
                                "phone must be text."
                            )

                        identity = f"{line_number}\0{line}"
                        if source != MESSAGES_PATH:
                            identity = f"{source.resolve()}\0{identity}"
                        legacy_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO contact_messages
                                (name, email, phone, message, received_at, legacy_key)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                record["name"],
                                record["email"],
                                phone,
                                record["message"],
                                record["received_at"],
                                legacy_key,
                            ),
                        )
        except OSError as error:
            raise RuntimeError("Could not import existing contact messages.") from error


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

    def send_admin_session(self, token):
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header(
            "Set-Cookie",
            f"wisdom_admin_session={token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={ADMIN_SESSION_MAX_AGE}{secure}",
        )

    def clear_admin_session(self):
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_header(
            "Set-Cookie",
            f"wisdom_admin_session=; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age=0{secure}",
        )

    def request_admin_session(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        session_cookie = cookies.get("wisdom_admin_session")
        if session_cookie is None:
            return None

        token_hash = hashlib.sha256(session_cookie.value.encode("utf-8")).hexdigest()
        with database_connection() as connection:
            row = connection.execute(
                "SELECT token_hash FROM admin_sessions WHERE token_hash = ? AND expires_at > ?",
                (token_hash, int(time.time())),
            ).fetchone()
        return row["token_hash"] if row else None

    def require_admin_session(self):
        try:
            session = self.request_admin_session()
        except sqlite3.Error:
            self.send_json(500, {"error": "Admin access could not be checked."})
            return False
        if session is None:
            self.send_json(401, {"error": "Sign in to the message inbox."})
            return False
        return True

    def request_is_same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            origin_url = urlsplit(origin)
        except ValueError:
            return False
        return (
            origin_url.scheme in ("http", "https")
            and origin_url.netloc.lower() == self.headers.get("Host", "").lower()
        )

    def handle_admin_login(self):
        if not ADMIN_PASSWORD:
            self.send_json(503, {"error": "Set WISDOM_ADMIN_PASSWORD before signing in to the inbox."})
            return

        payload = self.request_json()
        if payload is None:
            return
        password = payload.get("password")
        if not isinstance(password, str) or len(password) > 1024:
            self.send_json(400, {"error": "Enter a valid admin password."})
            return

        expected = hashlib.sha256(ADMIN_PASSWORD.encode("utf-8")).digest()
        provided = hashlib.sha256(password.encode("utf-8")).digest()
        if not hmac.compare_digest(provided, expected):
            self.send_json(401, {"error": "The admin password is incorrect."})
            return

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = int(time.time()) + ADMIN_SESSION_MAX_AGE
        try:
            with database_connection() as connection:
                connection.execute(
                    "DELETE FROM admin_sessions WHERE expires_at <= ?", (int(time.time()),)
                )
                connection.execute(
                    "INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)",
                    (token_hash, expires_at),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Admin sign-in could not be completed."})
            return

        body = json.dumps({"message": "Signed in."}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_admin_session(token)
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

        if path == "/admin":
            try:
                body = ADMIN_PAGE_PATH.read_bytes()
            except OSError:
                self.send_json(500, {"error": "The admin inbox page could not be loaded."})
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/admin/messages":
            if not self.require_admin_session():
                return

            search = parse_qs(urlsplit(self.path).query).get("q", [""])[0].strip()
            if len(search) > 100:
                self.send_json(400, {"error": "Search text must be 100 characters or fewer."})
                return
            escaped_search = search.replace("!", "!!").replace("%", "!%").replace("_", "!_")
            pattern = f"%{escaped_search}%"
            try:
                with database_connection() as connection:
                    rows = connection.execute(
                        """
                        SELECT id, name, email, phone, message, received_at
                        FROM contact_messages
                        WHERE ? = ''
                           OR name LIKE ? ESCAPE '!'
                           OR email LIKE ? ESCAPE '!'
                           OR phone LIKE ? ESCAPE '!'
                           OR message LIKE ? ESCAPE '!'
                        ORDER BY id DESC
                        LIMIT 500
                        """,
                        (search, pattern, pattern, pattern, pattern),
                    ).fetchall()
            except sqlite3.Error:
                self.send_json(500, {"error": "The contact inbox could not be loaded."})
                return

            self.send_json(200, {"messages": [dict(row) for row in rows]})
            return

        if path in ("/wisdom.png", "/logo.png"):
            try:
                body = (ROOT / path.lstrip("/")).read_bytes()
            except OSError:
                self.send_json(404, {"error": "The requested image could not be found."})
                return

            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
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
        if path in ("/api/admin/login", "/api/admin/logout"):
            if not self.request_is_same_origin():
                self.send_json(403, {"error": "Cross-origin admin requests are not allowed."})
                return
            if path == "/api/admin/login":
                self.handle_admin_login()
                return

            try:
                session = self.request_admin_session()
                if session:
                    with database_connection() as connection:
                        connection.execute(
                            "DELETE FROM admin_sessions WHERE token_hash = ?", (session,)
                        )
            except sqlite3.Error:
                self.send_json(500, {"error": "Admin sign-out could not be completed."})
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b'{"message":"Signed out."}')))
            self.send_header("Cache-Control", "no-store")
            self.clear_admin_session()
            self.end_headers()
            self.wfile.write(b'{"message":"Signed out."}')
            return

        if path == "/api/admin/messages/delete":
            if not self.request_is_same_origin():
                self.send_json(403, {"error": "Cross-origin admin requests are not allowed."})
                return
            if not self.require_admin_session():
                return

            payload = self.request_json()
            if payload is None:
                return
            message_ids = payload.get("message_ids")
            if (
                not isinstance(message_ids, list)
                or not message_ids
                or len(message_ids) > 500
                or any(type(message_id) is not int or message_id < 1 for message_id in message_ids)
            ):
                self.send_json(400, {"error": "Select between 1 and 500 valid messages to delete."})
                return

            unique_ids = list(dict.fromkeys(message_ids))
            placeholders = ", ".join("?" for _ in unique_ids)
            try:
                with database_connection() as connection:
                    cursor = connection.execute(
                        f"DELETE FROM contact_messages WHERE id IN ({placeholders})",
                        unique_ids,
                    )
            except sqlite3.Error:
                self.send_json(500, {"error": "The selected messages could not be deleted."})
                return

            self.send_json(200, {"deleted": cursor.rowcount})
            return

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
        phone = payload.get("phone", "")
        message = payload.get("message")
        if not all(isinstance(value, str) for value in (name, email, phone, message)):
            self.send_json(400, {"error": "Name, email, and message are required; phone must be text."})
            return

        name = name.strip()
        email = email.strip()
        phone = phone.strip()
        message = message.strip()
        if not name or len(name) > 100:
            self.send_json(400, {"error": "Name must be between 1 and 100 characters."})
            return
        if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
            self.send_json(400, {"error": "Enter a valid email address."})
            return
        if len(phone) > 40:
            self.send_json(400, {"error": "Phone number must be 40 characters or fewer."})
            return
        if phone and (
            not re.fullmatch(r"\+?\d[\d().\s-]*", phone)
            or not any(character.isdigit() for character in phone)
        ):
            self.send_json(400, {"error": "Enter a valid phone number."})
            return
        if not message or len(message) > 3000:
            self.send_json(400, {"error": "Message must be between 1 and 3000 characters."})
            return

        try:
            with database_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO contact_messages (name, email, phone, message, received_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (name, email, phone, message, datetime.now(timezone.utc).isoformat()),
                )
        except sqlite3.Error:
            self.send_json(500, {"error": "Your message could not be saved. Please try WhatsApp or email instead."})
            return

        self.send_json(201, {"message": "Your message has been received."})

    def log_message(self, format_string, *args):
        # Keep request logs free of contact-form contents.
        super().log_message(format_string, *args)


class _WSGIResponseBuffer(BytesIO):
    def close(self):
        self.flush()


class _WSGIConnection:
    def __init__(self, request_bytes):
        self.request_stream = BytesIO(request_bytes)
        self.response_stream = _WSGIResponseBuffer()

    def makefile(self, mode, buffering=None):
        if mode.startswith("r"):
            return self.request_stream
        return self.response_stream

    def sendall(self, data):
        self.response_stream.write(data)


def _handler_request_bytes(environ):
    method = environ["REQUEST_METHOD"]
    target = environ.get("RAW_URI")
    if not target:
        target = quote(
            environ.get("PATH_INFO", "/"),
            safe="/%:@!$&'()*+,;=-._~",
        )
        if environ.get("QUERY_STRING"):
            target += f"?{environ['QUERY_STRING']}"

    headers = []
    host = environ.get("HTTP_HOST")
    if host:
        headers.append(f"Host: {host}")
    for key, value in environ.items():
        if key.startswith("HTTP_") and key != "HTTP_HOST":
            header_name = key[5:].replace("_", "-")
            headers.append(f"{header_name}: {value}")

    content_type = environ.get("CONTENT_TYPE")
    if content_type:
        headers.append(f"Content-Type: {content_type}")
    content_length = int(environ.get("CONTENT_LENGTH") or "0")
    if content_length:
        headers.append(f"Content-Length: {content_length}")

    request_line = f"{method} {target} HTTP/1.1\r\n"
    header_block = "".join(f"{header}\r\n" for header in headers) + "\r\n"
    body = environ["wsgi.input"].read(content_length)
    if len(body) != content_length:
        raise ValueError("The WSGI request body ended before Content-Length bytes were read.")
    return request_line.encode("ascii") + header_block.encode("latin-1") + body


def _ensure_database_initialized():
    global DATABASE_INITIALIZED
    if DATABASE_INITIALIZED:
        return
    with DATABASE_INITIALIZE_LOCK:
        if not DATABASE_INITIALIZED:
            initialize_database()
            DATABASE_INITIALIZED = True


def application(environ, start_response):
    _ensure_database_initialized()
    connection = _WSGIConnection(_handler_request_bytes(environ))
    WisdomMarketHandler(connection, (environ.get("REMOTE_ADDR", ""), 0), None)

    raw_response = connection.response_stream.getvalue()
    header_block, separator, body = raw_response.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("The request handler did not produce a valid HTTP response.")

    status_line, *header_lines = header_block.split(b"\r\n")
    status_parts = status_line.split(b" ", 2)
    if len(status_parts) < 2:
        raise RuntimeError("The request handler produced an invalid HTTP status line.")
    status_code = status_parts[1].decode("ascii")
    reason = status_parts[2].decode("latin-1") if len(status_parts) == 3 else ""
    response_headers = []
    for line in header_lines:
        if b":" not in line:
            raise RuntimeError("The request handler produced an invalid HTTP response header.")
        name, value = line.split(b":", 1)
        response_headers.append(
            (name.decode("ascii"), value.strip().decode("latin-1"))
        )

    start_response(f"{status_code} {reason}", response_headers)
    if environ["REQUEST_METHOD"] == "HEAD":
        return [b""]
    return [body]


if __name__ == "__main__":
    _ensure_database_initialized()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), WisdomMarketHandler)
    print(f"HEX TECH is available at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HEX TECH.")
    finally:
        server.server_close()
