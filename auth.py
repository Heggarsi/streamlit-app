"""
Simple authentication backend using SQLite and secure password hashing (sha256 + salt).
This is intentionally lightweight for demo purposes only — do NOT use in production.
"""
import sqlite3
import hashlib
import secrets
import time
from typing import Optional, Tuple

DB_PATH = "users.db"


def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                email TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT,
                reset_token TEXT,
                reset_token_expiry INTEGER
            )
            """
        )
        conn.commit()


def _hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return salt, h


def create_user(username: str, email: str, password: str) -> bool:
    salt, pw_hash = _hash_password(password)
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (username, email.lower(), pw_hash, salt),
            )
            conn.commit()
        return True
    except Exception:
        return False


def verify_user(email: str, password: str) -> bool:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        if not row:
            return False
        stored_hash, salt = row
        _salt, _hash = _hash_password(password, salt)
        return _hash == stored_hash


def generate_reset_token(email: str, ttl_seconds: int = 3600) -> Optional[str]:
    token = secrets.token_urlsafe(32)
    expiry = int(time.time()) + ttl_seconds
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
            (token, expiry, email.lower()),
        )
        conn.commit()
    return token


def verify_reset_token(email: str, token: str) -> bool:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT reset_token, reset_token_expiry FROM users WHERE email = ?",
            (email.lower(),),
        )
        row = cur.fetchone()
        if not row:
            return False
        stored_token, expiry = row
        if stored_token != token:
            return False
        if expiry is None:
            return False
        if int(time.time()) > expiry:
            return False
        return True


def reset_password(email: str, token: str, new_password: str) -> bool:
    if not verify_reset_token(email, token):
        return False
    salt, pw_hash = _hash_password(new_password)
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ?, salt = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?",
            (pw_hash, salt, email.lower()),
        )
        conn.commit()
    return True


def user_exists(email: str) -> bool:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email.lower(),))
        return cur.fetchone() is not None
