"""JWT (pre-auth y access), hash de contraseñas, caché anti-replay y estado pre-auth en memoria."""
import os
import threading
import time
import uuid

import bcrypt
import jwt

JWT_SECRET = os.getenv("JWT_SECRET", "cambia-esto-en-el-.env")
PRE_AUTH_TTL = 300      # 5 min para meter el código
ACCESS_TTL = 1800       # 30 min de sesión elevada
REPLAY_TTL = 90         # 3 ventanas de 30 s


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def check_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


# ---------- Estado intermedio de autenticación (pre-auth) ----------
_pre_auth_sessions: dict[str, str] = {}   # jti -> user_id (un solo uso)
_lock = threading.Lock()


def issue_pre_auth_token(user_id: str) -> str:
    jti = str(uuid.uuid4())
    with _lock:
        _pre_auth_sessions[jti] = user_id
    payload = {"sub": user_id, "scope": "pre_auth", "allowed": ["/auth/verify-2fa"],
               "jti": jti, "exp": int(time.time()) + PRE_AUTH_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_pre_auth_token(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # valida firma y exp
    if payload.get("scope") != "pre_auth":
        raise ValueError("El token no es de tipo pre_auth")
    with _lock:
        if _pre_auth_sessions.get(payload["jti"]) != payload["sub"]:
            raise ValueError("pre_auth_token ya consumido o desconocido")
    return payload


def consume_pre_auth(jti: str) -> None:
    with _lock:
        _pre_auth_sessions.pop(jti, None)


def issue_access_token(user_id: str, method: str) -> str:
    payload = {"sub": user_id, "scope": "access", "mfa_verified": True, "amr": ["pwd", method],
               "exp": int(time.time()) + ACCESS_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    if payload.get("scope") != "access" or payload.get("mfa_verified") is not True:
        raise ValueError("Se requiere access_token con mfa_verified=true")
    return payload


# ---------- Caché anti-replay (dict en memoria con TTL) ----------
class AntiReplayCache:
    def __init__(self, ttl: int = REPLAY_TTL):
        self.ttl = ttl
        self._data: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def _purge(self):
        now = time.time()
        for k in [k for k, exp in self._data.items() if exp < now]:
            del self._data[k]

    def was_used(self, user_id: str, code: str) -> bool:
        with self._lock:
            self._purge()
            return (user_id, code) in self._data

    def mark_used(self, user_id: str, code: str) -> None:
        with self._lock:
            self._data[(user_id, code)] = time.time() + self.ttl


replay_cache = AntiReplayCache()
