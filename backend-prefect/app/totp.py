"""TOTP (RFC 6238) implementado desde cero: solo hmac/hashlib/base64 de la librería estándar."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOWS = (("C-1", -1), ("C", 0), ("C+1", 1))


def generate_secret() -> str:
    """Semilla de 160 bits (20 bytes) codificada en Base32, sin padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = secret.upper().replace(" ", "")
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)


def hotp(secret: str, counter: int, digits: int = DIGITS) -> str:
    key = _b32decode(secret)
    msg = struct.pack(">Q", counter)                       # contador en 8 bytes big-endian
    h = hmac.new(key, msg, hashlib.sha1).digest()          # HMAC-SHA1 -> 20 bytes
    offset = h[-1] & 0x0F                                  # truncamiento dinámico
    binary = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 10 ** digits).zfill(digits)


def current_counter(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def match_window(secret: str, code: str, now: float | None = None) -> str | None:
    """Devuelve 'C-1', 'C' o 'C+1' según la ventana donde coincide el código, o None."""
    c = current_counter(now)
    for label, delta in WINDOWS:
        if hmac.compare_digest(hotp(secret, c + delta), code):
            return label
    return None


def provisioning_uri(secret: str, account: str, issuer: str = "PatronesLab") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}"
            f"?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}")
