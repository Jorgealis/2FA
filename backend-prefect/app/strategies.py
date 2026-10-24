"""Strategy Pattern para el segundo factor."""
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass

from . import totp


@dataclass
class VerificationResult:
    ok: bool
    detail: str  # ventana TOTP (C-1/C/C+1) o "backup-code"


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


class SecondFactorStrategy(ABC):
    name: str

    @abstractmethod
    def verify(self, user: dict, code: str) -> VerificationResult: ...


class TOTPStrategy(SecondFactorStrategy):
    name = "totp"

    def verify(self, user: dict, code: str) -> VerificationResult:
        window = totp.match_window(user["totp_secret"], code)
        return VerificationResult(window is not None, window or "sin coincidencia")


class BackupCodeStrategy(SecondFactorStrategy):
    """Códigos de emergencia de un solo uso (se guardan hasheados y se consumen al usarse)."""
    name = "backup"

    def __init__(self, repo):
        self.repo = repo

    def verify(self, user: dict, code: str) -> VerificationResult:
        h = hash_backup_code(code)
        remaining = list(user.get("backup_codes") or [])
        if h not in remaining:
            return VerificationResult(False, "backup-code inválido o ya usado")
        remaining.remove(h)
        self.repo.update(user["id"], backup_codes=remaining)  # un solo uso
        return VerificationResult(True, f"backup-code (quedan {len(remaining)})")


def get_strategy(method: str, repo) -> SecondFactorStrategy:
    strategies = {"totp": TOTPStrategy(), "backup": BackupCodeStrategy(repo)}
    if method not in strategies:
        raise ValueError(f"Método 2FA no soportado: {method}")
    return strategies[method]
