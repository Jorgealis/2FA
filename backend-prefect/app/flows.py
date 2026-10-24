"""Flujos y tareas de Prefect: cada paso del pipeline de seguridad es observable en la UI."""
import base64
import io
import secrets

import qrcode
from prefect import flow, get_run_logger, task
from prefect.cache_policies import NO_CACHE

from . import security, totp
from .repo import repo
from .strategies import get_strategy, hash_backup_code


class InvalidCredentials(Exception): ...
class InvalidPreAuthToken(Exception): ...
class ReplayAttackDetected(Exception): ...
class InvalidSecondFactor(Exception): ...
class InvalidMfaState(Exception): ...


# =====================================================================
# FLOW 1: Aprovisionamiento (Process Manager / máquina de estados)
# DISABLED -> PENDING_VERIFICATION -> ACTIVE
# =====================================================================
@task(cache_policy=NO_CACHE)
def authenticate_password(email: str, password: str) -> dict:
    user = repo.get_by_email(email)
    if not user or not security.check_password(password, user["password_hash"]):
        raise InvalidCredentials("Usuario o contraseña incorrectos")
    get_run_logger().info(f"Credenciales OK para {email} (mfa_status={user['mfa_status']})")
    return user


@task(cache_policy=NO_CACHE)
def create_pending_totp_config(user: dict) -> dict:
    log = get_run_logger()
    if user["mfa_status"] == "ACTIVE":
        raise InvalidMfaState("El 2FA ya está ACTIVE; no se puede reprovisionar")
    secret = totp.generate_secret()
    codes = [secrets.token_hex(4).upper() for _ in range(8)]  # 8 códigos de respaldo
    repo.update(user["id"], totp_secret=secret, mfa_status="PENDING_VERIFICATION",
                backup_codes=[hash_backup_code(c) for c in codes])
    log.info(f"Estado: {user['mfa_status']} -> PENDING_VERIFICATION")
    return {"secret": secret, "backup_codes": codes}


@task(cache_policy=NO_CACHE)
def build_qr(email: str, secret: str) -> dict:
    uri = totp.provisioning_uri(secret, email)
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    get_run_logger().info("QR otpauth:// generado")
    return {"otpauth_uri": uri, "qr_png_base64": base64.b64encode(buf.getvalue()).decode()}


@flow(name="provision-2fa-flow")
def provision_2fa_flow(email: str, password: str) -> dict:
    user = authenticate_password(email, password)
    cfg = create_pending_totp_config(user)
    qr = build_qr(email, cfg["secret"])
    return {"mfa_status": "PENDING_VERIFICATION", "secret": cfg["secret"],
            "backup_codes": cfg["backup_codes"], **qr}


# =====================================================================
# FLOW 2: Login con contraseña -> pre_auth_token (Step-Up, paso 1)
# =====================================================================
@task(cache_policy=NO_CACHE)
def issue_pre_auth(user: dict) -> str:
    if user["mfa_status"] == "DISABLED":
        raise InvalidMfaState("Activa el 2FA primero (POST /2fa/setup)")
    get_run_logger().info("pre_auth_token emitido (solo sirve para /auth/verify-2fa)")
    return security.issue_pre_auth_token(user["id"])


@flow(name="login-flow")
def login_flow(email: str, password: str) -> dict:
    user = authenticate_password(email, password)
    token = issue_pre_auth(user)
    return {"pre_auth_token": token, "mfa_status": user["mfa_status"],
            "expires_in": security.PRE_AUTH_TTL}


# =====================================================================
# FLOW 3: Verificación 2FA (Step-Up, paso 2) — las 4 tareas del enunciado
# =====================================================================
@task(cache_policy=NO_CACHE)
def validate_pre_auth_state(pre_auth_token: str) -> dict:
    log = get_run_logger()
    try:
        claims = security.decode_pre_auth_token(pre_auth_token)
    except Exception as e:
        raise InvalidPreAuthToken(f"pre_auth_token inválido: {e}")
    user = repo.get_by_id(claims["sub"])
    if not user or user["mfa_status"] not in ("PENDING_VERIFICATION", "ACTIVE"):
        raise InvalidPreAuthToken("El usuario no tiene 2FA aprovisionado")
    log.info(f"pre_auth válido para {user['email']} (estado {user['mfa_status']})")
    return {"user": user, "jti": claims["jti"]}


@task(cache_policy=NO_CACHE)
def check_anti_replay_cache(user_id: str, code: str) -> None:
    if security.replay_cache.was_used(user_id, code):
        get_run_logger().error(f"Código {code} ya usado por {user_id} en los últimos 90 s")
        raise ReplayAttackDetected(f"Replay attack detectado: el código {code} ya fue usado")
    get_run_logger().info("Código no usado previamente ✔")


@task(cache_policy=NO_CACHE)
def execute_mfa_strategy(user: dict, code: str, method: str) -> str:
    log = get_run_logger()
    if method == "backup" and user["mfa_status"] != "ACTIVE":
        raise InvalidMfaState("Los backup codes solo sirven con 2FA ACTIVE")
    strategy = get_strategy(method, repo)
    log.info(f"Strategy seleccionada: {type(strategy).__name__}")
    result = strategy.verify(user, code)
    if not result.ok:
        raise InvalidSecondFactor(f"Segundo factor inválido ({result.detail})")
    if method == "totp":
        hint = {"C-1": "reloj del celular ATRASADO ~30 s",
                "C": "relojes sincronizados",
                "C+1": "reloj del celular ADELANTADO ~30 s"}[result.detail]
        log.info(f"✅ Código TOTP coincide en ventana {result.detail} -> {hint}")
    else:
        log.info(f"✅ Autenticado con {result.detail}")
    return result.detail


@task(cache_policy=NO_CACHE)
def issue_elevated_session(user: dict, code: str, method: str, jti: str) -> str:
    log = get_run_logger()
    security.replay_cache.mark_used(user["id"], code)
    security.consume_pre_auth(jti)
    if user["mfa_status"] == "PENDING_VERIFICATION" and method == "totp":
        repo.update(user["id"], mfa_status="ACTIVE")
        log.info("Estado: PENDING_VERIFICATION -> ACTIVE (primer código válido)")
    log.info("access_token emitido con mfa_verified=true")
    return security.issue_access_token(user["id"], method)


@flow(name="verify-2fa-flow")
def verify_2fa_flow(pre_auth_token: str, code: str, method: str = "totp") -> dict:
    code = code.strip().replace(" ", "")
    state = validate_pre_auth_state(pre_auth_token)
    user = state["user"]
    check_anti_replay_cache(user["id"], code)
    detail = execute_mfa_strategy(user, code, method)
    token = issue_elevated_session(user, code, method, state["jti"])
    return {"access_token": token, "token_type": "bearer", "matched": detail}
