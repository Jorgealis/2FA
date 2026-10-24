"""API FastAPI. Cada endpoint de autenticación invoca un @flow de Prefect."""
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import flows, security
from .repo import repo

app = FastAPI(title="Lab 2FA TOTP + Prefect")
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"

ERRORS = {
    flows.InvalidCredentials: 401,
    flows.InvalidPreAuthToken: 401,
    flows.InvalidSecondFactor: 401,
    flows.ReplayAttackDetected: 409,
    flows.InvalidMfaState: 400,
}


def run(flow_fn, *args):
    """Ejecuta el flow; si una task falla, Prefect marca el run en rojo y aquí lo traducimos a HTTP."""
    try:
        return flow_fn(*args)
    except tuple(ERRORS) as e:
        raise HTTPException(ERRORS[type(e)], f"{type(e).__name__}: {e}")


class Credentials(BaseModel):
    email: str
    password: str


class Verify2FA(BaseModel):
    pre_auth_token: str
    code: str
    method: str = "totp"  # "totp" | "backup"


@app.get("/")
def home():
    return FileResponse(WEB)


@app.post("/auth/register")
def register(body: Credentials):
    try:
        u = repo.create(body.email, security.hash_password(body.password))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"id": u["id"], "email": u["email"], "mfa_status": u["mfa_status"]}


@app.post("/2fa/setup")
def setup_2fa(body: Credentials):
    return run(flows.provision_2fa_flow, body.email, body.password)


@app.post("/auth/login")
def login(body: Credentials):
    return run(flows.login_flow, body.email, body.password)


@app.post("/auth/verify-2fa")
def verify_2fa(body: Verify2FA):
    return run(flows.verify_2fa_flow, body.pre_auth_token, body.code, body.method)


@app.get("/api/boveda-secreta")
def boveda(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = security.decode_access_token(token)
    except Exception as e:
        raise HTTPException(403, f"Acceso denegado: {e}")
    user = repo.get_by_id(claims["sub"])
    return {"mensaje": f"🔓 Bienvenido a la bóveda, {user['email']}",
            "mfa_verified": claims["mfa_verified"], "amr": claims["amr"]}
