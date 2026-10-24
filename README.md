# Lab 2FA (TOTP) desde cero + Observabilidad con Prefect

PoC de autenticación escalonada (Step-Up) con TOTP RFC 6238 implementado a mano, patrón Strategy (TOTP / códigos de respaldo), máquina de estados de aprovisionamiento y protección anti-replay, todo orquestado y observable en Prefect.

```
/backend-prefect        FastAPI + Prefect 3 + Supabase (web de login en web/index.html)
/mobile-authenticator   App Expo (React Native) que calcula el TOTP offline
```

## 1. Base de datos (Supabase)
1. SQL Editor → ejecutar `backend-prefect/supabase.sql`.
2. Copiar `backend-prefect/.env.example` a `backend-prefect/.env` y llenar `SUPABASE_URL`, `SUPABASE_KEY` (service_role) y `JWT_SECRET`.
   Sin credenciales de Supabase el backend usa un repositorio en memoria.

## 2. Servidor de Prefect
```bash
cd backend-prefect
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
prefect config set PREFECT_API_URL=http://127.0.0.1:4200/api
prefect server start                                     # UI: http://127.0.0.1:4200
```

## 3. Backend (otra terminal, mismo venv)
```bash
cd backend-prefect
uvicorn app.main:app --reload --port 8000                # Web: http://127.0.0.1:8000  ·  Swagger: /docs
```

| Endpoint | Flow de Prefect | Descripción |
|---|---|---|
| `POST /auth/register` | — | Crea usuario (`mfa_status=DISABLED`) |
| `POST /2fa/setup` | `provision-2fa-flow` | Genera semilla + QR + 8 backup codes → `PENDING_VERIFICATION` |
| `POST /auth/login` | `login-flow` | Usuario/contraseña → `pre_auth_token` (solo sirve para verify-2fa) |
| `POST /auth/verify-2fa` | `verify-2fa-flow` | `validate_pre_auth_state` → `check_anti_replay_cache` → `execute_mfa_strategy` → `issue_elevated_session` |
| `GET /api/boveda-secreta` | — | Requiere `access_token` con `mfa_verified: true` |

## 4. App móvil
```bash
npx create-expo-app@latest mobile-authenticator --template blank   # solo la primera vez
cd mobile-authenticator
npx expo install expo-camera expo-secure-store
npm install crypto-js
# copiar App.js y totp.js de este repo
npx expo start            # escanear con Expo Go (usar --tunnel si la red bloquea)
```
Escanear el QR que muestra la web o pegar la semilla Base32. Funciona en modo avión.

## Decisiones de diseño
- **TOTP sin librerías TOTP:** solo `hmac/hashlib/base64` (Python) y `crypto-js` para HMAC-SHA1 (JS). Base32 y truncamiento dinámico a mano. Verificado con los vectores del RFC 6238, Apéndice B.
- **Ventanas C-1/C/C+1** con `hmac.compare_digest`; la ventana que coincide se registra en los logs de Prefect.
- **Anti-replay:** dict `(user_id, código) → expiración` con TTL de 90 s (3 ventanas).
- **pre_auth_token de un solo uso:** su `jti` se registra en memoria y se consume al emitir el access token.
- **Backup codes:** guardados como hash SHA-256 y eliminados al usarse.
