# Lab 2FA (TOTP) desde cero + Observabilidad con Prefect — Guía paso a paso

> Actividad independiente del taller GraphQL/CQRS. Cada fase indica qué criterio de la rúbrica ataca.
> El código de referencia (ya probado) viene en el zip `lab-2fa.zip`: carpetas `/backend-prefect` y `/mobile-authenticator`.

---

## Stack recomendado (el más fácil y rápido)

| Pieza | Elección | Por qué es la más rápida |
|---|---|---|
| App móvil | **React Native con Expo (Expo Go)** + `crypto-js` (solo HMAC-SHA1) + `expo-camera` (QR) + `expo-secure-store` | No compilas nada: escaneas el QR de Metro con Expo Go y la app corre en tu celular. JS es el mismo lenguaje que ya manejas en RN. `crypto-js` es una librería de HMAC, **no** de TOTP → permitida. Base32 y truncamiento dinámico se hacen a mano. |
| Backend | **Python 3.11+ + FastAPI** | El enunciado recomienda Python porque Prefect es Python. FastAPI da `/docs` (Swagger) gratis para probar. |
| Orquestación | **Prefect 3 + `prefect server start`** local | Requerido. Llamar un `@flow` desde un endpoint es una línea. |
| TOTP backend | Implementado a mano con `hmac` + `hashlib` + `base64` (stdlib) | Necesitas saber en qué ventana (C-1, C, C+1) hizo match — `pyotp.verify()` no lo dice. Son ~15 líneas. |
| Tokens | `PyJWT` (HS256) | `pre_auth_token` y `access_token` con `scope` distinto. |
| Contraseñas | `bcrypt` | Estándar, 2 líneas. |
| BD usuarios | **Supabase** (tabla `users`) con `supabase-py` | El enunciado pide Supabase. Si falla la conexión, el código cae a un repositorio en memoria automáticamente (plan B, permitido por la nota de alcance). |
| Anti-replay y estado pre-auth | `dict` en memoria con TTL | Permitido explícitamente. Cero infraestructura. |
| QR | `qrcode[pil]` → PNG en base64 | La web lo muestra directo en un `<img>`. |
| Web de login | **Un solo `index.html` vanilla servido por FastAPI** | Sin React, sin build, sin CORS (mismo origen). |

**Descartados y por qué:** SwiftUI (requiere Mac), Kotlin (más lento de montar y compilar), Next.js para la web (build + CORS innecesarios), Redis (prohibido por alcance, innecesario).

---

## Arquitectura

```
[Web index.html] --(email+pwd)--> POST /auth/login ──► login-flow ──► pre_auth_token (scope=pre_auth)
        │                                                                  
        └─(pre_auth_token + 6 dígitos)─► POST /auth/verify-2fa ──► verify-2fa-flow
                                                  ├ Task 1 validate_pre_auth_state
                                                  ├ Task 2 check_anti_replay_cache   (falla → ReplayAttackDetected)
                                                  ├ Task 3 execute_mfa_strategy      (TOTPStrategy | BackupCodeStrategy, loguea C-1/C/C+1)
                                                  └ Task 4 issue_elevated_session    (marca usado, PENDING→ACTIVE, JWT mfa_verified=true)
        └─(Bearer access_token)──► GET /api/boveda-secreta

[App Expo, modo avión] HMAC-SHA1(secreto, floor(unix/30)) → 6 dígitos   (nunca habla con el backend)
[Supabase] tabla users(email, password_hash, mfa_status, totp_secret, backup_codes)
[Prefect UI :4200] grafo de cada flow, estados Completed/Failed, logs
```

**Máquina de estados del 2FA:** `DISABLED → PENDING_VERIFICATION` (al generar el QR en `POST /2fa/setup`) `→ ACTIVE` (con el primer código TOTP válido en `verify-2fa`). Mientras está `PENDING` se puede regenerar el QR cuantas veces sea (así nadie queda bloqueado si nunca lo escaneó); una vez `ACTIVE` se bloquea el re-aprovisionamiento.

---

## FASE 0 — Preparación (≈30 min)

1. Crear repo `lab-2fa-totp` en GitHub con dos carpetas: `/backend-prefect` y `/mobile-authenticator` (descomprime el zip ahí).
2. Instalar: Python 3.11+, Node 20+, y **Expo Go** en tu celular (Play Store / App Store). Opcional: Google Authenticator o Microsoft Authenticator para la prueba de paridad.
3. Crear proyecto en Supabase → **SQL Editor** → pegar y ejecutar `backend-prefect/supabase.sql`.
4. Supabase → Project Settings → API → copiar `Project URL` y la **service_role / secret key** (no la anon) a `backend-prefect/.env` (usa `.env.example` como base). Pon también un `JWT_SECRET` largo.

## FASE 1 — Backend: TOTP a mano (Rúbrica 30% patrones / base de todo)

Archivo `app/totp.py`. Los 5 pasos del RFC 6238:
1. `key = base32decode(secret)`
2. `counter = floor(unix_time / 30)` empaquetado en **8 bytes big-endian**
3. `h = HMAC-SHA1(key, counter)` → 20 bytes
4. **Truncamiento dinámico:** `offset = h[19] & 0x0F`; tomar 4 bytes desde `offset`, aplicar `& 0x7FFFFFFF`
5. `código = binario % 10^6`, rellenado con ceros a la izquierda

`match_window()` prueba `C-1`, `C`, `C+1` y devuelve la etiqueta de la que coincide (con `hmac.compare_digest` para evitar timing attacks).

✅ **Verificado** con los vectores oficiales del RFC 6238 (Apéndice B): t=59 → `94287082`, t=1111111109 → `07081804`, etc.

## FASE 2 — Backend: patrones (Rúbrica 30%)

- **Strategy** (`app/strategies.py`): clase abstracta `SecondFactorStrategy.verify(user, code)` con `TOTPStrategy` y `BackupCodeStrategy`. `get_strategy("totp"|"backup")` elige en tiempo de ejecución. Los backup codes se guardan **hasheados (SHA-256)** y se eliminan de la lista al usarse (un solo uso).
- **Step-Up** (`app/security.py`): `pre_auth_token` = JWT con `scope: "pre_auth"`, 5 min, y un `jti` registrado en un dict de sesiones pre-auth (de un solo uso). `access_token` = JWT con `scope: "access"` y `mfa_verified: true`. `/api/boveda-secreta` rechaza (403) cualquier token sin `mfa_verified`.
- **Process Manager / Estado** (`app/flows.py`): `create_pending_totp_config` deja `PENDING_VERIFICATION`; `issue_elevated_session` pasa a `ACTIVE` solo con el primer TOTP válido.

## FASE 3 — Backend: Prefect + anti-replay (Rúbrica 25% + 15%)

`app/flows.py` tiene 3 flows:

| Flow | Endpoint | Tasks |
|---|---|---|
| `provision-2fa-flow` | `POST /2fa/setup` | `authenticate_password` → `create_pending_totp_config` → `build_qr` |
| `login-flow` | `POST /auth/login` | `authenticate_password` → `issue_pre_auth` |
| `verify-2fa-flow` | `POST /auth/verify-2fa` | las **4 tasks del enunciado** |

Claves:
- Cada task lleva `@task(cache_policy=NO_CACHE)` para que Prefect no intente cachear inputs (dicts, tokens).
- `check_anti_replay_cache` lanza `ReplayAttackDetected` si `(user_id, código)` está en el dict con TTL de 90 s → el flow queda **Failed (rojo)** en esa task.
- `execute_mfa_strategy` usa `get_run_logger()` para escribir: `✅ Código TOTP coincide en ventana C-1 -> reloj del celular ATRASADO ~30 s`.
- `main.py` envuelve cada flow: si una task lanza excepción de dominio, se traduce a HTTP (401 / 409 / 400) y Prefect igual registra el run fallido.

## FASE 4 — Levantar y probar el backend (≈20 min)

Windows (PowerShell), en `backend-prefect/`:
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
prefect config set PREFECT_API_URL=http://127.0.0.1:4200/api
```
Terminal 1: `prefect server start` → UI en http://127.0.0.1:4200
Terminal 2 (con el venv activo): `uvicorn app.main:app --reload --port 8000` → web en http://127.0.0.1:8000 y Swagger en `/docs`

Prueba en la web: **Registro → Generar QR → Login → (código) Verificar → Bóveda**. En la UI de Prefect → *Runs* deben aparecer los flows.

> ⚠️ Si no configuras `PREFECT_API_URL`, Prefect usa un servidor temporal propio y los runs **no** se ven en tu UI (y en Windows puede dar `database is locked`).

## FASE 5 — App móvil Expo (Rúbrica 30%) (≈1 h)

```bash
npx create-expo-app@latest mobile-authenticator --template blank
cd mobile-authenticator
npx expo install expo-camera expo-secure-store
npm install crypto-js
```
Copia `App.js` y `totp.js` del zip (reemplaza el `App.js` generado). Agrega en `app.json` → `expo.plugins`: `["expo-camera", { "cameraPermission": "Para escanear el QR del 2FA" }]`.

`npx expo start` → escanea el QR de Metro con Expo Go (mismo Wi-Fi; si la red de la U lo bloquea: `npx expo start --tunnel`).

Qué hace la app:
- **Ingesta:** botón *Escanear QR* (extrae `secret=` de la URI `otpauth://totp/...`) o campo para pegar la semilla Base32 (útil en emulador).
- **Cálculo:** `totp.js` decodifica Base32 a mano, arma el contador en 8 bytes, `CryptoJS.HmacSHA1`, truncamiento dinámico. ✅ Probado con los mismos vectores RFC y da idéntico al backend Python.
- **UI:** código grande `123 456`, barra de progreso 30→0 s (roja los últimos 5 s), se regenera sola. La semilla se guarda en `SecureStore` (sobrevive sin red).

**Modo avión:** una vez cargada la app en Expo Go, activa modo avión y **no recargues** (sin red no puede volver a bajar el bundle). Plan B: emulador Android de Android Studio (modo avión en el emulador + pegar semilla). Plan C: APK standalone con `eas build -p android --profile preview`.

## FASE 6 — Ensayo de las 4 pruebas de aceptación (≈30 min)

Ten abiertas: la web (`:8000`), la UI de Prefect (`:4200`) y el celular.

1. **Paridad:** usuario nuevo → *Generar QR* → escanéalo con tu app **y** con Google/Microsoft Authenticator → mismo código a la vez.
2. **Modo avión:** activa modo avión, espera que cambie la ventana → *Login* → escribe el código → *Verificar* (pasa a `ACTIVE` si era el primero) → *GET /api/boveda-secreta* = 200. Extra: botón rojo *Intentar con pre_auth_token* = 403 (demuestra Step-Up).
3. **Replay:** *Login* otra vez → mete **el mismo código** antes de que cambie → 409 `ReplayAttackDetected`. En Prefect: `verify-2fa-flow` en rojo, task `check_anti_replay_cache` Failed.
4. **Clock skew / backup:** abre el run exitoso → Logs de `execute_mfa_strategy` → muestra `ventana C`. Para forzar `C-1`: espera a que el código cambie e ingresa rápido el anterior (lo copias justo antes). O bien: método *Código de respaldo* con uno de los 8 códigos → 200; reusarlo → falla.

## FASE 7 — Entregables

- [ ] Repo con `/mobile-authenticator` y `/backend-prefect`
- [ ] `README.md` (incluido en el zip) con: `prefect server start`, backend, app móvil
- [ ] `.env` fuera del repo (`.gitignore` incluido)
- [ ] Capturas: grafo de Prefect OK, flow rojo por replay, log de ventana, paridad con Google Authenticator

---

## Orden de prioridad si falta tiempo

1. TOTP en la app que coincida con Google Authenticator (30%).
2. `verify-2fa-flow` con las 4 tasks visibles en Prefect (25%).
3. Step-Up + estados + Strategy (30%).
4. Anti-replay (15%) — ya viene en el flow, solo ensáyalo.

## Preguntas probables en la sustentación

- **¿Por qué C-1 y C+1?** Tolerancia a desfase de reloj (±30 s) y a la latencia de escribir el código. Ampliar más la ventana aumenta la superficie de fuerza bruta.
- **¿Por qué 90 s en el anti-replay?** Un código es válido en 3 ventanas (C-1, C, C+1) = 90 s; pasado eso ya no sería aceptado de todos modos.
- **¿Por qué `& 0x7FFFFFFF`?** Quita el bit de signo para que el entero de 31 bits sea igual en todos los lenguajes.
- **¿Por qué el pre_auth_token no da acceso?** Step-Up: el password solo prueba un factor; el token tiene `scope=pre_auth` y la bóveda exige `mfa_verified=true`.
- **¿Por qué PENDING_VERIFICATION?** Si activáramos el 2FA al generar el QR y el usuario nunca lo escanea, quedaría bloqueado. Solo un código válido prueba que la app tiene la semilla.
