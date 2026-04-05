# Secure Serverless API with MFA

> A production-grade, cloud-native REST API built on AWS Lambda + API Gateway, with mandatory Multi-Factor Authentication (TOTP) enforced through Amazon Cognito. No persistent servers. No plaintext secrets. No unguarded routes.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Team](#2-team)
3. [Architecture](#3-architecture)
4. [How It Works](#4-how-it-works)
   - [MFA Enrolment Flow](#41-mfa-enrolment-flow)
   - [Sign-In Flow](#42-sign-in-flow)
   - [Protected Route Access](#43-protected-route-access)
5. [Functionality Reference](#5-functionality-reference)
   - [POST /auth/register](#post-authregister)
   - [POST /auth/enroll-totp](#post-authenroll-totp)
   - [POST /auth/login](#post-authlogin)
   - [POST /auth/verify-mfa](#post-authverify-mfa)
   - [POST /auth/refresh](#post-authrefresh)
   - [GET /api/profile](#get-apiprofile)
6. [Tech Stack](#6-tech-stack)
7. [Project Structure](#7-project-structure)
8. [Local Prototype Setup](#8-local-prototype-setup)
9. [Running the Prototype](#9-running-the-prototype)
10. [Cloud Deployment (AWS)](#10-cloud-deployment-aws)
11. [Security Design Decisions](#11-security-design-decisions)
12. [Environment Variables](#12-environment-variables)
13. [Testing](#13-testing)
14. [Roadmap](#14-roadmap)

---

## 1. Project Overview

This project implements a **Secure Serverless API with Multi-Factor Authentication** as part of a Distributed Systems & Cloud Computing (DSCC) coursework deliverable.

The system allows users to:
- Register an account with a hashed password
- Enrol a TOTP authenticator app (Google Authenticator, Authy, etc.) by scanning a QR code
- Log in using a two-step challenge: password → 6-digit TOTP code
- Receive a signed JWT access token on successful MFA
- Access protected API routes using that token

The design is **stateless by nature** — Lambda functions hold no session state between executions. All auth state lives in Amazon Cognito. All sensitive secrets live in AWS Secrets Manager. The local prototype mirrors this design using in-memory stores that can be swapped for AWS calls without changing any route logic.

---

## 2. Team

| Name | Role | Responsibilities |
|------|------|-----------------|
| **Member 1** | Backend Lead | FastAPI route design, boto3 Cognito integration, JWT issuance and validation logic |
| **Member 2** | Cloud Infrastructure | AWS CDK stacks (Cognito User Pool, Lambda, API Gateway, DynamoDB), IAM roles and least-privilege policies |
| **Member 3** | Security & Auth | TOTP enrolment flow, pyotp integration, QR code generation, pre-auth token TTL design, WAF rate-limiting rules |
| **Member 4** | Testing & DevOps | Unit tests (pytest + moto), integration test suite, Makefile automation, CI pipeline configuration |

> **Note to team:** Replace the names above with your actual names, student IDs, and any role adjustments before submitting or publishing.

---

## 3. Architecture

```
Client (Browser / Mobile / curl)
        │
        ▼
┌──────────────────┐
│   AWS CloudFront │  ← CDN + DDoS protection (production)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐       ┌─────────────────────┐
│  AWS API Gateway │──────▶│     AWS WAF          │
│  (HTTP API)      │       │ Rate-limit /auth/*   │
└────────┬─────────┘       └─────────────────────┘
         │
         │  JWT validated here (Cognito Authorizer)
         │  No Lambda cold start for auth check
         ▼
┌──────────────────────────────────────────────────┐
│                  AWS Lambda                       │
│         FastAPI app (wrapped by Mangum)           │
│                                                  │
│  ┌─────────────┐   ┌──────────────┐              │
│  │ /auth/*     │   │ /api/*       │              │
│  │ Auth routes │   │ Protected    │              │
│  │             │   │ business     │              │
│  └──────┬──────┘   │ routes       │              │
│         │          └──────────────┘              │
└─────────┼────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────┐
│                  AWS Services                        │
│                                                     │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────┐ │
│  │   Cognito    │  │  DynamoDB  │  │  Secrets    │ │
│  │  User Pool   │  │ (sessions) │  │  Manager    │ │
│  │  TOTP MFA    │  │            │  │  (API keys) │ │
│  └──────────────┘  └────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────┘
```

**Key architectural principles:**
- Lambda functions are **stateless and thin** — they delegate all auth decisions to Cognito
- API Gateway performs JWT validation **before** Lambda is invoked — no auth logic inside Lambda for protected routes
- TOTP secrets are **never stored by the application** — Cognito owns them via `AssociateSoftwareToken`
- Pre-auth session tokens (issued between password and TOTP step) have a **5-minute TTL** and are single-use

---

## 4. How It Works

### 4.1 MFA Enrolment Flow

This flow runs **once per user**, after registration.

```
User                    API (/auth/enroll-totp)        Cognito
 │                              │                          │
 │── POST (username+password) ──▶                          │
 │                              │── AssociateSoftwareToken ▶
 │                              │◀──── SecretCode ─────────│
 │                              │                          │
 │                   Build otpauth:// URI                  │
 │                   Render QR code (pyotp + qrcode)       │
 │                              │                          │
 │◀──── base64 QR image ────────│                          │
 │                              │                          │
 │  [User scans QR in app]      │                          │
 │                              │                          │
 │── POST (username + first TOTP code) ──▶                 │
 │                              │── VerifySoftwareToken ───▶
 │                              │── SetUserMFAPreference ──▶
 │◀──── 200 OK (TOTP active) ───│                          │
```

After this flow, TOTP is set as the user's **preferred and required** second factor. They cannot log in without it.

---

### 4.2 Sign-In Flow

Every login requires two sequential challenges.

```
User                  API                     Cognito
 │                     │                         │
 │── POST /auth/login ─▶                          │
 │   {username, pw}    │── InitiateAuth ──────────▶
 │                     │   (USER_SRP_AUTH)        │
 │                     │◀── PASSWORD_VERIFIER ────│
 │                     │── RespondToAuthChallenge ▶
 │                     │   (SRP proof)            │
 │                     │◀── SOFTWARE_TOKEN_MFA ───│
 │                     │                         │
 │◀── {pre_auth_token} │                         │
 │    (5-min TTL)      │                         │
 │                     │                         │
 │  [User opens app,   │                         │
 │   reads 6-digit     │                         │
 │   TOTP code]        │                         │
 │                     │                         │
 │── POST /auth/verify-mfa ▶                      │
 │   {pre_auth_token,  │── RespondToAuthChallenge ▶
 │    totp_code}       │   (SOFTWARE_TOKEN_MFA)   │
 │                     │◀── AuthenticationResult ─│
 │                     │    {AccessToken,          │
 │                     │     IdToken,              │
 │                     │     RefreshToken}         │
 │◀── {access_token} ──│                          │
```

The `pre_auth_token` is a server-issued opaque token that maps to the Cognito session string. It is:
- Single-use (deleted on verification attempt)
- Expires after 5 minutes
- Never exposes the Cognito session string to the client

---

### 4.3 Protected Route Access

After login, the client attaches the JWT to every request.

```
Client                  API Gateway              Lambda
  │                         │                      │
  │── GET /api/profile ─────▶                      │
  │   Authorization:        │                      │
  │   Bearer <AccessToken>  │                      │
  │                         │ Validate JWT against  │
  │                         │ Cognito JWKS endpoint │
  │                         │ (no Lambda needed)    │
  │                         │                      │
  │                    [If invalid]─────────────────▶ 401 returned
  │                    [If valid] ──────────────────▶
  │                         │                      │
  │                         │            Lambda receives decoded
  │                         │            claims in event context
  │                         │                      │
  │◀──── 200 {user data} ───│◀─── response ────────│
```

Lambda **never re-validates the JWT**. If a request reaches Lambda, it is already authenticated. The decoded claims (`sub`, `email`, `cognito:username`, etc.) are available in `event["requestContext"]["authorizer"]["claims"]`.

---

## 5. Functionality Reference

### POST /auth/register

**Purpose:** Create a new user account.

**Request body:**
```json
{
  "username": "alice",
  "password": "MyStr0ng!Pass"
}
```

**Behaviour:**
1. Validates that the username is not already taken
2. Hashes the password using `bcrypt` (via `passlib`)
3. Stores the user record: `{ hash, totp_secret: null, totp_active: false }`
4. Returns `201 Created`

**Response:**
```json
{
  "msg": "Registered. Now enroll TOTP at POST /auth/enroll-totp"
}
```

**Errors:**
- `400 Bad Request` — username already exists
- `422 Unprocessable Entity` — missing or invalid fields

**Production equivalent:** `cognito_client.sign_up(ClientId=..., Username=..., Password=...)`

---

### POST /auth/enroll-totp

**Purpose:** Generate a TOTP secret and QR code for the authenticated user.

**Request body:**
```json
{
  "username": "alice",
  "password": "MyStr0ng!Pass"
}
```

**Behaviour:**
1. Verifies password (bcrypt check)
2. Generates a Base32 TOTP secret using `pyotp.random_base32()`
3. Stores the secret against the user record
4. Builds an `otpauth://` URI using the secret, username, and issuer name
5. Renders the URI as a QR code PNG image
6. Returns the image as a base64-encoded string

**Response:**
```json
{
  "qr_base64": "<base64-encoded PNG>",
  "secret": "JBSWY3DPEHPK3PXP"
}
```

**How to use the QR code:**
- Decode `qr_base64` and render as a PNG image in your frontend
- Or paste `secret` manually into your authenticator app
- The user scans the QR with Google Authenticator, Authy, or any TOTP app

**Errors:**
- `401 Unauthorized` — wrong password
- `404 Not Found` — user does not exist

**Production equivalent:** `cognito_client.associate_software_token(AccessToken=...)` followed by `cognito_client.verify_software_token(...)` and `cognito_client.set_user_mfa_preference(...)`

---

### POST /auth/login

**Purpose:** First step of the two-step login. Verifies the password and issues a short-lived pre-auth token.

**Request body:**
```json
{
  "username": "alice",
  "password": "MyStr0ng!Pass"
}
```

**Behaviour:**
1. Looks up the user record
2. Verifies the password via `passlib.verify()`
3. Checks that TOTP has been enrolled (rejects if not)
4. Generates a cryptographically random `pre_auth_token` using `secrets.token_urlsafe(32)`
5. Stores `{ username, expires: now + 5 minutes }` against the token
6. Returns the token with instructions for the next step

**Response:**
```json
{
  "pre_auth_token": "Tz9fK3...",
  "next": "POST /auth/verify-mfa",
  "expires_in_seconds": 300
}
```

**Errors:**
- `401 Unauthorized` — wrong password
- `403 Forbidden` — TOTP not yet enrolled
- `404 Not Found` — user does not exist

**Important:** This token does **not** grant API access. It only permits one attempt at `/auth/verify-mfa` within 5 minutes.

**Production equivalent:** `cognito_client.initiate_auth(AuthFlow='USER_SRP_AUTH', ...)` followed by `cognito_client.respond_to_auth_challenge(ChallengeName='PASSWORD_VERIFIER', ...)`

---

### POST /auth/verify-mfa

**Purpose:** Second step of login. Verifies the TOTP code and issues the real JWT access token.

**Request body:**
```json
{
  "pre_auth_token": "Tz9fK3...",
  "totp_code": "482910"
}
```

**Behaviour:**
1. Looks up the `pre_auth_token` — if missing or expired, rejects immediately
2. Deletes the token (single-use enforcement)
3. Retrieves the user's TOTP secret
4. Calls `pyotp.TOTP(secret).verify(totp_code)` — validates the 6-digit code against the current 30-second TOTP window (also accepts the previous window to tolerate clock drift)
5. On success, calls `issue_jwt(username)` to create a signed JWT with a 1-hour expiry
6. Returns the access token

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Errors:**
- `401 Unauthorized` — session expired, token not found, or wrong TOTP code

**Why the pre_auth_token is deleted immediately:**
If an attacker intercepts the token and tries to brute-force TOTP codes, they get exactly one attempt before the token is invalidated. This limits brute-force surface to the 1-in-1,000,000 probability of guessing a valid 6-digit TOTP code on the first try.

**Production equivalent:** `cognito_client.respond_to_auth_challenge(ChallengeName='SOFTWARE_TOKEN_MFA', ChallengeResponses={'SOFTWARE_TOKEN_MFA_CODE': totp_code, ...})`

---

### POST /auth/refresh

**Purpose:** Exchange a valid refresh token for a new access token without re-authenticating.

**Request body:**
```json
{
  "refresh_token": "<refresh_token from login>"
}
```

**Behaviour:**
1. Validates the refresh token's signature and expiry
2. Issues a new access token with a fresh 1-hour expiry
3. Does **not** require the TOTP code again — MFA is enforced at login, not at refresh

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Errors:**
- `401 Unauthorized` — refresh token expired or tampered

**Production equivalent:** `cognito_client.initiate_auth(AuthFlow='REFRESH_TOKEN_AUTH', AuthParameters={'REFRESH_TOKEN': refresh_token})`

---

### GET /api/profile

**Purpose:** Example protected route. Returns the authenticated user's claims from the JWT.

**Headers required:**
```
Authorization: Bearer <access_token>
```

**Behaviour:**
1. FastAPI's `Depends(require_auth)` middleware intercepts the request
2. Extracts the Bearer token from the `Authorization` header
3. Calls `jose.jwt.decode(token, SECRET, algorithms=["HS256"])` — raises `JWTError` if invalid or expired
4. Injects the decoded `claims` dict into the route handler
5. Returns the user identity

**Response:**
```json
{
  "user": "alice",
  "message": "You passed MFA!"
}
```

**Errors:**
- `401 Unauthorized` — missing, malformed, or expired token
- `403 Forbidden` — token valid but insufficient scope (production only)

**Production note:** In the AWS deployment, this check is performed by API Gateway's Cognito JWT Authorizer before Lambda is ever invoked. Lambda receives pre-validated claims in `event["requestContext"]["authorizer"]["claims"]`.

---

## 6. Tech Stack

### Prototype (local, no cloud)

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API framework | `FastAPI` | Route definitions, request/response validation, OpenAPI docs |
| TOTP | `pyotp` | TOTP secret generation and code verification (RFC 6238) |
| QR code | `qrcode[pil]` | Renders `otpauth://` URI as a scannable PNG image |
| Password hashing | `passlib[bcrypt]` | Secure bcrypt hashing — never stores plaintext passwords |
| JWT | `python-jose` | Signs and verifies JSON Web Tokens (HS256 in prototype, RS256 in production) |
| Server | `uvicorn` | ASGI server — runs FastAPI locally |

### Production (AWS)

| Layer | Technology | Purpose |
|-------|-----------|---------|
| API layer | `AWS API Gateway (HTTP API)` | Routes, JWT validation, rate limits |
| Compute | `AWS Lambda` | Stateless function execution |
| Lambda adapter | `Mangum` | Wraps FastAPI to run inside Lambda |
| Auth & MFA | `Amazon Cognito User Pool` | User directory, SRP auth, TOTP MFA, JWT issuance |
| Session state | `Amazon DynamoDB` | Pre-auth token store with TTL |
| OTP cache | `Amazon ElastiCache (Redis)` | Alternative OTP store for sub-millisecond TTL lookup |
| Secrets | `AWS Secrets Manager` | API keys, signing secrets — never in environment variables |
| CDN + DDoS | `Amazon CloudFront + AWS Shield` | Edge caching, DDoS mitigation |
| Firewall | `AWS WAF` | Rate-limit `/auth/*` routes, block common exploits |
| Observability | `AWS CloudWatch + X-Ray` | Logs, traces, anomaly detection |
| IaC | `AWS CDK (Python)` | All infrastructure defined as code |

---

## 7. Project Structure

```
mfa_api/
├── app/
│   ├── routers/
│   │   ├── auth.py             # /auth/register, /login, /verify-mfa, /enroll-totp, /refresh
│   │   └── api.py              # Protected routes — /api/profile, etc.
│   ├── services/
│   │   ├── cognito.py          # All boto3 cognito-idp calls (production)
│   │   ├── totp.py             # pyotp secret generation, QR URI builder
│   │   └── token.py            # JWT decode, JWKS validation (for production RS256)
│   ├── middleware/
│   │   └── auth_guard.py       # FastAPI Depends() — validates Bearer JWT on protected routes
│   ├── config.py               # pydantic-settings: Cognito pool ID, client ID, region, secrets
│   └── main.py                 # FastAPI app instantiation + Mangum handler for Lambda
│
├── infra/                      # AWS CDK Python stacks
│   ├── cognito_stack.py        # User Pool, MFA policy (REQUIRED), app client
│   ├── lambda_stack.py         # Lambda function, IAM role, env vars
│   └── api_stack.py            # HTTP API Gateway, JWT authorizer, WAF association
│
├── tests/
│   ├── test_auth.py            # Integration tests — moto-mocked Cognito
│   └── test_totp.py            # Unit tests — TOTP generation and verification
│
├── prototype/
│   └── main.py                 # Single-file local prototype (no AWS needed)
│
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Test/dev dependencies (pytest, moto, httpx)
├── Makefile                    # make run / make test / make deploy
└── README.md                   # This file
```

---

## 8. Local Prototype Setup

### Prerequisites

- Python 3.10 or higher
- pip
- An authenticator app on your phone (Google Authenticator, Authy, or any TOTP app)

### Install dependencies

```bash
pip install fastapi uvicorn pyotp "qrcode[pil]" python-jose "passlib[bcrypt]"
```

### Complete prototype source

Save as `prototype/main.py`:

```python
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
import pyotp, qrcode, io, base64, secrets, datetime

app = FastAPI(title="MFA API Prototype")
pwd = CryptContext(schemes=["bcrypt"])
bearer = HTTPBearer()

# JWT signing key — ephemeral in prototype, use Secrets Manager in production
SECRET = secrets.token_hex(32)
ALGORITHM = "HS256"

# ── In-memory stores ──────────────────────────────────────────────────────────
# Replace with boto3 Cognito + DynamoDB calls for production.
users: dict = {}      # username → { hash, totp_secret, totp_active }
pre_auth: dict = {}   # token → { username, expires }

# ── Request schemas ───────────────────────────────────────────────────────────
class Creds(BaseModel):
    username: str
    password: str

class MFAVerify(BaseModel):
    pre_auth_token: str
    totp_code: str

class RefreshRequest(BaseModel):
    refresh_token: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def issue_jwt(username: str, expiry_hours: int = 1) -> str:
    """Issue a signed JWT access token."""
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)
    return jwt.encode({"sub": username, "exp": exp}, SECRET, ALGORITHM)

def require_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """FastAPI dependency — validates Bearer JWT. Inject into any protected route."""
    try:
        return jwt.decode(creds.credentials, SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/auth/register", status_code=201)
def register(body: Creds):
    """Register a new user. Password is bcrypt-hashed immediately — never stored plaintext."""
    if body.username in users:
        raise HTTPException(400, detail="Username already taken")
    users[body.username] = {
        "hash": pwd.hash(body.password),
        "totp_secret": None,
        "totp_active": False,
    }
    return {"msg": "Registered. Enroll TOTP next at POST /auth/enroll-totp"}


@app.post("/auth/enroll-totp")
def enroll_totp(body: Creds):
    """
    Generate a TOTP secret and QR code for the user.
    The user scans the returned QR code with their authenticator app.
    This must be completed before login is possible.
    """
    u = users.get(body.username)
    if not u or not pwd.verify(body.password, u["hash"]):
        raise HTTPException(401, detail="Invalid credentials")

    # Generate a cryptographically random Base32 TOTP secret
    secret = pyotp.random_base32()
    u["totp_secret"] = secret

    # Build the otpauth:// URI — this is what authenticator apps scan
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=body.username,
        issuer_name="MFA-API-Prototype"
    )

    # Render the URI as a QR code PNG and return as base64
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return {
        "qr_base64": qr_b64,
        "secret": secret,  # Also return raw secret for manual entry
        "instructions": "Scan the QR code with Google Authenticator or Authy",
    }


@app.post("/auth/login")
def login(body: Creds):
    """
    Step 1 of 2 in the login flow.
    Verifies the password. If correct, issues a short-lived pre_auth_token.
    The client must present this token + a valid TOTP code to /auth/verify-mfa
    within 5 minutes to receive the real JWT.
    """
    u = users.get(body.username)
    if not u or not pwd.verify(body.password, u["hash"]):
        raise HTTPException(401, detail="Invalid credentials")
    if not u["totp_secret"]:
        raise HTTPException(403, detail="TOTP not enrolled. Call POST /auth/enroll-totp first")

    # Issue a single-use, time-limited pre-auth token
    token = secrets.token_urlsafe(32)
    pre_auth[token] = {
        "username": body.username,
        "expires": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
    }
    return {
        "pre_auth_token": token,
        "next": "POST /auth/verify-mfa with this token + your TOTP code",
        "expires_in_seconds": 300,
    }


@app.post("/auth/verify-mfa")
def verify_mfa(body: MFAVerify):
    """
    Step 2 of 2 in the login flow.
    Validates the pre_auth_token and the 6-digit TOTP code.
    On success, returns a signed JWT access token valid for 1 hour.

    The pre_auth_token is deleted on first use — there is no retry.
    If the TOTP code is wrong, the user must call /auth/login again.
    """
    # Pop the token — enforces single use
    entry = pre_auth.pop(body.pre_auth_token, None)
    if not entry:
        raise HTTPException(401, detail="Session token not found or already used")
    if entry["expires"] < datetime.datetime.utcnow():
        raise HTTPException(401, detail="Session token expired — please login again")

    username = entry["username"]
    secret = users[username]["totp_secret"]

    # Verify TOTP code — valid_window=1 accepts the previous 30s window to handle clock drift
    if not pyotp.TOTP(secret).verify(body.totp_code, valid_window=1):
        raise HTTPException(401, detail="Invalid TOTP code")

    users[username]["totp_active"] = True

    # Issue real JWT access token
    access_token = issue_jwt(username, expiry_hours=1)
    # Prototype: refresh token is a longer-lived JWT (production uses Cognito refresh tokens)
    refresh_token = issue_jwt(username, expiry_hours=24 * 7)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


@app.post("/auth/refresh")
def refresh(body: RefreshRequest):
    """
    Exchange a valid refresh token for a new access token.
    MFA is NOT required again — it was already satisfied at login.
    """
    try:
        claims = jwt.decode(body.refresh_token, SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(401, detail="Refresh token invalid or expired")

    new_access_token = issue_jwt(claims["sub"], expiry_hours=1)
    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }


@app.get("/api/profile")
def profile(claims: dict = Depends(require_auth)):
    """
    Example protected route.
    Any route that uses Depends(require_auth) will reject requests
    without a valid, non-expired JWT access token.
    """
    return {
        "user": claims["sub"],
        "message": "MFA verified — you are authenticated",
    }


@app.get("/api/health")
def health():
    """Public health check — no auth required."""
    return {"status": "ok"}
```

---

## 9. Running the Prototype

```bash
# Navigate to the prototype directory
cd prototype

# Start the server
uvicorn main:app --reload --port 8000
```

Interactive API docs are available at `http://localhost:8000/docs` (Swagger UI).

### Full test sequence (using curl)

**Step 1 — Register**
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "MyStr0ng!Pass"}'
```

**Step 2 — Enroll TOTP**
```bash
curl -X POST http://localhost:8000/auth/enroll-totp \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "MyStr0ng!Pass"}'
```

Take the `qr_base64` value, decode it, and display the PNG. Or use the returned `secret` and add it manually to your authenticator app under "Enter a setup key".

**Step 3 — Login (password step)**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "MyStr0ng!Pass"}'
```

Save the `pre_auth_token` from the response.

**Step 4 — Verify MFA (TOTP step)**
```bash
curl -X POST http://localhost:8000/auth/verify-mfa \
  -H "Content-Type: application/json" \
  -d '{"pre_auth_token": "<token from step 3>", "totp_code": "482910"}'
```

Use the current 6-digit code from your authenticator app. Save the `access_token`.

**Step 5 — Access a protected route**
```bash
curl http://localhost:8000/api/profile \
  -H "Authorization: Bearer <access_token from step 4>"
```

**Expected response:**
```json
{
  "user": "alice",
  "message": "MFA verified — you are authenticated"
}
```

---

## 10. Cloud Deployment (AWS)

### Prerequisites

- AWS CLI configured: `aws configure`
- AWS CDK installed: `npm install -g aws-cdk`
- Python 3.10+

### Steps

```bash
# Bootstrap CDK (one-time per AWS account/region)
cdk bootstrap aws://YOUR_ACCOUNT_ID/us-east-1

# Synthesize CloudFormation templates
cdk synth

# Deploy all stacks
cdk deploy --all
```

### Cognito User Pool — critical settings

```python
# infra/cognito_stack.py
from aws_cdk import aws_cognito as cognito

user_pool = cognito.UserPool(
    self, "MFAUserPool",
    mfa=cognito.Mfa.REQUIRED,                    # MFA cannot be skipped
    mfa_second_factor=cognito.MfaSecondFactor(
        sms=False,                                # Disable SMS (SIM-swap risk)
        otp=True,                                 # TOTP only
    ),
    password_policy=cognito.PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_digits=True,
        require_symbols=True,
    ),
    self_sign_up_enabled=True,
    sign_in_aliases=cognito.SignInAliases(username=True, email=True),
)
```

> **Warning:** Cognito MFA policy cannot be changed after the User Pool is created. Set `mfa=cognito.Mfa.REQUIRED` from the start.

### Wrap FastAPI with Mangum (one line)

```python
# app/main.py
from mangum import Mangum
handler = Mangum(app)   # This becomes the Lambda handler
```

No route code changes needed when moving from local to Lambda.

---

## 11. Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| TOTP over SMS MFA | SMS is vulnerable to SIM-swap attacks. TOTP is offline and phishing-resistant. |
| SRP auth flow | The user's password is never sent over the network, not even to AWS. Cognito uses Secure Remote Password protocol. |
| Single-use pre_auth_token | Eliminates TOTP brute-force window. One wrong guess invalidates the session. |
| 5-minute TTL on pre_auth | Limits the window for token interception attacks without degrading UX. |
| JWT validated at API Gateway | Auth check happens before Lambda is invoked — no compute cost for rejected requests. |
| Secrets Manager for all keys | Rotating secrets does not require redeployment. No secrets in environment variables or code. |
| WAF rate limiting on /auth/* | Blocks brute-force attacks at the edge — before they reach Lambda or Cognito. |
| Least-privilege IAM roles | Each Lambda function has only the specific permissions it needs — nothing more. |
| bcrypt for prototype passwords | Work factor is tunable. Slow by design — makes offline dictionary attacks expensive. |

---

## 12. Environment Variables

For production, these are injected by CDK into Lambda's environment and the sensitive values are fetched from Secrets Manager at runtime — never hardcoded.

| Variable | Description | Example |
|----------|-------------|---------|
| `COGNITO_USER_POOL_ID` | Cognito User Pool ID | `us-east-1_AbCdEfGhI` |
| `COGNITO_CLIENT_ID` | Cognito App Client ID | `1a2b3c4d5e6f7g8h9i0j` |
| `COGNITO_REGION` | AWS region of the User Pool | `us-east-1` |
| `JWT_SECRET_ARN` | ARN of the JWT signing secret in Secrets Manager | `arn:aws:secretsmanager:...` |
| `DYNAMODB_TABLE_NAME` | DynamoDB table for session state | `mfa-api-sessions` |
| `ENVIRONMENT` | Runtime environment tag | `production` / `local` |

For the local prototype, none of these are required. The prototype uses an in-memory store and a randomly generated JWT secret on startup.

---

## 13. Testing

### Install dev dependencies

```bash
pip install pytest pytest-asyncio httpx moto boto3
```

### Run all tests

```bash
pytest tests/ -v
```

### Example unit test — TOTP verification

```python
# tests/test_totp.py
import pyotp

def test_totp_verify_valid_code():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    assert totp.verify(current_code) is True

def test_totp_verify_wrong_code():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    assert totp.verify("000000") is False
```

### Example integration test — full login flow

```python
# tests/test_auth.py
from fastapi.testclient import TestClient
from prototype.main import app
import pyotp

client = TestClient(app)

def test_full_mfa_login_flow():
    # 1. Register
    r = client.post("/auth/register", json={"username": "testuser", "password": "Str0ng!Pass12"})
    assert r.status_code == 201

    # 2. Enroll TOTP — capture the secret
    r = client.post("/auth/enroll-totp", json={"username": "testuser", "password": "Str0ng!Pass12"})
    assert r.status_code == 200
    secret = r.json()["secret"]

    # 3. Login — get pre_auth_token
    r = client.post("/auth/login", json={"username": "testuser", "password": "Str0ng!Pass12"})
    assert r.status_code == 200
    pre_auth_token = r.json()["pre_auth_token"]

    # 4. Verify MFA — generate a real TOTP code from the secret
    totp_code = pyotp.TOTP(secret).now()
    r = client.post("/auth/verify-mfa", json={"pre_auth_token": pre_auth_token, "totp_code": totp_code})
    assert r.status_code == 200
    access_token = r.json()["access_token"]

    # 5. Access protected route
    r = client.get("/api/profile", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    assert r.json()["user"] == "testuser"

def test_protected_route_blocked_without_token():
    r = client.get("/api/profile")
    assert r.status_code == 403  # No Authorization header

def test_wrong_totp_code_rejected():
    client.post("/auth/register", json={"username": "bob", "password": "Str0ng!Pass12"})
    client.post("/auth/enroll-totp", json={"username": "bob", "password": "Str0ng!Pass12"})
    r = client.post("/auth/login", json={"username": "bob", "password": "Str0ng!Pass12"})
    pre_auth_token = r.json()["pre_auth_token"]

    r = client.post("/auth/verify-mfa", json={"pre_auth_token": pre_auth_token, "totp_code": "000000"})
    assert r.status_code == 401
```

---

## 14. Roadmap

| Feature | Status | Notes |
|---------|--------|-------|
| User registration | Done (prototype) | |
| TOTP enrolment + QR code | Done (prototype) | |
| Two-step MFA login | Done (prototype) | |
| JWT access + refresh tokens | Done (prototype) | |
| Protected route guard | Done (prototype) | |
| Cognito integration (boto3) | Planned | Replace in-memory store |
| DynamoDB session store | Planned | Replace dict with TTL-enabled table |
| Lambda + Mangum deployment | Planned | One-line change from local |
| API Gateway + CDK stack | Planned | |
| WAF rate limiting | Planned | |
| SMS MFA fallback | Not planned | SIM-swap risk — TOTP preferred |
| Passkey / WebAuthn | Future | FIDO2 — phishing-resistant |

---

## References

- [Amazon Cognito — TOTP MFA documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html)
- [AWS — Secure API access with MFA](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html)
- [AWS Samples — step-up-auth (official reference implementation)](https://github.com/aws-samples/step-up-auth)
- [pyotp — Python TOTP library](https://github.com/pyauth/pyotp)
- [FastAPI — official documentation](https://fastapi.tiangolo.com/)
- [Mangum — FastAPI + Lambda adapter](https://mangum.io/)
- [RFC 6238 — TOTP standard](https://datatracker.ietf.org/doc/html/rfc6238)

---

*Built for DSCC coursework. Prototype is for demonstration only — do not use the in-memory store or ephemeral JWT secret in production.*
