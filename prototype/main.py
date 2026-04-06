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