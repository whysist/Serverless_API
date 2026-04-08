from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
import pyotp, qrcode, io, base64, secrets, datetime
import bcrypt


app = FastAPI(title="MFA API Prototype")
pwd = CryptContext(schemes=["bcrypt"])
bearer = HTTPBearer()

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# JWT signing key — ephemeral in prototype, use Secrets Manager in production
SECRET = secrets.token_hex(32)
ALGORITHM = "HS256"

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



def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode()[:72], hashed.encode())
# ── Routes ────────────────────────────────────────────────────────────────────
# to register a new user 
@app.post("/auth/register", status_code=201)
def register(body: Creds):
    if body.username in users:
        raise HTTPException(400, detail="Username already taken")

    users[body.username] = {
        "hash": hash_password(body.password), #hash the password 
        "totp_secret": None,
        "totp_active": False,
    }
    return {"msg": "Registered. Enroll TOTP next at POST /auth/enroll-totp"}


@app.post("/auth/enroll-totp")
def enroll_totp(body: Creds):
    #verify password
    # generates a random secret
    # then, creates a URI then creates a QR
    # return the QR code to be scanned with autheticator app
    
    u = users.get(body.username)
    if not u or not verify_password(body.password, u["hash"]):
        raise HTTPException(401, detail="Invalid credentials")

    secret = pyotp.random_base32() #creates a random base32 hash
    u["totp_secret"] = secret

    uri = pyotp.TOTP(secret).provisioning_uri( #creates a uri
        name=body.username,
        issuer_name="MFA-API-Prototype"
    )

    img = qrcode.make(uri) #creates a qr code out of the image
    buf = io.BytesIO()
    img.save(buf, format="PNG") #saves qr code as png
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return {
        "qr_base64": qr_b64,
        "secret": secret,  # Also return raw secret for manual entry
        "instructions": "Scan the QR code with Google Authenticator or Authy",
    }


@app.post("/auth/login")
def login(body: Creds):
   
    # verify password
    # issue single-use pre-auth token
    #set expiry to 5 minutes
    u = users.get(body.username)
    if not u or not verify_password(body.password, u["hash"]):
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

#verifies MFA
@app.post("/auth/verify-mfa")
def verify_mfa(body: MFAVerify):
    
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
    
    return {"status": "ok"}