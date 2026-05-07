import os
import io
import base64
import secrets
import datetime
import bcrypt
import pyotp
import qrcode
import boto3
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from mangum import Mangum

app = FastAPI(title="Cloud MFA API")
pwd = CryptContext(schemes=["bcrypt"])
bearer = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── AWS & Environment Setup ───────────────────────────────────────────────────
# We use boto3 to interact with DynamoDB and SSM
dynamodb = boto3.resource('dynamodb')
ssm = boto3.client('ssm')

USERS_TABLE_NAME = os.getenv("USERS_TABLE", "MfaUsersTable")
OTP_TABLE_NAME = os.getenv("OTP_TABLE", "MfaOTPStoreTable")

users_table = dynamodb.Table(USERS_TABLE_NAME)
otp_table = dynamodb.Table(OTP_TABLE_NAME)

ALGORITHM = "RS256"

# Load RSA Keys from AWS Systems Manager Parameter Store
# In production, these should be cached to prevent hitting SSM on every Lambda invocation.
def get_parameter(name: str, with_decryption: bool = True) -> str:
    try:
        response = ssm.get_parameter(Name=name, WithDecryption=with_decryption)
        return response['Parameter']['Value']
    except Exception as e:
        print(f"Failed to fetch parameter {name}: {str(e)}")
        # Fallback to local variables if running locally without SSM
        return os.getenv(name)

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
    """Issue a signed JWT access token using RS256 private key."""
    # Fetch private key on-demand or use cached global
    private_key = get_parameter("/mfa/jwt/private_key")
    if not private_key:
        raise HTTPException(500, detail="JWT Private Key not configured")
        
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=expiry_hours)
    return jwt.encode({"sub": username, "exp": exp}, private_key, algorithm=ALGORITHM)

def require_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    """Validate Bearer JWT using RS256 public key."""
    public_key = get_parameter("/mfa/jwt/public_key", with_decryption=False)
    if not public_key:
        raise HTTPException(500, detail="JWT Public Key not configured")
        
    try:
        return jwt.decode(creds.credentials, public_key, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode()[:72], hashed.encode())

# ── Routes ────────────────────────────────────────────────────────────────────
@app.post("/auth/register", status_code=201)
def register(body: Creds):
    # Check if user exists in DynamoDB
    response = users_table.get_item(Key={'username': body.username})
    if 'Item' in response:
        raise HTTPException(400, detail="Username already taken")

    # Store in DynamoDB instead of local dict
    users_table.put_item(
        Item={
            'username': body.username,
            'hash': hash_password(body.password),
            'totp_secret': None,
            'totp_active': False
        }
    )
    return {"msg": "Registered. Enroll TOTP next at POST /auth/enroll-totp"}

@app.post("/auth/enroll-totp")
def enroll_totp(body: Creds):
    # Verify user in DynamoDB
    response = users_table.get_item(Key={'username': body.username})
    if 'Item' not in response:
        raise HTTPException(401, detail="Invalid credentials")
        
    user = response['Item']
    if not verify_password(body.password, user["hash"]):
        raise HTTPException(401, detail="Invalid credentials")

    secret = pyotp.random_base32()
    
    # Update DynamoDB with the new secret
    users_table.update_item(
        Key={'username': body.username},
        UpdateExpression="SET totp_secret = :s",
        ExpressionAttributeValues={':s': secret}
    )

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=body.username,
        issuer_name="Cloud-MFA-API"
    )

    img = qrcode.make(uri)
    buf = io.BytesIO()
    try:
        img.save(buf, format="PNG")
    except TypeError:
        img.save(buf) # Fallback if using pure python PyPNGImage instead of Pillow
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return {
        "qr_base64": qr_b64,
        "secret": secret,
        "instructions": "Scan the QR code with Google Authenticator or Authy",
    }

@app.post("/auth/login")
def login(body: Creds):
    # Fetch user from DynamoDB
    response = users_table.get_item(Key={'username': body.username})
    if 'Item' not in response:
        raise HTTPException(401, detail="Invalid credentials")
        
    user = response['Item']
    if not verify_password(body.password, user["hash"]):
        raise HTTPException(401, detail="Invalid credentials")
    if not user.get("totp_secret"):
        raise HTTPException(403, detail="TOTP not enrolled. Call POST /auth/enroll-totp first")

    token = secrets.token_urlsafe(32)
    # DynamoDB TTL requires epoch time in seconds
    expires_at = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).timestamp())
    
    # Store pre_auth token in DynamoDB OTPStore
    otp_table.put_item(
        Item={
            'pre_auth_token': token,
            'username': body.username,
            'expiresAt': expires_at  # TTL attribute
        }
    )

    return {
        "pre_auth_token": token,
        "next": "POST /auth/verify-mfa with this token + your TOTP code",
        "expires_in_seconds": 300,
    }

@app.post("/auth/verify-mfa")
def verify_mfa(body: MFAVerify):
    # Fetch pre_auth token from DynamoDB
    response = otp_table.get_item(Key={'pre_auth_token': body.pre_auth_token})
    if 'Item' not in response:
        raise HTTPException(401, detail="Session token not found or expired")
        
    entry = response['Item']
    
    # Optional: Delete token after single use
    otp_table.delete_item(Key={'pre_auth_token': body.pre_auth_token})
    
    if entry.get("expiresAt", 0) < int(datetime.datetime.utcnow().timestamp()):
        raise HTTPException(401, detail="Session token expired — please login again")

    username = entry["username"]
    
    # Fetch user to get the totp_secret
    user_resp = users_table.get_item(Key={'username': username})
    user = user_resp['Item']
    secret = user["totp_secret"]

    if not pyotp.TOTP(secret).verify(body.totp_code, valid_window=1):
        raise HTTPException(401, detail="Invalid TOTP code")

    # Mark as active
    users_table.update_item(
        Key={'username': username},
        UpdateExpression="SET totp_active = :a",
        ExpressionAttributeValues={':a': True}
    )

    access_token = issue_jwt(username, expiry_hours=1)
    refresh_token = issue_jwt(username, expiry_hours=24 * 7)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 3600,
    }

@app.get("/api/profile")
def profile(claims: dict = Depends(require_auth)):
    return {
        "user": claims["sub"],
        "message": "MFA verified — you are authenticated via Cloud API",
    }

@app.get("/api/health")
def health():
    return {"status": "ok"}

# ── Mangum Adapter ────────────────────────────────────────────────────────────
# This single line wraps the FastAPI application to make it compatible with AWS Lambda
handler = Mangum(app)
