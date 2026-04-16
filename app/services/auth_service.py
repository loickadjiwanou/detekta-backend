import bcrypt
import jwt
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import HTTPException, Request
from bson import ObjectId
from app.config import settings

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def get_jwt_secret() -> str:
    return settings.JWT_SECRET

def create_access_token(user_id: str, email: str) -> str:
    """Create an access token (15 min expiry)."""
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    """Create a refresh token (7 days expiry)."""
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        "type": "refresh"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=settings.JWT_ALGORITHM)

async def get_current_user(request: Request, db) -> dict:
    """Extract and verify the current user from JWT token."""
    # Try cookie first, then Authorization header
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Convert ObjectId to string and remove sensitive data
        user["id"] = str(user["_id"])
        del user["_id"]
        user.pop("password_hash", None)
        user.pop("claude_api_key_encrypted", None)
        
        # Add has_api_key field
        user["has_api_key"] = bool(user.get("claude_api_key_encrypted_stored"))
        user.pop("claude_api_key_encrypted_stored", None)
        
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def check_brute_force(db, identifier: str) -> bool:
    """Check if login attempts exceed limit (5 attempts in 15 min = lockout)."""
    lockout_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    
    attempt = await db.login_attempts.find_one({
        "identifier": identifier,
        "last_attempt": {"$gte": lockout_time}
    })
    
    if attempt and attempt.get("count", 0) >= 5:
        return True
    return False

async def record_failed_login(db, identifier: str):
    """Record a failed login attempt."""
    now = datetime.now(timezone.utc)
    await db.login_attempts.update_one(
        {"identifier": identifier},
        {
            "$inc": {"count": 1},
            "$set": {"last_attempt": now}
        },
        upsert=True
    )

async def clear_login_attempts(db, identifier: str):
    """Clear login attempts on successful login."""
    await db.login_attempts.delete_one({"identifier": identifier})
