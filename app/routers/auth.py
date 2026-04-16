from fastapi import APIRouter, HTTPException, Request, Response, Depends
from datetime import datetime, timezone
from bson import ObjectId
import secrets

from app.models.user import UserCreate, UserLogin, UserResponse
from app.services.auth_service import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    get_current_user, check_brute_force, record_failed_login, clear_login_attempts
)
from app.database import get_database
from app.config import settings
import jwt

router = APIRouter(prefix="/auth", tags=["Authentication"])

def get_db():
    return get_database()

@router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate, response: Response):
    """Register a new user."""
    db = get_db()
    
    # Normalize email
    email = user_data.email.lower()
    
    # Check if email already exists
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    now = datetime.now(timezone.utc)
    user_doc = {
        "email": email,
        "password_hash": hash_password(user_data.password),
        "full_name": user_data.full_name,
        "role": "user",
        "total_audits": 0,
        "is_active": True,
        "is_verified": False,
        "preferred_language": settings.DEFAULT_LANGUAGE,
        "use_own_api_key": False,
        "marketing_emails": user_data.marketing_emails,
        "created_at": now,
        "updated_at": now
    }
    
    result = await db.users.insert_one(user_doc)
    user_id = str(result.inserted_id)
    
    # Create tokens
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    # Set cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=900,
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=604800,
        path="/"
    )
    
    return UserResponse(
        id=user_id,
        email=email,
        full_name=user_data.full_name,
        role="user",
        total_audits=0,
        is_active=True,
        is_verified=False,
        preferred_language=settings.DEFAULT_LANGUAGE,
        use_own_api_key=False,
        has_api_key=False,
        marketing_emails=user_data.marketing_emails,
        created_at=now
    )

@router.post("/login", response_model=UserResponse)
async def login(credentials: UserLogin, request: Request, response: Response):
    """Login with email and password."""
    db = get_db()
    
    email = credentials.email.lower()
    ip = request.client.host if request.client else "unknown"
    identifier = f"{ip}:{email}"
    
    # Check brute force
    if await check_brute_force(db, identifier):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again in 15 minutes."
        )
    
    # Find user
    user = await db.users.find_one({"email": email})
    if not user:
        await record_failed_login(db, identifier)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not verify_password(credentials.password, user["password_hash"]):
        await record_failed_login(db, identifier)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is disabled")
    
    # Clear login attempts on success
    await clear_login_attempts(db, identifier)
    
    user_id = str(user["_id"])
    
    # Create tokens
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    # Set cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=900,
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=604800,
        path="/"
    )
    
    return UserResponse(
        id=user_id,
        email=user["email"],
        full_name=user.get("full_name", ""),
        avatar_url=user.get("avatar_url"),
        role=user.get("role", "user"),
        total_audits=user.get("total_audits", 0),
        is_active=user.get("is_active", True),
        is_verified=user.get("is_verified", False),
        preferred_language=user.get("preferred_language", "en"),
        use_own_api_key=user.get("use_own_api_key", False),
        has_api_key=bool(user.get("claude_api_key_encrypted")),
        marketing_emails=user.get("marketing_emails", False),
        created_at=user.get("created_at", datetime.now(timezone.utc)),
        updated_at=user.get("updated_at")
    )

@router.post("/logout")
async def logout(response: Response):
    """Logout and clear cookies."""
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=UserResponse)
async def get_me(request: Request):
    """Get current user profile."""
    db = get_db()
    user = await get_current_user(request, db)
    
    return UserResponse(
        id=user["id"],
        email=user["email"],
        full_name=user.get("full_name", ""),
        avatar_url=user.get("avatar_url"),
        role=user.get("role", "user"),
        total_audits=user.get("total_audits", 0),
        is_active=user.get("is_active", True),
        is_verified=user.get("is_verified", False),
        preferred_language=user.get("preferred_language", "en"),
        use_own_api_key=user.get("use_own_api_key", False),
        has_api_key=user.get("has_api_key", False),
        marketing_emails=user.get("marketing_emails", False),
        created_at=user.get("created_at", datetime.now(timezone.utc)),
        updated_at=user.get("updated_at")
    )

@router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    """Refresh access token."""
    db = get_db()
    
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
    
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload["sub"]
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Create new access token
        access_token = create_access_token(user_id, user["email"])
        
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=900,
            path="/"
        )
        
        return {"message": "Token refreshed"}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

@router.post("/forgot-password")
async def forgot_password(email: str):
    """Request password reset."""
    db = get_db()
    
    user = await db.users.find_one({"email": email.lower()})
    if not user:
        # Don't reveal if email exists
        return {"message": "If the email exists, a reset link has been sent"}
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc).timestamp() + 3600  # 1 hour
    
    await db.password_reset_tokens.insert_one({
        "token": token,
        "user_id": str(user["_id"]),
        "expires_at": datetime.fromtimestamp(expires, tz=timezone.utc),
        "used": False
    })
    
    # In production, send email. For now, log it.
    reset_url = f"http://localhost:3000/reset-password?token={token}"
    print(f"[AUTH] Password reset link for {email}: {reset_url}")
    
    return {"message": "If the email exists, a reset link has been sent"}

@router.post("/reset-password")
async def reset_password(token: str, new_password: str):
    """Reset password with token."""
    db = get_db()
    
    # Find token
    token_doc = await db.password_reset_tokens.find_one({
        "token": token,
        "used": False
    })
    
    if not token_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    # Check expiry
    if token_doc["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token has expired")
    
    # Update password
    await db.users.update_one(
        {"_id": ObjectId(token_doc["user_id"])},
        {"$set": {"password_hash": hash_password(new_password)}}
    )
    
    # Mark token as used
    await db.password_reset_tokens.update_one(
        {"token": token},
        {"$set": {"used": True}}
    )
    
    return {"message": "Password reset successfully"}
