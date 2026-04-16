from fastapi import APIRouter, HTTPException, Request
from datetime import datetime, timezone
from bson import ObjectId

from app.models.user import UserUpdate, UserResponse, ApiKeyRequest, ApiKeyResponse, ApiKeyStatus
from app.services.auth_service import get_current_user
from app.services.ai_service import test_api_key
from app.utils.crypto import encrypt_api_key, decrypt_api_key, mask_api_key
from app.database import get_database

router = APIRouter(prefix="/users", tags=["Users"])

def get_db():
    return get_database()

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(request: Request):
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

@router.patch("/me", response_model=UserResponse)
async def update_profile(request: Request, update_data: UserUpdate):
    """Update current user profile."""
    db = get_db()
    user = await get_current_user(request, db)
    
    update_dict = {}
    if update_data.full_name is not None:
        update_dict["full_name"] = update_data.full_name
    if update_data.avatar_url is not None:
        update_dict["avatar_url"] = update_data.avatar_url
    if update_data.preferred_language is not None:
        update_dict["preferred_language"] = update_data.preferred_language
    if update_data.marketing_emails is not None:
        update_dict["marketing_emails"] = update_data.marketing_emails
    
    if update_dict:
        update_dict["updated_at"] = datetime.now(timezone.utc)
        await db.users.update_one(
            {"_id": ObjectId(user["id"])},
            {"$set": update_dict}
        )
    
    # Fetch updated user
    updated_user = await db.users.find_one({"_id": ObjectId(user["id"])})
    
    return UserResponse(
        id=str(updated_user["_id"]),
        email=updated_user["email"],
        full_name=updated_user.get("full_name", ""),
        avatar_url=updated_user.get("avatar_url"),
        role=updated_user.get("role", "user"),
        total_audits=updated_user.get("total_audits", 0),
        is_active=updated_user.get("is_active", True),
        is_verified=updated_user.get("is_verified", False),
        preferred_language=updated_user.get("preferred_language", "en"),
        use_own_api_key=updated_user.get("use_own_api_key", False),
        has_api_key=bool(updated_user.get("claude_api_key_encrypted")),
        marketing_emails=updated_user.get("marketing_emails", False),
        created_at=updated_user.get("created_at", datetime.now(timezone.utc)),
        updated_at=updated_user.get("updated_at")
    )

@router.post("/me/api-key", response_model=ApiKeyResponse)
async def set_api_key(request: Request, api_key_data: ApiKeyRequest):
    """Set or update Claude API key."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Test the API key first
    is_valid, message = await test_api_key(api_key_data.claude_api_key)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid API key: {message}")
    
    # Encrypt and store the key
    encrypted_key = encrypt_api_key(api_key_data.claude_api_key)
    
    await db.users.update_one(
        {"_id": ObjectId(user["id"])},
        {"$set": {
            "claude_api_key_encrypted": encrypted_key,
            "use_own_api_key": api_key_data.use_own,
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    return ApiKeyResponse(
        success=True,
        key_preview=mask_api_key(api_key_data.claude_api_key),
        message="API key saved successfully"
    )

@router.delete("/me/api-key")
async def delete_api_key(request: Request):
    """Delete Claude API key."""
    db = get_db()
    user = await get_current_user(request, db)
    
    await db.users.update_one(
        {"_id": ObjectId(user["id"])},
        {"$set": {
            "claude_api_key_encrypted": None,
            "use_own_api_key": False,
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    return {"message": "API key deleted successfully"}

@router.get("/me/api-key/status", response_model=ApiKeyStatus)
async def get_api_key_status(request: Request):
    """Get API key status."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Need to fetch full user doc to check encrypted key
    user_doc = await db.users.find_one({"_id": ObjectId(user["id"])})
    
    has_key = bool(user_doc.get("claude_api_key_encrypted"))
    key_preview = None
    
    if has_key:
        try:
            decrypted = decrypt_api_key(user_doc["claude_api_key_encrypted"])
            key_preview = mask_api_key(decrypted)
        except Exception:
            key_preview = "***"
    
    return ApiKeyStatus(
        has_key=has_key,
        use_own_api_key=user_doc.get("use_own_api_key", False),
        key_preview=key_preview
    )

@router.post("/me/api-key/test")
async def test_user_api_key(request: Request):
    """Test the stored API key."""
    db = get_db()
    user = await get_current_user(request, db)
    
    user_doc = await db.users.find_one({"_id": ObjectId(user["id"])})
    
    if not user_doc.get("claude_api_key_encrypted"):
        raise HTTPException(status_code=400, detail="No API key stored")
    
    try:
        decrypted = decrypt_api_key(user_doc["claude_api_key_encrypted"])
        is_valid, message = await test_api_key(decrypted)
        
        return {
            "valid": is_valid,
            "message": message
        }
    except Exception as e:
        return {
            "valid": False,
            "message": f"Error testing key: {str(e)}"
        }
