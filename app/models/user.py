from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, Literal
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=100)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    marketing_emails: bool = False

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    avatar_url: Optional[str] = None
    preferred_language: Optional[Literal["en", "fr"]] = None
    marketing_emails: Optional[bool] = None

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str
    email: str
    full_name: str
    avatar_url: Optional[str] = None
    role: Literal["user", "admin"] = "user"
    total_audits: int = 0
    is_active: bool = True
    is_verified: bool = False
    preferred_language: Literal["en", "fr"] = "en"
    use_own_api_key: bool = False
    has_api_key: bool = False
    marketing_emails: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None

class UserInDB(UserBase):
    model_config = ConfigDict(extra="ignore")
    
    id: str
    password_hash: str
    role: Literal["user", "admin"] = "user"
    total_audits: int = 0
    is_active: bool = True
    is_verified: bool = False
    preferred_language: Literal["en", "fr"] = "en"
    claude_api_key_encrypted: Optional[str] = None
    use_own_api_key: bool = False
    marketing_emails: bool = False
    created_at: datetime
    updated_at: Optional[datetime] = None

class ApiKeyRequest(BaseModel):
    claude_api_key: str = Field(..., min_length=10)
    use_own: bool = True

class ApiKeyResponse(BaseModel):
    success: bool
    key_preview: str
    message: str

class ApiKeyStatus(BaseModel):
    has_key: bool
    use_own_api_key: bool
    key_preview: Optional[str] = None
