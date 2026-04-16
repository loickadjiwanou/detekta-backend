from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Literal, Dict, Any, List
from datetime import datetime
import uuid

AuditType = Literal["web", "mobile", "backend", "api"]
AuditStatus = Literal["pending", "running", "completed", "failed"]
ScanDepth = Literal["quick", "standard", "deep"]

class AuditTarget(BaseModel):
    url: Optional[str] = None
    file_path: Optional[str] = None
    git_repo: Optional[str] = None
    api_endpoint: Optional[str] = None

class ScanConfig(BaseModel):
    depth: ScanDepth = "standard"
    include_ai_analysis: bool = True
    language: Literal["en", "fr"] = "en"

class AuditCreate(BaseModel):
    type: AuditType
    target: AuditTarget
    name: Optional[str] = None
    scan_config: Optional[ScanConfig] = None
    use_own_api_key: Optional[bool] = None

class AuditResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str
    user_id: str
    type: AuditType
    target: AuditTarget
    name: Optional[str] = None
    status: AuditStatus
    api_key_mode: Literal["own", "platform"]
    scan_config: ScanConfig
    error_message: Optional[str] = None
    is_archived: bool = False
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None

class AuditListItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str
    type: AuditType
    name: Optional[str] = None
    target_display: str
    status: AuditStatus
    is_archived: bool = False
    created_at: datetime
    completed_at: Optional[datetime] = None
    score: Optional[int] = None

class AuditInDB(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    type: AuditType
    name: Optional[str] = None
    target: AuditTarget
    status: AuditStatus = "pending"
    api_key_mode: Literal["own", "platform"] = "platform"
    scan_config: ScanConfig
    celery_task_id: Optional[str] = None
    error_message: Optional[str] = None
    is_archived: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now())
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    archived_at: Optional[datetime] = None
