from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Literal
from datetime import datetime
import uuid

class UsageLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    audit_id: Optional[str] = None
    action: str
    api_key_mode: Literal["own", "platform"]
    tokens_consumed: int = 0
    cost_usd: float = 0.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now())

class UsageLogCreate(BaseModel):
    user_id: str
    audit_id: Optional[str] = None
    action: str
    api_key_mode: Literal["own", "platform"]
    tokens_consumed: int = 0
    cost_usd: float = 0.0
