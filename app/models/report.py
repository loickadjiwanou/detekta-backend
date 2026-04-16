from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Literal
from datetime import datetime
import uuid

Severity = Literal["critical", "high", "medium", "low", "info"]
RiskLevel = Literal["critical", "high", "medium", "low", "secure"]

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    category: str
    description: str
    affected_component: str
    evidence: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_ids: Optional[List[str]] = None
    recommendation: Optional[str] = None
    code_fix: Optional[str] = None
    references: Optional[List[str]] = None

class ReportSummary(BaseModel):
    overall_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    executive_summary: str
    technical_summary: str

class AIAnalysis(BaseModel):
    model_used: str
    api_key_mode: Literal["own", "platform"]
    risk_narrative: str
    priority_actions: List[str]
    quick_wins: List[str]
    long_term_recommendations: List[str]

class ReportMetadata(BaseModel):
    scan_duration_seconds: int
    tools_used: List[str]
    scan_depth: str
    language: str
    mobsf_hash: Optional[str] = None

class ReportCreate(BaseModel):
    audit_id: str
    user_id: str
    summary: ReportSummary
    findings: List[Finding]
    ai_analysis: Optional[AIAnalysis] = None
    raw_scan_output: Optional[str] = None
    metadata: ReportMetadata

class ReportResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str
    audit_id: str
    user_id: str
    summary: ReportSummary
    findings: List[Finding]
    ai_analysis: Optional[AIAnalysis] = None
    metadata: ReportMetadata
    generated_at: datetime

class ReportInDB(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_id: str
    user_id: str
    summary: ReportSummary
    findings: List[Finding]
    ai_analysis: Optional[AIAnalysis] = None
    raw_scan_output: Optional[str] = None
    metadata: ReportMetadata
    generated_at: datetime = Field(default_factory=lambda: datetime.now())
