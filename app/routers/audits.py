import asyncio
import aiofiles
import os
import uuid
import re
from fastapi import APIRouter, HTTPException, Request, UploadFile, File, BackgroundTasks
from datetime import datetime, timezone
from typing import List, Optional
from bson import ObjectId

from app.models.audit import AuditCreate, AuditResponse, AuditListItem, AuditInDB, AuditTarget, ScanConfig
from app.services.auth_service import get_current_user
from app.services.audit_service import run_audit_pipeline
from app.utils.validators import is_safe_target, is_valid_git_repo, is_valid_mobile_file
from app.database import get_database
from app.config import settings

router = APIRouter(prefix="/audits", tags=["Audits"])

def get_db():
    return get_database()

@router.get("/validate-name")
async def validate_audit_name(
    request: Request,
    name: str,
    type: str
):
    """Validate if an audit name is unique for a given type."""
    db = get_db()
    user = await get_current_user(request, db)
    
    existing_audit = await db.audits.find_one({
        "user_id": user["id"],
        "type": type,
        "name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}
    })
    
    if existing_audit:
        raise HTTPException(
            status_code=400, 
            detail=f"An audit with the name '{name}' already exists for type '{type}'"
        )
    
    return {"valid": True}

@router.get("/", response_model=List[AuditListItem])
async def list_audits(
    request: Request,
    status: Optional[str] = None,
    type: Optional[str] = None,
    archived: Optional[bool] = False,
    limit: int = 20,
    skip: int = 0
):
    """List user's audits."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Build query
    query = {"user_id": user["id"]}
    if status:
        query["status"] = status
    if type:
        query["type"] = type
    
    # Filter by archived status
    query["is_archived"] = archived if archived else {"$ne": True}
    
    # Fetch audits
    cursor = db.audits.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    audits = await cursor.to_list(limit)
    
    # Fetch scores from reports
    result = []
    for audit in audits:
        # Determine target display
        target = audit.get("target", {})
        file_path = target.get("file_path")
        target_display = target.get("url") or target.get("git_repo") or target.get("api_endpoint") or (os.path.basename(file_path) if file_path else None) or "Unknown"
        
        # Get score if completed
        score = None
        if audit["status"] == "completed":
            report = await db.reports.find_one({"audit_id": audit["id"]}, {"_id": 0, "summary.overall_score": 1})
            if report:
                score = report.get("summary", {}).get("overall_score")
        
        result.append(AuditListItem(
            id=audit["id"],
            type=audit["type"],
            name=audit.get("name"),
            target_display=target_display,
            status=audit["status"],
            is_archived=audit.get("is_archived", False),
            created_at=audit["created_at"] if isinstance(audit["created_at"], datetime) else datetime.fromisoformat(audit["created_at"]),
            completed_at=audit.get("completed_at"),
            score=score
        ))
    
    return result

@router.post("/", response_model=AuditResponse)
async def create_audit(
    request: Request,
    audit_data: AuditCreate,
    background_tasks: BackgroundTasks
):
    """Create a new audit."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Check for duplicate name for the same type (case-insensitive) if name is provided
    if audit_data.name:
        existing_audit = await db.audits.find_one({
            "user_id": user["id"],
            "type": audit_data.type,
            "name": {"$regex": f"^{re.escape(audit_data.name)}$", "$options": "i"}
        })
        
        if existing_audit:
            raise HTTPException(
                status_code=400, 
                detail=f"An audit with the name '{audit_data.name}' already exists for type '{audit_data.type}'"
            )
    
    # Validate target based on type
    target = audit_data.target
    
    if audit_data.type == "web":
        if not target.url:
            raise HTTPException(status_code=400, detail="URL is required for web audit")
        is_safe, message = is_safe_target(target.url)
        if not is_safe:
            raise HTTPException(status_code=400, detail=message)
    
    elif audit_data.type == "api":
        if not target.api_endpoint:
            raise HTTPException(status_code=400, detail="API endpoint is required for API audit")
        is_safe, message = is_safe_target(target.api_endpoint)
        if not is_safe:
            raise HTTPException(status_code=400, detail=message)
    
    elif audit_data.type == "backend":
        if not target.git_repo:
            raise HTTPException(status_code=400, detail="Git repository URL is required for backend audit")
        if not is_valid_git_repo(target.git_repo):
            raise HTTPException(status_code=400, detail="Invalid Git repository URL")
    
    elif audit_data.type == "mobile":
        if not target.file_path:
            raise HTTPException(status_code=400, detail="File path is required for mobile audit. Use /audits/upload first.")
    
    # Determine API key mode
    user_doc = await db.users.find_one({"_id": ObjectId(user["id"])})
    
    if audit_data.use_own_api_key is not None:
        api_key_mode = "own" if audit_data.use_own_api_key else "platform"
    else:
        api_key_mode = "own" if user_doc.get("use_own_api_key") and user_doc.get("claude_api_key_encrypted") else "platform"
    
    # Create audit document
    now = datetime.now(timezone.utc)
    scan_config = audit_data.scan_config or ScanConfig()
    
    audit = AuditInDB(
        id=str(uuid.uuid4()),
        user_id=user["id"],
        type=audit_data.type,
        name=audit_data.name,
        target=target,
        status="pending",
        api_key_mode=api_key_mode,
        scan_config=scan_config,
        created_at=now
    )
    
    # Save to database
    audit_dict = audit.model_dump()
    audit_dict["created_at"] = audit_dict["created_at"].isoformat()
    await db.audits.insert_one(audit_dict)
    
    # Start audit in background
    background_tasks.add_task(run_audit_pipeline, audit.id, db)
    
    return AuditResponse(
        id=audit.id,
        user_id=user["id"],
        type=audit.type,
        target=target,
        status="pending",
        api_key_mode=api_key_mode,
        scan_config=scan_config,
        created_at=now
    )

@router.post("/upload")
async def upload_mobile_file(
    request: Request,
    file: UploadFile = File(...)
):
    """Upload APK/IPA file for mobile audit."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Validate file
    if not file.filename or not is_valid_mobile_file(file.filename):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only APK, IPA, and AAB files are allowed."
        )
    
    # Check file size
    content = await file.read()
    max_size = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    
    if len(content) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB."
        )
    
    # Save file with original name and timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    original_name = file.filename or "upload.apk"
    base_name, extension = os.path.splitext(original_name)
    
    # Sanitize name: remove non-alphanumeric (except dashes/underscores) and replace spaces
    safe_base_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', base_name)
    new_filename = f"{safe_base_name}_{timestamp}{extension}"
    
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(settings.UPLOAD_DIR, new_filename)
    
    async with aiofiles.open(file_path, "wb") as f:
        await f.write(content)
    
    return {
        "file_path": file_path,
        "filename": file.filename,
        "size_bytes": len(content)
    }

@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(request: Request, audit_id: str):
    """Get audit details."""
    db = get_db()
    user = await get_current_user(request, db)
    
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]}, {"_id": 0})
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    return AuditResponse(
        id=audit["id"],
        user_id=audit["user_id"],
        type=audit["type"],
        target=AuditTarget(**audit["target"]),
        status=audit["status"],
        api_key_mode=audit.get("api_key_mode", "platform"),
        scan_config=ScanConfig(**audit.get("scan_config", {})),
        error_message=audit.get("error_message"),
        is_archived=audit.get("is_archived", False),
        created_at=audit["created_at"] if isinstance(audit["created_at"], datetime) else datetime.fromisoformat(audit["created_at"]),
        started_at=audit.get("started_at"),
        completed_at=audit.get("completed_at"),
        archived_at=audit.get("archived_at"),
        name=audit.get("name")
    )

@router.post("/{audit_id}/archive")
async def archive_audit(request: Request, audit_id: str):
    """Archive an audit."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Check ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Can't archive running audits
    if audit["status"] == "running":
        raise HTTPException(status_code=400, detail="Cannot archive a running audit")
    
    # Archive the audit
    await db.audits.update_one(
        {"id": audit_id},
        {"$set": {
            "is_archived": True,
            "archived_at": datetime.now(timezone.utc)
        }}
    )
    
    return {"message": "Audit archived successfully"}

@router.post("/{audit_id}/unarchive")
async def unarchive_audit(request: Request, audit_id: str):
    """Restore an archived audit."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Check ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Unarchive the audit
    await db.audits.update_one(
        {"id": audit_id},
        {"$set": {
            "is_archived": False,
            "archived_at": None
        }}
    )
    
    return {"message": "Audit restored successfully"}

@router.delete("/{audit_id}")
async def delete_audit(request: Request, audit_id: str):
    """Delete an audit. Only archived audits can be deleted."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Check ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Can't delete running audits
    if audit["status"] == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running audit")
    
    # Can only delete archived audits
    if not audit.get("is_archived", False):
        raise HTTPException(status_code=400, detail="Only archived audits can be deleted. Please archive the audit first.")
    
    # Delete audit and associated report
    await db.audits.delete_one({"id": audit_id})
    await db.reports.delete_one({"audit_id": audit_id})
    
    return {"message": "Audit deleted successfully"}
