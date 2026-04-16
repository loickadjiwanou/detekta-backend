import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from bson import ObjectId

from app.models.audit import AuditInDB, AuditTarget, ScanConfig
from app.models.report import ReportInDB, ReportSummary, Finding, ReportMetadata
from app.services.scanner_service import run_simulated_scan, run_hybrid_scan, calculate_score, get_risk_level
from app.services.ai_service import analyze_findings
from app.utils.crypto import decrypt_api_key

logger = logging.getLogger(__name__)

# Store active WebSocket connections per audit
active_connections: Dict[str, List[Any]] = {}
# Temporary cache for logs during active scans to allow new connections to catch up
audit_logs_cache: Dict[str, List[dict]] = {}

async def register_connection(audit_id: str, websocket):
    """Register a WebSocket connection for an audit."""
    
    # If there are cached logs, replay them for the new connection FIRST
    if audit_id in audit_logs_cache:
        for message in audit_logs_cache[audit_id]:
            try:
                await websocket.send_json(message)
            except Exception:
                pass

    # ONLY THEN add to active connections to receive future broadcasts
    if websocket not in active_connections.get(audit_id, []):
        if audit_id not in active_connections:
            active_connections[audit_id] = []
        active_connections[audit_id].append(websocket)

def unregister_connection(audit_id: str, websocket):
    """Unregister a WebSocket connection."""
    if audit_id in active_connections:
        active_connections[audit_id] = [
            ws for ws in active_connections[audit_id] if ws != websocket
        ]

async def broadcast_to_audit(audit_id: str, message: dict):
    """Broadcast a message to all connections for an audit and cache logs."""
    # Cache log messages for new connections
    if message.get("type") in ["log", "progress", "test_result"]:
        if audit_id not in audit_logs_cache:
            audit_logs_cache[audit_id] = []
        audit_logs_cache[audit_id].append(message)

    if audit_id not in active_connections:
        return
    
    dead_connections = []
    for ws in active_connections[audit_id]:
        try:
            await ws.send_json(message)
        except Exception:
            dead_connections.append(ws)
    
    # Clean up dead connections
    for ws in dead_connections:
        unregister_connection(audit_id, ws)

async def run_audit_pipeline(audit_id: str, db):
    """
    Main audit pipeline that runs the scan and generates report.
    """
    try:
        # Get audit from database
        audit_doc = await db.audits.find_one({"id": audit_id})
        if not audit_doc:
            logger.error(f"Audit {audit_id} not found")
            return
        
        audit_doc.pop("_id", None)
        
        # Update status to running
        await db.audits.update_one(
            {"id": audit_id},
            {"$set": {
                "status": "running",
                "started_at": datetime.now(timezone.utc)
            }}
        )
        
        await broadcast_to_audit(audit_id, {
            "type": "log",
            "message": f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Audit started",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        # Determine target for display and for scanning
        target_data = audit_doc.get("target", {})
        file_path = target_data.get("file_path")
        
        # For Logs and UI display
        target_display = target_data.get("url") or target_data.get("git_repo") or target_data.get("api_endpoint") or (os.path.basename(file_path) if file_path else None) or "Unknown"
        
        # For the real scanner (absolute path/URL needed)
        scan_target = target_data.get("url") or target_data.get("git_repo") or target_data.get("api_endpoint") or file_path or "Unknown"
        
        # Get scan config
        scan_config = audit_doc.get("scan_config", {})
        depth = scan_config.get("depth", "standard")
        include_ai = scan_config.get("include_ai_analysis", True)
        language = scan_config.get("language", "en")
        
        # Progress callback
        async def progress_callback(msg_type: str, data):
            if msg_type == "log":
                await broadcast_to_audit(audit_id, {
                    "type": "log",
                    "message": data,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif msg_type == "progress":
                await broadcast_to_audit(audit_id, {
                    "type": "progress",
                    "percent": data["percent"],
                    "current_step": data["current_step"]
                })
            elif msg_type == "test_result":
                await broadcast_to_audit(audit_id, {
                    "type": "test_result",
                    "name": data["name"],
                    "status": data["status"],
                    "message": data["message"]
                })
        
        # Run scan - use scan_target for real security checks
        findings, logs, duration, mobsf_hash = await run_hybrid_scan(
            audit_type=audit_doc["type"],
            target=scan_target,
            depth=depth,
            progress_callback=progress_callback
        )
        
        # AI Analysis if enabled
        ai_analysis = None
        if include_ai:
            await broadcast_to_audit(audit_id, {
                "type": "log",
                "message": f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Running AI analysis...",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
            # Get user's API key if using own
            user_api_key = None
            if audit_doc.get("api_key_mode") == "own":
                user_doc = await db.users.find_one({"_id": ObjectId(audit_doc["user_id"])})
                if user_doc and user_doc.get("claude_api_key_encrypted"):
                    try:
                        user_api_key = decrypt_api_key(user_doc["claude_api_key_encrypted"])
                    except Exception as e:
                        logger.error(f"Failed to decrypt user API key: {e}")
            
            ai_analysis = await analyze_findings(
                findings=findings,
                audit_type=audit_doc["type"],
                target=target_display,
                language=language,
                use_own_key=(audit_doc.get("api_key_mode") == "own"),
                user_api_key=user_api_key
            )
            
            if ai_analysis:
                await broadcast_to_audit(audit_id, {
                    "type": "log",
                    "message": f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] AI analysis completed",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        
        # Calculate score
        score = calculate_score(findings)
        risk_level = get_risk_level(score)
        
        # Count findings by severity
        severity_counts = {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
            "info": sum(1 for f in findings if f.severity == "info")
        }
        
        # Create report
        report = ReportInDB(
            audit_id=audit_id,
            user_id=audit_doc["user_id"],
            summary=ReportSummary(
                overall_score=score,
                risk_level=risk_level,
                total_findings=len(findings),
                critical_count=severity_counts["critical"],
                high_count=severity_counts["high"],
                medium_count=severity_counts["medium"],
                low_count=severity_counts["low"],
                info_count=severity_counts["info"],
                executive_summary=ai_analysis.risk_narrative if ai_analysis else f"Security audit completed with {len(findings)} findings.",
                technical_summary=f"Scan identified {severity_counts['critical']} critical, {severity_counts['high']} high, {severity_counts['medium']} medium, {severity_counts['low']} low, and {severity_counts['info']} info severity issues."
            ),
            findings=[f.model_dump() for f in findings],
            ai_analysis=ai_analysis.model_dump() if ai_analysis else None,
            raw_scan_output="\n".join(logs),
            metadata=ReportMetadata(
                scan_duration_seconds=duration,
                tools_used=["Detekta Core", "Claude AI"] if ai_analysis else ["Detekta Core"],
                scan_depth=depth,
                language=language,
                mobsf_hash=mobsf_hash
            ),
            generated_at=datetime.now(timezone.utc)
        )
        
        # Save report
        report_dict = report.model_dump()
        report_dict["generated_at"] = report_dict["generated_at"].isoformat()
        await db.reports.insert_one(report_dict)
        
        # Update audit status
        await db.audits.update_one(
            {"id": audit_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc)
            }}
        )
        
        # Increment user's audit count
        await db.users.update_one(
            {"_id": ObjectId(audit_doc["user_id"])},
            {"$inc": {"total_audits": 1}}
        )
        
        # Broadcast completion
        await broadcast_to_audit(audit_id, {
            "type": "completed",
            "report_id": report.id,
            "score": score
        })
        
        # Cleanup log cache after successful completion
        if audit_id in audit_logs_cache:
            del audit_logs_cache[audit_id]
            
        logger.info(f"Audit {audit_id} completed with score {score}")
        
    except Exception as e:
        logger.error(f"Audit {audit_id} failed: {e}")
        
        # Update audit status to failed
        await db.audits.update_one(
            {"id": audit_id},
            {"$set": {
                "status": "failed",
                "error_message": str(e)
            }}
        )
        
        # Broadcast error
        await broadcast_to_audit(audit_id, {
            "type": "error",
            "message": str(e)
        })
        
        # Cleanup log cache after failure
        if audit_id in audit_logs_cache:
            del audit_logs_cache[audit_id]
