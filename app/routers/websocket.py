from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.audit_service import register_connection, unregister_connection
from app.database import get_database

router = APIRouter(prefix="/ws", tags=["WebSocket"])

@router.websocket("/audit/{audit_id}")
async def audit_websocket(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint for real-time audit updates."""
    await websocket.accept()
    
    db = get_database()
    
    # Register connection
    await register_connection(audit_id, websocket)
    
    try:
        # Check if audit exists and get initial status
        audit = await db.audits.find_one({"id": audit_id}, {"_id": 0, "status": 1})
        
        if audit:
            await websocket.send_json({
                "type": "connected",
                "audit_id": audit_id,
                "status": audit["status"]
            })
            
            # If already completed, send the report info
            if audit["status"] == "completed":
                report = await db.reports.find_one({"audit_id": audit_id}, {"_id": 0, "id": 1, "summary.overall_score": 1})
                if report:
                    await websocket.send_json({
                        "type": "completed",
                        "report_id": report["id"],
                        "score": report.get("summary", {}).get("overall_score")
                    })
        else:
            await websocket.send_json({
                "type": "error",
                "message": "Audit not found"
            })
        
        # Keep connection alive and listen for messages
        while True:
            try:
                data = await websocket.receive_text()
                # Handle ping/pong for keepalive
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break
            
    except WebSocketDisconnect:
        pass
    finally:
        unregister_connection(audit_id, websocket)
