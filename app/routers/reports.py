from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from datetime import datetime
from typing import Optional
from bson import ObjectId
import io

from app.models.report import ReportResponse, Finding, ReportSummary, AIAnalysis, ReportMetadata
from app.services.auth_service import get_current_user
from app.services.pdf_service import generate_pdf_report
from app.database import get_database

router = APIRouter(prefix="/reports", tags=["Reports"])

def get_db():
    return get_database()

@router.get("/{audit_id}", response_model=ReportResponse)
async def get_report(request: Request, audit_id: str):
    """Get report for an audit."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Verify audit ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]}, {"_id": 0})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Get report
    report = await db.reports.find_one({"audit_id": audit_id}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Parse findings
    findings = [Finding(**f) for f in report.get("findings", [])]
    
    return ReportResponse(
        id=report["id"],
        audit_id=report["audit_id"],
        user_id=report["user_id"],
        summary=ReportSummary(**report["summary"]),
        findings=findings,
        ai_analysis=AIAnalysis(**report["ai_analysis"]) if report.get("ai_analysis") else None,
        metadata=ReportMetadata(**report["metadata"]),
        generated_at=report["generated_at"] if isinstance(report["generated_at"], datetime) else datetime.fromisoformat(report["generated_at"])
    )

@router.get("/{audit_id}/download/html", response_class=HTMLResponse)
async def download_report_html(request: Request, audit_id: str, theme: str = "dark"):
    """Download report as HTML."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Verify audit ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]}, {"_id": 0})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    report = await db.reports.find_one({"audit_id": audit_id}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Generate HTML report
    html = generate_html_report(report, audit, theme)
    
    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="detekta-report-{audit_id}.html"'
        }
    )

@router.get("/{audit_id}/download/pdf")
async def download_report_pdf(request: Request, audit_id: str, theme: str = "dark"):
    """Download report as PDF."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Verify audit ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]}, {"_id": 0})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    report = await db.reports.find_one({"audit_id": audit_id}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Generate PDF report
    try:
        pdf_bytes = generate_pdf_report(report, audit, theme)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="detekta-report-{audit_id}.pdf"'
            }
        )
    except Exception as e:
        # Fallback to HTML if PDF generation fails
        html = generate_html_report(report, audit, theme)
        return StreamingResponse(
            io.BytesIO(html.encode()),
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="detekta-report-{audit_id}.html"'
            }
        )

@router.get("/{audit_id}/download/mobsf")
async def download_mobsf_report(request: Request, audit_id: str):
    """Download the original MobSF PDF report."""
    db = get_db()
    user = await get_current_user(request, db)
    
    # Verify audit ownership
    audit = await db.audits.find_one({"id": audit_id, "user_id": user["id"]}, {"_id": 0})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Get report
    report = await db.reports.find_one({"audit_id": audit_id}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    metadata = report.get("metadata", {})
    mobsf_hash = metadata.get("mobsf_hash")
    
    if not mobsf_hash:
        raise HTTPException(status_code=400, detail="No MobSF report available for this audit")
    
    from app.services.mobsf_service import MobSFService
    mobsf_service = MobSFService()
    
    pdf_content = await mobsf_service.download_pdf(mobsf_hash)
    if not pdf_content:
        raise HTTPException(status_code=500, detail="Failed to download report from MobSF")
    
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="mobsf-report-{audit_id}.pdf"'
        }
    )

def generate_html_report(report: dict, audit: dict, theme: str = "dark") -> str:
    """Generate HTML report from report data."""
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    ai_analysis = report.get("ai_analysis", {})
    metadata = report.get("metadata", {})
    
    # Determine target
    target = audit.get("target", {})
    target_display = target.get("url") or target.get("git_repo") or target.get("api_endpoint") or target.get("file_path") or "Unknown"
    
    # Risk level colors
    risk_colors = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#84CC16",
        "secure": "#22C55E"
    }
    
    severity_colors = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#84CC16",
        "info": "#3B82F6"
    }
    
    findings_html = ""
    for f in findings:
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity" style="background-color: {severity_colors.get(f.get('severity', 'info'), '#3B82F6')}">{f.get('severity', 'info').upper()}</span>
                <h3>{f.get('title', 'Unknown Finding')}</h3>
            </div>
            <p><strong>Category:</strong> {f.get('category', 'N/A')}</p>
            <p><strong>Affected Component:</strong> {f.get('affected_component', 'N/A')}</p>
            <p><strong>Description:</strong> {f.get('description', 'N/A')}</p>
            {f'<p><strong>CVSS Score:</strong> {f.get("cvss_score")}</p>' if f.get('cvss_score') else ''}
            {f'<p><strong>Recommendation:</strong> {f.get("recommendation")}</p>' if f.get('recommendation') else ''}
        </div>
        """
    
    # Theme colors
    is_dark = theme == "dark"
    bg_color = "#0D0F14" if is_dark else "#FFFFFF"
    text_color = "#FFFFFF" if is_dark else "#09090B"
    card_bg = "#13161D" if is_dark else "#F9FAFB"
    border_color = "rgba(255,255,255,0.05)" if is_dark else "#E4E4E7"
    muted_text = "#888888" if is_dark else "#71717A"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detekta Security Report - {audit.get('id', 'Unknown')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: {bg_color};
            color: {text_color};
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid {border_color};
        }}
        .logo {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #3B82F6;
            letter-spacing: -2px;
        }}
        .score {{
            font-size: 4rem;
            font-weight: bold;
            color: {risk_colors.get(summary.get('risk_level', 'medium'), '#EAB308')};
            margin: 20px 0;
        }}
        .risk-level {{
            display: inline-block;
            padding: 8px 20px;
            background: {risk_colors.get(summary.get('risk_level', 'medium'), '#EAB308')};
            color: #000;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .section {{
            margin: 40px 0;
            padding: 30px;
            background: {card_bg};
            border-radius: 8px;
            border: 1px solid {border_color};
        }}
        .section h2 {{
            color: #06B6D4;
            margin-top: 0;
            border-bottom: 1px solid {border_color};
            padding-bottom: 10px;
        }}
        .finding {{
            background: {bg_color};
            padding: 20px;
            margin: 15px 0;
            border-radius: 6px;
            border: 1px solid {border_color};
            border-left: 4px solid #3B82F6;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }}
        .finding h3 {{
            margin: 0;
            color: {text_color};
        }}
        .severity {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            color: #000;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat {{
            text-align: center;
            padding: 20px;
            background: {bg_color};
            border: 1px solid {border_color};
            border-radius: 8px;
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .stat-label {{
            color: {muted_text};
            font-size: 0.875rem;
        }}
        .meta {{
            color: {muted_text};
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">DETEKTA</div>
            <p class="meta">Security Audit Report</p>
            <div class="score">{summary.get('overall_score', 0)}/100</div>
            <span class="risk-level">{summary.get('risk_level', 'unknown')} Risk</span>
            <p class="meta">Generated: {report.get('generated_at', 'N/A')}</p>
        </div>
        
        <div class="section">
            <h2>Audit Details</h2>
            <p><strong>Target:</strong> {target_display}</p>
            <p><strong>Type:</strong> {audit.get('type', 'unknown').upper()}</p>
            <p><strong>Duration:</strong> {metadata.get('scan_duration_seconds', 0)} seconds</p>
            <p><strong>Tools:</strong> {', '.join(metadata.get('tools_used', []))}</p>
        </div>
        
        <div class="section">
            <h2>Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" style="color: #EF4444">{summary.get('critical_count', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #F97316">{summary.get('high_count', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #EAB308">{summary.get('medium_count', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-value" style="color: #84CC16">{summary.get('low_count', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            <p>{summary.get('executive_summary', 'No summary available.')}</p>
        </div>
        
        <div class="section">
            <h2>Findings ({len(findings)})</h2>
            {findings_html if findings_html else '<p>No findings detected.</p>'}
        </div>
        
        {f'''
        <div class="section">
            <h2>AI Analysis</h2>
            <p><strong>Risk Narrative:</strong> {ai_analysis.get('risk_narrative', 'N/A')}</p>
            <h3>Priority Actions</h3>
            <ul>{''.join(f'<li>{action}</li>' for action in ai_analysis.get('priority_actions', []))}</ul>
            <h3>Quick Wins</h3>
            <ul>{''.join(f'<li>{win}</li>' for win in ai_analysis.get('quick_wins', []))}</ul>
        </div>
        ''' if ai_analysis else ''}
        
        <div class="meta" style="text-align: center; padding: 40px 0; border-top: 1px solid {border_color}; margin-top: 40px;">
            <p>This report was generated by Detekta - Automated Security Audit Platform</p>
            <p>© 2026 Detekta. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
    """
    
    return html
