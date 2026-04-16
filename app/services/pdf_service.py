import io
import html
from datetime import datetime
from typing import Dict, Any, List
from weasyprint import HTML, CSS
import logging

logger = logging.getLogger(__name__)

def generate_pdf_report(report: Dict, audit: Dict, theme: str = "dark") -> bytes:
    """Generate a PDF report from report data."""
    
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
    
    score_color = risk_colors.get(summary.get('risk_level', 'medium'), '#EAB308')
    
    # Generate findings HTML
    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev_color = severity_colors.get(f.get('severity', 'info'), '#3B82F6')
        
        # Escape content for safety and to prevent HTML breakage
        safe_title = html.escape(str(f.get('title', 'Unknown Finding')))
        safe_category = html.escape(str(f.get('category', 'N/A')))
        safe_affected = html.escape(str(f.get('affected_component', 'N/A')))
        safe_description = html.escape(str(f.get('description', 'N/A')))
        safe_recommendation = html.escape(str(f.get('recommendation', '')))
        safe_code_fix = html.escape(str(f.get('code_fix', '')))
        safe_evidence = html.escape(str(f.get('evidence', '')))
        
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="finding-number">#{i}</span>
                <span class="severity" style="background-color: {sev_color}">{f.get('severity', 'info').upper()}</span>
                <span class="finding-title">{safe_title}</span>
            </div>
            <table class="finding-details">
                <tr>
                    <td class="label">Category:</td>
                    <td>{safe_category}</td>
                </tr>
                <tr>
                    <td class="label">Affected:</td>
                    <td><code>{safe_affected}</code></td>
                </tr>
                <tr>
                    <td class="label">Description:</td>
                    <td>{safe_description}</td>
                </tr>
                {'<tr><td class="label">CVSS Score:</td><td><strong>' + str(f.get("cvss_score")) + '</strong></td></tr>' if f.get('cvss_score') else ''}
                {f'<tr><td class="label">Evidence:</td><td><code>{safe_evidence}</code></td></tr>' if safe_evidence else ''}
            </table>
            {f'<div class="recommendation"><strong>Recommendation:</strong> {safe_recommendation}</div>' if safe_recommendation else ''}
            {f'<div class="code-fix"><strong>Code Fix:</strong><pre>{safe_code_fix}</pre></div>' if safe_code_fix else ''}
        </div>
        """
    
    # AI Analysis section
    ai_section = ""
    if ai_analysis:
        priority_items = ''.join(f'<li>{html.escape(action)}</li>' for action in ai_analysis.get('priority_actions', []))
        quick_wins = ''.join(f'<li>{html.escape(win)}</li>' for win in ai_analysis.get('quick_wins', []))
        long_term = ''.join(f'<li>{html.escape(rec)}</li>' for rec in ai_analysis.get('long_term_recommendations', []))
        
        safe_risk_narrative = html.escape(str(ai_analysis.get('risk_narrative', '')))
        
        ai_section = f"""
        <div class="section">
            <h2>AI Analysis</h2>
            <p class="risk-narrative">{safe_risk_narrative}</p>
            
            <h3>Priority Actions</h3>
            <ol class="action-list priority">{priority_items}</ol>
            
            <h3>Quick Wins</h3>
            <ul class="action-list quick-wins">{quick_wins}</ul>
            
            <h3>Long-term Recommendations</h3>
            <ul class="action-list long-term">{long_term}</ul>
        </div>
        """
    
    # Theme colors
    is_dark = theme == "dark"
    bg_color = "#0D0F14" if is_dark else "#FFFFFF"
    text_color = "#FFFFFF" if is_dark else "#09090B"
    card_bg = "#13161D" if is_dark else "#F9FAFB"
    border_color = "rgba(255,255,255,0.05)" if is_dark else "#E4E4E7"
    muted_text = "#888888" if is_dark else "#71717A"
    
    # Full HTML template
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Detekta Security Report</title>
        <style>
            @page {{
                size: A4;
                margin: 2cm;
                background-color: {bg_color};
                @top-right {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 9pt;
                    color: {muted_text};
                }}
            }}
            
            * {{
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Helvetica Neue', Arial, sans-serif;
                font-size: 10pt;
                line-height: 1.5;
                color: {text_color};
                background-color: {bg_color};
                margin: 0;
                padding: 0;
            }}
            
            .header {{
                background: {bg_color};
                color: {text_color};
                padding: 30px;
                margin: -2cm -2cm 20px -2cm;
                text-align: center;
                border-bottom: 1px solid {border_color};
            }}
            
            .logo {{
                font-size: 28pt;
                font-weight: bold;
                letter-spacing: -1px;
                margin-bottom: 5px;
                color: {text_color};
            }}
            
            .logo-accent {{
                color: #06B6D4;
            }}
            
            .tagline {{
                font-size: 10pt;
                color: {muted_text};
                margin-bottom: 20px;
            }}
            
            .score-container {{
                display: inline-block;
                background: {card_bg};
                border: 1px solid {border_color};
                border-radius: 10px;
                padding: 20px 40px;
                margin-top: 10px;
            }}
            
            .score {{
                font-size: 48pt;
                font-weight: bold;
                color: {score_color};
            }}
            
            .score-label {{
                font-size: 12pt;
                color: {muted_text};
            }}
            
            .risk-badge {{
                display: inline-block;
                padding: 5px 20px;
                background: {score_color};
                color: #000;
                border-radius: 20px;
                font-weight: bold;
                text-transform: uppercase;
                font-size: 10pt;
                margin-top: 10px;
            }}
            
            .meta-info {{
                margin-top: 20px;
                font-size: 9pt;
                color: {muted_text};
            }}
            
            .section {{
                margin: 20px 0;
            }}
            
            h2 {{
                color: {text_color};
                font-size: 14pt;
                border-bottom: 2px solid #06B6D4;
                padding-bottom: 5px;
                margin-bottom: 15px;
            }}
            
            h3 {{
                color: {text_color};
                font-size: 11pt;
                margin: 15px 0 10px 0;
            }}
            
            .summary-stats {{
                display: table;
                width: 100%;
                margin: 20px 0;
                border-collapse: collapse;
            }}
            
            .stat-box {{
                display: table-cell;
                width: 20%;
                text-align: center;
                padding: 15px;
                border: 1px solid {border_color};
            }}
            
            .stat-value {{
                font-size: 24pt;
                font-weight: bold;
            }}
            
            .stat-label {{
                font-size: 8pt;
                color: {muted_text};
                text-transform: uppercase;
            }}
            
            .stat-critical .stat-value {{ color: #EF4444; }}
            .stat-high .stat-value {{ color: #F97316; }}
            .stat-medium .stat-value {{ color: #EAB308; }}
            .stat-low .stat-value {{ color: #84CC16; }}
            .stat-info .stat-value {{ color: #3B82F6; }}
            
            .finding {{
                background: {card_bg};
                border: 1px solid {border_color};
                border-radius: 5px;
                margin: 15px 0;
                padding: 15px;
                page-break-inside: avoid;
            }}
            
            .finding-header {{
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 10px;
            }}
            
            .finding-number {{
                background: #333;
                color: white;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 9pt;
            }}
            
            .severity {{
                padding: 2px 10px;
                border-radius: 3px;
                font-size: 8pt;
                font-weight: bold;
                color: white;
            }}
            
            .finding-title {{
                font-weight: bold;
                font-size: 11pt;
                color: {text_color};
            }}
            
            .finding-details {{
                width: 100%;
                font-size: 9pt;
                margin: 10px 0;
            }}
            
            .finding-details td {{
                padding: 3px 0;
                vertical-align: top;
            }}
            
            .finding-details .label {{
                width: 100px;
                color: {muted_text};
                font-weight: bold;
            }}
            
            .recommendation {{
                background: {'rgba(6, 182, 212, 0.1)' if theme == 'dark' else '#f0f9ff'};
                border-left: 3px solid #06B6D4;
                padding: 10px;
                margin-top: 10px;
                font-size: 9pt;
                color: {text_color};
            }}
            
            .code-fix {{
                margin-top: 10px;
            }}
            
            .code-fix pre {{
                background: #1a1d24;
                color: #84CC16;
                padding: 10px;
                border-radius: 3px;
                font-size: 8pt;
                overflow-x: auto;
                white-space: pre-wrap;
            }}
            
            code {{
                background: {card_bg};
                border: 1px solid {border_color};
                padding: 1px 5px;
                border-radius: 3px;
                font-size: 9pt;
                color: {text_color};
            }}
            
            .executive-summary {{
                background: {card_bg};
                border: 1px solid {border_color};
                padding: 15px;
                border-radius: 5px;
                margin: 15px 0;
            }}
            
            .risk-narrative {{
                font-style: italic;
                color: {muted_text};
                margin-bottom: 15px;
            }}
            
            .action-list {{
                margin: 10px 0;
                padding-left: 25px;
            }}
            
            .action-list li {{
                margin: 5px 0;
            }}
            
            .action-list.priority li {{
                color: #dc2626;
            }}
            
            .footer {{
                margin-top: 30px;
                padding-top: 15px;
                border-top: 1px solid {border_color};
                text-align: center;
                font-size: 8pt;
                color: {muted_text};
            }}
            
            .no-findings {{
                text-align: center;
                padding: 40px;
                background: {'rgba(34, 197, 94, 0.1)' if theme == 'dark' else '#f0fdf4'};
                border: 1px solid {'rgba(34, 197, 94, 0.2)' if theme == 'dark' else '#86efac'};
                border-radius: 5px;
            }}
            
            .no-findings h3 {{
                color: #22c55e;
                margin: 0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="logo">DETE<span class="logo-accent">KTA</span></div>
            <div class="tagline">See every flaw. Fix every risk.</div>
            <div class="score-container">
                <div class="score">{summary.get('overall_score', 0)}</div>
                <div class="score-label">Security Score</div>
            </div>
            <div class="risk-badge">{summary.get('risk_level', 'unknown').upper()} RISK</div>
            <div class="meta-info">
                Target: {target_display}<br>
                Generated: {report.get('generated_at', datetime.now().isoformat())}<br>
                Scan Duration: {metadata.get('scan_duration_seconds', 0)}s | Tools: {', '.join(metadata.get('tools_used', []))}
            </div>
        </div>
        
        <div class="section">
            <h2>Summary</h2>
            <div class="summary-stats">
                <div class="stat-box stat-critical">
                    <div class="stat-value">{summary.get('critical_count', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box stat-high">
                    <div class="stat-value">{summary.get('high_count', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-box stat-medium">
                    <div class="stat-value">{summary.get('medium_count', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-box stat-low">
                    <div class="stat-value">{summary.get('low_count', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-box stat-info">
                    <div class="stat-value">{summary.get('info_count', 0)}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            
            <div class="executive-summary">
                <h3>Executive Summary</h3>
                <p>{html.escape(str(summary.get('executive_summary', 'No summary available.')))}</p>
            </div>
            
            <h3>Technical Summary</h3>
            <p>{html.escape(str(summary.get('technical_summary', 'No technical summary available.')))}</p>
        </div>
        
        <div class="section">
            <h2>Findings ({len(findings)})</h2>
            {findings_html if findings else '<div class="no-findings"><h3>No vulnerabilities found</h3><p>Great job! No security issues were detected.</p></div>'}
        </div>
        
        {ai_section}
        
        <div class="footer">
            <p>This report was generated by Detekta - Automated Security Audit Platform</p>
            <p>© 2026 Detekta. All rights reserved.</p>
        </div>
    </body>
    </html>
    """
    
    # Generate PDF
    try:
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise
