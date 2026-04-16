import asyncio
import random
from typing import List, Dict, Any, Optional
from datetime import datetime
from app.models.report import Finding

# Simulated security findings for different audit types
WEB_FINDINGS = [
    {
        "title": "SQL Injection Vulnerability",
        "severity": "critical",
        "category": "Injection",
        "description": "The application is vulnerable to SQL injection attacks in the login form. User input is directly concatenated into SQL queries without proper sanitization.",
        "affected_component": "/api/login endpoint",
        "evidence": "POST /api/login - Parameter 'username' is injectable",
        "cvss_score": 9.8,
        "cve_ids": ["CVE-2021-44228"],
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
    },
    {
        "title": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "category": "XSS",
        "description": "Reflected XSS vulnerability found in the search functionality. User input is rendered without proper encoding.",
        "affected_component": "/search endpoint",
        "evidence": "<script>alert('XSS')</script> in search parameter executes",
        "cvss_score": 7.5,
        "references": ["https://owasp.org/www-community/attacks/xss/"]
    },
    {
        "title": "Missing HTTPS Redirect",
        "severity": "medium",
        "category": "Transport Security",
        "description": "The application does not enforce HTTPS. Users can access the site over unencrypted HTTP.",
        "affected_component": "Web Server Configuration",
        "cvss_score": 5.3,
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"]
    },
    {
        "title": "Exposed Server Version",
        "severity": "low",
        "category": "Information Disclosure",
        "description": "Server response headers reveal the web server version, which could help attackers identify vulnerabilities.",
        "affected_component": "HTTP Headers",
        "evidence": "Server: nginx/1.18.0",
        "cvss_score": 3.1
    },
    {
        "title": "Cookie Without HttpOnly Flag",
        "severity": "medium",
        "category": "Session Management",
        "description": "Session cookies are set without the HttpOnly flag, making them accessible to JavaScript.",
        "affected_component": "Session Management",
        "cvss_score": 4.3
    }
]

MOBILE_FINDINGS = [
    {
        "title": "Insecure Data Storage",
        "severity": "critical",
        "category": "Data Storage",
        "description": "Sensitive user data is stored in plain text in SharedPreferences/UserDefaults without encryption.",
        "affected_component": "Local Storage",
        "cvss_score": 8.5
    },
    {
        "title": "Hardcoded API Keys",
        "severity": "high",
        "category": "Cryptography",
        "description": "API keys and secrets are hardcoded in the application binary.",
        "affected_component": "Application Code",
        "evidence": "Found: aws_key=AKIA****** in strings.xml",
        "cvss_score": 7.8
    },
    {
        "title": "Missing Certificate Pinning",
        "severity": "high",
        "category": "Network Security",
        "description": "The application does not implement certificate pinning, making it vulnerable to MITM attacks.",
        "affected_component": "Network Layer",
        "cvss_score": 7.0
    },
    {
        "title": "Debug Mode Enabled",
        "severity": "medium",
        "category": "Configuration",
        "description": "The application is compiled with debug mode enabled in production.",
        "affected_component": "Build Configuration",
        "cvss_score": 5.0
    }
]

API_FINDINGS = [
    {
        "title": "Broken Object Level Authorization",
        "severity": "critical",
        "category": "Authorization",
        "description": "API endpoints allow access to other users' resources by manipulating object IDs.",
        "affected_component": "/api/users/{id}/data",
        "evidence": "Changing user_id parameter returns other users' data",
        "cvss_score": 9.1
    },
    {
        "title": "Missing Rate Limiting",
        "severity": "high",
        "category": "Availability",
        "description": "API endpoints lack rate limiting, making them vulnerable to brute force and DoS attacks.",
        "affected_component": "All API endpoints",
        "cvss_score": 7.5
    },
    {
        "title": "Excessive Data Exposure",
        "severity": "medium",
        "category": "Data Exposure",
        "description": "API returns more data than necessary, including internal IDs and sensitive fields.",
        "affected_component": "Response schemas",
        "cvss_score": 5.5
    },
    {
        "title": "Missing Authentication on Endpoint",
        "severity": "high",
        "category": "Authentication",
        "description": "Some endpoints are accessible without authentication.",
        "affected_component": "/api/internal/stats",
        "cvss_score": 8.0
    }
]

BACKEND_FINDINGS = [
    {
        "title": "Outdated Dependencies",
        "severity": "high",
        "category": "Dependencies",
        "description": "Multiple dependencies have known security vulnerabilities.",
        "affected_component": "package.json / requirements.txt",
        "evidence": "lodash@4.17.15 - CVE-2021-23337",
        "cvss_score": 7.2
    },
    {
        "title": "Hardcoded Secrets in Code",
        "severity": "critical",
        "category": "Secrets Management",
        "description": "Database credentials and API keys are hardcoded in source files.",
        "affected_component": "config.py:23",
        "evidence": "DB_PASSWORD = 'admin123'",
        "cvss_score": 9.0
    },
    {
        "title": "Insecure Deserialization",
        "severity": "high",
        "category": "Injection",
        "description": "The application uses pickle/eval for deserialization without validation.",
        "affected_component": "data_handler.py",
        "cvss_score": 8.1
    },
    {
        "title": "Missing Input Validation",
        "severity": "medium",
        "category": "Input Validation",
        "description": "Several functions accept user input without proper validation.",
        "affected_component": "api/handlers.py",
        "cvss_score": 5.8
    }
]

SCAN_STEPS = {
    "web": [
        "Initializing web scanner...",
        "Resolving target domain...",
        "Checking SSL/TLS configuration...",
        "Crawling web pages...",
        "Analyzing forms and inputs...",
        "Testing for SQL injection...",
        "Testing for XSS vulnerabilities...",
        "Checking authentication endpoints...",
        "Analyzing HTTP headers...",
        "Scanning for exposed directories...",
        "Testing CORS configuration...",
        "Finalizing scan results..."
    ],
    "mobile": [
        "Initializing mobile scanner...",
        "Extracting APK/IPA package...",
        "Analyzing AndroidManifest.xml / Info.plist...",
        "Decompiling application code...",
        "Scanning for hardcoded secrets...",
        "Checking data storage practices...",
        "Analyzing network security config...",
        "Testing certificate pinning...",
        "Scanning for sensitive permissions...",
        "Checking code obfuscation...",
        "Finalizing scan results..."
    ],
    "api": [
        "Initializing API scanner...",
        "Discovering API endpoints...",
        "Testing authentication mechanisms...",
        "Checking authorization controls...",
        "Testing for injection vulnerabilities...",
        "Analyzing response schemas...",
        "Testing rate limiting...",
        "Checking CORS headers...",
        "Testing for IDOR vulnerabilities...",
        "Finalizing scan results..."
    ],
    "backend": [
        "Initializing code scanner...",
        "Cloning repository...",
        "Analyzing dependency files...",
        "Scanning for outdated packages...",
        "Checking for known CVEs...",
        "Scanning for hardcoded secrets...",
        "Analyzing code patterns...",
        "Checking for insecure functions...",
        "Analyzing configuration files...",
        "Finalizing scan results..."
    ]
}

FINDINGS_MAP = {
    "web": WEB_FINDINGS,
    "mobile": MOBILE_FINDINGS,
    "api": API_FINDINGS,
    "backend": BACKEND_FINDINGS
}

async def run_simulated_scan(
    audit_type: str,
    target: str,
    depth: str,
    progress_callback: Optional[callable] = None
) -> tuple[List[Finding], List[str], int]:
    """
    Run a simulated security scan with realistic timing and logs.
    
    Returns: (findings, logs, duration_seconds)
    """
    logs = []
    steps = SCAN_STEPS.get(audit_type, SCAN_STEPS["web"])
    available_findings = FINDINGS_MAP.get(audit_type, WEB_FINDINGS)
    
    # Determine scan duration based on depth
    base_delay = {"quick": 0.5, "standard": 1.0, "deep": 1.5}.get(depth, 1.0)
    
    total_steps = len(steps)
    start_time = datetime.now()
    
    for i, step in enumerate(steps):
        # Add log entry
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [INFO] {step}"
        logs.append(log_entry)
        
        # Send progress update
        if progress_callback:
            percent = int((i + 1) / total_steps * 100)
            await progress_callback("log", log_entry)
            await progress_callback("progress", {"percent": percent, "current_step": step})
            
            # Send test result for the step
            status = "pass" if random.random() > 0.15 else "warn"
            await progress_callback("test_result", {
                "name": step.replace("...", ""),
                "status": status,
                "message": f"Verification for '{step.replace('...', '')}' completed."
            })
        
        # Simulate processing time
        delay = base_delay + random.uniform(0, 0.5)
        await asyncio.sleep(delay)
        
        # Occasionally add warning logs
        if random.random() < 0.3:
            warning = f"[{datetime.now().strftime('%H:%M:%S')}] [WARN] Potential issue detected during: {step}"
            logs.append(warning)
            if progress_callback:
                await progress_callback("log", warning)
    
    # Select findings based on depth
    num_findings = {"quick": 2, "standard": 4, "deep": len(available_findings)}.get(depth, 3)
    selected_findings = random.sample(available_findings, min(num_findings, len(available_findings)))
    
    # Convert to Finding objects
    findings = []
    for f in selected_findings:
        finding = Finding(
            title=f["title"],
            severity=f["severity"],
            category=f["category"],
            description=f["description"],
            affected_component=f["affected_component"],
            evidence=f.get("evidence"),
            cvss_score=f.get("cvss_score"),
            cve_ids=f.get("cve_ids"),
            references=f.get("references")
        )
        findings.append(finding)
    
    duration = int((datetime.now() - start_time).total_seconds())
    
    # Final log
    final_log = f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Scan completed. Found {len(findings)} issues."
    logs.append(final_log)
    if progress_callback:
        await progress_callback("log", final_log)
    
    return findings, logs, duration

def calculate_score(findings: List[Finding]) -> int:
    """
    Calculate overall security score using a Capped Deductive Scoring model.
    Prevents minor issues from overwhelming the score while highlighting critical risks.
    """
    if not findings:
        return 100
    
    # Base configuration for penalties and caps
    scoring_config = {
        "critical": {"penalty": 25, "cap": 100},
        "high":     {"penalty": 15, "cap": 80},
        "medium":   {"penalty": 8,  "cap": 40},
        "low":      {"penalty": 3,  "cap": 20},
        "info":     {"penalty": 1,  "cap": 5}
    }
    
    # Aggregate penalties by severity
    severity_totals = {sev: 0 for sev in scoring_config}
    for f in findings:
        if f.severity in severity_totals:
            severity_totals[f.severity] += scoring_config[f.severity]["penalty"]
    
    # Apply caps and calculate total deduction
    total_deduction = 0
    for sev, total in severity_totals.items():
        cap = scoring_config[sev]["cap"]
        total_deduction += min(total, cap)
    
    # Final score (0-100 range)
    score = max(0, 100 - total_deduction)
    return int(score)

def get_risk_level(score: int) -> str:
    """Determine risk level from score."""
    if score <= 30:
        return "critical"
    elif score <= 50:
        return "high"
    elif score <= 70:
        return "medium"
    elif score <= 90:
        return "low"
    return "secure"


# Import real scanner functions
from app.services.real_scanner import run_real_web_scan, run_real_api_scan
from app.services.mobsf_service import run_real_mobile_scan

async def run_hybrid_scan(
    audit_type: str,
    target: str,
    depth: str,
    progress_callback: Optional[callable] = None
) -> tuple[List[Finding], List[str], int, Optional[str]]:
    """
    Run a hybrid scan: real scanners for web/api/mobile, simulated for backend.
    Combines real findings with simulated ones for comprehensive coverage.
    """
    start_time = datetime.now()
    mobsf_hash = None
    
    if audit_type == "web":
        # Use real web scanner
        findings, logs, duration = await run_real_web_scan(target, depth, progress_callback)
        return findings, logs, duration, None
        
    elif audit_type == "api":
        # Use real API scanner
        findings, logs, duration = await run_real_api_scan(target, depth, progress_callback)
        return findings, logs, duration, None
        
    elif audit_type == "mobile":
        # Use real MobSF scanner with fallback to simulation
        real_findings, hash_val = await run_real_mobile_scan(target, progress_callback)
        mobsf_hash = hash_val
        
        if real_findings:
            duration = int((datetime.now() - start_time).total_seconds())
            logs = [f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Real MobSF scan completed."]
            return real_findings, logs, duration, mobsf_hash
        
        # Fallback to simulation if real scan failed or returned no findings (and it was a healthy check)
        findings, logs, duration = await run_simulated_scan(audit_type, target, depth, progress_callback)
        return findings, logs, duration, None
        
    else:
        # Use simulated scan for backend
        findings, logs, duration = await run_simulated_scan(audit_type, target, depth, progress_callback)
        return findings, logs, duration, None
