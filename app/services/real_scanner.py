import asyncio
import subprocess
import re
import json
import httpx
import ssl
import socket
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse
import logging

from app.models.report import Finding

logger = logging.getLogger(__name__)

class RealScanner:
    """Real security scanner using various tools and techniques, aligned with OWASP Top 10 (2025)."""
    
    @staticmethod
    async def check_A01_broken_access_control(url: str) -> List[Finding]:
        """A01:2025 - Broken Access Control checks."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                common_sensitive_paths = [
                    '/.git/', '/.env', '/config/', '/admin/', '/backup/', '/db_backup.sql', 
                    '/.ssh/', '/.vscode/', '/.idea/', '/web.config', '/.htaccess'
                ]
                for path in common_sensitive_paths:
                    try:
                        test_url = url.rstrip('/') + path
                        response = await client.get(test_url)
                        if response.status_code == 200:
                            findings.append(Finding(
                                title=f"Exposed Sensitive Path: {path}",
                                severity="critical" if any(x in path for x in ['.git', '.env', '.ssh']) else "high",
                                category="A01:2025 Access Control",
                                description=f"The path '{path}' is publicly accessible, which may lead to serious information disclosure or unauthorized access.",
                                affected_component=test_url,
                                cvss_score=9.1 if '.env' in path else 7.5,
                                recommendation=f"Restrict access to '{path}' at the web server level."
                            ))
                            
                        # Check for directory listing
                        if response.status_code == 200 and ('Index of' in response.text or 'Directory listing' in response.text):
                            findings.append(Finding(
                                title="Directory Listing Enabled",
                                severity="medium",
                                category="A01:2025 Access Control",
                                description=f"Directory listing is enabled at {path}.",
                                affected_component=test_url,
                                recommendation="Disable directory listing (e.g., 'Options -Indexes' in Apache)."
                            ))
                    except Exception:
                        continue
        except Exception as e:
            logger.warning(f"A01 check failed: {e}")
        return findings

    @staticmethod
    async def check_A02_security_misconfiguration(url: str) -> List[Finding]:
        """A02:2025 - Security Misconfiguration checks."""
        findings = []
        required_headers = {
            'Strict-Transport-Security': 'HSTS header missing.',
            'X-Content-Type-Options': 'MIME-sniffing protection missing.',
            'X-Frame-Options': 'Clickjacking protection missing.',
            'Content-Security-Policy': 'CSP missing, increases XSS risk.',
            'X-XSS-Protection': 'Old XSS filter missing.',
            'Referrer-Policy': 'Referrer-Policy missing or insecure.',
            'Permissions-Policy': 'Permissions-Policy missing.',
            'Cross-Origin-Embedder-Policy': 'COEP missing.',
            'Cross-Origin-Resource-Policy': 'CORP missing.',
            'Cross-Origin-Opener-Policy': 'COOP missing.'
        }
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                for header, msg in required_headers.items():
                    if header.lower() not in headers:
                        findings.append(Finding(
                            title=f"Missing {header} Header",
                            severity="medium" if any(x in header for x in ['Frame', 'Content', 'Policy']) else "low",
                            category="A02:2025 Misconfiguration",
                            description=msg,
                            affected_component=url,
                            recommendation=f"Configure '{header}' in your web server response headers."
                        ))
                
                # Cookie Security
                for cookie_name, cookie_value in response.cookies.items():
                    # httpx doesn't easily expose cookie attributes like Secure/HttpOnly in a simple way 
                    # from the response.cookies dict. For a real scanner, we'd check Set-Cookie headers.
                    pass
                
                # Check Set-Cookie headers directly for more attributes
                set_cookies = [v for k, v in response.headers.items() if k.lower() == 'set-cookie']
                for sc in set_cookies:
                    if 'secure' not in sc.lower():
                        findings.append(Finding(
                            title="Cookie Missing Secure Flag",
                            severity="medium",
                            category="A02:2025 Misconfiguration",
                            description=f"A cookie was set without the 'Secure' attribute: {sc[:50]}...",
                            affected_component=url,
                            recommendation="Ensure all 'Set-Cookie' headers include the 'Secure' attribute."
                        ))
                    if 'httponly' not in sc.lower():
                        findings.append(Finding(
                            title="Cookie Missing HttpOnly Flag",
                            severity="medium",
                            category="A02:2025 Misconfiguration",
                            description=f"A cookie was set without the 'HttpOnly' attribute: {sc[:50]}...",
                            affected_component=url,
                            recommendation="Ensure all 'Set-Cookie' headers include the 'HttpOnly' attribute."
                        ))

                # Info Disclosure
                for server_header in ['server', 'x-powered-by', 'x-aspnet-version']:
                    if server_header in headers:
                        findings.append(Finding(
                            title=f"Information Disclosure in {server_header}",
                            severity="low",
                            category="A02:2025 Misconfiguration",
                            description=f"Server reveals technical stack details: {headers[server_header]}",
                            affected_component=url,
                            evidence=f"{server_header}: {headers[server_header]}",
                            recommendation="Remove or mask server identification headers."
                        ))
        except Exception as e:
            logger.warning(f"A02 check failed: {e}")
        return findings

    @staticmethod
    async def check_A03_supply_chain(url: str) -> List[Finding]:
        """A03:2025 - Software Supply Chain Failures checks."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
                # Look for common outdated libraries patterns
                outdated_patterns = [
                    (r'jquery/1\.\d+\.\d+', 'jQuery 1.x is highly outdated and has multiple vulnerabilities.'),
                    (r'bootstrap/3\.\d+\.\d+', 'Bootstrap 3.x is reaching end-of-life and contains known issues.'),
                    (r'angularjs/1\.\d+\.\d+', 'AngularJS (v1) is end-of-life and unsupported.')
                ]
                for pattern, msg in outdated_patterns:
                    if re.search(pattern, response.text, re.I):
                        findings.append(Finding(
                            title="Outdated Third-Party Library Detected",
                            severity="high",
                            category="A03:2025 Supply Chain",
                            description=msg,
                            affected_component=url,
                            recommendation="Update the library to the latest stable version."
                        ))
        except Exception as e:
            logger.warning(f"A03 check failed: {e}")
        return findings

    @staticmethod
    async def check_A04_cryptographic_failures(url: str) -> List[Finding]:
        """A04:2025 - Cryptographic Failures checks."""
        findings = []
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if parsed.scheme != 'https':
                findings.append(Finding(
                    title="Insecure Protocol (HTTP)",
                    severity="high",
                    category="A04:2025 Cryptography",
                    description="The application uses plain HTTP. All traffic is unencrypted.",
                    affected_component=url,
                    recommendation="Enable HTTPS and redirect all HTTP traffic to HTTPS."
                ))
                return findings
            
            # Basic SSL verification
            context = ssl.create_default_context()
            try:
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if (not_after - datetime.utcnow()).days < 30:
                            findings.append(Finding(
                                title="SSL Certificate Expiring Soon",
                                severity="medium",
                                category="A04:2025 Cryptography",
                                description=f"Certificate expires in {(not_after - datetime.utcnow()).days} days.",
                                affected_component=hostname,
                                recommendation="Renew the SSL certificate."
                            ))
            except ssl.SSLCertVerificationError:
                findings.append(Finding(
                    title="Untrusted SSL Certificate",
                    severity="high",
                    category="A04:2025 Cryptography",
                    description="SSL certificate verification failed (self-signed or untrusted CA).",
                    affected_component=hostname,
                    recommendation="Install a valid certificate from a trusted authority."
                ))
        except Exception as e:
            logger.warning(f"A04 check failed: {e}")
        return findings

    @staticmethod
    async def check_A05_injection(url: str) -> List[Finding]:
        """A05:2025 - Injection checks."""
        findings = []
        # Reuse existing SQLi logic
        sqli_findings = await RealScanner.check_sql_injection_logic(url)
        findings.extend(sqli_findings)
        
        # Add basic XSS check
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                payload = "<script>alert('detekta')</script>"
                test_url = f"{url}{'&' if '?' in url else '?'}debug_msg={payload}"
                response = await client.get(test_url)
                if payload in response.text:
                    findings.append(Finding(
                        title="Reflected XSS Detected",
                        severity="high",
                        category="A05:2025 Injection",
                        description="User-provided input is reflected in the response without proper sanitization.",
                        affected_component=url,
                        evidence=f"Payload reflected: {payload}",
                        cvss_score=7.1,
                        recommendation="Implement proper output encoding and input validation."
                    ))
        except Exception: pass
        return findings

    @staticmethod
    async def check_sql_injection_logic(url: str) -> List[Finding]:
        """Internal helper for SQLi detection."""
        findings = []
        parsed = urlparse(url)
        if not parsed.query and '?' not in url: return findings
        error_sigs = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite3", "Driver Error"]
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                for p in ["'", "\"", "1' OR '1'='1"]:
                    test_url = f"{url}&sqli_test={p}" if parsed.query else f"{url}?sqli_test={p}"
                    resp = await client.get(test_url)
                    for sig in error_sigs:
                        if sig in resp.text:
                            findings.append(Finding(
                                title="Potential SQL Injection (Error-based)",
                                severity="critical",
                                category="A05:2025 Injection",
                                description=f"Database error found after payload: {p}",
                                affected_component=url,
                                evidence=f"Found: {sig}",
                                recommendation="Use parameterized queries."
                            ))
                            return findings
        except Exception: pass
        return findings

    @staticmethod
    async def check_A06_insecure_design(url: str) -> List[Finding]:
        """A06:2025 - Insecure Design checks."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # Check for overly permissive CORS
                resp = await client.options(url, headers={"Origin": "https://evil.com"})
                if resp.headers.get("access-control-allow-origin") == "*" or resp.headers.get("access-control-allow-origin") == "https://evil.com":
                    findings.append(Finding(
                        title="Insecure CORS Policy",
                        severity="medium",
                        category="A06:2025 Insecure Design",
                        description="Policy allows requests from any origin or untrusted origins.",
                        affected_component=url,
                        recommendation="Restrict Access-Control-Allow-Origin to trusted domains."
                    ))
        except Exception: pass
        return findings

    @staticmethod
    async def check_A07_authentication_failures(url: str) -> List[Finding]:
        """A07:2025 - Authentication Failures checks."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                common_auth_paths = ['/login', '/signin', '/admin', '/wp-login.php', '/auth']
                for path in common_auth_paths:
                    test_url = url.rstrip('/') + path
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and ('password' in resp.text.lower() or 'login' in resp.text.lower()):
                        findings.append(Finding(
                            title=f"Exposed Authentication Interface: {path}",
                            severity="medium",
                            category="A07:2025 Authentication",
                            description=f"An authentication interface was found at {path}. Ensure strong credentials and rate limiting are enforced.",
                            affected_component=test_url,
                            recommendation="Enforce MFA and IP-based rate limiting on this endpoint."
                        ))
                        break
        except Exception: pass
        return findings

    @staticmethod
    async def check_A08_integrity_failures(url: str) -> List[Finding]:
        """A08:2025 - Software or Data Integrity Failures and Domain Analysis."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(url)
                html = response.text
                
                # 1. SRI (Subresource Integrity)
                # Improved regex to find script tags and their content/integrity attribute
                script_tags = re.findall(r'<script([^>]+)>', html, re.I)
                for tag_content in script_tags:
                    src_match = re.search(r'src=["\'](http[^"\']+)["\']', tag_content, re.I)
                    if src_match:
                        script_url = src_match.group(1)
                        if 'integrity=' not in tag_content.lower():
                            findings.append(Finding(
                                title="Missing Subresource Integrity (SRI)",
                                severity="low",
                                category="A08:2025 Integrity",
                                description=f"External script from {urlparse(script_url).hostname} is loaded without integrity validation.",
                                affected_component=script_url,
                                recommendation="Add 'integrity' attribute with a valid hash to your external <script> tags."
                            ))
                
                # 2. Domain & Tracker Analysis (Parity with MobSF style)
                # Collect all unique external domains
                external_urls = re.findall(r'(?:href|src|action)=["\'](http[^"\']+)["\']', html, re.I)
                base_domain = urlparse(url).netloc
                seen_domains = set()
                
                trackers = {
                    'google-analytics.com': 'Google Analytics',
                    'googletagmanager.com': 'Google Tag Manager',
                    'facebook.net': 'Facebook Pixel',
                    'doubleclick.net': 'DoubleClick (Ads)',
                    'hotjar.com': 'Hotjar',
                    'sentry.io': 'Sentry (Error Tracking)'
                }
                
                for ext_url in external_urls:
                    domain = urlparse(ext_url).netloc
                    if domain and domain != base_domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        
                        # Check if it's a known tracker
                        tracker_name = next((v for k, v in trackers.items() if k in domain), None)
                        if tracker_name:
                            findings.append(Finding(
                                title=f"Third-Party Tracker Detected: {tracker_name}",
                                severity="info",
                                category="Privacy / Data Integrity",
                                description=f"The application uses {tracker_name} which may track user behavior.",
                                affected_component=domain,
                                recommendation="Ensure your privacy policy discloses the use of this third-party tracker."
                            ))
                        else:
                            findings.append(Finding(
                                title=f"External Domain Connection: {domain}",
                                severity="low",
                                category="A08:2025 Integrity",
                                description=f"The application communicates with an external domain: {domain}",
                                affected_component=domain,
                                recommendation="Verify that this external connection is expected and trusted."
                            ))
                            
        except Exception as e:
            logger.warning(f"A08 check failed: {e}")
        return findings

    @staticmethod
    async def check_A09_logging_failures(url: str) -> List[Finding]:
        """A09:2025 - Security Logging and Alerting Failures checks."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                log_files = ['/error.log', '/access.log', '/debug.log', '/logs/production.log', '/phpinfo.php', '/trace.axd']
                for log_file in log_files:
                    test_url = url.rstrip('/') + log_file
                    resp = await client.get(test_url)
                    if resp.status_code == 200:
                        findings.append(Finding(
                            title=f"Exposed Diagnostic/Log File: {log_file}",
                            severity="high",
                            category="A09:2025 Logging",
                            description=f"A potentially sensitive diagnostic or log file is publicly accessible at {log_file}.",
                            affected_component=test_url,
                            recommendation="Block access to all log and trace files."
                        ))
        except Exception: pass
        return findings

    @staticmethod
    async def check_A10_exceptional_conditions(url: str) -> List[Finding]:
        """A10:2025 - Mishandling of Exceptional Conditions checks."""
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # Force an error by sending invalid characters or methods
                test_url = f"{url}?debug=1&id=';DROP TABLE users"
                resp = await client.get(test_url)
                verbose_indicators = ["Stack Trace", "Exception in", "at line", "System.Web.", "Fatal error:", "Traceback (most recent call last)"]
                for indicator in verbose_indicators:
                    if indicator in resp.text:
                        findings.append(Finding(
                            title="Verbose Error Messages (Stack Trace)",
                            severity="medium",
                            category="A10:2025 Exceptions",
                            description="Application reveals detailed internal technical information in error responses.",
                            affected_component=url,
                            evidence=f"Found indicator: {indicator}",
                            recommendation="Configure custom error pages and disable descriptive error messages in production."
                        ))
                        break
        except Exception: pass
        return findings

    @staticmethod
    async def run_nmap_scan(target: str) -> List[Finding]:
        """Run nmap port scan if available (Integrated into A02)."""
        findings = []
        try:
            hostname = urlparse(target).hostname
            result = subprocess.run(['nmap', '-sV', '--top-ports', '50', '-T4', hostname], capture_output=True, text=True, timeout=60)
            port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
            for match in re.finditer(port_pattern, result.stdout):
                port, service = match.groups()
                if port not in ['80', '443']:
                    findings.append(Finding(
                        title=f"Exposed Service on Port {port}",
                        severity="medium",
                        category="A02:2025 Misconfiguration",
                        description=f"Non-standard port {port} ({service}) is open and exposed.",
                        affected_component=f"{hostname}:{port}",
                        recommendation="Firewall restrict all non-web ports."
                    ))
        except Exception: pass
        return findings

async def run_real_web_scan(
    url: str,
    depth: str,
    progress_callback: Optional[callable] = None
) -> Tuple[List[Finding], List[str], int]:
    """Run real security scan following OWASP Top 10 (2025) compliance."""
    findings = []
    logs = []
    start_time = datetime.now()
    
    async def log(msg: str):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] {msg}"
        logs.append(entry)
        if progress_callback: await progress_callback("log", entry)
            
    async def report_test(id: str, status: str, message: str):
        if progress_callback:
            await progress_callback("test_result", {
                "name": f"A{id.zfill(2)}:2025",
                "status": status,
                "message": message
            })
    
    # Define steps based on depth in numerical OWASP order (2025)
    owasp_steps = [
        {"id": "01", "method": RealScanner.check_A01_broken_access_control, "name": "Broken Access Control", "depth": ["standard", "deep"]},
        {"id": "02", "method": RealScanner.check_A02_security_misconfiguration, "name": "Security Misconfiguration", "depth": ["quick", "standard", "deep"]},
        {"id": "03", "method": RealScanner.check_A03_supply_chain, "name": "Supply Chain Failures", "depth": ["deep"]},
        {"id": "04", "method": RealScanner.check_A04_cryptographic_failures, "name": "Cryptographic Failures", "depth": ["quick", "standard", "deep"]},
        {"id": "05", "method": RealScanner.check_A05_injection, "name": "Injection", "depth": ["standard", "deep"]},
        {"id": "06", "method": RealScanner.check_A06_insecure_design, "name": "Insecure Design", "depth": ["deep"]},
        {"id": "07", "method": RealScanner.check_A07_authentication_failures, "name": "Authentication Failures", "depth": ["standard", "deep"]},
        {"id": "08", "method": RealScanner.check_A08_integrity_failures, "name": "Integrity Failures", "depth": ["deep"]},
        {"id": "09", "method": RealScanner.check_A09_logging_failures, "name": "Logging & Alerting Failures", "depth": ["deep"]},
        {"id": "10", "method": RealScanner.check_A10_exceptional_conditions, "name": "Exceptional Conditions", "depth": ["standard", "deep"]},
    ]
    
    enabled_steps = [s for s in owasp_steps if depth in s["depth"]]
    total = len(enabled_steps)
    
    for i, step in enumerate(enabled_steps):
        await log(f"Running Step {i+1}/{total}: {step['name']} (OWASP A{step['id']})")
        if progress_callback:
            await progress_callback("progress", {
                "percent": int((i+1)/total * 100),
                "current_step": f"OWASP A{step['id']}: {step['name']}"
            })
        
        step_findings = await step["method"](url)
        findings.extend(step_findings)
        
        status = "pass" if not step_findings else "fail" if any(f.severity in ["critical", "high"] for f in step_findings) else "warn"
        await report_test(step["id"], status, f"Analyzed {step['name']}. Found {len(step_findings)} issues.")
        
        # Additional port scan for Standard/Deep in A02
        if step["id"] == "02" and depth in ["standard", "deep"]:
            port_findings = await RealScanner.run_nmap_scan(url)
            findings.extend(port_findings)
    
    duration = int((datetime.now() - start_time).total_seconds())
    await log(f"Scan completed. Total findings: {len(findings)} ({duration}s)")
    return findings, logs, duration


async def run_real_api_scan(
    api_endpoint: str,
    depth: str,
    progress_callback: Optional[callable] = None
) -> Tuple[List[Finding], List[str], int]:
    """Run security scan on an API endpoint."""
    findings = []
    logs = []
    start_time = datetime.now()
    
    async def log(message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [INFO] {message}"
        logs.append(entry)
        if progress_callback:
            await progress_callback("log", entry)
    
    async def warn(message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [WARN] {message}"
        logs.append(entry)
        if progress_callback:
            await progress_callback("log", entry)
    
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            await log("Testing API endpoint accessibility...")
            if progress_callback:
                await progress_callback("progress", {"percent": 20, "current_step": "Connectivity Test"})
            
            # Test basic connectivity
            response = await client.get(api_endpoint)
            
            await log("Checking authentication requirements...")
            if progress_callback:
                await progress_callback("progress", {"percent": 40, "current_step": "Auth Check"})
            
            # Check if API is open
            if response.status_code == 200:
                findings.append(Finding(
                    title="API Endpoint Accessible Without Authentication",
                    severity="high" if 'data' in response.text.lower() or '[' in response.text else "medium",
                    category="Authentication",
                    description="The API endpoint returns data without requiring authentication.",
                    affected_component=api_endpoint,
                    recommendation="Implement authentication (API key, JWT, OAuth) for all API endpoints."
                ))
            
            await log("Testing for CORS misconfiguration...")
            if progress_callback:
                await progress_callback("progress", {"percent": 60, "current_step": "CORS Check"})
            
            # Check CORS
            cors_response = await client.options(
                api_endpoint,
                headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"}
            )
            
            if 'access-control-allow-origin' in cors_response.headers:
                origin = cors_response.headers.get('access-control-allow-origin', '')
                if origin == '*':
                    findings.append(Finding(
                        title="Overly Permissive CORS Policy",
                        severity="medium",
                        category="CORS",
                        description="API allows requests from any origin (Access-Control-Allow-Origin: *)",
                        affected_component=api_endpoint,
                        evidence=f"Access-Control-Allow-Origin: {origin}",
                        recommendation="Restrict CORS to specific trusted origins."
                    ))
            
            await log("Checking rate limiting...")
            if progress_callback:
                await progress_callback("progress", {"percent": 80, "current_step": "Rate Limiting"})
            
            # Test rate limiting (make 10 quick requests)
            rate_limited = False
            for i in range(10):
                try:
                    r = await client.get(api_endpoint)
                    if r.status_code == 429:
                        rate_limited = True
                        break
                except Exception:
                    break
            
            if not rate_limited:
                findings.append(Finding(
                    title="No Rate Limiting Detected",
                    severity="medium",
                    category="Availability",
                    description="The API does not appear to implement rate limiting, making it vulnerable to abuse.",
                    affected_component=api_endpoint,
                    recommendation="Implement rate limiting to prevent abuse and DoS attacks."
                ))
            
            # Add header findings
            header_findings = await RealScanner.check_security_headers(api_endpoint)
            findings.extend(header_findings)
            
    except Exception as e:
        await warn(f"API scan error: {str(e)}")
    
    duration = int((datetime.now() - start_time).total_seconds())
    await log(f"API scan completed. Found {len(findings)} issues.")
    
    if progress_callback:
        await progress_callback("progress", {"percent": 100, "current_step": "Complete"})
    
    return findings, logs, duration
