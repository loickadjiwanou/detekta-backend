import httpx
import asyncio
import logging
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.models.report import Finding
from app.config import settings

logger = logging.getLogger(__name__)

class MobSFService:
    """Service to interact with MobSF REST API."""
    
    def __init__(self):
        self.url = settings.MOBSF_URL.rstrip('/')
        self.api_key = settings.MOBSF_API_KEY
        self.headers = {'Authorization': self.api_key}
        self.timeout = httpx.Timeout(30.0, read=300.0) # Long timeout for scan
        logger.info(f"MobSF Service initialized with URL: {self.url}")

    async def check_health(self) -> bool:
        """Check if MobSF is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                # Use root endpoint as it's more universally supported across versions
                response = await client.get(f"{self.url}/", headers=self.headers)
                # Accept any status < 400 (allows 200, 302, etc.)
                return response.status_code < 400
        except Exception as e:
            logger.error(f"MobSF health check failed (Target: {self.url}/): {str(e)}")
            return False

    async def upload_file(self, file_path: str) -> Optional[str]:
        """Upload APK/IPA file to MobSF and return the file hash."""
        try:
            filename = os.path.basename(file_path)
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                with open(file_path, 'rb') as f:
                    files = {'file': (filename, f)}
                    response = await client.post(
                        f"{self.url}/api/v1/upload",
                        headers=self.headers,
                        files=files
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get('hash')
                else:
                    logger.error(f"MobSF upload failed ({response.status_code}) at {self.url}/api/v1/upload: {response.text}")
                    return None
        except Exception as e:
            logger.error(f"MobSF upload error: {e}")
            return None

    async def start_scan(self, file_hash: str) -> bool:
        """Trigger a scan for the uploaded file."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.url}/api/v1/scan",
                    headers=self.headers,
                    data={'hash': file_hash}
                )
                return response.status_code == 200
        except Exception as e:
            logger.error(f"MobSF scan start error: {e}")
            return False

    async def get_report_data(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch the full JSON report from MobSF."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.url}/api/v1/report_json",
                    headers=self.headers,
                    data={'hash': file_hash}
                )
                if response.status_code == 200:
                    return response.json()
                return None
        except Exception as e:
            logger.error(f"MobSF report fetch error: {e}")
            return None

    async def download_pdf(self, file_hash: str) -> Optional[bytes]:
        """Download the original PDF report from MobSF."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.url}/api/v1/download_pdf",
                    headers=self.headers,
                    data={'hash': file_hash}
                )
                if response.status_code == 200:
                    return response.content
                logger.error(f"MobSF PDF download failed ({response.status_code}): {response.text}")
                return None
        except Exception as e:
            logger.error(f"MobSF PDF download error: {e}")
            return None

    def map_mobsf_to_findings(self, report: Dict[str, Any]) -> List[Finding]:
        """Transform MobSF report issues into Detekta Finding objects with full parity."""
        findings = []
        
        # 1. Manifest Analysis
        manifest_analysis = report.get('manifest_analysis', [])
        for issue in manifest_analysis:
            if isinstance(issue, dict) and issue.get('stat') not in ['info', 'secure', 'ok']:
                severity = self._map_severity(issue.get('stat', 'low'))
                findings.append(Finding(
                    title=f"Manifest: {issue.get('title', 'Unknown Issue')}",
                    severity=severity,
                    category="Manifest Security",
                    description=issue.get('desc', 'No description provided.'),
                    affected_component="AndroidManifest.xml",
                    recommendation="Review manifest configuration for principle of least privilege."
                ))

        # 2. Code Analysis (Core of the report)
        code_analysis = report.get('code_analysis', {})
        for rule_id, details in code_analysis.items():
            if not isinstance(details, dict):
                continue
                
            metadata = details.get('metadata', {})
            if not isinstance(metadata, dict):
                metadata = {}
                
            severity_raw = metadata.get('severity', 'warning')
            title = metadata.get('title', rule_id.replace('_', ' ').title())
            description = metadata.get('description', '')
            
            files = details.get('files', {})
            if isinstance(files, dict):
                for file_path, line_numbers in files.items():
                    findings.append(Finding(
                        title=f"Code: {title}",
                        severity=self._map_severity(severity_raw),
                        category="Static Code Analysis",
                        description=description or f"Potential vulnerability detected: {rule_id}",
                        affected_component=f"{file_path} (Lines: {line_numbers})",
                        recommendation="Refer to OWASP Mobile Top 10 for mitigation strategies."
                    ))

        # 3. Secret Analysis
        secrets = report.get('secrets', [])
        for secret in secrets:
            if isinstance(secret, dict):
                findings.append(Finding(
                    title=f"Secret Found: {secret.get('type', 'Sensitive Data')}",
                    severity="critical",
                    category="Information Disclosure",
                    description=f"Potential hardcoded secret discovered: {secret.get('match', '***')}",
                    affected_component=secret.get('file', 'Internal Database'),
                    recommendation="Never hardcode secrets. Use a Secure Vault or Environment Variables."
                ))

        # 4. Certificate Analysis
        cert_analysis = report.get('certificate_analysis', {})
        if isinstance(cert_analysis, dict):
            cert_info = cert_analysis.get('certificate_info', {})
            if cert_analysis and cert_info and cert_analysis.get('certificate_status') != 'good':
                findings.append(Finding(
                    title="Potential Certificate Issue",
                    severity="high",
                    category="Network Security",
                    description=cert_analysis.get('certificate_status', 'Certificate issue detected.'),
                    affected_component="App Binary / Security Certificate",
                    recommendation="Configure secure certificate pinning and verify certificate validity."
                ))

        # 5. Permission Analysis (Dangerous ones)
        permissions = report.get('permissions', {})
        if isinstance(permissions, dict):
            for perm_name, perm_data in permissions.items():
                if isinstance(perm_data, dict) and perm_data.get('status') == 'dangerous':
                    findings.append(Finding(
                        title=f"Dangerous Permission: {perm_name.split('.')[-1]}",
                        severity="medium",
                        category="Permissions",
                        description=perm_data.get('description', 'Requesting a dangerous permission.'),
                        affected_component="AndroidManifest.xml",
                        recommendation="Verify if this permission is strictly necessary for the app to function."
                    ))

        # 6. Binary Analysis
        binary_analysis = report.get('binary_analysis', [])
        if isinstance(binary_analysis, list):
            for item in binary_analysis:
                if isinstance(item, dict) and item.get('stat') == 'fail':
                    findings.append(Finding(
                        title=f"Binary Protection: {item.get('title', 'Hardening Issue')}",
                        severity="medium",
                        category="Binary Hardening",
                        description=item.get('desc', 'Insecure binary compilation flags detected.'),
                        affected_component="Application Binary",
                        recommendation="Enable security flags (ASLR, Stack Canary, ARC) during compilation."
                    ))

        # 7. Trackers & Privacy Analysis
        trackers = report.get('trackers', {}).get('trackers', [])
        if isinstance(trackers, list):
            for tracker in trackers:
                findings.append(Finding(
                    title=f"Privacy Tracker: {tracker.get('name', 'Unknown')}",
                    severity="info",
                    category="Privacy",
                    description=f"Tracker detected: {tracker.get('name')}. Category: {tracker.get('categories')}",
                    affected_component="Ad/Analytics SDK",
                    recommendation="Review the privacy policy and ensure compliance with GDPR/CCPA."
                ))

        # 8. Malicious Domain Analysis
        domains = report.get('domains', {})
        if isinstance(domains, dict):
            for domain, details in domains.items():
                if isinstance(details, dict) and details.get('bad') == 'yes':
                    findings.append(Finding(
                        title=f"Insecure Domain: {domain}",
                        severity="high",
                        category="Network Security",
                        description=f"The application communicates with a known insecure or malicious domain: {domain}.",
                        affected_component="Networking Code",
                        recommendation="Block communication with this domain and investigate why it is being contacted."
                    ))

        # 9. Network Security Configuration
        network_security = report.get('network_security', [])
        if isinstance(network_security, list):
            for net_sec in network_security:
                if isinstance(net_sec, dict) and net_sec.get('stat') not in ['info', 'secure', 'ok']:
                    findings.append(Finding(
                        title=f"Network Config: {net_sec.get('title', 'Misconfiguration')}",
                        severity=self._map_severity(net_sec.get('stat', 'low')),
                        category="Network Security",
                        description=net_sec.get('desc', 'Insecure network security configuration.'),
                        affected_component="network_security_config.xml",
                        recommendation="Follow Android network security best practices for TLS/SSL."
                    ))

        return findings

    def _map_severity(self, mobsf_stat: str) -> str:
        """Map MobSF severity levels to Detekta levels for perfect UI parity."""
        s = mobsf_stat.lower() if mobsf_stat else 'low'
        
        # Exact alignment with MobSF Summary counts
        if s == 'high':
            return 'high'
        if s == 'warning':
            return 'medium'
        if s == 'medium':
            return 'medium'
        if s == 'low' or s == 'hotspot':
            return 'low'
        
        # Default to info for secure/ok/info
        return 'info'

async def run_real_mobile_scan(
    file_path: str,
    progress_callback: Optional[callable] = None
) -> tuple[List[Finding], Optional[str]]:
    """Orchestrate a real mobile scan via MobSF."""
    service = MobSFService()
    findings = []
    
    async def log(msg: str):
        if progress_callback:
            await progress_callback("log", f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] {msg}")

    async def report_test(name: str, status: str, message: str):
        if progress_callback:
            await progress_callback("test_result", {
                "name": name,
                "status": status,
                "message": message
            })

    # 1. Check health
    if not await service.check_health():
        await log("⚠️ MobSF service is not reachable (Health check failed).")
        await log("💡 Falling back to Simulated Scan mode for this audit.")
        return [], None

    # 2. Upload
    await log("Uploading APK/IPA to MobSF engine...")
    await progress_callback("progress", {"percent": 20, "current_step": "Uploading file"})
    file_hash = await service.upload_file(file_path)
    if not file_hash:
        await log("Failed to upload file to MobSF.")
        return [], None
    await report_test("File Upload", "pass", "File successfully uploaded and indexed.")

    # 3. Scan
    await log("Starting static analysis (jadx, apktool, code analysis)...")
    await progress_callback("progress", {"percent": 40, "current_step": "Static Analysis"})
    if not await service.start_scan(file_hash):
        await log("Failed to start scan on MobSF.")
        return [], None
    
    # MobSF is synchronous on scan start usually, but let's give it a moment
    await asyncio.sleep(2)
    await report_test("Static Analysis", "pass", "Static analysis engine triggered.")

    # 4. Fetch Results
    await log("Fetching detailed results from MobSF...")
    await progress_callback("progress", {"percent": 80, "current_step": "Processing results"})
    report = await service.get_report_data(file_hash)
    if not report:
        await log("Failed to retrieve report data.")
        return [], None
    
    findings = service.map_mobsf_to_findings(report)
    await report_test("Vulnerability Mapping", "pass" if not findings else "fail", f"Identified {len(findings)} potential security issues.")
    
    await progress_callback("progress", {"percent": 100, "current_step": "Completed"})
    return findings, file_hash
