import re
import ipaddress
from urllib.parse import urlparse

def is_valid_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_url(url: str) -> bool:
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def is_private_ip(ip_str: str) -> bool:
    """Check if IP address is private (anti-SSRF)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved
        )
    except ValueError:
        return False

def is_safe_target(url: str) -> tuple[bool, str]:
    """Validate that a URL target is safe to scan (anti-SSRF)."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format"
        
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP/HTTPS protocols allowed"
        
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid hostname"
        
        # Block localhost and variants
        localhost_variants = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
        if hostname.lower() in localhost_variants:
            return False, "Localhost targets not allowed"
        
        # Try to parse as IP and check if private
        try:
            if is_private_ip(hostname):
                return False, "Private IP addresses not allowed"
        except ValueError:
            # Not an IP, it's a hostname - that's fine
            pass
        
        return True, "OK"
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

def is_valid_git_repo(url: str) -> bool:
    """Validate Git repository URL."""
    git_patterns = [
        r'^https?://github\.com/[\w-]+/[\w.-]+(?:\.git)?$',
        r'^https?://gitlab\.com/[\w-]+/[\w.-]+(?:\.git)?$',
        r'^https?://bitbucket\.org/[\w-]+/[\w.-]+(?:\.git)?$',
        r'^git@[\w.-]+:[\w-]+/[\w.-]+(?:\.git)?$'
    ]
    return any(re.match(pattern, url) for pattern in git_patterns)

ALLOWED_FILE_EXTENSIONS = {'.apk', '.ipa', '.aab'}
ALLOWED_MIME_TYPES = {
    'application/vnd.android.package-archive': '.apk',
    'application/octet-stream': ['.apk', '.ipa', '.aab'],
}

def is_valid_mobile_file(filename: str) -> bool:
    """Validate mobile app file extension."""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    return f'.{ext}' in ALLOWED_FILE_EXTENSIONS
