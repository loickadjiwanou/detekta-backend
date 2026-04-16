from cryptography.fernet import Fernet
from app.config import settings

_fernet = None

def get_fernet():
    global _fernet
    if _fernet is None:
        key = settings.ENCRYPTION_KEY
        if isinstance(key, str):
            key = key.encode()
        _fernet = Fernet(key)
    return _fernet

def encrypt_api_key(api_key: str) -> str:
    """Encrypt an API key for secure storage."""
    fernet = get_fernet()
    return fernet.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt an API key from storage."""
    fernet = get_fernet()
    return fernet.decrypt(encrypted_key.encode()).decode()

def mask_api_key(api_key: str) -> str:
    """Return a masked version of the API key for display."""
    if len(api_key) <= 10:
        return "***"
    return f"{api_key[:7]}***{api_key[-3:]}"
