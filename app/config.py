import os
from pathlib import Path

class Settings:
    APP_NAME: str = "Detekta"
    APP_ENV: str = os.environ.get("APP_ENV", "development")
    
    # JWT Settings
    JWT_SECRET: str = os.environ["JWT_SECRET"]
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Encryption
    ENCRYPTION_KEY: str = os.environ["ENCRYPTION_KEY"]
    
    # Database
    MONGODB_URL: str = os.environ["MONGO_URL"]
    MONGODB_DB_NAME: str = os.environ["DB_NAME"]
    
    # Claude API
    AI_LLM_KEY: str = os.environ.get("AI_LLM_KEY", "")
    CLAUDE_MODEL: str = os.environ.get("CLAUDE_MODEL", "claude-opus-4-5")
    
    # File uploads
    UPLOAD_DIR: str = os.environ.get("UPLOAD_DIR", "/tmp/detekta_uploads")
    MAX_FILE_SIZE_MB: int = int(os.environ.get("MAX_FILE_SIZE_MB", "200"))
    
    # i18n
    DEFAULT_LANGUAGE: str = os.environ.get("DEFAULT_LANGUAGE", "en")
    SUPPORTED_LANGUAGES: list = ["en", "fr"]
    
    # MobSF
    MOBSF_URL: str = os.environ.get("MOBSF_URL", "http://localhost:8008")
    MOBSF_API_KEY: str = os.environ.get("MOBSF_API_KEY", "7282a5146c9861e687a7183e29f8f4a13eaf72e909562ac1e88e8940c6c729c1")

settings = Settings()
