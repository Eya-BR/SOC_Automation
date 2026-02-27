"""
Configuration Management

Loads environment variables and provides configuration settings
"""

import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application settings"""
    
    # LLM Configuration
    local_llm_model: str = os.getenv("LOCAL_LLM_MODEL", "llama3.2")
    
    # OpenAI Configuration (Optional)
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
    
    # Vector Database
    chroma_persist_directory: str = os.getenv("CHROMA_PERSIST_DIRECTORY", os.path.join(os.getcwd(), "data", "chroma"))
    vector_db_path: str = os.getenv("VECTOR_DB_PATH", os.path.join(os.getcwd(), "data", "vector_db"))
    
    # API Server
    api_host: str = os.getenv("API_HOST", "10.10.128.17")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    
    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_file: str = os.getenv("LOG_FILE", os.path.join(os.getcwd(), "logs", "alert_enrichment.log"))
    
    # Threat Intelligence API Keys
    virustotal_api_key: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
    otx_api_key: Optional[str] = os.getenv("OTX_API_KEY")
    
    # GeoIP API Keys
    ipinfo_api_key: Optional[str] = os.getenv("IPINFO_API_KEY")
    maxmind_api_key: Optional[str] = os.getenv("MAXMIND_API_KEY")
    
    class Config:
        env_file = ".env"

settings = Settings()
