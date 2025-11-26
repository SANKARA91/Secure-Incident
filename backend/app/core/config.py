# backend/app/core/config.py

from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = os.getenv("API_V1_STR", "/api/v1")
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Secure Incident Response")

    # Security
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
    )
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql://postgres:admin123@localhost:5432/cyberdb"
    )

    # Wazuh Configuration
    WAZUH_HOST: str = os.getenv("WAZUH_HOST", "192.168.1.19")
    WAZUH_PORT: int = int(os.getenv("WAZUH_PORT", 55000))
    WAZUH_API_URL: str = f"https://{WAZUH_HOST}:{WAZUH_PORT}"
    WAZUH_USERNAME: str = os.getenv("WAZUH_USERNAME", "wazuh")
    WAZUH_PASSWORD: str = os.getenv("WAZUH_PASSWORD", "WzH@2025!Secure+Admin_99")
    #WAZUH_USERNAME: str = os.getenv("WAZUH_USERNAME", "wazuh")
    #WAZUH_PASSWORD: str = os.getenv("WAZUH_PASSWORD", "wazuh")
    VERIFY_SSL: bool = bool(int(os.getenv("VERIFY_SSL", "0")))  # 0 = False, 1 = True

settings = Settings()
