import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "NIDS CyberDefend"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "nids-super-secure-production-secret-key-32chars-min-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./nids.db")
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost",
    ]
    
    # Default analyst credentials
    DEFAULT_ADMIN_USERNAME: str = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD: str = os.getenv("DEFAULT_ADMIN_PASSWORD", "CyberDefense2026!")
    DEFAULT_ANALYST_USERNAME: str = os.getenv("DEFAULT_ANALYST_USERNAME", "analyst")
    DEFAULT_ANALYST_PASSWORD: str = os.getenv("DEFAULT_ANALYST_PASSWORD", "Analyst2026!")

    # Detection Thresholds
    PORT_SCAN_PORT_THRESHOLD: int = 5
    PORT_SCAN_WINDOW_SECS: float = 12.0
    
    BRUTE_FORCE_ATTEMPT_THRESHOLD: int = 4
    BRUTE_FORCE_WINDOW_SECS: float = 15.0
    BRUTE_FORCE_PORTS: List[int] = [22, 3389, 21, 23, 3306, 5432, 8080]
    
    DDOS_PACKET_THRESHOLD: int = 400
    DDOS_FLOW_THRESHOLD: int = 25
    DDOS_WINDOW_SECS: float = 5.0
    
    SUSPICIOUS_OUTBOUND_PORTS: List[int] = [4444, 1337, 6667, 31337, 8888, 9999, 5555]
    SUSPICIOUS_BYTE_THRESHOLD: int = 5_000_000  # 5 MB in single short flow
    
    KNOWN_BLACKLISTED_IPS: List[str] = [
        "198.51.100.23",
        "203.0.113.88",
        "185.220.101.5",
        "45.154.255.99",
        "194.26.29.112",
        "103.251.167.20"
    ]

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
