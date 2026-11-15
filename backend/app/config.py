import os
from pydantic import BaseModel


class Settings(BaseModel):
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Allowed CORS Origins
    ALLOWED_ORIGINS: list[str] = [
        origin.strip()
        for origin in os.getenv(
            "ALLOWED_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
        ).split(",")
        if origin.strip()
    ]
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    MAX_CONTENT_LENGTH: int = int(os.getenv("MAX_CONTENT_LENGTH", "10000"))
    
    # Scoring Thresholds
    SUSPICIOUS_THRESHOLD: int = int(os.getenv("SUSPICIOUS_THRESHOLD", "25"))
    
    # External Reputation Integrations
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    
    # LLaMA / AI Model Integration Settings
    # Supports Local Ollama (http://127.0.0.1:11434) or OpenAI-compatible endpoints (Groq, vLLM, Together)
    LLAMA_ENABLED: bool = os.getenv("LLAMA_ENABLED", "true").lower() in ("true", "1", "yes")
    LLAMA_PROVIDER: str = os.getenv("LLAMA_PROVIDER", "ollama")  # 'ollama' or 'openai_compatible'
    LLAMA_BASE_URL: str = os.getenv("LLAMA_BASE_URL", "http://127.0.0.1:11434")
    LLAMA_MODEL: str = os.getenv("LLAMA_MODEL", "llama3.1:8b")
    LLAMA_API_KEY: str = os.getenv("LLAMA_API_KEY", "")
    LLAMA_TIMEOUT_SECONDS: float = float(os.getenv("LLAMA_TIMEOUT_SECONDS", "15.0"))

    ENGINE_VERSION: str = "1.0.0"


settings = Settings()
