"""
Shared Configuration Loader
Reads environment variables with defaults suitable for both Docker and local dev.
"""
import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Cyber Range & Security Validation Platform"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEV_AUTH_ENABLED: bool = False
    # Local username/password authentication; override the secret and bootstrap credentials outside a demo.
    AUTH_SECRET_KEY: str = "local-only-change-this-cyber-range-secret-before-deploying"
    AUTH_TOKEN_TTL_MINUTES: int = 480
    INITIAL_ADMIN_USERNAME: str = os.getenv("INITIAL_ADMIN_USERNAME", "admin")
    INITIAL_ADMIN_PASSWORD: str = os.getenv("INITIAL_ADMIN_PASSWORD", "admin123")
    DEFAULT_TENANT_ID: str = "00000000-0000-0000-0000-000000000123"
    CORS_ALLOW_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    KEYCLOAK_JWT_AUDIENCE: str = "cyberrange-web"
    ATTACK_EXECUTION_MODE: str = "simulation"  # simulation or live
    ALLOW_SIMULATED_SANDBOX: bool = True

    # Database Backend ('sqlite' or 'postgres')
    DATABASE_BACKEND: str = os.getenv("DATABASE_BACKEND", "sqlite")

    # PostgreSQL
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "cyberrange")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "dev_only_change_me")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "cyberrange")
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    TOPIC_RAW_ATTACK: str = "raw.attack"
    TOPIC_RAW_NETWORK: str = "raw.network"
    TOPIC_RAW_HOST: str = "raw.host"
    TOPIC_RAW_SOC: str = "raw.soc"
    TOPIC_NORMALIZED_EVENTS: str = "normalized.events"

    # OpenSearch
    OPENSEARCH_HOST: str = os.getenv("OPENSEARCH_HOST", "http://localhost:9200")
    OPENSEARCH_INDEX_PATTERN: str = "events-*"

    # MinIO
    MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    MINIO_ROOT_USER: str = os.getenv("MINIO_ROOT_USER", "minioadmin")
    MINIO_ROOT_PASSWORD: str = os.getenv("MINIO_ROOT_PASSWORD", "dev_only_change_me")
    MINIO_BUCKET_SESSIONS: str = "sessions"
    MINIO_SECURE: bool = False

    # Keycloak
    KEYCLOAK_URL: str = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
    KEYCLOAK_REALM: str = "cyberrange"
    KEYCLOAK_CLIENT_ID: str = "cyberrange-web"

    # AI Security Copilot (Google Gemini & multi-provider)
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "dev_placeholder_or_local_mock")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    # Optional legacy Anthropic configuration
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "dev_placeholder")
    ANTHROPIC_MODEL: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    ANTHROPIC_API_VERSION: str = os.getenv("ANTHROPIC_API_VERSION", "2026-10-21")


    @property
    def cors_origins(self) -> list[str]:
        return [item.strip() for item in self.CORS_ALLOW_ORIGINS.split(",") if item.strip()]

    model_config = {
        "env_file": ".env",
        "extra": "ignore"
    }


settings = Settings()
