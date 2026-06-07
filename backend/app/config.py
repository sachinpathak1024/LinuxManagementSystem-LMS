"""Central configuration, loaded from environment / .env."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Core
    sentinel_env: str = "production"
    secret_key: str = "insecure-change-me"
    access_token_expire_minutes: int = 30
    cors_origins: str = "http://localhost:8080"

    # First admin (seeded once)
    admin_username: str = "admin"
    admin_password: str = "changeme1234"

    # Database
    postgres_user: str = "sentinel"
    postgres_password: str = "sentinel"
    postgres_db: str = "sentinel"
    postgres_host: str = "db"
    postgres_port: int = 5432

    # Thresholds
    alert_cpu_percent: float = 90.0
    alert_mem_percent: float = 90.0
    alert_disk_percent: float = 90.0
    alert_load_per_core: float = 2.0
    sample_interval_seconds: int = 5
    scan_interval_seconds: int = 30

    # Host integration
    host_root: str = "/host"
    host_log_dir: str = "/host/var/log"
    host_proc: str = "/host/proc"
    allow_host_commands: bool = False
    use_nsenter: bool = True  # when running privileged with pid:host

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
