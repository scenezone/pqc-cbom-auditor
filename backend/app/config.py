from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_env: str = "development"
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_database: str = "pqc_cbom_auditor"
    cors_origins: str = "http://localhost:5173"
    max_upload_size_mb: int = 100
    max_extracted_size_mb: int = 500
    max_repository_files: int = 10000
    max_file_size_mb: int = 10
    max_scan_duration_seconds: int = 600
    max_active_scans: int = 3
    scan_temp_directory: Path = Path("./tmp/scans")
    scan_retention_hours: int = 24
    report_retention_hours: int = 168
    allowed_git_hosts: str = "github.com,gitlab.com,bitbucket.org"
    max_clone_size_mb: int = 200
    clone_timeout_seconds: int = 120
    tls_probe_timeout_seconds: int = 10
    tls_probe_inter_probe_delay_seconds: float = 0.25
    tls_probe_retry_backoff_seconds: float = 0.75
    tls_openssl_binary: str = "openssl"
    cyclonedx_schema_path: Path = Path("./schemas/cyclonedx-1.7.schema.json")
    report_storage_directory: Path = Path("./tmp/reports")
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")
    @property
    def allowed_origins(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]
    @property
    def allowed_git_host_list(self):
        return [x.strip().lower() for x in self.allowed_git_hosts.split(",") if x.strip()]

@lru_cache
def get_settings():
    s = Settings()
    s.scan_temp_directory.mkdir(parents=True, exist_ok=True)
    s.report_storage_directory.mkdir(parents=True, exist_ok=True)
    return s
