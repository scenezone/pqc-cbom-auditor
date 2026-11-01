from typing import Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator
from app.scanner.repository_loader import SUPPORTED_LANGUAGES

class BusinessContext(BaseModel):
    business_criticality: str = "Moderate"
    data_sensitivity: str = "Internal"
    data_retention_horizon: str = "1-3 years"
    external_exposure: str = "Internal"

class ScanConfiguration(BaseModel):
    languages: list[str] = Field(default_factory=lambda: SUPPORTED_LANGUAGES.copy())
    scan_depth: int = Field(default=10, ge=1, le=20)
    include_tests: bool = False

class RepositoryURLScanRequest(BaseModel):
    scan_name: str = Field(min_length=3, max_length=120)
    repository_url: HttpUrl
    tls_target_url: Optional[HttpUrl] = None
    business_context: BusinessContext = BusinessContext()
    scan_configuration: ScanConfiguration = ScanConfiguration()

    @field_validator("repository_url")
    @classmethod
    def require_https(cls, v):
        if v.scheme != "https":
            raise ValueError("Only HTTPS repository URLs are accepted")
        return v

    @field_validator("tls_target_url")
    @classmethod
    def require_tls_target_https(cls, v):
        if v is not None and v.scheme != "https":
            raise ValueError("TLS probe target must use HTTPS")
        return v

class TLSEndpointScanRequest(BaseModel):
    scan_name: str = Field(default="HTTPS endpoint assessment", min_length=3, max_length=120)
    target_url: HttpUrl
    business_context: BusinessContext = Field(default_factory=BusinessContext)

    @field_validator("target_url")
    @classmethod
    def require_https_endpoint(cls, v):
        if v.scheme != "https":
            raise ValueError("TLS probe target must use HTTPS")
        return v

class FeedbackRequest(BaseModel):
    scan_id: Optional[str] = None
    category: str
    message: str = Field(min_length=5, max_length=4000)
    contact_email: Optional[str] = None
