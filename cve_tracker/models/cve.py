"""Pydantic v2 domain models for Vulnerability and CVE representations."""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, computed_field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_score(cls, score: Optional[float]) -> "Severity":
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.UNKNOWN


class SourceType(str, Enum):
    NVD = "NVD"
    CISA_KEV = "CISA_KEV"
    GITHUB = "GITHUB"


class CVSSData(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: Optional[str] = None
    score: Optional[float] = None
    vector_string: Optional[str] = None
    severity: Severity = Severity.UNKNOWN


class Reference(BaseModel):
    model_config = ConfigDict(frozen=True)

    url: str
    tags: List[str] = Field(default_factory=list)

    @property
    def is_exploit(self) -> bool:
        lower_url = self.url.lower()
        exploit_domains = [
            "exploit-db.com",
            "packetstormsecurity.com",
            "cxsecurity.com",
            "0day.today",
            "sploitus.com",
            "seclists.org/fulldisclosure",
        ]
        tag_markers = ["exploit", "proof of concept", "technical description"]
        matches_tag = any(m in tag.lower() for tag in self.tags for m in tag_markers)
        matches_domain = any(marker in lower_url for marker in exploit_domains)
        matches_github_poc = "github.com" in lower_url and any(
            k in lower_url for k in ("/poc", "-poc", "poc-", "/exploit", "-exploit", "cve-")
        )
        return matches_tag or matches_domain or matches_github_poc


class CVEItem(BaseModel):
    """Normalized, strictly validated vulnerability entity."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., pattern=r"^(CVE-\d{4}-\d{4,}|GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})$")
    source: SourceType
    description: str
    title: Optional[str] = None
    cvss: Optional[CVSSData] = None
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    references: List[Reference] = Field(default_factory=list)
    cwes: List[str] = Field(default_factory=list)
    affected_vendors: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)
    is_cisa_kev: bool = False
    cisa_action_due: Optional[datetime] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    @computed_field
    @property
    def poc_urls(self) -> List[str]:
        return [ref.url for ref in self.references if ref.is_exploit]

    @computed_field
    @property
    def severity(self) -> Severity:
        if self.cvss and self.cvss.severity != Severity.UNKNOWN:
            return self.cvss.severity
        score = self.cvss.score if self.cvss else None
        return Severity.from_score(score)

    @computed_field
    @property
    def content_hash(self) -> str:
        """SHA-256 hash representing meaningful vulnerability updates.
        
        Quantizes EPSS score into discrete risk bands to prevent daily micro-decimal
        fluctuations from triggering duplicate notification loops.
        """
        epss_band = 0
        if self.epss_score is not None:
            if self.epss_score >= 0.50:
                epss_band = 3
            elif self.epss_score >= 0.25:
                epss_band = 2
            elif self.epss_score >= 0.10:
                epss_band = 1

        cvss_str = f"{self.cvss.score:.1f}" if self.cvss and self.cvss.score is not None else ""
        raw = f"{self.id}|{cvss_str}|{self.severity.value}|{epss_band}|{self.is_cisa_kev}|{self.description[:150]}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
