"""Subscription filter criteria model with evaluation logic."""

import re
from typing import List, Optional
from pydantic import BaseModel, Field
from cve_tracker.models.cve import CVEItem, Severity


KEYWORD_SYNONYMS = {
    "rce": ["rce", "remote code execution", "code execution"],
    "sqli": ["sqli", "sql injection"],
    "xss": ["xss", "cross-site scripting"],
    "dos": ["dos", "denial of service"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "lfi": ["lfi", "local file inclusion"],
    "rfi": ["rfi", "remote file inclusion"],
    "privesc": ["privesc", "privilege escalation"],
}


class SubscriptionFilter(BaseModel):
    """Filter configuration applied to match CVEs for a specific subscriber."""

    min_cvss: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    min_epss: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    severities: List[Severity] = Field(default_factory=list)
    vendors: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    cwes: List[str] = Field(default_factory=list)
    watchlist: List[str] = Field(default_factory=list)
    cisa_kev_only: bool = False
    has_poc_only: bool = False

    def matches(self, cve: CVEItem) -> bool:
        """
        Evaluate whether a CVE matches the subscriber's filter criteria.
        Empty filter lists mean 'no restriction' on that field.
        """
        # CISA KEV filter
        if self.cisa_kev_only and not cve.is_cisa_kev:
            return False

        # PoC requirement
        if self.has_poc_only and not cve.poc_urls:
            return False

        # Minimum CVSS
        if self.min_cvss is not None:
            cve_score = cve.cvss.score if cve.cvss else None
            if cve_score is None or cve_score < self.min_cvss:
                return False

        # Minimum EPSS exploitation probability
        if self.min_epss is not None:
            if cve.epss_score is None or cve.epss_score < self.min_epss:
                return False

        # Severity filter
        if self.severities:
            if cve.severity not in self.severities:
                return False

        # CWE filter
        if self.cwes:
            norm_filter_cwes = {c.upper() for c in self.cwes}
            norm_cve_cwes = {c.upper() for c in cve.cwes}
            if not norm_filter_cwes.intersection(norm_cve_cwes):
                # Check if CWE string is in description as fallback
                desc_upper = cve.description.upper()
                if not any(c in desc_upper for c in norm_filter_cwes):
                    return False

        # Prepare searchable text corpus for vendors, products, and keywords
        search_corpus = " ".join([
            cve.id.lower(),
            (cve.title or "").lower(),
            cve.description.lower(),
            " ".join(v.lower() for v in cve.affected_vendors),
            " ".join(p.lower() for p in cve.affected_products),
        ])

        # Vendor matching
        if self.vendors:
            if not any(v.lower() in search_corpus for v in self.vendors):
                return False

        # Product matching
        if self.products:
            if not any(p.lower() in search_corpus for p in self.products):
                return False

        # Keyword matching (supports acronyms like 'rce' -> 'remote code execution')
        if self.keywords:
            matched = False
            for k in self.keywords:
                k_clean = k.strip().lower()
                if not k_clean:
                    continue
                variants = KEYWORD_SYNONYMS.get(k_clean, [k_clean])
                for var in variants:
                    if len(var) <= 4:
                        if re.search(rf"\b{re.escape(var)}\b", search_corpus):
                            matched = True
                            break
                    elif var in search_corpus:
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                return False

        # Watchlist matching (direct asset tracking, skip empty strings)
        if self.watchlist:
            valid_items = [item.strip().lower() for item in self.watchlist if item.strip()]
            if valid_items and not any(item in search_corpus for item in valid_items):
                return False

        return True
