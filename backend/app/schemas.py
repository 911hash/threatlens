"""
Pydantic schemas for request validation and API responses.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect (will be checked for SSRF)")
    force_rescan: bool = Field(False, description="Bypass cache and perform fresh lookups")


class AnalyzeHashRequest(BaseModel):
    hash: str = Field(..., description="MD5, SHA-1, or SHA-256 hash")


class FactorResponse(BaseModel):
    id: str
    group: str
    type: str
    severity: str
    points: int
    title: str
    description: str
    source: str
    evidence_ref: Dict[str, Any] = Field(default_factory=dict)


class AttackChainNode(BaseModel):
    id: str
    label: str
    type: str  # url, redirect, domain, ip, process, action, threat
    status: str  # safe, suspicious, malicious, neutral
    details: Optional[str] = None


class AttackChainLink(BaseModel):
    source: str
    target: str
    label: Optional[str] = None


class AttackChainGraph(BaseModel):
    nodes: List[AttackChainNode]
    links: List[AttackChainLink]


class SourceResult(BaseModel):
    name: Optional[str] = None
    status: str
    data: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    cached: Optional[bool] = None
    fetched_at: Optional[str] = None

    @model_validator(mode="after")
    def validate_status_data_consistency(self):
        has_data = self.data is not None and bool(self.data)
        if has_data and self.status in ("no_data", "error"):
            raise ValueError(
                f"SourceResult invariant violation: status cannot be '{self.status}' when data is populated: {self.data}"
            )
        if self.status == "no_data" and has_data:
            raise ValueError("SourceResult invariant violation: status 'no_data' requires data to be None or empty")
        return self


class ScanResponse(BaseModel):
    id: str
    target: str
    target_type: str
    timestamp: datetime
    risk_score: int
    risk_level: str
    confidence: int
    detection_count: int
    total_engines: int
    factors: List[FactorResponse]
    group_breakdown: Dict[str, int]
    raw_summary: Dict[str, Any]
    sources: Dict[str, Any]
    attack_chain: AttackChainGraph
    is_demo: bool
    explanation: str
    recommended_action: str
    defanged_target: Optional[str] = None
    delta_vs_previous: Optional[int] = None
    level_changed_vs_previous: Optional[bool] = None
    previous_scan_id: Optional[str] = None
    geo_results: List[Dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_sources_consistency(self):
        if self.sources:
            for s_name, s_val in self.sources.items():
                if isinstance(s_val, dict) and "status" in s_val:
                    SourceResult(**s_val)
        return self


class CompareResponse(BaseModel):
    score_delta: int
    detection_delta: int
    level_change: Dict[str, Any]
    factors_added: List[FactorResponse]
    factors_removed: List[FactorResponse]
    factors_changed: List[Dict[str, Any]]
    redirect_chain_change: Dict[str, Any]
    reputation_changes: Dict[str, Any]
    summary: str
    scan_a_id: Optional[str] = None
    scan_b_id: Optional[str] = None
    scan_a_timestamp: Optional[Any] = None
    scan_b_timestamp: Optional[Any] = None
    scan_a_score: int
    scan_b_score: int
    scan_a_level: str
    scan_b_level: str


class WatchlistCreate(BaseModel):
    target: str
    target_type: str = "url"


class WatchlistResponse(BaseModel):
    id: str
    target: str
    target_type: str
    added_at: datetime
    last_scanned_at: Optional[datetime] = None
    last_level: Optional[str] = None
    last_score: Optional[int] = None
    active: bool


class AlertResponse(BaseModel):
    id: str
    target: str
    scan_id: str
    previous_scan_id: Optional[str] = None
    kind: str
    message: str
    created_at: datetime
    seen: bool


class HealthResponse(BaseModel):
    status: str
    configured_sources: Dict[str, bool]
    demo_mode: bool
    timestamp: str


class SourceConfigItem(BaseModel):
    configured: bool
    type: str


class LLMProviderConfigItem(BaseModel):
    provider: str
    configured: bool


class LLMChainConfig(BaseModel):
    primary: LLMProviderConfigItem
    fallback_1: LLMProviderConfigItem
    fallback_2: LLMProviderConfigItem


class HealthConfigResponse(BaseModel):
    sources: Dict[str, SourceConfigItem]
    llm: LLMChainConfig
    demo_mode: bool


class EmailAttachment(BaseModel):
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    md5: Optional[str] = None
    is_suspicious: bool = False


class EmailParseResult(BaseModel):
    message_id: Optional[str] = None
    date: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    to_addresses: List[str] = Field(default_factory=list)
    cc_addresses: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    headers: Dict[str, Any] = Field(default_factory=dict)
    plain_body: Optional[str] = None
    html_body: Optional[str] = None
    sanitized_html: Optional[str] = None
    attachments: List[EmailAttachment] = Field(default_factory=list)
    sender_ips: List[str] = Field(default_factory=list)
    hop_count: int = 0
    is_malformed: bool = False
    parse_errors: List[str] = Field(default_factory=list)


class EmailAuthResult(BaseModel):
    spf: str = "none"  # pass, fail, none, neutral
    dkim: str = "none"  # pass, fail, none, neutral
    dmarc: str = "none"  # pass, fail, none
    arc: str = "none"  # pass, fail, none
    spf_domain: Optional[str] = None
    dkim_domain: Optional[str] = None
    from_domain: Optional[str] = None
    spf_aligned: Optional[bool] = None
    dkim_aligned: Optional[bool] = None
    dmarc_policy: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class EmailHeaderHop(BaseModel):
    hop_index: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[int] = None


class EmailHeaderAnalysis(BaseModel):
    hop_count: int = 0
    hops: List[EmailHeaderHop] = Field(default_factory=list)
    timing_gaps: List[str] = Field(default_factory=list)
    unexpected_relays: List[str] = Field(default_factory=list)
    has_timing_anomaly: bool = False
    sender_reply_to_mismatch: bool = False
    mismatch_details: Optional[str] = None
    x_spam_status: Optional[str] = None
    x_mailer: Optional[str] = None
    x_originating_ip: Optional[str] = None
    sender_ips: List[str] = Field(default_factory=list)
    geo_results: List["GeoLocationResponse"] = Field(default_factory=list)
    anomalies: List[str] = Field(default_factory=list)


class GeoLocationResponse(BaseModel):
    ip: str
    country: str = "unknown"
    country_code: Optional[str] = None
    region: str = "unknown"
    city: str = "unknown"
    lat: Optional[float] = None
    lon: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_unknown: bool = False
    cached: bool = False


class EmailAnalysisResponse(BaseModel):
    id: str
    target: str
    target_type: str = "email"
    subject: Optional[str] = None
    timestamp: datetime
    risk_score: int
    risk_level: str
    confidence: int
    detection_count: int
    total_engines: int
    factors: List[FactorResponse]
    group_breakdown: Dict[str, int]
    raw_summary: Dict[str, Any]
    sources: Dict[str, Any]
    attack_chain: AttackChainGraph
    is_demo: bool
    explanation: str
    recommended_action: str
    defanged_target: Optional[str] = None
    delta_vs_previous: Optional[int] = None
    level_changed_vs_previous: Optional[bool] = None
    previous_scan_id: Optional[str] = None
    parse_result: EmailParseResult
    auth_result: EmailAuthResult
    header_analysis: EmailHeaderAnalysis
    sanitized_html: Optional[str] = None
    file_sha256: Optional[str] = None
    file_size: Optional[int] = None
    geo_results: List[GeoLocationResponse] = Field(default_factory=list)
    privacy_mode: str = "full"
    llm_result: Optional[Dict[str, Any]] = None
    anonymized_prompt: Optional[str] = None


