"""
Pydantic schemas for request validation and API responses.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


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
