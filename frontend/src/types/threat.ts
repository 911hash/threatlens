export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';

export interface Factor {
  id: string;
  group: 'AV_DETECTIONS' | 'REPUTATION_LISTS' | 'DOMAIN_INFRA' | 'BEHAVIOR' | 'MITIGATING' | string;
  type: 'indicator' | 'mitigating' | 'neutral' | 'conflict' | string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical' | string;
  points: number;
  title: string;
  description: string;
  source: string;
  evidence_ref?: Record<string, any>;
}

export interface AttackChainNode {
  id: string;
  label: string;
  type: 'url' | 'redirect' | 'domain' | 'ip' | 'process' | 'action' | 'threat' | string;
  status: 'safe' | 'suspicious' | 'malicious' | 'neutral' | string;
  details?: string;
}

export interface AttackChainLink {
  source: string;
  target: string;
  label?: string;
}

export interface AttackChainGraph {
  nodes: AttackChainNode[];
  links: AttackChainLink[];
}

export interface Scan {
  id: string;
  target: string;
  target_type: 'url' | 'hash' | 'file' | 'email';
  timestamp: string;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  detection_count: number;
  total_engines: number;
  factors: Factor[];
  group_breakdown: Record<string, number>;
  raw_summary: Record<string, any>;
  sources: Record<string, any>;
  attack_chain: AttackChainGraph;
  is_demo: boolean;
  explanation: string;
  recommended_action: string;
  defanged_target?: string;
  delta_vs_previous?: number;
  level_changed_vs_previous?: boolean;
  previous_scan_id?: string;
  // Email-specific extensions
  parse_result?: EmailParseResult;
  auth_result?: EmailAuthResult;
  header_analysis?: EmailHeaderAnalysis;
  sanitized_html?: string;
  file_sha256?: string;
  file_size?: number;
  geo_results?: GeoLocation[];
  privacy_mode?: 'hash_only' | 'full' | string;
  llm_result?: LLMResult;
  anonymized_prompt?: string;
  gmail_id?: string;
}

export interface LLMResult {
  summary: string;
  provider_used: string;
  latency_ms: number;
  cache_hit: boolean;
  raw_response?: string;
  anonymized_prompt?: string;
}

export interface GmailAuthStatus {
  connected: boolean;
  email: string | null;
  connected_at?: string | null;
  last_sync_at?: string | null;
}

export interface InboxItem {
  gmail_id: string;
  message_id?: string;
  subject?: string;
  from_address?: string;
  from_domain?: string;
  date?: string;
  risk_score: number;
  risk_level: RiskLevel;
  has_geo: boolean;
  has_ai: boolean;
  scan_id: string;
}

export interface GeoLocation {
  ip: string;
  country: string;
  country_code?: string;
  region: string;
  city: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  asn?: string;
  org?: string;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  is_unknown: boolean;
  cached: boolean;
}

export interface EmailAttachment {
  filename: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  md5?: string;
  is_suspicious: boolean;
}

export interface EmailAuthResult {
  spf: 'pass' | 'fail' | 'none' | 'neutral' | string;
  dkim: 'pass' | 'fail' | 'none' | 'neutral' | string;
  dmarc: 'pass' | 'fail' | 'none' | string;
  arc: 'pass' | 'fail' | 'none' | string;
  spf_domain?: string;
  dkim_domain?: string;
  from_domain?: string;
  spf_aligned?: boolean;
  dkim_aligned?: boolean;
  dmarc_policy?: string;
  details?: Record<string, any>;
}

export interface EmailHeaderHop {
  hop_index: number;
  from_host?: string;
  by_host?: string;
  ip?: string;
  timestamp?: string;
  delay_seconds?: number;
}

export interface EmailHeaderAnalysis {
  hop_count: number;
  hops: EmailHeaderHop[];
  timing_gaps: string[];
  unexpected_relays: string[];
  has_timing_anomaly: boolean;
  sender_reply_to_mismatch: boolean;
  mismatch_details?: string;
  x_spam_status?: string;
  x_mailer?: string;
  x_originating_ip?: string;
  sender_ips?: string[];
  geo_results?: GeoLocation[];
  anomalies: string[];
}

export interface EmailParseResult {
  message_id?: string;
  date?: string;
  subject?: string;
  sender?: string;
  from_address?: string;
  from_domain?: string;
  to_addresses: string[];
  cc_addresses: string[];
  reply_to?: string;
  headers: Record<string, any>;
  plain_body?: string;
  html_body?: string;
  sanitized_html?: string;
  attachments: EmailAttachment[];
  sender_ips: string[];
  hop_count: number;
  is_malformed: boolean;
  parse_errors: string[];
}

export type EmailAnalysisResponse = Scan;

export interface CompareResult {
  score_delta: number;
  detection_delta: number;
  level_change: {
    from: string;
    to: string;
    changed: boolean;
  };
  factors_added: Factor[];
  factors_removed: Factor[];
  factors_changed: Array<{
    id: string;
    title: string;
    old_points: number;
    new_points: number;
    old_severity: string;
    new_severity: string;
    source?: string;
  }>;
  redirect_chain_change: {
    final_domain_changed: boolean;
    hop_count_delta: number;
    from_domain: string;
    to_domain: string;
    from_hops: number;
    to_hops: number;
  };
  reputation_changes: {
    newly_flagged: string[];
    unflagged: string[];
  };
  summary: string;
  scan_a_id?: string;
  scan_b_id?: string;
  scan_a_timestamp?: string;
  scan_b_timestamp?: string;
  scan_a_score: number;
  scan_b_score: number;
  scan_a_level: string;
  scan_b_level: string;
}

export interface WatchlistItem {
  id: string;
  target: string;
  target_type: string;
  added_at: string;
  last_scanned_at?: string;
  last_level?: string;
  last_score?: number;
  active: boolean;
}

export interface AlertItem {
  id: string;
  target: string;
  scan_id: string;
  previous_scan_id?: string;
  kind: string;
  message: string;
  created_at: string;
  seen: boolean;
}

export interface HealthStatus {
  status: string;
  configured_sources: Record<string, boolean>;
  demo_mode: boolean;
  timestamp: string;
}

export interface SourceConfigItem {
  configured: boolean;
  type: 'keyed' | 'keyless' | string;
}

export interface LLMProviderConfigItem {
  provider: string;
  configured: boolean;
}

export interface HealthConfig {
  sources: {
    virustotal: SourceConfigItem;
    google_safe_browsing: SourceConfigItem;
    urlhaus: SourceConfigItem;
    openphish: SourceConfigItem;
    rdap: SourceConfigItem;
    dns: SourceConfigItem;
    crtsh: SourceConfigItem;
    [key: string]: SourceConfigItem;
  };
  llm: {
    primary: LLMProviderConfigItem;
    fallback_1: LLMProviderConfigItem;
    fallback_2: LLMProviderConfigItem;
  };
  demo_mode: boolean;
}

export interface DemoInfo {
  is_demo: boolean;
  label: string;
  featured_target: string;
  sample_targets: Array<{
    target: string;
    type: string;
    label: string;
    description: string;
  }>;
}
