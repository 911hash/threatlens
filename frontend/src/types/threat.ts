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
  target_type: 'url' | 'hash' | 'file';
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
}

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
