import type {
  AlertItem,
  Case,
  CaseAudit,
  CaseComment,
  CaseItem,
  CompareResult,
  DemoInfo,
  ForensicEvent,
  GraphEdge,
  GraphNode,
  GraphPivot,
  HealthConfig,
  HealthStatus,
  Scan,
  WatchlistItem,
} from '../types/threat';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMsg = `Server error (${res.status})`;
    try {
      const errorJson = await res.json();
      if (errorJson.error && errorJson.error.message) {
        errorMsg = errorJson.error.message;
      } else if (errorJson.detail) {
        errorMsg = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(errorMsg);
  }
  return res.json();
}

export const api = {
  async getHealth(): Promise<HealthStatus> {
    const res = await fetch(`${API_BASE}/api/health`);
    return handleResponse<HealthStatus>(res);
  },

  async getHealthConfig(): Promise<HealthConfig> {
    const res = await fetch(`${API_BASE}/api/health/config`);
    return handleResponse<HealthConfig>(res);
  },

  async getDemoInfo(): Promise<DemoInfo> {
    const res = await fetch(`${API_BASE}/api/demo`);
    return handleResponse<DemoInfo>(res);
  },

  async seedDemo(reset = false): Promise<{ status: string; message: string; featured_target: string; featured_scan_id: string }> {
    const url = reset ? `${API_BASE}/api/demo/seed?reset=true` : `${API_BASE}/api/demo/seed`;
    const res = await fetch(url, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  async resetDemo(): Promise<{ status: string; message: string; featured_target: string; featured_scan_id: string }> {
    return this.seedDemo(true);
  },

  async analyzeUrl(url: string, forceRescan = false): Promise<Scan> {
    const res = await fetch(`${API_BASE}/api/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, force_rescan: forceRescan }),
    });
    return handleResponse<Scan>(res);
  },

  async analyzeHash(hash: string): Promise<Scan> {
    const res = await fetch(`${API_BASE}/api/analyze/hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash }),
    });
    return handleResponse<Scan>(res);
  },

  async analyzeFile(file: File): Promise<Scan> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/analyze/file`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<Scan>(res);
  },

  async analyzeEmail(file: File): Promise<Scan> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/analyze/email`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<Scan>(res);
  },

  async getScans(type?: string, limit = 50, offset = 0): Promise<Scan[]> {
    const query = new URLSearchParams();
    if (type && type !== 'all') query.append('type', type);
    query.append('limit', limit.toString());
    query.append('offset', offset.toString());
    const res = await fetch(`${API_BASE}/api/scans?${query.toString()}`);
    return handleResponse<Scan[]>(res);
  },

  async getScan(id: string): Promise<Scan> {
    const res = await fetch(`${API_BASE}/api/scans/${id}`);
    return handleResponse<Scan>(res);
  },

  async getTargetHistory(target: string): Promise<{
    target: string;
    total_scans: number;
    first_scanned: string;
    last_scanned: string;
    scans: Scan[];
  }> {
    const res = await fetch(`${API_BASE}/api/history/${encodeURIComponent(target)}`);
    return handleResponse(res);
  },

  async compareScans(id1: string, id2: string): Promise<CompareResult> {
    const res = await fetch(`${API_BASE}/api/compare/${id1}/${id2}`);
    return handleResponse<CompareResult>(res);
  },

  async getWatchlist(): Promise<WatchlistItem[]> {
    const res = await fetch(`${API_BASE}/api/watchlist`);
    return handleResponse<WatchlistItem[]>(res);
  },

  async addToWatchlist(target: string, targetType = 'url'): Promise<WatchlistItem> {
    const res = await fetch(`${API_BASE}/api/watchlist`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, target_type: targetType }),
    });
    return handleResponse<WatchlistItem>(res);
  },

  async deleteFromWatchlist(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/api/watchlist/${id}`, {
      method: 'DELETE',
    });
    return handleResponse(res);
  },

  async rescanWatchlistItem(id: string): Promise<{ status: string; scan_id: string; score: number; level: string }> {
    const res = await fetch(`${API_BASE}/api/watchlist/${id}/rescan`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  async getAlerts(): Promise<AlertItem[]> {
    const res = await fetch(`${API_BASE}/api/alerts`);
    return handleResponse<AlertItem[]>(res);
  },

  async markAlertRead(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/api/alerts/${id}/read`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  // Gmail OAuth & Inbox API
  async getGmailStatus(): Promise<{ connected: boolean; email: string | null; connected_at?: string; last_sync_at?: string }> {
    const res = await fetch(`${API_BASE}/api/auth/gmail/status`);
    return handleResponse(res);
  },

  async disconnectGmail(): Promise<{ connected: boolean; disconnected: boolean; message: string }> {
    const res = await fetch(`${API_BASE}/api/auth/gmail/disconnect`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  async getInbox(page = 1, limit = 50): Promise<any[]> {
    const res = await fetch(`${API_BASE}/api/inbox?page=${page}&limit=${limit}`);
    return handleResponse<any[]>(res);
  },

  async syncInbox(): Promise<{ status: string; synced_count: number; last_sync_at?: string }> {
    const res = await fetch(`${API_BASE}/api/inbox/sync`, {
      method: 'POST',
    });
    return handleResponse(res);
  },

  async getInboxMessageDetail(gmailId: string): Promise<Scan> {
    const res = await fetch(`${API_BASE}/api/inbox/${encodeURIComponent(gmailId)}`);
    return handleResponse<Scan>(res);
  },

  // =====================================================================
  // PHASE 10: FORENSIC PLATFORM API
  // =====================================================================

  async getRecentGraphNodes(
    limit = 20
  ): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
    const res = await fetch(`${API_BASE}/api/graph/recent?limit=${limit}`);
    return handleResponse(res);
  },

  async getNodeNeighbors(
    nodeId: string,
    depth = 1
  ): Promise<{ root_id: string; nodes: GraphNode[]; edges: GraphEdge[] }> {
    const res = await fetch(`${API_BASE}/api/graph/nodes/${encodeURIComponent(nodeId)}?depth=${depth}`);
    return handleResponse(res);
  },

  async getNodePivot(nodeId: string): Promise<GraphPivot> {
    const res = await fetch(`${API_BASE}/api/graph/pivot/${encodeURIComponent(nodeId)}`);
    return handleResponse<GraphPivot>(res);
  },

  async lookupGraphNode(value: string, type?: string): Promise<GraphNode> {
    const url = type
      ? `${API_BASE}/api/graph/lookup?value=${encodeURIComponent(value)}&type=${encodeURIComponent(type)}`
      : `${API_BASE}/api/graph/lookup?value=${encodeURIComponent(value)}`;
    const res = await fetch(url);
    return handleResponse<GraphNode>(res);
  },

  async getTimeline(
    scanId: string,
    forceRebuild = false
  ): Promise<{ scan_id: string; events: ForensicEvent[] }> {
    const url = forceRebuild
      ? `${API_BASE}/api/timeline/${encodeURIComponent(scanId)}?force_rebuild=true`
      : `${API_BASE}/api/timeline/${encodeURIComponent(scanId)}`;
    const res = await fetch(url);
    return handleResponse(res);
  },

  async getCases(status?: string): Promise<Case[]> {
    const url = status ? `${API_BASE}/api/cases?status=${encodeURIComponent(status)}` : `${API_BASE}/api/cases`;
    const res = await fetch(url);
    return handleResponse<Case[]>(res);
  },

  async getCaseDetail(caseId: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}`);
    return handleResponse<Case>(res);
  },

  async createCase(payload: { title: string; description?: string }): Promise<Case> {
    const res = await fetch(`${API_BASE}/api/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return handleResponse<Case>(res);
  },

  async addCaseItem(caseId: string, scanId: string): Promise<CaseItem> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/items`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId }),
    });
    return handleResponse<CaseItem>(res);
  },

  async addCaseComment(caseId: string, body: string): Promise<CaseComment> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body }),
    });
    return handleResponse<CaseComment>(res);
  },

  async escalateCase(caseId: string, note: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/escalate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note }),
    });
    return handleResponse<Case>(res);
  },

  async resolveCase(caseId: string, note: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note }),
    });
    return handleResponse<Case>(res);
  },

  async reopenCase(caseId: string, note: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/reopen`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note }),
    });
    return handleResponse<Case>(res);
  },

  async getCaseAudit(caseId: string): Promise<CaseAudit[]> {
    const res = await fetch(`${API_BASE}/api/cases/${encodeURIComponent(caseId)}/audit`);
    return handleResponse<CaseAudit[]>(res);
  },
};

