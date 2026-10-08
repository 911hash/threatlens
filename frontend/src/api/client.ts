import type {
  AlertItem,
  CompareResult,
  DemoInfo,
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
};
