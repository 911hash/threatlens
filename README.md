# ThreatLens

> **"VirusTotal tells you what security engines found. ThreatLens tells you what it means."**

**ThreatLens is an explainability and threat-evolution layer, not a replacement for antivirus engines.**

ThreatLens bridges the gap between raw, opaque telemetry (such as "14/72 engines flagged this URL") and actionable, explainable security decisions. It provides transparent scoring, historical verdict evolution tracking ("What changed?"), attack/redirect chain visualization, and executive plain-English summaries.

---

## 1. What It Is & The Problem It Solves

### The Problem
Traditional threat intelligence databases like VirusTotal excel at cataloging what security vendors detect at a single moment in time. However, security analysts, incident responders, and executives routinely face critical pain points:
- **Opaque Scoring**: What does "4 detections" mean? Is it a high-confidence malware delivery site, or three legacy heuristics flagging an expired certificate?
- **No Temporal Context (Verdict Drift)**: Attackers do not launch campaigns statically. A domain starts benign, builds reputation, modifies its redirect chain to point to credential harvesters, and is subsequently blacklisted. Traditional tools provide a snapshot without highlighting *what specifically changed*.
- **Double Counting**: If five vendors ingest the same public blacklist feed, their 5 hits represent 1 independent signal, not 5 separate corroborations.
- **Jargon & Decision Paralysis**: Non-specialists and decision makers need clear, plain-English guidance on what to do (e.g. "Do not enter credentials; revoke active sessions"), not just a wall of detection strings.

### The Solution: ThreatLens
ThreatLens acts as an explainable interpretation layer sitting on top of multi-source intelligence:
- **Transparent Scoring Formula**: Every point in the 0–100 risk score is mapped to visible evidence groups with explicit caps (`AV_DETECTIONS`, `REPUTATION_LISTS`, `DOMAIN_INFRA`, `BEHAVIOR`, `MITIGATING`) to mathematically prevent double-counting.
- **Verdict Drift Tracking ("What Changed?")**: Deterministic comparative diffs highlight exact changes across scans: score deltas, added/removed factors, redirect hop deviations, and reputation feed additions.
- **Independent Multi-Source Correlation**: Balances keyless sources (DNS resolution, RDAP domain age, crt.sh Certificate Transparency, OpenPhish) and keyed sources (VirusTotal, Google Safe Browsing, abuse.ch URLhaus) to compute an explicit **Confidence Score** (0–100%).
- **Attack Chain Graph**: Hand-crafted interactive SVG/CSS visualization tracing traffic flow through intermediate redirects, hosting ASN/IPs, and final landing destinations.
- **Plain English Perspective**: Deterministic, LLM-free executive summaries for non-technical stakeholders alongside complete technical evidence breakdowns for SOC analysts.

---

## 2. Why It Differs from VirusTotal

| Capability | VirusTotal | ThreatLens |
| :--- | :--- | :--- |
| **Primary Goal** | Massive malware & scanner aggregation database | Explainability, correlation & evolution layer |
| **Scoring Model** | Engine count ratio (e.g. 14/72) | Transparent 0–100 score with group caps & anti-double-counting |
| **Confidence Metric** | Implicit | Explicit 0–100% score based on independent source agreement |
| **Verdict Evolution** | Historical scan timestamps | Direct comparative diffs ("What Changed?") with deterministic summaries |
| **Attack Chain** | Multi-hop relationship graphs | Lightweight, focused redirect & infrastructure flow visualization |
| **Language** | Security vendor technical tags | Dual-view: Plain English (executive) + Technical (SOC analyst) |
| **Privacy Default** | Public submissions scanned & shared globally | Private lookup only by default; zero file uploads without explicit consent |

---

## 3. Architecture & Tech Stack

ThreatLens is designed as a modular, responsive full-stack system:

```
[ Client: React 18 + TS + Tailwind + Vite ]
                    │
            HTTP / REST (Port 5173 -> 8000)
                    ▼
[ FastAPI App (Python 3.11+) ]
   ├── SSRF Protection & Safe DNS Resolver (socket / ipaddress)
   ├── Pure Risk Engine (Deterministic, Zero I/O)
   ├── Comparison Service (Verdict Drift & Metric Diffs)
   ├── Background Watchlist Monitor (Asyncio Task)
   └── SQLite Database (SQLAlchemy 2.x)
```

### Stack Breakdown:
- **Frontend**:
  - React 18 + TypeScript + Vite
  - Tailwind CSS v3 for high-density SOC styling
  - Lucide React for consistent icons
  - Recharts for time-series verdict evolution charts
  - Hand-crafted SVG/CSS for Attack Chain Graphs (zero React Flow dependency)
  - React Router v6
- **Backend**:
  - Python 3.11+
  - FastAPI + Pydantic v2
  - SQLite + SQLAlchemy 2.x
  - `httpx` (async HTTP client with timeouts & streaming)
  - Pure deterministic scoring module (isolated from network & database)
- **Servers & Ports**:
  - Backend: `http://localhost:8000`
  - Frontend: `http://localhost:5173`

---

## 4. Setup & Running Locally

### Prerequisites
- Python 3.11+ installed and on your PATH
- Node.js 18+ (Node 20+ recommended) and `npm`

### One-Command Start (Linux / macOS)
```bash
chmod +x dev.sh
./dev.sh
```
`dev.sh` will:
1. Copy `.env.example` to `.env` if not present.
2. Create `backend/venv`, activate it, and install `requirements.txt`.
3. Install frontend dependencies via `npm install`.
4. Launch the FastAPI backend on port 8000 and the Vite frontend on port 5173 concurrently.

### One-Command Start (Windows PowerShell)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\dev.ps1
```
Or start manually in two terminal tabs:
```powershell
# Terminal 1: Backend
cd backend
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
$env:PYTHONPATH = "backend"
.\venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm install
npm run dev -- --host
```

---

## 5. Environment Variables & Demo Mode

ThreatLens runs **100% out of the box in DEMO MODE** with zero external API keys required. All simulated data is clearly labeled `[DEMO / SIMULATED]`.

Copy `.env.example` to `.env`:
```ini
# Optional Keyed Threat Feeds
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
ABUSECH_AUTH_KEY=

# Privacy Toggles (Strict Default False)
ALLOW_VT_URL_SUBMISSION=false
ALLOW_FILE_UPLOAD_TO_VT=false

# Networking & Scheduling
FRONTEND_ORIGIN=http://localhost:5173
VITE_API_BASE_URL=http://localhost:8000
WATCHLIST_INTERVAL_MINUTES=15
```

### Evidence Sources:
- **Keyless / Free (Active by default)**:
  - DNS resolution (A/AAAA/MX/NS via socket)
  - RDAP for registrar and domain age (newly registered domain detection)
  - crt.sh Certificate Transparency (certificate age, typosquatting SANs)
  - OpenPhish community feed (cached in-memory, refreshed periodically)
- **Keyed (Optional)**:
  - VirusTotal API v3 (URL & file hash lookups with 4 req/min token bucket & 10-minute caching)
  - Google Safe Browsing API v4
  - Abuse.ch URLhaus API

---

## 6. Security & SSRF Protection

Because ThreatLens actively traces URL redirect chains across the public web, strict enterprise SSRF defenses are enforced:
1. **Scheme Restriction**: Allows only `http://` and `https://`. Rejects all exotic schemes (`file://`, `ftp://`, `gopher://`).
2. **Pre-Flight DNS Resolution & IP Blocklist**: Resolves hostnames before making HTTP requests and blocks:
   - Loopback (`127.0.0.0/8`, `::1`)
   - RFC 1918 Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local and Carrier-Grade NAT (`169.254.0.0/16`, `100.64.0.0/10`)
   - Cloud metadata IP (`169.254.169.254`)
   - IPv6 unique local and link-local (`fc00::/7`, `fe80::/10`)
3. **Per-Hop Redirect Validation**: Re-validates the resolved destination IP at **every single redirect hop** to prevent DNS rebinding or redirect-to-internal attacks.
4. **Budget & Body Limits**: Maximum 5 redirects, 5-second per-request timeout, 10-second total budget. Uses `HEAD` first, falls back to streamed `GET` and terminates immediately after headers (no large body downloads).
5. **Port & Credential Filtering**: Only standard ports 80 and 443 permitted. Userinfo (`user:pass@host`) is rejected.
6. **Defanging Everywhere**: All displayed URLs and network indicators are defanged by default (`hxxp://`, `example[.]com`) with an interactive toggle to prevent accidental clicks.

---

## 7. Privacy Guarantees

1. **No Automatic URL Submission**: By default, URLs are looked up by report hash only (`ALLOW_VT_URL_SUBMISSION=false`). They are never submitted to public scanning engines without consent.
2. **Zero File Uploads**: Uploaded files are stream-hashed in memory (`SHA-256`, `SHA-1`, `MD5`) and looked up by hash. Binary file contents are **never saved to disk** and never uploaded to external services unless `ALLOW_FILE_UPLOAD_TO_VT=true`.

---

## 8. API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, active telemetry connections, demo mode status |
| `POST` | `/api/analyze/url` | Analyze URL with SSRF-safe redirect tracing & multi-source scoring |
| `POST` | `/api/analyze/hash` | Analyze MD5/SHA-1/SHA-256 hash |
| `POST` | `/api/analyze/file` | Stream-hash file (up to 32MB) and look up threat reputation |
| `GET` | `/api/scans` | Paginated investigation history |
| `GET` | `/api/scans/{id}` | Retrieve individual scan report |
| `GET` | `/api/history/{target}` | Retrieve all scans recorded for a specific target |
| `GET` | `/api/compare/{id1}/{id2}`| Comparative verdict drift diff between two scans |
| `GET` | `/api/watchlist` | Retrieve monitored targets and scan states |
| `POST` | `/api/watchlist` | Add target to scheduled watchlist |
| `DELETE` | `/api/watchlist/{id}` | Remove target from watchlist |
| `POST` | `/api/watchlist/{id}/rescan` | Manually trigger rescan of monitored target |
| `GET` | `/api/alerts` | List threat escalation notifications |
| `POST` | `/api/demo/seed` | Seed demo dataset (`?reset=true` wipes and re-seeds clean baseline) |
| `POST` | `/api/demo/reset` | Shortcut to reset demo dataset to pristine baseline |

---

## 9. Limitations & Future Improvements

### Limitations
- **No Native Antivirus Engine**: ThreatLens does not dissemble binaries or run an in-house malware scanning engine.
- **RDAP Rate Limits**: Public RDAP endpoints can rate-limit high-throughput bulk queries.
- **Keyless DNS Visibility**: Passive DNS and historical DNS records require commercial feeds (e.g. SecurityTrails/Farsight).

### Future Improvements
- **Automated Sandbox Detonation**: Native integration with Cuckoo / CAPE sandbox for live behavioral capture.
- **MITRE ATT&CK Matrix Mapping**: Dynamic mapping of behavioral factors to ATT&CK tactics and techniques.
- **Enterprise Webhook Integrations**: Slack, Microsoft Teams, and PagerDuty notifications for watchlist drift alerts.
- **Custom Policy Ensembles**: Configurable scoring weights tailored to specific enterprise risk appetites.
