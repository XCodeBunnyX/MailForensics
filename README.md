# GmailGuard — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> **Smart India Hackathon 2026 · Problem Statement SIH26106 · AICTE**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GmailGuard is a **defensive cybersecurity platform** that accepts a suspicious email (`.eml` / raw RFC 5322), runs a multi-signal automated analysis pipeline, and produces an explainable forensic intelligence report — usable by a security analyst without deep technical expertise.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Running the Backend](#running-the-backend)
- [Using the Dashboard](#using-the-dashboard)
- [CLI Usage](#cli-usage)
- [API Reference](#api-reference)
- [Running Tests](#running-tests)
- [ML Model](#ml-model)
- [Sample Emails](#sample-emails)
- [Security Notes](#security-notes)
- [Team](#team)

---

## Features

| Module | Capability |
|---|---|
| **Email Parser** | Parse `.eml` files; extract headers, body, attachments |
| **Header Analysis** | Mail-server hop chain, spoofing indicators, `Reply-To` mismatches |
| **Auth Analysis** | SPF / DKIM / DMARC result extraction from headers |
| **IP Intelligence** | Public IP extraction, ASN, ISP, organization lookup |
| **IP Geolocation** | Country / region / city via IPinfo API (approximate infrastructure location) |
| **URL Analysis** | URL extraction, suspicious TLD detection, IP-based URLs, HTTPS check |
| **URL Sandbox** | Dynamic browser execution via local Browserless Chromium in Docker (isolated, Playwright-driven, disposable contexts) |
| **Domain Intelligence** | Domain reputation, forensic DNS history |
| **Attachment Analysis** | Safe static analysis — filename, MIME, SHA-256, suspicious extensions; **no execution** |
| **Attachment Content** | PDF text extraction and keyword scanning (static only) |
| **OSINT Layer** | Passive IOC investigation across domains, IPs, URLs |
| **PhishTank** | Known phishing URL lookup |
| **ML Classifier** | SVM + TF-IDF phishing classifier with probability score |
| **Evidence Correlator** | Cross-vector evidence correlation engine |
| **Threat Scorer** | Explainable 0–100 threat score with per-category breakdown |
| **Forensic Report** | Full structured JSON report with IOCs, timeline, graph data |
| **SOC Dashboard** | Single-page web UI with D3 relationship graph, live browser screenshots, and telemetry |

---

## Architecture

```
Browser  ──►  FastAPI (backend/)  ──►  Analysis Pipeline
 (UI)         serves index.html        │
              /analyze  POST           ▼
              /health   GET     ┌─────────────────┐
                                │  email_parser   │
                                │  header_anal.   │
                                │  auth_anal.     │
                                │  ip_intel.      │
                                │  geolocation    │
                                │  url_analyzer   │
                                │  url_sandbox ───┼──► Local Browserless Docker (Chromium)
                                │  domain_intel   │
                                │  attach_anal.   │
                                │  ml_classif.    │
                                │  osint_intel.   │
                                │  phish_tank     │
                                │  evidence_cor.  │
                                │  threat_scorer  │
                                │  report_gen.    │
                                └─────────────────┘
```

### Browserless Local Sandbox Architecture

```
Email URL
  │
  ▼
GmailGuard Backend
  │  (SSRF Guard: blocks localhost, RFC 1918 private IPs, link-local metadata)
  ▼
Local Browserless Docker (ghcr.io/browserless/chromium :3000)
  │
  ▼
Playwright over CDP/WebSocket
  │
  ├─► Disposable Browser Context (no persistent cookies/storage)
  ├─► Live Page Screenshot Capture (/screenshots/{uuid}.png)
  ├─► Final Effective URL & Redirect Chain Tracking
  ├─► Network Monitoring (contacted domains, IPs, status codes, failed requests)
  ├─► JavaScript Telemetry (console messages, console/page errors)
  └─► Download Interception & Quarantine (zero execution, auto-cleanup)
  │
  ▼
Evidence Correlator ──► Threat Scorer ──► Forensic Report ──► SOC Dashboard
```

The FastAPI backend serves both the REST API **and** the static frontend from a single process — no separate frontend server needed.

---

## Project Structure

```
MailForensics/
├── index.html                        # SOC dashboard (served by FastAPI)
├── css/
│   └── main.css                      # Dashboard styles
├── js/
│   ├── app.js                        # Main application logic
│   ├── api.js                        # Backend API calls
│   ├── analyzer.js                   # Analysis result rendering
│   ├── graph.js                      # D3 relationship graph
│   ├── models.js                     # Data models
│   ├── report.js                     # Report rendering
│   └── data.js                       # Static reference data
├── assets/                           # Static assets
├── backend/
│   ├── main.py                       # Pipeline orchestrator + CLI entry
│   ├── api.py                        # FastAPI application + endpoints
│   ├── config.py                     # All configuration and constants
│   ├── email_parser.py               # .eml parsing
│   ├── header_analyzer.py            # Hop chain builder, spoofing detection
│   ├── authentication_analyzer.py    # SPF / DKIM / DMARC extraction
│   ├── ip_intelligence.py            # IP extraction and reputation
│   ├── geolocation.py                # IPinfo geolocation
│   ├── url_analyzer.py               # URL extraction and risk scoring
│   ├── url_sandbox.py                # urlscan.io dynamic sandbox
│   ├── domain_intelligence.py        # Domain reputation
│   ├── forensic_domain_intelligence.py  # DNS history, forensic context
│   ├── attachment_analyzer.py        # Static attachment metadata analysis
│   ├── attachment_content_analyzer.py   # PDF content inspection (static)
│   ├── ml_classifier.py              # SVM + TF-IDF phishing classifier
│   ├── osint_intelligence.py         # Passive OSINT IOC correlation
│   ├── phish_tank.py                 # PhishTank URL intelligence
│   ├── ioc_extractor.py              # IOC extraction layer
│   ├── evidence_correlator.py        # Cross-vector evidence correlation
│   ├── threat_scorer.py              # Explainable 0–100 threat score
│   ├── report_generator.py           # Unified forensic report builder
│   ├── models/
│   │   ├── gmailguard_svm.pkl        # Trained SVM classifier (git-ignored)
│   │   └── gmailguard_tfidf.pkl      # Trained TF-IDF vectorizer (git-ignored)
│   ├── mock_data/                    # Demo/mock data for offline dev
│   ├── sample_emails/                # Test .eml files
│   │   ├── phishing_bank.eml
│   │   ├── ceo_fraud.eml
│   │   └── legitimate.eml
│   ├── tests/                        # pytest test suite
│   └── requirements.txt
├── .env.example                      # Environment variable template (safe to commit)
├── .gitignore
└── README.md
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11 or higher | Backend & ML classifier |
| pip | Latest | Python package management |
| Git | Any recent version | Version control |
| Docker | Recent | For self-hosted Browserless Chromium sandbox |

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/XCodeBunnyX/MailForensics.git
cd MailForensics
```

### 2. Start the Local Browserless Docker Sandbox

GmailGuard uses a self-hosted Browserless Chromium container for safe, isolated dynamic URL inspection.

> **Important**: Browserless must be running before GmailGuard performs dynamic URL investigations.

```bash
docker run --rm \
  -p 3000:3000 \
  -e "TOKEN=gmailguard-local" \
  -e "CONCURRENT=2" \
  -e "TIMEOUT=60000" \
  --shm-size=2g \
  ghcr.io/browserless/chromium
```

### 3. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate      # macOS / Linux
# .venv\Scripts\activate       # Windows
```

### 4. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 5. Configure environment variables

```bash
cp .env.example backend/.env
# Open backend/.env and verify BROWSERLESS_URL=http://localhost:3000 and BROWSERLESS_TOKEN=gmailguard-local
```

### 6. Start the server

```bash
uvicorn backend.api:app --reload --host 0.0.0.0 --port 8000
```

### 7. Open the dashboard

Open your browser at **http://localhost:8000**

The dashboard and API are served from the same process — no separate frontend server needed.

---

## Environment Variables

Copy `.env.example` to `backend/.env` and configure as needed.

| Variable | Default / Required | Description |
|---|---|---|
| `BROWSERLESS_URL` | `http://localhost:3000` | Local Browserless Docker HTTP/WebSocket endpoint |
| `BROWSERLESS_TOKEN` | `gmailguard-local` | Authentication token for Browserless instance |
| `BROWSER_SANDBOX_ENABLED` | `true` | Set to `true` to enable dynamic URL investigation |
| `BROWSER_SANDBOX_TIMEOUT_MS` | `15000` | Page navigation and capture timeout in milliseconds |
| `BROWSER_SANDBOX_MAX_URLS` | `3` | Maximum number of URLs investigated per email |
| `MOCK_URLSCAN` | `false` | `true` to use mock sandbox data instead of live Browserless |
| `IPINFO_TOKEN` | Recommended | IPinfo API token for IP geolocation. Get at [ipinfo.io](https://ipinfo.io/signup) |
| `VIRUSTOTAL_API_KEY` | Optional | VirusTotal API key for forensic domain intelligence |
| `SECURITYTRAILS_API_KEY` | Optional | SecurityTrails API key for DNS history |
| `FORENSIC_PROVIDER` | `virustotal` | `virustotal` or `securitytrails` |
| `MOCK_THREAT_INTEL` | `true` | `true` = use mock domain intel (default: `true`) |
| `MOCK_OSINT` | `true` | `true` = use mock OSINT data (default: `true`) |
| `MOCK_PHISHTANK` | `true` | `true` = use mock PhishTank data (default: `true`) |
| `PHISHTANK_API_KEY` | Optional | PhishTank API key for live URL lookups |

> **Without any API keys**, the platform runs fully in demo/mock mode and still produces a complete forensic report. API keys only enable live external lookups.

---

## Running the Backend

### Development (with auto-reload)

```bash
uvicorn backend.api:app --reload --host 0.0.0.0 --port 8000
```

### Production

```bash
uvicorn backend.api:app --host 0.0.0.0 --port 8000 --workers 2
```

### Verify the server is running

```bash
curl http://localhost:8000/health
# {"status":"ok","service":"GmailGuard"}
```

---

## Using the Dashboard

1. Open **http://localhost:8000** in your browser
2. Click **Upload Email** and select a `.eml` file (or use the samples in `backend/sample_emails/`)
3. Click **Analyze**
4. Review:
   - **Threat Score** (0–100) and verdict
   - **Header Analysis** and hop chain
   - **Authentication** (SPF / DKIM / DMARC)
   - **IP Geolocation** map
   - **URL / Domain Intelligence** table
   - **Attachment Analysis**
   - **ML Prediction** with confidence
   - **Relationship Graph** (D3 interactive graph)
   - **IOC List**
   - **Forensic Report** (downloadable JSON)

---

## CLI Usage

Analyze an email directly from the terminal without starting the web server:

```bash
# Human-readable summary
python -m backend.main backend/sample_emails/phishing_bank.eml

# Full JSON report
python -m backend.main backend/sample_emails/phishing_bank.eml --pretty

# Save report to file
python -m backend.main backend/sample_emails/ceo_fraud.eml --pretty --output report.json
```

---

## API Reference

### GET /health

```bash
curl http://localhost:8000/health
# {"status":"ok","service":"GmailGuard"}
```

### POST /analyze

Upload a `.eml` file for full threat analysis.

```bash
curl -X POST http://localhost:8000/analyze \
  -F "file=@backend/sample_emails/phishing_bank.eml"
```

Response (abbreviated):

```json
{
  "threat_score": 87,
  "verdict": "HIGH RISK",
  "email": {
    "from": "security@paypa1-verify.com",
    "subject": "Urgent: Verify your account"
  },
  "authentication": { "spf": "fail", "dkim": "none", "dmarc": "fail" },
  "ml": { "prediction": "phishing", "confidence": 0.94 },
  "evidence": [...],
  "urls": {...},
  "attachments": {...},
  "forensics": {...}
}
```

### POST /analyze-text

Analyze a raw RFC 5322 email string as JSON.

```bash
curl -X POST http://localhost:8000/analyze-text \
  -H "Content-Type: application/json" \
  -d '{"text": "From: attacker@evil.com\nSubject: Test\n\nBody"}'
```

### POST /sandbox/scan-url

Submit a URL to the urlscan.io dynamic sandbox.

```bash
curl -X POST http://localhost:8000/sandbox/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example-suspicious.com/login"}'
```

### Interactive Docs

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## Running Tests

```bash
# Run all tests
pytest backend/tests/ -v

# Run a specific test file
pytest backend/tests/test_email_parser.py -v

# Run with coverage
pip install pytest-cov
pytest backend/tests/ --cov=backend --cov-report=term-missing
```

---

## ML Model

The ML classifier uses a **TF-IDF + SVM** pipeline trained on public phishing and spam datasets:

| Dataset | File |
|---|---|
| Ling Spam | `Ling.csv` |
| Nazario Phishing | `Nazario.csv` |
| Nigerian Fraud | `Nigerian_Fraud.csv` |
| SpamAssassin | `SpamAssasin.csv` |

> **Note:** Trained model files (`*.pkl`) are excluded from Git. To regenerate the models, open and run the training notebook:

```bash
jupyter notebook Untitled.ipynb
```

Models will be saved to `backend/models/`.

---

## Sample Emails

| File | Description |
|---|---|
| `backend/sample_emails/phishing_bank.eml` | Simulated bank phishing email |
| `backend/sample_emails/ceo_fraud.eml` | Business email compromise (BEC) / CEO fraud |
| `backend/sample_emails/legitimate.eml` | Legitimate email (should score low) |

---

## Security Notes

- **Isolated Browser Sandbox**: Dynamic URL investigations execute inside a self-hosted Browserless Chromium container in Docker via Playwright over WebSocket. Each URL scan creates an ephemeral, disposable browser context with zero persistence (no shared cookies, localStorage, or sessions). The Docker container runs isolated and does not mount host filesystems, Docker sockets, or project source code. *Note*: This provides isolated containerized browser process isolation; it is not a VM-level hypervisor sandbox.
- **SSRF Protection**: All target URLs undergo strict pre-flight validation before navigation. Requests resolving to `localhost`, `127.0.0.0/8`, `::1`, RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud metadata IP (`169.254.169.254`), broadcast, and non-standard schemes (`file:`, `javascript:`, `ftp:`) are blocked outright.
- **Download Quarantine & Auto-Cleanup**: Browser-triggered downloads are intercepted, strictly prevented from executing, quarantined into temporary storage, and immediately cleaned up after analysis.
- **No File Execution**: Attachments are inspected statically only (MIME type, SHA-256 hash, extensions, PDF text scanning). No uploaded file or attachment is ever executed.
- **No External URL Leaks**: Suspicious URLs are never transmitted to third-party public scanners like urlscan.io or VirusTotal. All dynamic analysis runs locally inside your private Docker environment.
- **API Keys & Secrets**: Never committed to Git. Always loaded from `backend/.env` (excluded via `.gitignore`).
- **Resource Limits**: Strict timeout safeguards (`BROWSER_SANDBOX_TIMEOUT_MS`), maximum URLs per email (`BROWSER_SANDBOX_MAX_URLS`), and network event caps prevent resource exhaustion.
- **Defensive Purpose Only**: This platform is designed exclusively for authorized forensic investigation of suspicious emails.
- **Geolocation Disclaimer**: IP geolocation indicates approximate *infrastructure location*, not the attacker's physical location.

---

## Team

Built for **Smart India Hackathon 2026** — Problem Statement **SIH26106** (AICTE)

> *GmailGuard — See Beyond the Inbox.*
