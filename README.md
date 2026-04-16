# Detekta-backend

The FastAPI-powered backend for **Detekta** — an automated security audit platform that scans web applications, REST APIs, mobile apps (APK/IPA), and backend code for vulnerabilities, then enriches findings with AI-generated analysis via Claude Sonnet.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Local Development Setup](#local-development-setup)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [Scanning Engine](#scanning-engine)
- [AI Analysis](#ai-analysis)
- [PDF Reports](#pdf-reports)
- [WebSocket — Real-Time Logs](#websocket--real-time-logs)
- [MobSF Integration](#mobsf-integration)
- [Database](#database)
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Contributing](#contributing)
- [Changelog](#changelog)

---

## Overview

`detekta-backend` exposes a REST + WebSocket API consumed by `detekta-frontend`. Its core responsibilities are:

| Responsibility | Implementation |
|---|---|
| User authentication & authorisation | JWT (access + refresh tokens), bcrypt passwords |
| Audit orchestration | `audit_service.py` — pipeline that fans out to specialised scanners |
| Security scanning | `real_scanner.py` (SSL/TLS, CORS, headers, nmap) + `scanner_service.py` (simulated/hybrid checks) |
| Mobile analysis | MobSF Docker integration via `mobsf_service.py` |
| AI-powered analysis | Claude Sonnet via Anthropic SDK + litellm (`ai_service.py`) |
| Report generation | WeasyPrint HTML→PDF with theme-aware templates (`pdf_service.py`) |
| Real-time streaming | WebSocket endpoint in `websocket.py` |
| Persistence | MongoDB (async Motor driver) |

---

## Architecture

```
                           ┌──────────────────┐
  detekta-frontend ────────►   FastAPI App      │
  (HTTP + WS)              │   (server.py)      │
                           └────────┬─────────┘
                                    │
              ┌─────────────────────┼──────────────────────┐
              ▼                     ▼                        ▼
     ┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐
     │  Auth Router │    │  Audits Router   │    │  Reports Router │
     │  /api/auth/  │    │  /api/audits/    │    │  /api/reports/  │
     └──────┬───────┘    └────────┬─────────┘    └────────┬────────┘
            │                     │                        │
            ▼                     ▼                        ▼
     ┌──────────────┐    ┌──────────────────┐    ┌─────────────────┐
     │ auth_service │    │  audit_service   │    │  pdf_service    │
     │ (JWT/bcrypt) │    │  (orchestrator)  │    │  (WeasyPrint)   │
     └──────────────┘    └────────┬─────────┘    └─────────────────┘
                                  │
              ┌───────────────────┼──────────────────────┐
              ▼                   ▼                        ▼
     ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐
     │ real_scanner │  │ scanner_service  │  │  mobsf_service       │
     │ (SSL/nmap/   │  │ (simulated/      │  │  (APK/IPA analysis)  │
     │  CORS/hdrs)  │  │  hybrid checks)  │  └──────────────────────┘
     └──────────────┘  └──────────────────┘
                                  │
                                  ▼
                        ┌──────────────────┐
                        │   ai_service     │
                        │ (Claude Sonnet)  │
                        └──────────────────┘
                                  │
                                  ▼
                        ┌──────────────────┐
                        │    MongoDB       │
                        │  (Motor async)   │
                        └──────────────────┘
```

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Web framework | FastAPI | 0.110.1 |
| ASGI server | Uvicorn | 0.25.0 |
| Database | MongoDB + Motor (async) | 4.5.0 / 3.3.1 |
| Data validation | Pydantic v2 | 2.12.5 |
| Authentication | PyJWT + bcrypt + python-jose | 2.12.1 / 4.1.3 |
| AI analysis | Anthropic SDK + litellm | ≥0.40.0 / 1.80.0 |
| Security scanning | python-nmap, httpx, requests | 0.7.1 / 0.28.1 |
| Mobile analysis | MobSF (Docker) | latest |
| PDF generation | WeasyPrint | 68.1 |
| Encryption | cryptography (Fernet) | 46.0.7 |
| Config | python-dotenv | 1.2.2 |
| Testing | pytest | 9.0.3 |
| Linting | Flake8, Black, isort, MyPy | latest |

---

## Project Structure

```
detekta-backend/
├── server.py                    # FastAPI application factory & startup
├── requirements.txt             # Pinned Python dependencies (129 packages)
├── .env.example                 # Environment variables template
│
├── app/
│   ├── config.py               # Settings loaded from .env (Pydantic BaseSettings)
│   ├── database.py             # Async MongoDB connection pool (Motor)
│   │
│   ├── models/
│   │   ├── audit.py            # Audit, AuditCreate, AuditResponse schemas
│   │   ├── user.py             # User, UserCreate, UserResponse schemas
│   │   ├── report.py           # Finding, ReportSummary, AIAnalysis schemas
│   │   └── usage_log.py        # API usage tracking schema
│   │
│   ├── routers/
│   │   ├── auth.py             # POST /register, /login, /refresh, /logout
│   │   ├── audits.py           # CRUD + launch endpoints for audits
│   │   ├── users.py            # Profile, Claude API key management
│   │   ├── reports.py          # Report generation, PDF download
│   │   └── websocket.py        # WS /api/ws/audits/{id} — live scan logs
│   │
│   ├── services/
│   │   ├── auth_service.py     # Token issuance, refresh, credential validation
│   │   ├── audit_service.py    # Main pipeline: create → scan → analyse → store
│   │   ├── scanner_service.py  # Simulated / hybrid vulnerability checks
│   │   ├── real_scanner.py     # Live checks: SSL, TLS, headers, CORS, nmap
│   │   ├── ai_service.py       # Claude Sonnet prompts, analysis parsing
│   │   ├── pdf_service.py      # Jinja2 HTML template → WeasyPrint PDF
│   │   └── mobsf_service.py    # MobSF REST client (upload, scan, fetch results)
│   │
│   └── utils/
│       ├── validators.py       # URL, Git repo, IP input sanitisation
│       └── crypto.py           # Fernet encrypt/decrypt for user API keys
│
└── mobsf/
    └── docker-compose.yml      # Isolated MobSF instance (port 8008 by default)
```

---

## Prerequisites

| Tool | Minimum Version | Notes |
|---|---|---|
| Python | 3.11+ | f-string syntax, `asyncio` improvements |
| MongoDB | 5.0+ | Needs to be running before the server starts |
| nmap | any | Required by `real_scanner.py` — `sudo apt install nmap` |
| Docker + Docker Compose | 20.10+ / 2.x | Optional — only needed for MobSF mobile scans |
| Anthropic API key | — | Free tier is fine for testing |

---

## Local Development Setup

### 1. Clone and enter the backend directory

```bash
git clone <repo-url>
cd detekta/detekta-backend
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
# .\venv\Scripts\Activate.ps1  # Windows PowerShell
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

Then open `.env` and set at minimum:

```env
JWT_SECRET=<output of: openssl rand -hex 32>
ENCRYPTION_KEY=<output of: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
MONGO_URL=mongodb://localhost:27017
AI_LLM_KEY=sk-ant-...
```

### 5. Start MongoDB (if not already running)

```bash
# macOS via Homebrew
brew services start mongodb-community

# Docker (quick option)
docker run -d -p 27017:27017 --name mongo mongo:7
```

### 6. (Optional) Start MobSF for mobile audits

```bash
cd mobsf
docker compose up -d
# MobSF UI available at http://localhost:8008
```

### 7. Run the development server

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

The API is now available at:
- `http://localhost:8000` — local access
- `http://<your-local-ip>:8000` — access from other devices on the network

Interactive docs (Swagger UI): `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `APP_ENV` | No | `development` | `development` \| `production` \| `staging` |
| `JWT_SECRET` | **Yes** | — | `openssl rand -hex 32` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `15` | Access token TTL |
| `REFRESH_TOKEN_EXPIRE_DAYS` | No | `7` | Refresh token TTL |
| `ENCRYPTION_KEY` | **Yes** | — | Fernet key for encrypting stored Claude API keys |
| `MONGO_URL` | **Yes** | — | MongoDB connection string |
| `DB_NAME` | No | `detekta` | MongoDB database name |
| `AI_LLM_KEY` | **Yes** | — | Platform-level Anthropic API key |
| `CLAUDE_MODEL` | No | `claude-sonnet-4-5-20250929` | Claude model ID |
| `CORS_ORIGINS` | **Yes** | — | Comma-separated allowed origins (e.g. `http://localhost:3000`) |
| `UPLOAD_DIR` | No | `/tmp/detekta_uploads` | Temporary storage for APK/IPA uploads |
| `MAX_FILE_SIZE_MB` | No | `200` | Maximum upload size in MB |
| `DEFAULT_LANGUAGE` | No | `en` | `en` or `fr` — default AI report language |
| `MOBSF_URL` | No | `http://localhost:8008` | MobSF base URL |

> **Security note:** Never commit `.env` to version control. Generate fresh secrets for every deployment.

---

## API Reference

All endpoints are prefixed with `/api/`.  
Full interactive documentation is available at `/docs` when the server is running.

### Authentication — `/api/auth/`

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create a new user account |
| `POST` | `/api/auth/login` | Obtain access + refresh tokens |
| `POST` | `/api/auth/refresh` | Exchange refresh token for new access token |
| `POST` | `/api/auth/logout` | Invalidate refresh token |

### Audits — `/api/audits/`

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/audits/` | List all audits for the authenticated user |
| `POST` | `/api/audits/` | Create and launch a new audit |
| `GET` | `/api/audits/{audit_id}` | Get a single audit (with status and findings) |
| `PATCH` | `/api/audits/{audit_id}` | Update audit metadata |
| `DELETE` | `/api/audits/{audit_id}` | Delete an audit |
| `POST` | `/api/audits/{audit_id}/archive` | Archive / unarchive an audit |

### Reports — `/api/reports/`

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/reports/{audit_id}/generate` | Trigger AI analysis and build report |
| `GET` | `/api/reports/{audit_id}` | Fetch the generated report (JSON) |
| `GET` | `/api/reports/{audit_id}/pdf` | Download the report as a PDF |

### Users — `/api/users/`

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/users/me` | Get current user profile |
| `PATCH` | `/api/users/me` | Update profile (name, language, theme) |
| `POST` | `/api/users/me/api-key` | Save / update encrypted Claude API key |
| `DELETE` | `/api/users/me/api-key` | Remove stored Claude API key |

### WebSocket — Real-Time Scan Logs

```
WS /api/ws/audits/{audit_id}
```

Connect with a valid JWT in the `Authorization` header or `token` query parameter. The server streams newline-delimited JSON messages:

```json
{ "type": "log", "message": "Checking SSL certificate...", "timestamp": "..." }
{ "type": "progress", "step": "ssl", "percent": 25 }
{ "type": "done", "status": "completed" }
```

---

## Authentication

Detekta uses a dual-token strategy:

- **Access token** — short-lived JWT (default 15 min), sent as `Bearer` in `Authorization` header.
- **Refresh token** — longer-lived JWT (default 7 days), stored securely by the client, used only to obtain a new access token via `/api/auth/refresh`.

Passwords are hashed with **bcrypt** (no plaintext ever stored).

Per-user Claude API keys are encrypted at rest with **Fernet** (symmetric AES-128-CBC + HMAC) before being stored in MongoDB.

---

## Scanning Engine

### Audit Types

| Type | Description | Key Checks |
|---|---|---|
| `web` | Website / web application | SSL/TLS cert validity, modern security headers (COOP/COEP/CORP), SRI integrity, cookies (Secure/HttpOnly), tracker/external domain analysis (Google Analytics, etc.) |
| `api` | REST API | Authentication enforcement, rate limiting, CORS headers, HTTPS enforcement |
| `mobile` | Android APK / iOS IPA | MobSF static analysis: permissions, hardcoded secrets, insecure storage, weak crypto |
| `backend` | Source code / backend | Simulated code-level checks: injection risks, auth patterns, dependency vulnerabilities |

### Scan Depths

| Depth | Description |
|---|---|
| `quick` | Fast surface-level checks (~1–2 min) |
| `standard` | Full default scan (~3–5 min) |
| `deep` | Thorough in-depth analysis (~8–15 min) |

### Real Scanner (`real_scanner.py`)

Performs live network checks against the target:

- **SSL/TLS** — certificate expiry, protocol versions, cipher suites
- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COEP, CORP, COOP
- **CORS** — validates `Access-Control-Allow-Origin` policies
- **Cookies** — checks for `Secure` and `HttpOnly` flags on sensitive cookies
- **External Trackers** — identifies 3rd-party trackers like Google Analytics, Facebook Pixel, etc.
- **Port scanning** — nmap SYN scan on common web ports

### Simulated Scanner (`scanner_service.py`)

Produces structured findings for checks that can't be performed purely via network probing (e.g. logic-level vulnerability patterns), useful for demo and development environments.

---

## AI Analysis

After scanning completes, `ai_service.py` calls **Claude Sonnet** with a structured prompt containing the raw findings. Claude returns:

- **Executive Summary** — non-technical overview for stakeholders
- **Technical Summary** — detailed breakdown for developers
- **Priority Actions** — ordered list of most critical remediations
- **Quick Wins** — low-effort, high-impact fixes
- **Long-Term Recommendations** — architectural improvements

Users can supply their own Claude API key via Settings. If not provided, the platform key (`AI_LLM_KEY`) is used.

---

## PDF Reports

`pdf_service.py` uses a Jinja2 HTML template + **WeasyPrint** to generate fully styled PDF reports. Features:

- Supports **light** and **dark** themes (respects user preference)
- **Multi-page stability**: Sections correctly span multiple pages without truncation
- **Security hardened**: All scan data is HTML-escaped to prevent layout breakage
- Includes the full `AIAnalysis` block
- Lists all `Finding` objects with severity badges, CVSS scores, CVE IDs, and code-fix suggestions
- Summary statistics: overall security score (0–100), risk level, finding counts by severity

---

## WebSocket — Real-Time Logs

During an active scan, the frontend opens a WebSocket connection to `/api/ws/audits/{audit_id}`. The backend:

1. Replays any log lines already emitted before the client connected (catch-up buffer)
2. Streams new log lines in real time as scanners report progress
3. Sends a terminal `done` event when the audit completes or errors

---

## MobSF Integration

MobSF (Mobile Security Framework) runs as a separate Docker container. `mobsf_service.py` acts as a REST client:

1. **Upload** the APK/IPA file to the MobSF instance
2. **Trigger** a scan
3. **Poll** for completion
4. **Fetch** the JSON report and map findings to Detekta's `Finding` schema

Start MobSF before running mobile audits:

```bash
cd mobsf
docker compose up -d
```

Confirm MobSF is healthy: `http://localhost:8008`

---

## Database

MongoDB collections:

| Collection | Purpose |
|---|---|
| `users` | User accounts, hashed passwords, encrypted API keys |
| `audits` | Audit records, metadata, status, raw findings |
| `reports` | AI analysis results, final `ReportSummary` |
| `usage_logs` | Per-request API usage tracking |
| `login_attempts` | Brute-force protection |
| `password_reset_tokens` | Short-lived tokens for password reset flow |

Indexes: unique index on `users.email`; compound indexes on `audits` by `user_id` + `status`.

---

## Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test file
pytest tests/test_auth.py
```

The root `test_db.py` validates the MongoDB connection independently of the full test suite.

---

## Code Quality

```bash
# Format code
black app/ server.py

# Sort imports
isort app/ server.py

# Lint
flake8 app/ server.py

# Type-check
mypy app/ server.py
```

The project targets PEP 8 compliance enforced via Flake8 + Black.

---

## Contributing

1. Fork the repository and create a feature branch from `main`.
2. Follow the existing code style (Black, isort, Flake8).
3. Add or update tests for any changed behaviour.
4. Open a pull request with a clear description of the change.

---

## Changelog

All notable changes to the **Detekta** project will be documented in this section.

### [0.0.3] - 2026-04-16

#### Added
- **Web Scanner Parity Upgrade**: Added modern security header checks (COOP/CORP/COEP/Referrer/Permissions) and identification of external trackers (Analytics, Pixels, etc.) for parity with professional tools.
- **Subresource Integrity (SRI) Fix**: Resolved cases where SRI findings were dropped; coverage now includes all external scripts.
- **Improved Reporting**: PDF reports now support multiple pages correctly (fixed truncation bug) and include `Low` and `Info` finding counts in technical summaries.
- **Early Validation**: Implemented early audit name validation to prevent duplicate names per type before starting a scan.
- **File Limit Increase**: Raised default max file upload size from 100MB to 200MB.

#### Fixed
- **PDF Report Security**: Integrated HTML escaping for all finding fields to ensure malformed data cannot break report generation.
- **SRI Regex Logic**: Improved reliability of script tag parsing for integrity validation.

### [0.0.2] - 2026-04-10

#### Added
- **MobSF Integration**: Integrated Mobile Security Framework (MobSF) for professional-grade static analysis of APK/IPA files.
- **Interactive Scoring System**: New pulsating animation around the security score with a dedicated help modal explaining the scoring logic.
- **Theme-Aware Reports**: PDF and HTML report downloads now automatically match the user's selected theme (Light/Dark).
- **Custom Audit Names**: Users can now assign a custom name to audits for better organization and tracking.
- **Landing Page Theme Toggle**: Added a theme switcher (Sun/Moon) to the main landing page.
- **Audit Details Improvements**: Real-time "Live Tests" population for mobile and backend audits.

#### Fixed
- **WebSocket Synchronization**: Fixed race condition causing duplicated log entries at the start of an audit.
- **PDF Dark Mode**: Resolved issues with white margins and text visibility in dark mode PDF exports.
- **Footer Consistency**: Standardized footer across PDF and HTML report formats.
- **Mobile Audit UI**: Fixed the "Waiting for tests to start..." hanging state for mobile scans.

#### Changed
- Improved recommendation block styling in PDF reports.
- Updated `scanner_service` to use a hybrid approach (real tools for Web/API/Mobile, high-fidelity simulation for Backend).

### [0.0.1] - 2026-03-25

#### Added
- Initial project release.
- Core scanning engine for Web apps and APIs.
- AI-powered analysis with Claude Sonnet.
- Basic PDF report generation.
- User authentication and multi-language support (EN/FR).
- Real-time terminal logs via WebSocket.
- Landing page and basic dashboard.

---

## License

MIT — see [LICENCE](LICENCE)

Copyright © 2026 Detekta Inc. All rights reserved.