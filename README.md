# CyberDefense XDR

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-315%2B%20Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](#license)

**CyberDefense XDR** is an enterprise-grade, AI-augmented Extended Detection and Response platform engineered for Security Operations Centers (SOC). It provides end-to-end security visibility, automated threat correlation, multi-domain hunting, incident management, privilege-safe network intrusion detection, and advisory-only AI investigation workflows.

Developed as a comprehensive B.Tech cybersecurity capstone and portfolio project, CyberDefense XDR integrates industry-standard security tools into a cohesive analyst workbench.

---

## Table of Contents

1. [Key Features](#key-features)
2. [Architecture Overview](#architecture-overview)
3. [Module Catalog](#module-catalog)
4. [Technology Stack](#technology-stack)
5. [Security Architecture & Hardening](#security-architecture--hardening)
6. [AI Assistant Architecture](#ai-assistant-architecture)
7. [Network IDS Architecture](#network-ids-architecture)
8. [Core SOC Workflows](#core-soc-workflows)
   - [Detection → Alert → Incident Workflow](#1-detection--alert--incident-workflow)
   - [Threat Intelligence Workflow](#2-threat-intelligence-workflow)
   - [Threat Hunting & Correlation Workflow](#3-threat-hunting--correlation-workflow)
   - [SOAR Playbook Workflow](#4-soar-playbook-workflow)
9. [Database Architecture](#database-architecture)
10. [Installation & Local Development](#installation--local-development)
11. [Docker Deployment](#docker-deployment)
12. [Environment Configuration](#environment-configuration)
13. [Database Migrations](#database-migrations)
14. [Testing & Quality Assurance](#testing--quality-assurance)
15. [Documentation Directory](#documentation-directory)
16. [Project Limitations & Host Dependencies](#project-limitations--host-dependencies)
17. [Future Enhancements](#future-enhancements)
18. [License](#license)

---

## Key Features

- **Multi-Sensor Telemetry Ingestion**: Correlates security telemetry from SIEM log streams, Suricata Network IDS, endpoint scans, PCAP uploads, and threat intelligence feeds.
- **AI-Powered SOC Analyst**: Advisory-only security assistant powered by Google Gemini 3.6 Flash via an OpenAI-compatible interface, featuring automatic fallback to an offline deterministic heuristic engine.
- **Privilege-Safe Network IDS**: Live Suricata capture engine utilizing `dumpcap` Linux capabilities over an unprivileged FIFO pipe, eliminating root container execution risks.
- **Deep Packet Inspection**: Embedded TShark engine providing dissection trees, conversation analysis, endpoint tracking, and protocol hierarchies directly in the browser.
- **Multi-Engine Vulnerability Scanner**: Orchestrates Nmap, Nikto, WhatWeb, Nuclei, and testssl.sh with automated finding deduplication and SHA-256 fingerprinting.
- **Human-in-the-Loop SOAR**: 10 automated investigation playbooks with strict containment approval workflows—no unvetted destructive actions.
- **Enterprise RBAC**: 5 canonical roles, 38 fine-grained permissions, brute-force lockout, and full compliance audit logging.
- **VAPT-Hardened**: Strict Content Security Policy (CSP), OWASP security headers, CSV injection defenses, shell injection prevention, and display filter validation.

---

## Architecture Overview

CyberDefense XDR is built upon the Flask application factory pattern, using PostgreSQL as the central relational store, SQLAlchemy 2.0 ORM, and Alembic migrations.

```mermaid
flowchart TD
    subgraph Ingestion["Telemetry & Ingestion Layer"]
        NIDS["Suricata IDS (EVE JSON)"]
        PCAP["PCAP Uploads (TShark)"]
        SCAN["Vulnerability Scanners (Nmap/Nuclei/Nikto)"]
        SIEM_IN["SIEM Ingestion Logs"]
        INTEL["Threat Intel Feeds (IOCs)"]
    end

    subgraph Processing["Processing & Correlation Engine"]
        ROT["Log Rotator & Deduplicator"]
        DET["Detection Engine (Rules & Events)"]
        CORR["Correlation Engine (0-100 Risk Scoring)"]
        HUNT["Threat Hunting Federated Search"]
    end

    subgraph Operations["SOC Operations & Management"]
        ALERTS["Alert Center"]
        INC["Incident Response Workbench"]
        SOAR_ENG["SOAR Engine (10 Playbooks)"]
        NOTIF["Notification Dispatcher"]
        AUDIT["Audit Logger"]
    end

    subgraph Intelligence["Intelligence & Presentation Layer"]
        AI["AI Assistant (Gemini 3.6 Flash / Local Fallback)"]
        UI["Web Shell (HTML5 / Bootstrap / CSS3 / Vanilla JS)"]
        API["REST API Endpoints"]
    end

    subgraph Storage["Persistent Storage"]
        DB[(PostgreSQL 15 Database)]
        VOL[("Local / Named Volumes")]
    end

    NIDS --> ROT --> DB
    PCAP --> DB
    SCAN --> DB
    SIEM_IN --> DB
    INTEL --> DB

    DB --> DET --> ALERTS
    DB --> CORR
    DB --> HUNT
    ALERTS --> INC
    INC --> SOAR_ENG
    SOAR_ENG --> NOTIF
    SOAR_ENG --> AUDIT

    DB --> AI
    DB --> UI
    DB --> API
```

---

## Module Catalog

The platform consists of **23 registered Blueprints** and **31 relational database models**:

| Module | Blueprint Prefix | Primary Responsibility | Key Models |
|:---|:---|:---|:---|
| **Dashboard** | `/dashboard` | SOC executive overview & KPI metrics | Reads multi-table aggregates |
| **Alert Center** | `/alert-center` | Alert triage, status updates, incident escalation | `Alert` |
| **Incident Response** | `/incidents` | Case workbench, evidence timeline, containment | `Incident` |
| **Detection Engine** | `/detection` | Custom detection rule authoring and event tracking | `DetectionRule`, `DetectionEvent` |
| **SIEM** | `/siem` | Log Explorer, saved searches, real-time ingestion | `SiemEvent`, `SiemSavedSearch` |
| **Network IDS** | `/network-ids` | Suricata engine control, EVE JSON ingestion | `NetworkIDSEvent`, `IDSSensor` |
| **Packet Analysis** | `/packet-analysis` | TShark PCAP dissections, conversation flows | `PacketAnalysis` |
| **Vulnerability Scanner** | `/scanner` | Nmap, Nikto, Nuclei, WhatWeb, testssl.sh runs | `Scan`, `VulnerabilityFinding`, `ScanTarget` |
| **Threat Intelligence** | `/threat-intelligence` | Threat actors, campaigns, feeds, and IOCs | `IOC`, `ThreatActor`, `ThreatCampaign`, `ThreatFeed` |
| **Threat Hunting** | `/threat-hunting` | Federated multi-domain search across 10 tables | `ThreatHuntQuery` |
| **Correlation Engine** | `/correlation` | Multi-vector 0–100 risk scoring & D3 graph | In-memory cross-source aggregation |
| **AI Assistant** | `/ai-assistant` | Gemini 3.6 Flash advisory chatbot & context gatherer | `AIConversation`, `AIMessage` |
| **SOAR** | `/soar` | 10 automated playbooks with human approvals | `SoarPlaybookExecution`, `SoarApproval` |
| **Asset Management** | `/assets` | Asset discovery, hardware/OS inventory, risk ranking | `Asset` |
| **SOC Command Center** | `/soc-dashboard` | Real-time live SOC command center interface | Aggregated cross-sensor views |
| **Reports** | `/reports` | Executive and technical PDF/CSV report builder | `Report` |
| **Analytics** | `/analytics` | MTTD, MTTR, severity distribution, MITRE heatmaps | Analytical time-series queries |
| **User Management** | `/user-management` | RBAC administration, role assignment, lockout controls | `User` |
| **Authentication** | `/auth` | Login, registration, password reset, rate limiting | `User` |
| **Audit Logs** | `/audit-logs` | Tamper-resistant compliance event logging | `AuditLog` |
| **Notifications** | `/notifications` | In-app alerts, email, webhooks, quiet hours | `Notification` |
| **Settings** | `/settings` | Security settings, API keys, SIEM integrations | `SecuritySettings`, `NotificationSettings`, `APIKey`, etc. |
| **Main / Landing** | `/` | Root application landing router | — |

---

## Technology Stack

- **Backend Framework**: Flask 3.1.3, Werkzeug 3.1.8
- **Database & ORM**: PostgreSQL 15+, SQLAlchemy 2.0.51, Flask-SQLAlchemy 3.1.1
- **Database Migrations**: Alembic 1.18.5, Flask-Migrate 4.1.0
- **Authentication & Security**: Flask-Login 0.6.3, Flask-Bcrypt 1.0.1, Flask-WTF 1.3.0 (CSRF), ItsDangerous 2.2.0
- **WSGI Production Server**: Gunicorn 26.0.0
- **Security & Inspection Binaries**:
  - `suricata` & `dumpcap` (Network IDS)
  - `tshark` & `capinfos` (Packet Analysis)
  - `nmap`, `nikto`, `whatweb`, `nuclei`, `testssl.sh` (Vulnerability Scanner)
- **AI Integration**: Google Gemini 3.6 Flash via OpenAI-compatible endpoint (`generativelanguage.googleapis.com/v1beta/openai/`)
- **Frontend Architecture**: Server-side rendered Jinja2 templates, modern responsive CSS3 design tokens (`variables.css`, `layout.css`), Vanilla ES6+ JavaScript (`shell.js`, modular page scripts). Zero heavy frontend build steps required.

---

## Security Architecture & Hardening

CyberDefense XDR implements rigorous defensive engineering validated by automated test suites and an internal VAPT audit:

1. **OWASP Security Headers**: Every HTTP response automatically receives `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, and a restrictive `Content-Security-Policy`.
2. **Account Lockout & Rate Limiting**: In-memory sliding-window tracker combined with persistent database lockout. 5 consecutive failed logins trigger a 15-minute account lock (`account_locked_until`).
3. **Session Hardening**: HTTPOnly, SameSite=Lax, permanent session lifetimes bounded to 8 hours.
4. **Shell Injection Defenses**: The Vulnerability Scanner target validator strictly enforces a character whitelist, rejecting metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, `!`).
5. **Display Filter Whitelisting**: PCAP display filters are checked against safe regex character sets and evaluated through dry-run syntax verification before execution.
6. **CSV Injection Defense**: Audit Log and Report CSV exports automatically sanitize formula trigger characters (`=`, `+`, `-`, `@`).
7. **Advisory-Only AI Boundaries**: System prompts strictly forbid code or shell execution. Untrusted telemetry is isolated inside `<security_telemetry>` delimiter blocks to mitigate prompt injection and instruction smuggling. Sensitive credentials (AWS keys, Google API keys, tokens, passwords) are scrubbed via regex before dispatch.
8. **Information Disclosure Prevention**: Production-configured global error handlers catch 400, 403, 404, and 500 responses, rolling back database sessions and emitting sanitized JSON or generic error templates.

---

## AI Assistant Architecture

The AI Assistant module ([`app/ai_assistant/`](file:///home/kali/Projects/CyberDefense-XDR/app/ai_assistant/)) functions strictly as an **advisory SOC co-pilot**:

```mermaid
sequenceDiagram
    participant User as SOC Analyst
    participant Route as /ai-assistant/api/chat
    participant Sec as Security & Scrubbing
    participant Ctx as Context Engine
    participant Prov as OpenAICompatibleProvider
    participant Gemini as Gemini 3.6 Flash
    participant Fallback as LocalDeterministicProvider
    participant DB as PostgreSQL

    User->>Route: Submit query
    Route->>Sec: Sanitize input (max 4000 chars)
    Sec->>Sec: Scrub secrets (API keys, passwords, tokens)
    Route->>Ctx: Gather active alerts, CVEs, IDS, IOCs
    Ctx-->>Route: Formatted security telemetry
    Route->>Sec: Wrap telemetry in <security_telemetry>
    Route->>Prov: Dispatch prompt + system advisory instructions
    alt Gemini API Available
        Prov->>Gemini: HTTPS POST /chat/completions (model: gemini-3.6-flash)
        Gemini-->>Prov: Structured markdown response
    else Network / API Failure (503, timeout)
        Prov->>Fallback: Trigger local heuristic analysis
        Fallback-->>Prov: Deterministic risk assessment
    end
    Prov-->>Route: Advisory report
    Route->>DB: Persist AIConversation & AIMessage
    Route-->>User: Render assistant analysis
```

- **Advisory Only**: Cannot execute commands, modify rules, delete data, or escalate incidents directly.
- **Noise Awareness**: The system prompt specifically instructs the model that Suricata SID 2200074 (`invalid checksum`) is benign NIC offload artifact.
- **Privacy & Redaction**: Replaces sensitive tokens with `[REDACTED_API_KEY]`, `[REDACTED_PASSWORD]`, etc.

---

## Network IDS Architecture

Live packet capture requires elevated privileges that should never be granted to a web application container. CyberDefense XDR solves this with an unprivileged FIFO architecture:

```mermaid
flowchart LR
    IFACE["Network Interface (eth0)"] -->|Raw Sockets| DUMPCAP["dumpcap (cap_net_raw+eip)"]
    DUMPCAP -->|Write Stream| FIFO["instance/ids/suricata_pipe (FIFO)"]
    FIFO -->|Read Stream (-r)| SURI["suricata (non-root, -k none)"]
    SURI -->|JSON Stream| EVE["instance/ids/eve.json"]
    EVE -->|Background Thread| INGEST["EVE Ingestion & Deduplication"]
    INGEST -->|Filter Diagnostic SID 2200074| SIEM_DB[("SIEM & Network IDS DB")]
    INGEST -->|Real Alerts| ALERTS["Alert Center"]
```

- **Privilege Separation**: Only `/usr/bin/dumpcap` carries Linux capabilities. Suricata runs unprivileged reading from the pipe.
- **Diagnostic Classification**: Checksum offload anomalies (SID 2200074) are ingested into the database and SIEM for complete forensic records, but automatically tagged as `diagnostic` to prevent Alert Center clutter.
- **Log Rotation**: A background thread monitors `eve.json` size, compressing old logs with gzip when exceeding `IDS_LOG_ROTATION_SIZE_MB`.

---

## Core SOC Workflows

### 1. Detection → Alert → Incident Workflow
1. **Event Generation**: Suricata IDS, SIEM log ingestion, or Vulnerability Scanners record raw events.
2. **Rule Evaluation**: Detection Engine evaluates custom `DetectionRule` patterns against streaming events.
3. **Alert Creation**: High-confidence detections create an `Alert` record in `/alert-center/`.
4. **Analyst Triage**: Analysts review details, acknowledge alerts, or mark false positives.
5. **Incident Escalation**: High-severity alerts are escalated to an `Incident`, creating an investigation workspace with evidence logging and containment playbooks.

### 2. Threat Intelligence Workflow
1. **Feed Synchronization**: Threat Intel module fetches indicators from external threat feeds or manual entry.
2. **IOC Normalization**: IP, Domain, Hash, and URL indicators are indexed in the `IOC` database table.
3. **Automated Cross-Referencing**:
   - Vulnerability scanner checks target hosts against IOC databases.
   - Correlation engine correlates open alerts with known threat actors and campaigns.

### 3. Threat Hunting & Correlation Workflow
1. **Federated Search**: The Threat Hunting console (`/threat-hunting/`) executes queries across 10 database tables simultaneously.
2. **Entity Profiling**: Generates unified timelines for any IP, domain, hash, or CVE.
3. **Risk Scoring**: The Correlation Engine calculates a deterministic 0–100 risk score based on active alerts, IDS high-severity detections, CVE exploitability, threat intelligence ties, and asset criticality.

### 4. SOAR Playbook Workflow
1. **Trigger**: An analyst triggers a playbook (e.g., `alert_investigation`, `endpoint_containment_staging`) via the SOAR dashboard or API.
2. **Automated Steps**: The engine executes non-destructive reconnaissance and enrichment steps, logging progress in `SoarPlaybookExecution`.
3. **Staged Approval**: Any containment action (e.g., firewall block, host isolation) creates a `SoarApproval` record.
4. **Human Decision**: A Tier 2 Analyst or Administrator must explicitly approve or reject the action. Destructive actions are never executed unprompted.

---

## Database Architecture

CyberDefense XDR uses PostgreSQL with **31 relational models** managed across **23 Alembic migrations**:

```mermaid
erDiagram
    User ||--o{ AuditLog : generates
    User ||--o{ AIConversation : owns
    User ||--o{ Incident : creates_or_assigned
    AIConversation ||--o{ AIMessage : contains
    Incident ||--o{ Alert : aggregates
    DetectionRule ||--o{ DetectionEvent : triggers
    Scan ||--o{ VulnerabilityFinding : discovers
    ScanTarget ||--o{ Scan : targets
    IDSSensor ||--o{ NetworkIDSEvent : captures
    ThreatCampaign ||--o{ IOC : associates
    ThreatActor ||--o{ ThreatCampaign : conducts
    SoarPlaybookExecution ||--o{ SoarApproval : stages
```

---

## Installation & Local Development

### Prerequisites

- **Operating System**: Linux (Kali Linux, Ubuntu 22.04+, or Debian 12 recommended)
- **Python**: 3.13+ (or 3.11+)
- **PostgreSQL**: Version 15 or higher
- **Security Tools** (for full host capability):
  ```bash
  sudo apt-get update && sudo apt-get install -y \
      tshark \
      nmap \
      nikto \
      whatweb \
      testssl.sh \
      suricata \
      postgresql-client
  ```

### Step-by-Step Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/sam29sahil/CyberDefense-XDR.git
   cd CyberDefense-XDR
   ```

2. **Set Up Python Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Configure PostgreSQL**:
   ```bash
   sudo -u postgres psql
   ```
   ```sql
   CREATE DATABASE cyberdefense_xdr;
   CREATE USER cyberadmin WITH PASSWORD 'YourSecurePasswordHere';
   GRANT ALL PRIVILEGES ON DATABASE cyberdefense_xdr TO cyberadmin;
   \q
   ```

4. **Set Up Environment Variables**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and set your `SECRET_KEY`, `DATABASE_URL`, and `AI_API_KEY`.

5. **Run Database Migrations**:
   ```bash
   flask --app run.py db upgrade
   ```

6. **Seed Initial Data (Optional)**:
   ```bash
   python3 scripts/seed_threatintel.py
   python3 scripts/seed_threat_actors.py
   ```

7. **Start the Development Server**:
   ```bash
   python3 run.py
   ```
   The platform will be accessible at `http://localhost:5000`.

---

## Docker Deployment

The application and PostgreSQL database can be deployed using Docker Compose.

> [!IMPORTANT]
> Network IDS (Suricata/dumpcap) requires host raw packet sockets (`AF_PACKET`) and runs as a host service, not inside the container. All other modules (including TShark, Nmap, Nikto, WhatWeb, and the AI Assistant) are fully container-ready.

### 1. Configure Environment

Ensure `.env` exists with your deployment configuration:
```bash
cp .env.example .env
```
Ensure `DB_PASSWORD` and `SECRET_KEY` are populated.

### 2. Build and Start Services

```bash
docker compose up -d --build
```

This starts:
- **`xdr-db`**: PostgreSQL 15 on an isolated internal network with named volume `xdr_pgdata`.
- **`xdr-app`**: CyberDefense XDR served via Gunicorn (3 workers) on port 5000, with automated health checks.

### 3. Verify Container Status

```bash
docker compose ps
docker compose logs -f app
```

### 4. Run Migrations in Docker

The `entrypoint.sh` script automatically runs `flask --app run.py db upgrade` on startup. To execute manual migrations:
```bash
docker compose exec app flask --app run.py db upgrade
```

### 5. Stop Containers

```bash
docker compose down
# To remove persistent database volume as well:
# docker compose down -v
```

---

## Environment Configuration

Key configuration parameters defined in `.env`:

| Variable | Default / Example | Purpose |
|:---|:---|:---|
| `FLASK_APP` | `run.py` | Flask entrypoint |
| `FLASK_ENV` | `production` | Environment mode |
| `DEBUG` | `False` | Application debug mode |
| `SECRET_KEY` | *(random 32-byte hex)* | Session & CSRF encryption key |
| `DATABASE_URL` | `postgresql://cyberadmin:pass@localhost:5432/cyberdefense_xdr` | Database connection URI |
| `AI_PROVIDER` | `gemini` | AI engine (`gemini` or `mock`) |
| `AI_API_KEY` | *(your Gemini key)* | Google Generative Language API key |
| `AI_MODEL` | `gemini-3.6-flash` | Gemini model name |
| `MAX_PCAP_UPLOAD_MB` | `50` | Maximum PCAP file upload size |
| `TSHARK_TIMEOUT_SECONDS` | `120` | TShark dissection command timeout |

See [`docs/configuration.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/configuration.md) for the complete variable catalog.

---

## Database Migrations

Database schema changes are tracked via Flask-Migrate / Alembic in `migrations/`:

```bash
# Check current database revision
flask --app run.py db current

# View available migration heads
flask --app run.py db heads

# Upgrade to latest revision
flask --app run.py db upgrade

# Roll back by one revision
flask --app run.py db downgrade
```

---

## Testing & Quality Assurance

The test suite covers unit tests, RBAC authorization, security controls, and route conflict verification:

```bash
# Run the entire test suite
venv/bin/pytest -q

# Run focused module tests
venv/bin/pytest tests/unit/test_ai_assistant.py -v
venv/bin/pytest tests/unit/test_rbac_hardening.py -v
venv/bin/pytest tests/unit/test_soar.py -v
venv/bin/pytest tests/unit/test_security_hardening.py -v
```

**Verified Test Baseline**: **315 passed, 0 failures**.

---

## Documentation Directory

Comprehensive, architecture-specific technical documentation is available in [`docs/`](file:///home/kali/Projects/CyberDefense-XDR/docs/):

- [`docs/architecture.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/architecture.md) — System architecture, module map, and design patterns
- [`docs/installation.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/installation.md) — Complete installation & dependency guide
- [`docs/configuration.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/configuration.md) — Comprehensive environment variable guide
- [`docs/database.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/database.md) — 31 database models, relationships, and migrations
- [`docs/authentication-rbac.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/authentication-rbac.md) — Roles, permissions, lockout, and session controls
- [`docs/security.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/security.md) — Security hardening, OWASP headers, and sanitization
- [`docs/ai-assistant.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/ai-assistant.md) — Gemini 3.6 Flash integration & advisory guardrails
- [`docs/network-ids.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/network-ids.md) — Suricata privilege-safe FIFO capture pipeline
- [`docs/packet-analysis.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/packet-analysis.md) — TShark integration & PCAP processing
- [`docs/vulnerability-scanner.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/vulnerability-scanner.md) — Nmap/Nuclei/Nikto/WhatWeb/testssl architecture
- [`docs/detection.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/detection.md) — Detection rules, event matching, and triggers
- [`docs/siem.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/siem.md) — Log Explorer, search syntax, and event ingestion
- [`docs/incident-response.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/incident-response.md) — Case management and evidence timeline
- [`docs/threat-intelligence.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/threat-intelligence.md) — IOC database, feeds, and actor tracking
- [`docs/threat-hunting.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/threat-hunting.md) — Federated multi-table hunt engine
- [`docs/correlation.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/correlation.md) — Risk scoring algorithm and graph engine
- [`docs/soar.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/soar.md) — 10 playbooks and human approval workflow
- [`docs/notifications.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/notifications.md) — Dispatch channels, quiet hours, and routing
- [`docs/audit-logs.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/audit-logs.md) — Compliance logging and CSV export defenses
- [`docs/testing.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/testing.md) — Test suite architecture and execution guide
- [`docs/troubleshooting.md`](file:///home/kali/Projects/CyberDefense-XDR/docs/troubleshooting.md) — Diagnostic guide and common error resolutions

---

## Project Limitations & Host Dependencies

Honest architectural boundaries of the current implementation:

1. **Network IDS Sensor**: Requires `AF_PACKET` raw socket permissions and resides on the host OS. The containerized application can ingest Suricata EVE logs, but live sensor capture cannot run inside an unprivileged Docker container.
2. **Scanner OS Detection (`nmap -O`)**: Requires `cap_net_raw`. In unprivileged containers, port scanning and service detection (`-sV`) function normally, but raw TCP fingerprinting requires host execution or specific container capabilities.
3. **Single-Node Architecture**: Uses a single PostgreSQL database instance and Gunicorn worker pool suited for departmental or mid-sized deployments; distributed multi-cluster deployment is not currently implemented.
4. **AI Capabilities**: Strictly advisory and read-only by design; cannot execute shell commands or automatically remediate alerts without analyst approval.

---

## Future Enhancements

- Distributed sensor agents using gRPC telemetry streaming.
- OpenTelemetry ingestion pipeline integration.
- Automated Sigma rule compilation into native Detection Rules.
- WebAuthn / FIDO2 multi-factor authentication support.
- STIX/TAXII 2.1 automated threat feed synchronization.

---

## License

This project was developed for academic and portfolio demonstration purposes. All rights reserved. See repository license file or contact the author for licensing inquiries.
