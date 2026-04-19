<div align="center">

# ⚡ LogMap

### Blue Team Log Analyzer — 100% Local, Zero Cloud

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://reactjs.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-E33B2A?style=flat-square)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![GDPR](https://img.shields.io/badge/GDPR-Compliant-4CAF50?style=flat-square)](#security--privacy)
[![No Internet](https://img.shields.io/badge/Internet-Not%20Required-blue?style=flat-square)](#security--privacy)

**LogMap** parses your security logs, builds an interactive attack graph, detects MITRE ATT&CK techniques, and scores risk 0–100 — entirely on your machine. No data ever leaves your network.

[Quick Start](#quick-start) · [CLI Usage](#cli-usage) · [Docker UI](#docker-ui) · [MITRE Coverage](#mitre-attck-coverage) · [Architecture](#architecture) · [Roadmap](#roadmap)

---

<!-- Replace with an actual screenshot or animated GIF of your UI -->
![LogMap Screenshot](https://placehold.co/900x500/0a0e1a/38bdf8?text=LogMap+Attack+Graph+UI)

*Attack graph showing brute-force → credential theft → lateral movement → persistence chain, scored 92/100 CRITICAL*

</div>

---

## What is LogMap?

LogMap is an **offline Blue Team forensic tool** that turns raw log files into an interactive attack graph with automatic threat detection. It is designed for:

- **Incident responders** who need to reconstruct attack timelines quickly
- **SOC analysts** who want structured MITRE ATT&CK mapping without manual work
- **Compliance teams** who must document security incidents without touching cloud services
- **Threat hunters** looking for lateral movement and persistence patterns in historical logs

LogMap works entirely in memory — no database, no external API calls, no telemetry.

---

## Quick Start

### Option A — Docker UI (recommended)

```bash
git clone https://github.com/your-username/logmap.git
cd logmap
docker compose up --build
```

Open **http://localhost:3000** — drag & drop a log file and click **Analyze Logs**.

> **Requirements:** Docker Desktop 24+ with Compose v2

### Option B — CLI (no Docker needed)

```bash
pip install -r requirements.txt
python logmap.py analyze path/to/your.log
```

> **Requirements:** Python 3.10+

---

## CLI Usage

```bash
python logmap.py analyze <file> [options]
```

| Option | Description | Example |
|--------|-------------|---------|
| *(none)* | Full report with all findings | `python logmap.py analyze events.log` |
| `--severity` | Filter events by severity level | `--severity critical` |
| `--mitre` | Show only events matching a technique | `--mitre T1110` |
| `--output` | Save plain-text report to file | `--output report.txt` |

### Example output

```
╔══════════════════════════════════════╗
║       LOGMAP — ANALYSIS REPORT       ║
╚══════════════════════════════════════╝
  Format    : WINDOWS
  Events    : 3,200
  Suspicious: 47
  Risk Score: 87/100 CRITICAL

ATTACK GRAPH:
203.0.113.45 (IP)
  ├──[AUTHENTICATED_AS x342]──► administrator (USER)
  │                                  └──[EXECUTED]──► powershell.exe
  │                                       └──[MAPS_TO]──► T1059.001
  └──[MAPS_TO]──► T1110 / T1078

MITRE TECHNIQUES:
  T1110  Brute Force        342  ██████████  CRITICAL
  T1078  Valid Accounts      89  ██████      HIGH
  T1059  PowerShell          23  ███         MEDIUM

DETECTED PATTERNS:
  [BRUTE_FORCE]  203.0.113.45: 342 failures in 5 min
  [PERSISTENCE]  Scheduled task created after suspicious auth

RECOMMENDATIONS:
  [1] Block 203.0.113.45 at firewall
  [2] Reset administrator credentials
  [3] Review PowerShell execution policy
```

---

## Docker UI

```bash
docker compose up --build
```

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | React UI — graph, timeline, inspector |
| Backend  | http://localhost:8000 | FastAPI — JSON API |
| Health   | http://localhost:8000/health | Docker healthcheck |

### UI Features

| Panel | Description |
|-------|-------------|
| **Upload** | Drag & drop or paste raw log content |
| **Attack Graph** | Interactive Cytoscape.js graph with CoSE-Bilkent layout |
| **Node Legend** | Color + shape key for all entity types |
| **Node Inspector** | Click any node to see risk score, MITRE techniques, and metadata |
| **Technique Detail** | Click a purple MITRE node to see full scoring explanation with Sigma references |
| **Events Log** | Structured, filterable event list (severity, search, suspicious-only toggle) |
| **Timeline** | Recharts stacked bar chart of events over time, colored by severity |
| **Risk Panel** | Gauge + per-technique score breakdown with expandable rationale |
| **Patterns** | Detected attack patterns (brute force, lateral move, persistence, etc.) |
| **Recommendations** | Prioritized remediation actions |
| **Export PNG** | Download the current graph as a high-resolution image |

---

## Supported Log Formats

LogMap auto-detects the format from the first 4 KB of the file. No configuration needed.

| Format | Detection | Parsed Fields |
|--------|-----------|---------------|
| **Windows Event Log** | `EventID=`, `Account Name`, `Logon Type` | EventID, timestamp, username, domain, IP, process, logon type, workstation |
| **Linux auth.log** | `sshd[`, `sudo:`, `pam_unix` | SSH accepted/failed, sudo escalation, PAM sessions |
| **Syslog RFC 3164** | `<priority>MMM DD HH:MM:SS` | Hostname, process, PID, message, IPs |
| **Syslog RFC 5424** | `<priority>1 YYYY-MM-DDTHH:MM:SSZ` | Structured-data, hostname, app, message |

If auto-detection fails, all three parsers are tried and the one producing the most events wins.

---

## MITRE ATT&CK Coverage

### Windows Event IDs

| Event ID | Description | MITRE Technique |
|----------|-------------|-----------------|
| 4624 | Successful Logon | — |
| 4625 | Failed Logon | T1110 |
| 4634 | Logoff | — |
| 4648 | Logon with Explicit Credentials | T1078, T1550.002 |
| 4672 | Special Privileges Assigned | T1078.002 |
| 4688 | New Process Created | T1059 |
| 4698 | Scheduled Task Created | T1053.005 |
| 4720 | User Account Created | T1136.001 |
| 4732 | User Added to Group | T1098 |
| 4776 | Credential Validation | T1110.002 |
| 7045 | New Service Installed | T1543.003 |

### Techniques Scored

Scores are derived from `tactic_score × 0.4 + sigma_score × 0.6` using official MITRE ATT&CK v14 tactic phase weights and SigmaHQ community severity levels.

| Technique | Name | Tactic | Sigma | Base Score |
|-----------|------|--------|-------|-----------|
| T1078.002 | Domain Accounts | Privilege Escalation | **CRITICAL** | 83.6 |
| T1550.002 | Pass the Hash | Lateral Movement / Defense Evasion | **CRITICAL** | 83.2 |
| T1098 | Account Manipulation | Persistence / Privilege Escalation | HIGH | 72.8 |
| T1543.003 | Windows Service | Persistence / Privilege Escalation | HIGH | 72.8 |
| T1548.003 | Sudo and Sudo Caching | Privilege Escalation / Defense Evasion | HIGH | 71.6 |
| T1078 | Valid Accounts | Defense Evasion / Persistence | HIGH | 71.6 |
| T1053.005 | Scheduled Task | Persistence / Privilege Escalation | HIGH | 71.2 |
| T1110 | Brute Force | Credential Access | HIGH | 70.4 |
| T1110.003 | Password Spraying | Credential Access | HIGH | 70.4 |
| T1059.001 | PowerShell | Execution | HIGH | 68.0 |
| T1136.001 | Create Local Account | Persistence | MEDIUM | 60.8 |
| T1110.002 | Password Cracking | Credential Access | MEDIUM | 58.4 |
| T1059 | Command & Scripting | Execution | MEDIUM | 56.0 |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | MEDIUM | 62.4 |

### Detected Attack Patterns

| Pattern | Trigger Condition | Severity |
|---------|-------------------|----------|
| `BRUTE_FORCE` | ≥ 5 failed logins from the same IP within 5 minutes | CRITICAL |
| `SPRAY_ATTACK` | Same IP targeting ≥ 3 distinct user accounts | CRITICAL |
| `PASS_THE_HASH` | Event 4648 (explicit creds) from an internal IP with no prior 4624 | CRITICAL |
| `LATERAL_MOVE` | RDP logins (Type 10) to ≥ 2 distinct internal hosts | HIGH |
| `PERSISTENCE` | Task or service creation (4698/7045) after a suspicious authentication | HIGH |
| `PRIV_ESCALATION` | Event 4672 within 2 minutes of a suspicious 4624 | CRITICAL |

### Risk Score Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 76–100 | 🔴 CRITICAL | Active attack in progress or confirmed breach |
| 51–75 | 🟠 HIGH | Strong indicators of compromise, immediate review required |
| 26–50 | 🟡 MEDIUM | Suspicious activity, investigation recommended |
| 0–25 | 🟢 LOW | Routine activity, no significant indicators |

---

## Security & Privacy

LogMap was designed from the ground up for environments where **data confidentiality is non-negotiable**.

### What LogMap does NOT do

- ❌ Send logs, IPs, hashes, or filenames to any external server
- ❌ Require an internet connection at any point
- ❌ Write data to disk (all analysis is in-memory, discarded on container restart)
- ❌ Collect usage telemetry or analytics
- ❌ Phone home for updates or license checks

### What LogMap does

- ✅ Processes all data locally inside your Docker network or Python process
- ✅ Stores analysis results only in process memory for the duration of the session
- ✅ Exposes no unauthenticated endpoints beyond your local machine

### Regulatory Compatibility

| Framework | Relevant Requirement | LogMap's Approach |
|-----------|---------------------|-------------------|
| **GDPR** (Art. 25, 32) | Data minimisation and processing on appropriate legal basis | No data leaves the processing environment; logs are never persisted |
| **ISO 27001** (A.12.4) | Logging and monitoring of systems | Supports offline forensic analysis of log files without external exposure |
| **PCI-DSS** (Req. 10) | Protect audit trails | Log files remain in the analyst's controlled environment throughout |
| **HIPAA** (§ 164.312(b)) | Audit controls for systems containing ePHI | No transmission of log content; all processing is in-memory and local |

> **Note:** LogMap is a forensic analysis tool, not a log management platform. Consult your compliance officer for your specific deployment context.

---

## Optional: VirusTotal Enrichment

LogMap is designed to optionally enrich IP addresses and file hashes against the VirusTotal public API. This feature is **not enabled by default** and is **opt-in only**.

### Privacy-first design

When VirusTotal enrichment is enabled:

- **Only IP addresses and file hashes (MD5/SHA256) are submitted** — never log lines, filenames, or any content from the log file itself
- IPs and hashes are already public-facing identifiers; submitting them does not reveal anything about your internal systems beyond what is already observable on the internet
- You control which IPs/hashes are submitted via an explicit allowlist or interactive confirmation
- The raw log file **never leaves your machine**

### Planned implementation

```yaml
# logmap.yml (future configuration)
enrichment:
  virustotal:
    enabled: false          # opt-in
    api_key: "${VT_API_KEY}"
    submit_ips: true
    submit_hashes: true
    submit_domains: false   # never
    submit_log_content: false  # always false, hardcoded
```

> ⚠️ VirusTotal enrichment is on the [roadmap](#roadmap) and not yet implemented. This section documents the intended design.

---

## API Reference

The FastAPI backend exposes a simple REST interface consumed by the React frontend.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ingest` | Upload raw log text; returns `session_id` + summary stats |
| `GET` | `/api/graph/{id}` | Cytoscape-ready nodes + edges JSON |
| `GET` | `/api/timeline/{id}` | All events sorted by timestamp |
| `GET` | `/api/risk/{id}` | Global score + per-technique breakdown + detected patterns |
| `GET` | `/health` | Docker healthcheck |

### POST /api/ingest

```json
// Request
{ "raw_logs": "<log file content>", "filename": "events.log" }

// Response
{
  "session_id": "3fa85f64-...",
  "format": "windows",
  "total_events": 3200,
  "suspicious_events": 47,
  "risk_score": 87,
  "risk_level": "CRITICAL",
  "node_count": 33,
  "edge_count": 65,
  "pattern_count": 5
}
```

### GET /api/risk/{id} — technique score example

```json
{
  "technique": "T1110",
  "name": "Brute Force",
  "tactic": "Credential Access",
  "tactic_id": "TA0006",
  "tactic_score": 68,
  "sigma_severity": "high",
  "sigma_score": 72,
  "base_score": 70.4,
  "formula": "(68 × 0.4) + (72 × 0.6) = 70.4  ×  freq_mult(342) = 87.9",
  "final_score": 87.9,
  "risk_level": "CRITICAL",
  "why": "Repeated authentication attempts generate detectable noise...",
  "sigma_rule_refs": ["win_security_susp_failed_logon_reasons.yml"]
}
```

---

## Architecture

```
logmap/
├── logmap.py                       CLI entry point (Click + Rich)
├── docker-compose.yml              Backend + frontend services
├── requirements.txt                CLI + backend dependencies
│
├── backend/
│   ├── main.py                     FastAPI application, session store
│   ├── parsers/
│   │   ├── base_model.py           LogEvent dataclass, EventSeverity enum
│   │   ├── detector.py             Format auto-detection + fallback logic
│   │   ├── windows_parser.py       Windows Event Log (11 Event IDs)
│   │   ├── syslog_parser.py        RFC 3164 + RFC 5424
│   │   └── auth_log_parser.py      SSH, sudo, PAM patterns
│   └── engine/
│       ├── graph_model.py          Node, Edge, GraphModel dataclasses
│       ├── entity_extractor.py     LogEvent[] → Node[] (dedup by MD5 hash)
│       ├── relationship_builder.py LogEvent[] → Edge[] (7 relation types)
│       ├── pattern_detector.py     6 attack pattern detectors
│       ├── technique_db.py         MITRE + Sigma scoring database (14 techniques)
│       └── risk_scorer.py          Global score: tactic×0.4 + sigma×0.6
│
├── frontend/
│   └── src/
│       ├── App.jsx                 Layout: left tabs / graph+timeline / right inspector
│       ├── components/
│       │   ├── LogInput/           Drag & drop + textarea upload
│       │   ├── GraphView/          Cytoscape.js + legend + zoom + neighbourhood highlight
│       │   ├── Timeline/           Recharts stacked bar by severity
│       │   ├── EventsLog/          Filterable structured event list
│       │   ├── NodeInspector/      Generic + Technique deep-dive panels
│       │   ├── RiskPanel/          Gauge + expandable technique scoring breakdown
│       │   └── RecommendationCard/ Prioritised remediation actions
│       └── hooks/
│           ├── useAnalysis.js      API client (ingest + graph + timeline + risk)
│           └── useGraph.js         GraphData → Cytoscape elements (size, color, shape)
│
└── tests/
    ├── test_parsers.py             11 tests — format detection + field extraction
    ├── test_engine.py              13 tests — nodes, edges, risk propagation
    ├── test_patterns.py             8 tests — all 6 attack pattern detectors
    ├── test_api.py                  7 tests — FastAPI endpoints
    ├── test_technique_db.py        13 tests — DB integrity + scoring formula
    ├── sample_windows.log          Minimal Windows Event Log sample
    └── sample_attack.log           Full attack scenario: brute force → lateral move → persistence
```

### Data flow

```
Log file
   │
   ▼
[detector.py]  ──── auto-detect format (Windows / syslog / auth)
   │
   ▼
[*_parser.py]  ──── LogEvent[]  (timestamp, severity, IPs, users, techniques)
   │
   ├──► [entity_extractor.py]  ──── Node[]  (dedup by MD5, risk accumulation)
   │
   ├──► [relationship_builder.py] ── Edge[]  (7 relation types, weight accumulation)
   │
   ├──► [pattern_detector.py]  ──── DetectedPattern[]  (6 pattern types)
   │
   └──► [risk_scorer.py]  ────────── RiskReport  (global score 0-100 + per-technique)
                                       │
                        ┌──────────────┼──────────────┐
                        ▼              ▼               ▼
                 /api/graph      /api/timeline    /api/risk
                        │
                        ▼
                 React UI  (Cytoscape.js graph, Recharts timeline,
                            Node Inspector, Risk Panel, Events Log)
```

---

## Development

### Running tests

```bash
# All test suites
python tests/test_parsers.py
python tests/test_engine.py
python tests/test_patterns.py
python tests/test_api.py
python tests/test_technique_db.py

# Or all at once
for f in tests/test_*.py; do python "$f"; done
```

### Running locally without Docker

```bash
# Terminal 1 — backend
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000

# Terminal 2 — frontend
cd frontend
npm install --legacy-peer-deps
npm run dev          # http://localhost:3000
```

### Adding a new MITRE technique

1. Add an entry to `backend/engine/technique_db.py` with `tactic_score`, `sigma_severity`, `why`, and `sigma_rule_refs`
2. Map it to the relevant Event IDs in `backend/parsers/windows_parser.py` (or the appropriate parser)
3. Add a test case in `tests/test_technique_db.py`

### Adding a new log format

1. Create `backend/parsers/myformat_parser.py` with a `parse_myformat(text) -> list[LogEvent]` function
2. Add detection signatures to `backend/parsers/detector.py`
3. Register the parser in `backend/parsers/__init__.py`
4. Add tests in `tests/test_parsers.py`

---

## Roadmap

### v1.1 — Enhanced Detection
- [ ] **Zeek/Bro log support** — network-layer visibility
- [ ] **Suricata/Snort alert logs** — IDS integration
- [ ] **AWS CloudTrail** — cloud incident response
- [ ] **Sysmon XML** — rich process telemetry

### v1.2 — Investigation Workflows
- [ ] **VirusTotal enrichment** (opt-in) — IP and hash reputation, no log content transmitted
- [ ] **Case management** — save and reload analysis sessions to disk
- [ ] **Attack timeline export** — PDF/HTML report generation
- [ ] **Graph diff** — compare two log files side-by-side

### v1.3 — Scale & Performance
- [ ] **Streaming ingestion** — analyze logs as they arrive (WebSocket)
- [ ] **Large file support** — chunked parsing for multi-GB log files
- [ ] **SQLite persistence** — optional session storage across restarts
- [ ] **Multi-file correlation** — correlate events across several log sources simultaneously

### v1.4 — Enterprise
- [ ] **LDAP/AD integration** — enrich user nodes with directory attributes
- [ ] **SIEM export** — push findings to Splunk / Elastic / QRadar
- [ ] **REST API authentication** — API key or mTLS for shared deployments
- [ ] **Custom Sigma rules** — load your own `.yml` rule files

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Add tests for any new detection logic
4. Open a pull request — describe the threat scenario your change addresses

---

## License

```
MIT License

Copyright (c) 2024 LogMap Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

Built for defenders, by defenders.

**[⚡ LogMap](https://github.com/your-username/logmap)** · MIT License · No cloud required

</div>
