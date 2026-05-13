# 🛡️ Aegis Sentinel v3.0

![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/fastapi-0.109-green)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Detection](https://img.shields.io/badge/detection-rule--based%20%2B%20ML-orange)
![Auth](https://img.shields.io/badge/auth-JWT-red)

> Real-time threat detection and SOC monitoring platform — multi-signal behavioral analysis, ML threat scoring, automated IP blocking, JWT auth, and a live SOC dashboard. Built with FastAPI + SQLite + Chart.js.

---

## Overview

Aegis Sentinel is a full-stack cybersecurity monitoring system that analyzes incoming HTTP traffic in real time, scores threats using a weighted multi-signal engine, auto-blocks malicious IPs, generates alerts, and surfaces everything in a SOC-style dashboard.

The system combines **rule-based detection** (known bot signatures, suspicious headers, path matching) with a **behavioral ML scoring engine** (request frequency, session entropy, temporal patterns, header variance) to classify threats from `minimal` to `critical`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      AEGIS SENTINEL v3.0                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              FASTAPI BACKEND (main.py)                    │  │
│  │   Request interception, rate limiting, IP tracking        │  │
│  │   JWT auth middleware, REST API, dashboard serving        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
│            ┌─────────────────┼──────────────────┐               │
│            ▼                 ▼                  ▼               │
│  ┌──────────────────┐ ┌────────────────┐ ┌──────────────────┐   │
│  │  THREAT DETECTOR │ │  ML SCORER     │ │  AUTH MODULE     │   │
│  │  detection.py    │ │  detection.py  │ │  auth.py         │   │
│  │                  │ │                │ │                  │   │
│  │ - Request rate   │ │ - 8 ML features│ │ - JWT HS256      │   │
│  │ - Bot patterns   │ │ - Weighted     │ │ - PBKDF2 hashing │   │
│  │ - Suspicious UA  │ │   scoring      │ │ - Role-based     │   │
│  │ - Path matching  │ │ - Anomaly flag │ │ - 60min expiry   │   │
│  │ - Header analysis│ │ - Category     │ │ - Middleware     │   │
│  │ - Behavioral     │ │   prediction   │ │   enforcement    │   │
│  │ - Reputation     │ │                │ │                  │   │
│  └──────────────────┘ └────────────────┘ └──────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │              DATABASE LAYER (database.py)                 │  │
│  │   SQLite + 7 tables: users, ip_tracking, request_log,     │  │
│  │   alerts, threat_signatures, ml_model_cache, settings     │  │
│  └────────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         SOC DASHBOARD (index.html + Chart.js)             │  │
│  │   Live stats, IP table, alert feed, threat visualization  │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Detection Engine

### ThreatDetector — Rule-Based (5 signals, weighted)

| Signal | Weight | What It Analyzes |
|--------|--------|-----------------|
| `request_rate` | 25% | Requests per second vs window threshold |
| `behavioral` | 25% | RPM, unique agents, total request volume |
| `pattern_match` | 20% | Known bot UAs, suspicious paths, tool signatures |
| `header_analysis` | 15% | Suspicious headers, missing headers, proxy indicators |
| `reputation` | 15% | IP class analysis, multicast ranges |

**Known bot/scanner signatures detected:**
`curl`, `wget`, `python`, `scrapy`, `nmap`, `sqlmap`, `hydra`, `metasploit`, `nikto`, `masscan`, `burp`, `dirbuster`, `gobuster`, and more.

**Suspicious paths flagged:**
`/admin`, `/wp-login`, `/wp-admin`, `/phpmyadmin`, `/.env`, `/.git`, `/config`, `/backup`, `/xmlrpc.php`, `/wp-config.php`, `/administrator`, and more.

### MLThreatScorer — Behavioral ML (8 features, weighted)

| Feature | Weight | Logic |
|---------|--------|-------|
| `request_frequency` | 15% | RPM scoring — 100+ RPM = 1.0 |
| `behavioral` | 15% | Requests/second thresholds |
| `temporal_pattern` | 15% | Interval variance — low variance = bot |
| `path_entropy` | 12% | Path diversity ratio — low = scanning |
| `header_variance` | 13% | Header count — sparse = automated |
| `session_duration` | 10% | Very short sessions = high score |
| `threat_history` | 10% | Historical score amplified 1.2x |
| `geo_anomaly` | 10% | Reserved for future geolocation |

**Threat category prediction:**
```
request_frequency > 0.8  → ddos
behavior_anomaly > 0.7   → bruteforce
path_entropy > 0.6       → scanning
header_variance > 0.5    → bot
else                     → unknown
```

### Risk Levels

| Score | Risk Level | Severity | Action |
|-------|-----------|---------|--------|
| 0.0 – 0.19 | minimal | low | Monitor |
| 0.2 – 0.39 | low | low | Monitor |
| 0.4 – 0.59 | medium | medium | Flag |
| 0.6 – 0.79 | high | high | Alert + Block |
| 0.8 – 1.0 | critical | critical | Auto-block + Alert |

---

## Authentication System

- **JWT HS256** tokens with 60-minute expiry
- **PBKDF2-HMAC-SHA256** password hashing (100,000 iterations) with random salt
- **Role-based access** — `admin` and `operator` roles
- **Auth middleware** — all API routes protected except `/api/login`, `/api/register`, `/`, `/docs`
- Default admin: `admin` / `aegis2024!` (change in production)

---

## Database Schema (7 Tables)

| Table | Purpose |
|-------|---------|
| `users` | User accounts with PBKDF2 hashed passwords, roles, last login |
| `ip_tracking` | Per-IP state — request count, block status, threat score, risk level |
| `request_log` | Full request history — IP, status, UA, threat score, response time |
| `alerts` | Alert feed — severity, message, acknowledgment tracking |
| `threat_signatures` | Extensible threat pattern database |
| `ml_model_cache` | ML prediction cache per IP |
| `settings` | Runtime configurable parameters |

**Indexes:** `request_log.ip_address`, `request_log.timestamp`, `alerts.severity`

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/` | No | SOC Dashboard |
| `POST` | `/api/login` | No | JWT login |
| `POST` | `/api/register` | No | User registration |
| `GET` | `/api/data` | Yes | Analyze request, returns threat assessment |
| `GET` | `/api/stats` | Yes | Full stats — IPs, alerts, recent requests |
| `GET` | `/api/alerts` | Yes | Active alert feed |
| `POST` | `/api/alerts/{id}/acknowledge` | Yes | Acknowledge alert |
| `GET` | `/api/threat-analysis/{ip}` | Yes | Deep analysis for specific IP |
| `GET` | `/api/ml-training-data` | Yes | ML feature export for training |
| `DELETE` | `/api/unblock/{ip}` | Yes | Unblock an IP |
| `DELETE` | `/api/reset` | Yes | Clear all tracking data |
| `GET` | `/api/settings` | Yes | Get runtime config |
| `POST` | `/api/settings` | Yes | Update runtime config |

---

## Runtime Configuration (Adjustable via API)

| Setting | Default | Description |
|---------|---------|-------------|
| `max_requests` | 10 | Max requests per window before block |
| `window_seconds` | 15 | Rate limit sliding window |
| `block_duration` | 300 | IP block duration in seconds |
| `ml_threshold` | 0.7 | ML score threshold for flagging |
| `enable_ml` | true | Enable ML scoring |
| `auto_block` | true | Automatically block critical threats |

---

## Installation

```bash
git clone https://github.com/Ki1shan/Aegis_Sentinel.git
cd Aegis_Sentinel
pip install -r requirements.txt
python main.py
```

Open the SOC dashboard at `http://127.0.0.1:8000/`

---

## Usage

### Default Login
```
Username: admin
Password: aegis2024!
```

### API Usage

**Login:**
```bash
curl -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "aegis2024!"}'
```

**Analyze a request:**
```bash
curl http://127.0.0.1:8000/api/data \
  -H "Authorization: Bearer <token>"
```

**Get full stats:**
```bash
curl http://127.0.0.1:8000/api/stats \
  -H "Authorization: Bearer <token>"
```

**Deep IP threat analysis:**
```bash
curl http://127.0.0.1:8000/api/threat-analysis/192.168.1.100 \
  -H "Authorization: Bearer <token>"
```

---

## Sample Threat Response

```json
{
  "status": "danger",
  "message": "DDoS SIGNATURE DETECTED - IP QUARANTINED",
  "ip": "192.168.1.9",
  "count": 15,
  "threat_score": 0.87,
  "risk_level": "critical",
  "detected_patterns": ["Rapid requests: 15 in 15s"],
  "ml_analysis": {
    "confidence": 0.92,
    "recommendations": ["Consider IP blocking", "Enable enhanced monitoring"]
  },
  "blocked": true,
  "response_time_ms": 2.41
}
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, FastAPI, uvicorn |
| Frontend | HTML, TailwindCSS, JavaScript, Chart.js |
| Auth | JWT (PyJWT), PBKDF2-HMAC-SHA256 |
| Database | SQLite3 |
| Detection | Rule-based + weighted ML scoring |

---

## Author

**Kishan N**
Offensive Security Engineer | Blue Team & Detection Engineering

Built Aegis Sentinel to demonstrate how multi-signal behavioral analysis and ML scoring can be combined in a lightweight, deployable SOC platform without requiring external ML frameworks.

---

## License

MIT License — see `LICENSE` file for details.

---

*Detect early. Block fast. Stay vigilant.*
