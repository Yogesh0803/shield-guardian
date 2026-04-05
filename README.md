# Guardian Shield: Context-Aware ML Firewall

A full-stack, context-aware ML firewall powered by machine learning. Captures live network traffic, analyzes it in real-time using an ensemble of ML models, makes intelligent blocking decisions based on application context, and displays everything through a modern React dashboard.

---

## Prerequisites

Make sure the following are installed on your system before proceeding:

| Tool | Version | Download |
|------|---------|----------|
| **Python** | 3.10 or higher | https://www.python.org/downloads/ |
| **Node.js** | 18 or higher (includes npm) | https://nodejs.org/ |
| **pip** | comes with Python | — |

> **Verify installations** by running these in any terminal:
> ```
> python --version
> node --version
> npm --version
> pip --version
> ```

---

## How to Run (Verified on Windows)

### Option A (recommended): use the dev runner

This starts backend + frontend together and handles logs in one terminal.

1. Open **PowerShell as Administrator**.
2. Go to the repo root:
   ```powershell
   cd "path\to\guardian-shield"
   ```
3. Install dependencies (first run only):
   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
   cd frontend
   npm install --legacy-peer-deps
   cd ..
   ```
4. Start the project:
   ```powershell
   .\.venv\Scripts\python.exe run_dev.py
   ```

Expected startup output includes backend/frontend tags and URLs for `http://localhost:8000` and `http://localhost:3000`.

Quick verification:
```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:3000
```

### Option B: start services manually (fallback)

Use this if you want separate terminals or need to debug startup.

1. Terminal 1 (backend):
   ```powershell
   cd "path\to\guardian-shield"
   .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
   $env:PYTHONPATH = (Get-Location).Path
   cd backend
   ..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

2. Backend health check (new terminal):
   ```powershell
   curl http://127.0.0.1:8000/health
   ```
   Expected response:
   ```json
   {"status":"healthy"}
   ```

3. Terminal 2 (frontend):
   ```powershell
   cd "path\to\guardian-shield\frontend"
   npm install --legacy-peer-deps
   npm start
   ```

4. Verify both services:
   ```powershell
   curl http://127.0.0.1:8000/health
   curl http://127.0.0.1:3000
   ```

5. Open the dashboard at `http://localhost:3000`.

### Exact commands that were validated in this workspace

From repo root (`e:\guardian-shield`), this sequence successfully started both services:

```powershell
# Backend terminal
cd e:\guardian-shield
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
$env:PYTHONPATH = "e:/guardian-shield"
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
# Frontend terminal
cd e:\guardian-shield\frontend
npm install --legacy-peer-deps
npm start
```

Expected checks:
- `http://127.0.0.1:8000/health` returns `{"status":"healthy"}`
- `http://127.0.0.1:3000` returns HTTP 200

---

### Step 2 — Log In

Use the default admin credentials to log in:

| Field | Value |
|-------|-------|
| **Email** | `admin@guardian.com` |
| **Password** | `password123` |

The backend auto-seeds sample data (endpoints, alerts, network traffic) on first startup, so the dashboard will already have content to explore.

---

### Step 3 — (Optional) Start the ML Engine

The ML engine captures live network packets and feeds real-time predictions to the dashboard. It requires admin/root privileges for packet capture.

1. Open a **new Administrator terminal**.
2. Navigate to the ML folder:
   ```powershell
   cd "path\to\guardian-shield\ml"
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Run the ML engine:
   ```powershell
   python -m ml.main
   ```

---

## Summary — What to Run

| # | Terminal | Folder | Command | Admin? |
|---|----------|--------|---------|--------|
| 1 | Dev runner (recommended) | repo root | `.\.venv\Scripts\python.exe run_dev.py` | **Yes** |
| 2 | Backend (manual fallback) | `backend/` | `$env:PYTHONPATH='<repo-root>'; ..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000` | No (recommended Yes for enforcement) |
| 3 | Frontend | `frontend/` | `npm install --legacy-peer-deps && npm start` | No |
| 4 | ML Engine *(optional)* | `ml/` | `python -m ml.main` | **Yes** |

| Service | URL |
|---------|-----|
| Frontend (Dashboard) | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |

---

## Architecture

```
                        React Frontend (TypeScript)
               Dashboard | Endpoints | Policies | Alerts | ML Status
                              |
                     REST API + WebSocket
                              |
                    FastAPI Backend (Python)
              Auth | CRUD | WebSocket Broadcast | Seed Data
                              |
                   ________________________
                  |                        |
              SQLite DB              ML Engine
                              |
            ___________________________________
           |          |           |             |
      Scapy       Context     ML Models     Policy
     Capture      Engine      Ensemble      Engine
                     |           |             |
               App Identity   Isolation    User Rules
               Time/Geo       Forest +     + ML-based
               Behavior       Autoencoder    Decisions
               Baseline       LSTM+CNN         |
                              XGBoost      Firewall
                                          Enforcement
                                        (netsh/iptables)
```

## What It Does

1. **Captures live network traffic** using Scapy — groups packets into flows
2. **Builds context** for every flow:
   - Which app made the request (psutil PID mapping)
   - Time of day, business hours, day of week
   - Behavioral baseline deviations (is this request rate normal?)
   - Geographic destination (GeoIP lookup)
3. **Analyzes with 4 ML models** (ensemble):
   - **Isolation Forest** — fast anomaly scoring
   - **Autoencoder** (PyTorch) — reconstruction-based anomaly detection
   - **LSTM+CNN hybrid** — deep learning on packet features
   - **XGBoost** — attack type classification (DoS, DDoS, PortScan, BruteForce, WebAttack, Botnet, Infiltration)
4. **Makes smart decisions** combining user policies + ML predictions
5. **Enforces firewall rules** — actually blocks malicious IPs (netsh on Windows, iptables on Linux)
6. **Displays everything** on a real-time dashboard with WebSocket streaming

## Project Structure

```
guardian-shield/
├── frontend/                # React + TypeScript
│   ├── src/
│   │   ├── pages/           # Dashboard, Endpoints, Policies, Alerts, Network, MLEngine
│   │   ├── components/      # Reusable UI (Card, Badge, Button, Modal, etc.)
│   │   ├── services/        # API service layer (axios + JWT)
│   │   ├── hooks/           # useWebSocket, useAuth
│   │   ├── context/         # AuthContext
│   │   └── types/           # TypeScript interfaces
│   ├── Dockerfile
│   └── package.json
│
├── backend/                 # Python FastAPI
│   ├── app/
│   │   ├── routes/          # auth, endpoints, policies, alerts, attacks, ml
│   │   ├── models/          # SQLAlchemy models (User, Endpoint, Policy, Alert, etc.)
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── middleware/      # JWT auth, role-based access
│   │   ├── websocket/       # ConnectionManager + real-time handlers
│   │   ├── services/        # Database seeding + policy enforcer
│   │   └── main.py          # FastAPI app entry
│   ├── Dockerfile
│   └── requirements.txt
│
├── ml/                      # ML Engine
│   ├── capture/             # Scapy packet capture + feature extraction
│   ├── context/             # App identifier, time, behavior, geo lookup
│   ├── models/              # Anomaly detector, attack classifier, LSTM+CNN
│   ├── pipeline/            # Inference pipeline + training scripts
│   ├── enforcer/            # Policy engine, firewall rules, NLP parser
│   ├── main.py              # ML engine entry point
│   └── requirements.txt
│
├── docker-compose.yml
└── README.md
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, TypeScript, Tailwind CSS, Chart.js, Framer Motion, Lucide Icons |
| **Backend** | Python, FastAPI, SQLAlchemy, Alembic, JWT (python-jose), Pydantic |
| **ML** | Scapy, scikit-learn, XGBoost, PyTorch, psutil, geoip2 |
| **Database** | SQLite (dev) / PostgreSQL (prod) |
| **DevOps** | Docker, Docker Compose |

## Natural Language Policies

Users can describe policies in plain English:

> "Block Chrome from accessing Russian IPs after 10PM"

The NLP parser extracts:
- **Action**: block
- **App**: chrome
- **Country**: RU
- **Time**: after 22:00

Supported conditions: apps, IPs, domains, ports, protocols, time ranges, days of week, geolocation, anomaly thresholds, attack types, rate limits.

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/auth/register` | Register user |
| POST | `/api/auth/login` | Login (returns JWT) |
| GET | `/api/auth/me` | Current user |
| GET | `/api/endpoints` | List endpoints |
| GET | `/api/endpoints/:id` | Endpoint details |
| POST | `/api/endpoints/:id/apps` | Add app to endpoint |
| GET/POST/DELETE | `/api/policies/*` | Policy CRUD |
| POST | `/api/policies/parse` | NLP policy parsing |
| GET | `/api/alerts` | Alerts (filterable) |
| GET | `/api/attacks/endpoint/:id` | Attack statistics |
| GET | `/api/ml/status` | ML engine status |
| POST | `/api/ml/retrain` | Trigger retraining |
| WS | `/ws/network` | Real-time network data |
| WS | `/ws/alerts` | Real-time alert stream |
| WS | `/ws/predictions` | Real-time ML predictions |

## Key Features

- **Real JWT Authentication** with access/refresh tokens and role-based access
- **Live Network Traffic Charts** updating in real-time via WebSocket
- **ML Prediction Feed** showing every allow/block/alert decision with confidence
- **Context Viewer** — click any alert to see full context (app, time, behavior, geo)
- **Attack Distribution Charts** from real ML classification
- **Natural Language Policy Creation** — describe rules in plain English
- **Cross-platform Enforcement** — blocks traffic on Windows (netsh) and Linux (iptables)
- **Automated Seed Data** — backend auto-populates with realistic sample data

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Backend needs Administrator privileges for policy enforcement` when using `run_dev.py` | Run PowerShell as Administrator and start again, or use the manual fallback commands above. |
| `ModuleNotFoundError: No module named 'ml'` when starting backend manually | Start from repo root and set `PYTHONPATH` to the repo root before launching Uvicorn. |
| `npm install` fails with peer dependency errors | Use `npm install --legacy-peer-deps` |
| `'react-scripts' is not recognized` | Run `npm install --legacy-peer-deps` in `frontend/` (even if `node_modules` already exists). |
| Port 8000 already in use | Stop the other process or change the port: `uvicorn app.main:app --reload --port 8001` |
| Port 3000 already in use | React will prompt you to use another port — type `Y` to accept |
| Frontend can't reach backend | Make sure the backend is running first, and both `.env` files point to the correct URLs |

### Windows quick fix: free port 3000

If `npm start` says something is already running on port 3000 and you get access-denied when stopping it from a normal shell:

1. Open **PowerShell as Administrator**.
2. Find the process on port 3000:
   ```powershell
   Get-NetTCPConnection -LocalPort 3000 -State Listen | Select-Object OwningProcess, LocalAddress, LocalPort
   ```
3. Kill that process (replace PID):
   ```powershell
   taskkill /PID <PID> /T /F
   ```
4. Start frontend again:
   ```powershell
   cd e:\guardian-shield\frontend
   npm start
   ```

Temporary workaround if you cannot kill PID 3000 owner immediately:

```powershell
cd e:\guardian-shield\frontend
$env:PORT = "3001"
npm start
```

## License

MIT License — see [LICENSE](LICENSE) for details.

# Updated on 05-04-2026 (20:42)