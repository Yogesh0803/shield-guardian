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

## How to Run (Step by Step)

### Step 1 — Open the Project Folder

Open the `guardian-shield` folder in your file explorer or in VS Code.

---

### Step 2 — Start the Backend (Run as Administrator)

> **Important:** The backend **must** run with Administrator privileges so that firewall blocking (hosts file + netsh rules) works correctly. Without admin rights the app will start but blocking features will be disabled.

#### Windows (PowerShell — recommended)

1. **Right-click** on **Windows Terminal** or **PowerShell** and select **"Run as Administrator"**.
2. Navigate to the backend folder:
   ```powershell
   cd "path\to\guardian-shield\backend"
   ```
3. Install Python dependencies (only needed the first time):
   ```powershell
   pip install -r requirements.txt
   ```
4. *(Optional)* Create a `.env` file from the example:
   ```powershell
   copy .env.example .env
   ```
   The defaults work out of the box — no changes needed for local development.

5. Start the backend server:
   ```powershell
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
6. You should see:
   ```
   INFO:     Uvicorn running on http://0.0.0.0:8000
   INFO:     Application startup complete.
   ```

> **Keep this terminal open.** The backend runs on **http://localhost:8000**.

#### Quick health check

Open a browser or a new terminal and run:
```
curl http://localhost:8000/health
```
Expected response: `{"status":"healthy"}`

---

### Step 3 — Start the Frontend

Open a **new / separate terminal** (admin is not required for the frontend).

1. Navigate to the frontend folder:
   ```powershell
   cd "path\to\guardian-shield\frontend"
   ```
2. Install Node dependencies (only needed the first time):
   ```powershell
   npm install --legacy-peer-deps
   ```
3. *(Optional)* Create a `.env` file from the example:
   ```powershell
   copy .env.example .env
   ```
   The defaults (`REACT_APP_API_URL=http://localhost:8000`) work out of the box.

4. Start the React development server:
   ```powershell
   npm start
   ```
5. The browser will automatically open **http://localhost:3000** with the Guardian Shield dashboard.

> **Keep this terminal open.** The frontend runs on **http://localhost:3000**.

---

### Step 4 — Log In

Use the default admin credentials to log in:

| Field | Value |
|-------|-------|
| **Email** | `admin@guardian.com` |
| **Password** | `password123` |

The backend auto-seeds sample data (endpoints, alerts, network traffic) on first startup, so the dashboard will already have content to explore.

---

### Step 5 — (Optional) Start the ML Engine

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
| 1 | Backend | `backend/` | `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000` | **Yes** |
| 2 | Frontend | `frontend/` | `npm start` | No |
| 3 | ML Engine *(optional)* | `ml/` | `python -m ml.main` | **Yes** |

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
| `PermissionError` / hosts file warning | You are not running the backend as Administrator. Close the terminal, reopen with **Run as Administrator**, and start again. |
| `npm install` fails with peer dependency errors | Use `npm install --legacy-peer-deps` |
| Port 8000 already in use | Stop the other process or change the port: `uvicorn app.main:app --reload --port 8001` |
| Port 3000 already in use | React will prompt you to use another port — type `Y` to accept |
| Frontend can't reach backend | Make sure the backend is running first, and both `.env` files point to the correct URLs |

## License

MIT License — see [LICENSE](LICENSE) for details.
