from contextlib import asynccontextmanager
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, SessionLocal, Base
from app.models import (
    User, Endpoint, Application, Policy, Alert, NetworkUsage, MLPrediction,
)
from app.routes.auth import router as auth_router
from app.routes.endpoints import router as endpoints_router
from app.routes.policies import router as policies_router
from app.routes.alerts import router as alerts_router
from app.routes.attacks import router as attacks_router
from app.routes.ml import router as ml_router
from app.websocket.handlers import (
    websocket_network_endpoint,
    websocket_alerts_endpoint,
    websocket_predictions_endpoint,
)
from app.services.seed import seed_database
from app.services.enforcer import enforcer
from app.services.ml_loader import probe_models

_prune_logger = logging.getLogger("guardian-shield.prune")

# Maximum age for ml_predictions rows (days).
_PREDICTION_RETENTION_DAYS = 7
# How often the pruning task runs (seconds).
_PRUNE_INTERVAL_SECONDS = 3600


async def _prune_old_predictions():
    """Background task that deletes ml_predictions older than retention period."""
    from datetime import datetime, timezone, timedelta
    while True:
        await asyncio.sleep(_PRUNE_INTERVAL_SECONDS)
        try:
            db = SessionLocal()
            cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
                days=_PREDICTION_RETENTION_DAYS
            )
            deleted = (
                db.query(MLPrediction)
                .filter(MLPrediction.timestamp < cutoff)
                .delete(synchronize_session=False)
            )
            db.commit()
            if deleted:
                _prune_logger.info(
                    f"Pruned {deleted} ml_predictions older than {_PREDICTION_RETENTION_DAYS}d"
                )
        except Exception as e:
            _prune_logger.warning(f"Prediction pruning failed: {e}")
        finally:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Increase default thread-pool so WebSocket `to_thread` calls don't
    # starve HTTP sync handlers.
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=40))

    # Startup: create tables and seed data
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
        # Sync enforcer: re-apply all active block policies (hosts file + firewall)
        enforcer.sync_from_db(db)
    finally:
        db.close()

    # Probe ML model files so /api/ml/status reports them immediately
    import logging as _logging
    _ml_log = _logging.getLogger("guardian-shield.startup")
    _ml_log.info("Probing ML model artefacts …")
    try:
        found = probe_models()
        _ml_log.info(f"ML models available: {found}")
    except Exception as _exc:
        _ml_log.warning(f"ML model probe failed (non-fatal): {_exc}")

    # Start background task that prunes old ml_predictions rows
    prune_task = asyncio.create_task(_prune_old_predictions())

    yield

    # Shutdown: cancel the pruning task
    prune_task.cancel()
    try:
        await prune_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Guardian Shield - Context-Aware ML Firewall",
    description="Backend API for Guardian Shield — a context-aware ML firewall with real-time threat detection",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(endpoints_router)
app.include_router(policies_router)
app.include_router(alerts_router)
app.include_router(attacks_router)
app.include_router(ml_router)


# WebSocket endpoints
@app.websocket("/ws/network")
async def ws_network(websocket: WebSocket):
    await websocket_network_endpoint(websocket)


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket_alerts_endpoint(websocket)


@app.websocket("/ws/predictions")
async def ws_predictions(websocket: WebSocket):
    await websocket_predictions_endpoint(websocket)


@app.get("/")
def root():
    return {
        "name": "Guardian Shield API",
        "version": "1.0.0",
        "status": "operational",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}
