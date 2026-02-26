"""
Lightweight model-status service for the backend.

The backend does NOT run inference itself — that is handled by the
separate ML engine process (``python -m ml.main``).  However, the
``GET /api/ml/status`` endpoint needs to report which model files
exist and are loadable *right now*, even when the ML engine has not
yet sent any prediction batches.

This module probes the shared ``ml/models/saved/`` directory and
records which artefacts are present.  It is called once during the
FastAPI lifespan startup and the result is cached for the life of
the process.
"""

import os
import logging
from typing import List

logger = logging.getLogger("guardian-shield.ml_loader")

# Expected model artefact filenames → frontend model key
_MODEL_FILES = {
    "isolation_forest.joblib": "isolation_forest",
    "autoencoder.pth":         "autoencoder",
    "xgboost_classifier.joblib": "xgboost",
    "lstm_cnn.pth":            "lstm_cnn",
}

# Singleton state
_loaded_models: List[str] = []


def probe_models(model_dir: str | None = None) -> List[str]:
    """Scan *model_dir* and return the list of model keys whose files exist.

    The result is cached in module-level ``_loaded_models`` so that
    ``get_loaded_models()`` can be called cheaply from the route handler.
    """
    global _loaded_models

    if model_dir is None:
        # The ML models live at  <project_root>/ml/models/saved/
        # The backend runs from  <project_root>/backend/
        backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        model_dir = os.path.join(os.path.dirname(backend_dir), "ml", "models", "saved")

    found: List[str] = []
    if not os.path.isdir(model_dir):
        logger.warning(f"Model directory does not exist: {model_dir}")
        _loaded_models = found
        return found

    for filename, key in _MODEL_FILES.items():
        full_path = os.path.join(model_dir, filename)
        if os.path.isfile(full_path):
            size_kb = os.path.getsize(full_path) / 1024
            logger.info(f"  ✓ {key:20s}  ({filename}, {size_kb:.1f} KB)")
            found.append(key)
        else:
            logger.info(f"  ✗ {key:20s}  ({filename} not found)")

    _loaded_models = found
    logger.info(f"Models available: {found}")
    return found


def get_loaded_models() -> List[str]:
    """Return the cached list of model keys discovered at startup."""
    return _loaded_models
