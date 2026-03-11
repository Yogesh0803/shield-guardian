import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent

root_str = str(PROJECT_ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)

backend_dir = PROJECT_ROOT / "backend"
backend_str = str(backend_dir)
if backend_dir.exists() and backend_str not in sys.path:
    sys.path.insert(0, backend_str)

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_guardian_shield.db")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("ML_API_KEY", "test-ml-key")
