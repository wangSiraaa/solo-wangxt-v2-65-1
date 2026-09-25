"""Configuration.

PostgreSQL is the production store (docker-compose starts postgres:16).
DATABASE_URL=postgresql+psycopg://... overrides; otherwise SQLite under
./data is used so the whole workbench is runnable/tested without a DB.
"""
import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("RLAB_DATA", Path(__file__).resolve().parents[1] / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    f"sqlite:///{DATA_DIR / 'rlab.db'}",
)

FRR_HOST_A = os.environ.get("FRR_HOST_A", "127.0.0.1")
FRR_HOST_B = os.environ.get("FRR_HOST_B", "127.0.0.1")
FRR_SSH_PORT_A = int(os.environ.get("FRR_SSH_PORT_A", "2222"))
FRR_SSH_PORT_B = int(os.environ.get("FRR_SSH_PORT_B", "2223"))
FRR_SSH_USER = os.environ.get("FRR_SSH_USER", "root")
FRR_SSH_PASSWORD = os.environ.get("FRR_SSH_PASSWORD", "frrouting")

# Local isolated FRR lab containers (names overridable for nested/isolated
# environments). These are the ONLY devices publish touches; production gear
# is never contacted.
FRR_CONTAINER_A = os.environ.get("FRR_CONTAINER_A", "rpolicy-router-a")
FRR_CONTAINER_B = os.environ.get("FRR_CONTAINER_B", "rpolicy-router-b")

# Validation policy: an FRR cross-validation is part of the frozen approval
# evidence. In container-less labs it may be explicitly relaxed.
RLAB_REQUIRE_FRR = os.environ.get(
    "RLAB_REQUIRE_FRR", "1").lower() not in ("0", "false", "no")

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
