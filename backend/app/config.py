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

# Nodes a simulated publish writes to; publish validates/applies every node
# listed here.  Lab-only (internal bridge), never production equipment.
PUBLISH_NODES = [n.strip() for n in os.environ.get(
    "RLAB_PUBLISH_NODES", "a,b").split(",") if n.strip()]
# Prefix-list name reserved for the currently published revision of a policy.
# Validation runs use the policy's own name and delete it afterwards, so the
# two never collide inside the isolated FRR containers.
PUBLISH_PLIST_PREFIX = os.environ.get("RLAB_PUBLISH_PLIST_PREFIX", "rlabpub")

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
