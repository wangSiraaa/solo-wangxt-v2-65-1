"""Pytest configuration: backend on sys.path, temp DB, stub FRR transport."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

_tmpdir = tempfile.mkdtemp(prefix="rlab-test-")
os.environ["RLAB_DATA"] = _tmpdir
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmpdir) / 'test.db'}"
# no docker socket in CI/unit runs: drive the isolated-FRR semantics through
# the in-process stub (same prefix_list_apply model; supports failure
# injection). Live-container tests probe for docker and skip when absent.
os.environ["RLAB_FRR_TRANSPORT"] = "stub"
os.environ["RLAB_PUBLISH_NODES"] = "a,b"
# env must be set before any app.* import reads config.py


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    from app import db as dbmod
    from app.migrate import upgrade
    upgrade()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db():
    from app import db as dbmod
    from app.frr_bridge import reset_stub
    dbmod.init_db()
    s = dbmod.SessionLocal()
    # clean slate for ordering-sensitive tests
    for tbl in (dbmod.ReleaseEvent, dbmod.Release, dbmod.Run, dbmod.Scenario,
                dbmod.Snapshot, dbmod.Rule, dbmod.Policy, dbmod.Neighbor):
        s.query(tbl).delete()
    s.commit()
    reset_stub()
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _reset_isolated_frr():
    """Every test starts with empty isolated FRR containers."""
    from app.frr_bridge import reset_stub
    reset_stub()
    yield
    reset_stub()
