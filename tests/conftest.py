import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DSC_MONITORING_SCHEDULER_ENABLED", "false")
os.environ.setdefault("DSC_MONITORING_PLUS_SCHEDULER_ENABLED", "false")
os.environ.setdefault("DSC_SESSION_SECRET", "test-session-secret")

from app.db.base import Base
from app.db.session import engine
from app.main import create_app


@pytest.fixture()
def client() -> TestClient:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
