import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("GWS_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("GWS_DOMAIN", "example.com")
    monkeypatch.setenv("GWS_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.delenv("GWS_SERVICE_ACCOUNT_PATH", raising=False)
    yield
