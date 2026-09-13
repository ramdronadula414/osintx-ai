"""Unit/regression tests never contact real targets or use personal credentials."""
import pytest
import requests


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    import config.loader
    import database.store
    monkeypatch.setattr(config.loader, 'USER_CONFIG_PATH', tmp_path / 'config.yaml')
    monkeypatch.setattr(database.store, 'DB_PATH', tmp_path / 'history.db')
    for name in ['GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GROQ_API_KEY', 'GEMINI_MODEL', 'GROQ_MODEL', 'OSINTX_AI_PROVIDER']:
        monkeypatch.delenv(name, raising=False)
    def blocked(*args, **kwargs):
        raise requests.ConnectionError('offline test environment')
    monkeypatch.setattr(requests, 'request', blocked)
