import pytest
import httpx
@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'false')
    monkeypatch.setenv('GUARDIAN_DB', str(tmp_path / 'scans.sqlite3'))

@pytest.fixture(autouse=True)
def no_external_advisory_requests(monkeypatch):
    def offline(*args, **kwargs):
        raise httpx.ConnectError('Test network disabled')
    monkeypatch.setattr(httpx, 'get', offline)
    from backend.guardian import ingestion
    monkeypatch.setattr(ingestion, 'download', offline)
