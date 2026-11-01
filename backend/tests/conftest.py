import pytest
import httpx
@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'false')
    monkeypatch.setenv('GUARDIAN_DB', str(tmp_path / 'scans.sqlite3'))
    # Never use a developer's real account database/Auth configuration in tests.
    for key in ('GUARDIAN_DATABASE_URL','SUPABASE_URL','SUPABASE_PUBLISHABLE_KEY','NEXT_PUBLIC_SUPABASE_URL','NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY'):
        monkeypatch.delenv(key,raising=False)
    monkeypatch.setenv('GUARDIAN_ACCOUNT_STORE','sqlite')
    monkeypatch.setenv('GUARDIAN_CLOUD_MODE','false')

@pytest.fixture(autouse=True)
def no_external_advisory_requests(monkeypatch):
    def offline(*args, **kwargs):
        raise httpx.ConnectError('Test network disabled')
    monkeypatch.setattr(httpx, 'get', offline)
    from backend.guardian import ingestion
    monkeypatch.setattr(ingestion, 'download', offline)
