"""Loopback by default; Render's PORT is used only in explicit cloud account mode."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.guardian.environment import load_environment

load_environment()
if os.getenv('GUARDIAN_CLOUD_MODE', 'false').lower() == 'true':
    from backend.guardian.account_auth import settings, trusted_origin
    settings()
    if not os.getenv('GUARDIAN_DATABASE_URL'):
        raise SystemExit('Set GUARDIAN_DATABASE_URL and apply the Supabase account migration before deployment.')
    for key in ('GUARDIAN_FRONTEND_URL','GUARDIAN_PUBLIC_API_URL'):
        if not os.getenv(key): raise SystemExit('Set '+key+' before deployment.')
        trusted_origin(os.environ[key],key)
    if not os.getenv('GUARDIAN_ALLOWED_ORIGINS'): raise SystemExit('Set GUARDIAN_ALLOWED_ORIGINS to the exact frontend origin.')
    host, port = '0.0.0.0', int(os.getenv('PORT','8000'))
else:
    host, port = '127.0.0.1', 8000

if __name__ == '__main__':
    import uvicorn
    # Access logs include callback authorization-code query strings; disable them.
    uvicorn.run('backend.guardian.main:app', host=host, port=port, access_log=False)
