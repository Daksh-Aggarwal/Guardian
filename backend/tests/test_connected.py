"""Local callback/credential tests and CLI-to-API flow; Supabase/provider calls are mocked."""
import json
import os
import threading
import time
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.guardian import account_api, connected, credential_store, local_reports
from backend.guardian.credential_store import Credentials
from backend.guardian.main import app
from backend.guardian.supply_models import AcquisitionError
from backend.tests.test_accounts import auth, report


@pytest.fixture(autouse=True)
def private_home(monkeypatch,tmp_path):
    monkeypatch.setenv('GUARDIAN_HOME',str(tmp_path/'state'))
    monkeypatch.setenv('GUARDIAN_API_URL','http://127.0.0.1:8000')
    monkeypatch.setenv('GUARDIAN_ALLOW_FILE_CREDENTIALS','false')


def test_explicit_private_file_fallback_persistence_logout_and_new_device(monkeypatch):
    monkeypatch.setattr(Credentials,'secure_backend',lambda self:None)
    c=Credentials('https://guardian.example')
    with pytest.raises(AcquisitionError,match='credential manager'): c.prepare()
    c.allow_file=True
    assert c.prepare()=='file'
    c.save({'access_token':'private','refresh_token':'private-refresh'})
    next_client=Credentials('https://guardian.example')
    assert next_client.meta['device_id']==c.meta['device_id'] and next_client.load()['refresh_token']=='private-refresh'
    assert next_client.file.stat().st_mode & 0o077 == 0
    newer=Credentials('https://guardian.example',allow_file=True,new_device=True)
    assert newer.meta['device_id']!=c.meta['device_id'] and not c.file.exists()
    newer.prepare();newer.save({'refresh_token':'new-private'});newer.clear()
    assert newer.load() is None


def test_os_keyring_persistence_and_deletion(monkeypatch):
    entries={}
    class Store:
        def get_password(self,s,u): return entries.get((s,u))
        def set_password(self,s,u,p): entries[(s,u)]=p
        def delete_password(self,s,u): entries.pop((s,u),None)
    store=Store()
    monkeypatch.setattr(Credentials,'secure_backend',lambda self:store)
    c=Credentials('https://guardian.example');assert c.prepare()=='keyring'
    c.save({'refresh_token':'keychain-only'})
    assert not c.file.exists() and 'keychain-only' not in c.metadata.read_text()
    assert Credentials(c.api_url).load()['refresh_token']=='keychain-only'
    c.clear();assert c.load() is None


def test_insecure_or_symbolic_credential_files_rejected(monkeypatch,tmp_path):
    monkeypatch.setattr(Credentials,'secure_backend',lambda self:None)
    c=Credentials('https://guardian.example',allow_file=True);c.prepare();c.save({'refresh_token':'secret'})
    if os.name!='nt':
        c.file.chmod(0o644)
        with pytest.raises(AcquisitionError,match='permissions'):c.load()
    c.file.unlink();target=tmp_path/'target';target.write_text('{}');c.file.symlink_to(target)
    with pytest.raises(AcquisitionError):c.load()


def test_loopback_rejects_wrong_state_then_accepts_correct_state():
    with connected.CallbackServer('correct-state') as server:
        worker=threading.Thread(target=lambda:[server.handle_request(),server.handle_request()]);worker.start()
        with httpx.Client(timeout=3) as client:
            base=f'http://127.0.0.1:{server.server_port}/callback'
            assert client.get(base,params={'state':'wrong','code':'x'}).status_code==400
            assert server.result is None
            assert client.get(base,params={'state':'correct-state','code':'valid-code'}).status_code==200
        worker.join(timeout=3)
        assert server.receive(1)=='valid-code'


def test_cli_login_sync_dashboard_and_logout_through_actual_api(auth,monkeypatch):
    monkeypatch.setattr(Credentials,'secure_backend',lambda self:None)
    api=TestClient(app);token=auth();browser_threads=[]
    monkeypatch.setattr(account_api,'supabase_request',lambda path,payload=None,access_token=None:{'access_token':token,'refresh_token':'mock-supabase-refresh-token','expires_in':3600})
    def request(self,method,path,payload=None,token=None):
        result=api.request(method,'/api/account'+path,json=payload,headers={'Authorization':'Bearer '+token} if token else {})
        if result.status_code>=300:raise AcquisitionError('Account request failed')
        return result.json()
    monkeypatch.setattr(connected.AccountClient,'request',request)
    def browser(url):
        identifier=parse_qs(urlparse(url).query)['request_id'][0]
        info=api.get('/api/account/cli/requests/'+identifier).json()
        assert parse_qs(urlparse(info['authorize_url']).query)['code_challenge_method']==['s256']
        callback=api.get('/api/account/cli/callback/'+identifier,params={'code':'mock-supabase-one-use-code'},follow_redirects=False)
        thread=threading.Thread(target=lambda:httpx.Client(timeout=3).get(callback.headers['location']))
        thread.start();browser_threads.append(thread)
        return True
    monkeypatch.setattr(connected.webbrowser,'open',browser)
    cli=connected.AccountClient(allow_file=True)
    assert cli.login('0.2.0',timeout=5)['authentication']=='Connected'
    for thread in browser_threads:thread.join(timeout=3)
    local=report();path=local_reports.save(local);before=path.read_bytes()
    assert cli.sync([local])['count']==1
    assert connected.AccountClient().sync([local])['count']==0
    headers={'Authorization':'Bearer '+token}
    assert api.get('/api/account/overview',headers=headers).json()['total_scans']==1
    stored=api.get('/api/account/scans/'+local.id,headers=headers).json()
    assert stored['cli']['decision']['decision']=='BLOCK'
    assert len(api.get('/api/account/devices',headers=headers).json())==1
    assert cli.status()['authentication']=='Connected'
    assert cli.logout()['authentication']=='Local'
    assert Credentials(cli.base).load() is None and path.read_bytes()==before
    assert api.get('/api/account/me',headers=headers).status_code==403


def test_refresh_rotation_persists_and_failure_keeps_local_reports(monkeypatch):
    monkeypatch.setattr(Credentials,'secure_backend',lambda self:None)
    cli=connected.AccountClient(allow_file=True);cli.credentials.prepare()
    session={'access_token':'old','refresh_token':'old-refresh','expires_at':1,'device':{'id':str(uuid4())},'user':{'id':str(uuid4())}}
    cli.credentials.save(session)
    calls=[]
    def refresh(method,path,payload=None,token=None):
        calls.append(path)
        return {'access_token':'new','refresh_token':'rotated-refresh','expires_in':3600}
    monkeypatch.setattr(cli,'request',refresh)
    assert cli.authenticated()['access_token']=='new'
    assert Credentials(cli.base).load()['refresh_token']=='rotated-refresh'
    assert calls==['/cli/refresh']
    local=report();path=local_reports.save(local);before=path.read_bytes()
    def unavailable(*args,**kwargs):raise AcquisitionError('offline')
    monkeypatch.setattr(cli,'request',unavailable)
    with pytest.raises(AcquisitionError):cli.sync([local])
    assert path.read_bytes()==before and not list(path.parent.glob('sync-ledger-*'))
    with pytest.raises(AcquisitionError,match='Local credentials removed'):cli.logout()
    assert Credentials(cli.base).load() is None and path.read_bytes()==before


def test_chained_backend_uses_os_store_and_rejects_plaintext_backends(monkeypatch):
    import keyring
    class Secure:
        priority=5
        def get_password(self,*args):return None
        def set_password(self,*args):pass
        def delete_password(self,*args):pass
    class Plain(Secure):pass
    Secure.__module__='keyring.backends.SecretService'
    Plain.__module__='keyrings.alt.file'
    class Chain:pass
    Chain.__module__='keyring.backends.chainer'
    backend=Chain();backend.backends=[Plain(),Secure()]
    monkeypatch.setattr(keyring,'get_keyring',lambda:backend)
    c=Credentials('https://guardian.example');assert c.prepare()=='keyring'
    backend.backends=[Plain()]
    assert c.secure_backend() is None
