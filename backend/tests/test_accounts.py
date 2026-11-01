"""Account API contracts, real JWT signatures and owner isolation; external Auth is mocked."""
import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend.guardian import account_api, account_auth
from backend.guardian.account_store import account_store
from backend.guardian.main import app
from backend.guardian.models import Evidence, Report
from backend.guardian.engine import finding
from backend.guardian.report_sync import prepare_report

KEY=rsa.generate_private_key(public_exponent=65537,key_size=2048)
JWK=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()));JWK.update(kid='test-key',alg='RS256')


@pytest.fixture
def auth(monkeypatch):
    monkeypatch.setenv('SUPABASE_URL','https://guardian-test.supabase.co')
    monkeypatch.setenv('SUPABASE_PUBLISHABLE_KEY','sb_publishable_test')
    monkeypatch.setenv('GUARDIAN_ACCOUNT_STORE','sqlite')
    monkeypatch.setenv('GUARDIAN_CLOUD_MODE','false')
    monkeypatch.delenv('GUARDIAN_DATABASE_URL',raising=False)
    monkeypatch.setenv('GUARDIAN_FRONTEND_URL','http://127.0.0.1:3000')
    monkeypatch.setenv('GUARDIAN_PUBLIC_API_URL','http://127.0.0.1:8000')
    monkeypatch.setattr(account_auth.verifier,'keys',lambda issuer,kid:JWK if kid=='test-key' else None)
    account_api._rate.clear()
    def token(user=None,session=None,**changes):
        user=user or str(uuid4());session=session or str(uuid4())
        claims={'sub':user,'session_id':session,'email':'user@example.test','role':'authenticated','aud':'authenticated','iss':'https://guardian-test.supabase.co/auth/v1','iat':int(time.time()),'exp':int(time.time())+3600,'user_metadata':{'user_name':'guardian-user'}}
        claims.update(changes)
        return jwt.encode(claims,KEY,algorithm='RS256',headers={'kid':'test-key'})
    return token


def headers(token): return {'Authorization':'Bearer '+token}


def device(): return {'id':str(uuid4()),'device_name':'Test terminal','operating_system':'Test OS','cli_version':'0.2.0'}


def report(identifier=None):
    f=finding('SENSITIVE_TRANSMISSION','Sensitive data transmitted','Data exposure','high','high','api_key="secret-value"','Sensitive source reaches network.','Credential loss.','Investigate.',[Evidence(file='index.js',line=2,snippet='FULL_SOURCE_NEVER_UPLOAD',detail='api_key="secret-value"')])
    return Report(id=identifier or uuid4().hex,name='test-package',version='1.0.0',created_at=datetime.now(timezone.utc).isoformat(),source='Guardian CLI',risk='High concern',rationale='Observed credential flow.',findings=[f],dependencies=[],files_analyzed=1,coverage=['Unsupported dynamic import; source incomplete.'],intelligence='not checked',duration_ms=10,cli={'schema_version':'1.0','ecosystem':'npm','decision':{'decision':'BLOCK','reasons':['Credential flow.'],'review_reasons':['Incomplete source.']},'installation':{'status':'blocked before installation'},'overrides':[],'lifecycle_scripts':'disabled','sync':'disabled'})


def test_unauthorized_account_endpoints(auth):
    client=TestClient(app)
    for path in ('/me','/devices','/scans','/overview'):
        assert client.get('/api/account'+path).status_code==401
        assert client.get('/api/account'+path,headers=headers('broken.jwt.token')).status_code==401


@pytest.mark.parametrize('changes',[{'exp':1},{'iss':'https://attacker.invalid/auth/v1'},{'aud':'other'},{'role':'service_role'},{'sub':'not-a-uuid'},{'session_id':'bad'},{'iat':int(time.time())+1000}])
def test_invalid_expired_or_wrong_claims_rejected(auth,changes):
    result=TestClient(app).get('/api/account/me',headers=headers(auth(**changes)))
    assert result.status_code==401


def test_unknown_key_and_unsigned_jwt_rejected(auth):
    token=auth()
    payload=jwt.decode(token,options={'verify_signature':False})
    fake=jwt.encode(payload,None,algorithm='none')
    assert TestClient(app).get('/api/account/me',headers=headers(fake)).status_code==401
    fake=jwt.encode(payload,rsa.generate_private_key(public_exponent=65537,key_size=2048),algorithm='RS256',headers={'kid':'test-key'})
    assert TestClient(app).get('/api/account/me',headers=headers(fake)).status_code==401


def test_identity_is_derived_from_verified_token(auth):
    token=auth();expected=jwt.decode(token,options={'verify_signature':False})['sub']
    result=TestClient(app).get('/api/account/me',headers=headers(token))
    assert result.status_code==200 and result.json()['id']==expected
    bad=device();bad['user_id']=str(uuid4())
    assert TestClient(app).post('/api/account/devices',headers=headers(token),json=bad).status_code==422


def test_device_owner_isolation_revocation_and_registration_bypass(auth):
    client=TestClient(app);a=auth();b=auth();d=device()
    assert client.post('/api/account/devices',headers=headers(a),json=d).status_code==200
    assert client.get('/api/account/devices',headers=headers(b)).json()==[]
    assert client.post('/api/account/devices',headers=headers(b),json=d).status_code==409
    assert client.post('/api/account/devices/'+d['id']+'/revoke',headers=headers(b)).status_code==404
    assert client.post('/api/account/devices/'+d['id']+'/seen',headers=headers(a)).status_code==200
    assert client.post('/api/account/devices/'+d['id']+'/revoke',headers=headers(a)).status_code==200
    assert client.get('/api/account/me',headers=headers(a)).status_code==403
    assert client.post('/api/account/devices',headers=headers(a),json=device()).status_code==403


def test_report_sync_preserves_decision_evidence_and_local_source(auth):
    client=TestClient(app);a=auth();d=device();original=report();before=original.model_dump_json()
    client.post('/api/account/devices',headers=headers(a),json=d)
    payload={'report':original.model_dump(mode='json'),'device_id':d['id'],'consent':True}
    assert client.post('/api/account/scans',headers=headers(a),json={**payload,'consent':False}).status_code==400
    result=client.post('/api/account/scans',headers=headers(a),json=payload)
    assert result.status_code==200
    assert client.post('/api/account/scans',headers=headers(a),json=payload).status_code==200
    stored=client.get('/api/account/scans/'+original.id,headers=headers(a)).json()
    assert stored['cli']['decision']==original.cli['decision']
    assert 'FULL_SOURCE_NEVER_UPLOAD' not in json.dumps(stored) and 'secret-value' not in json.dumps(stored)
    assert stored['findings'][0]['id']==original.findings[0].id
    assert stored['findings'][0]['evidence'][0]['line']==2
    assert 'Unsupported dynamic import' in str(stored['coverage'])
    assert original.model_dump_json()==before
    overview=client.get('/api/account/overview',headers=headers(a)).json()
    assert overview=={'total_scans':1,'connected_devices':1,'decisions':{'ALLOW':0,'WARN':0,'BLOCK':1,'REVIEW':0}}
    assert len(client.get('/api/account/scans',headers=headers(a)).json())==1
    payload['report']['rationale']='Different immutable snapshot'
    assert client.post('/api/account/scans',headers=headers(a),json=payload).status_code==409


def test_cross_user_report_access_and_unregistered_device_denied(auth):
    client=TestClient(app);a=auth();b=auth();d=device();r=report()
    client.post('/api/account/devices',headers=headers(a),json=d)
    body={'report':r.model_dump(mode='json'),'device_id':d['id'],'consent':True}
    assert client.post('/api/account/scans',headers=headers(b),json=body).status_code==403
    client.post('/api/account/scans',headers=headers(a),json=body)
    assert client.get('/api/account/scans/'+r.id,headers=headers(b)).status_code==404
    assert client.get('/api/account/scans',headers=headers(b)).json()==[]
    assert client.post('/api/account/scans/'+r.id+'/handoff',headers=headers(b),json={'target':'universal','mode':'focused_fix'}).status_code==404
    assert client.post('/api/account/scans/'+r.id+'/handoff',headers=headers(a),json={'target':'universal','mode':'focused_fix'}).status_code==200


def test_device_cannot_sync_with_another_session_of_same_account(auth):
    client=TestClient(app);user=str(uuid4());a=auth(user=user);b=auth(user=user);d=device()
    client.post('/api/account/devices',headers=headers(a),json=d)
    body={'report':report().model_dump(mode='json'),'device_id':d['id'],'consent':True}
    assert client.post('/api/account/scans',headers=headers(b),json=body).status_code==403


def begin(client):
    verifier='v'*64
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    data={**device(),'state':'s'*43,'code_challenge':challenge,'redirect_uri':'http://127.0.0.1:45123/callback'}
    result=client.post('/api/account/cli/authorize',json=data)
    assert result.status_code==200
    return result.json()['request_id'],data,verifier


def test_cli_pkce_authorization_exchange_is_single_use(auth,monkeypatch):
    client=TestClient(app);identifier,data,verifier=begin(client)
    info=client.get('/api/account/cli/requests/'+identifier)
    assert info.status_code==200
    url=urlparse(info.json()['authorize_url']);query=parse_qs(url.query)
    assert url.hostname=='guardian-test.supabase.co' and query['code_challenge']==[data['code_challenge']]
    assert query['code_challenge_method']==['s256']
    callback=client.get('/api/account/cli/callback/'+identifier+'?code=one-use-code',follow_redirects=False)
    assert callback.status_code==302 and parse_qs(urlparse(callback.headers['location']).query)['state']==[data['state']]
    assert client.get('/api/account/cli/callback/'+identifier+'?code=other',follow_redirects=False).status_code==400
    token=auth();calls=[]
    def exchange(path,payload):
        calls.append((path,payload))
        return {'access_token':token,'refresh_token':'refresh-token-private','expires_in':3600}
    monkeypatch.setattr(account_api,'supabase_request',exchange)
    body={'request_id':identifier,'auth_code':'one-use-code','state':data['state'],'code_verifier':verifier}
    for changes in ({'state':'t'*43},{'code_verifier':'x'*64},{'auth_code':'wrong-code'}):
        assert client.post('/api/account/cli/exchange',json={**body,**changes}).status_code==400
    result=client.post('/api/account/cli/exchange',json=body)
    assert result.status_code==200 and result.headers['cache-control']=='no-store'
    assert result.json()['device']['id']==data['id'] and result.json()['refresh_token']=='refresh-token-private'
    assert calls==[('token?grant_type=pkce',{'auth_code':'one-use-code','code_verifier':verifier})]
    assert client.post('/api/account/cli/exchange',json=body).status_code==400
    with account_store.connection() as db:
        row=dict(db.execute('SELECT * FROM guardian_cli_authorizations WHERE id=?',(identifier,)).fetchone())
    assert 'one-use-code' not in str(row) and 'refresh-token-private' not in str(row)


@pytest.mark.parametrize('redirect',['http://evil.invalid:45123/callback','https://127.0.0.1:45123/callback','http://127.0.0.1:80/callback','http://user@127.0.0.1:45123/callback','http://127.0.0.1:45123/other','http://127.0.0.1:45123/callback?next=evil'])
def test_cli_redirect_allowlist(auth,redirect):
    data={**device(),'state':'s'*43,'code_challenge':'c'*43,'redirect_uri':redirect}
    assert TestClient(app).post('/api/account/cli/authorize',json=data).status_code==422


def test_expired_cli_request_rejected(auth):
    client=TestClient(app);identifier,_,_=begin(client)
    with account_store.connection() as db: db.execute('UPDATE guardian_cli_authorizations SET expires_at=1 WHERE id=?',(identifier,))
    assert client.get('/api/account/cli/requests/'+identifier).status_code==400
    assert client.get('/api/account/cli/callback/'+identifier+'?code=some-code',follow_redirects=False).status_code==400


def test_old_device_session_remains_revoked_after_fresh_login(auth):
    user=str(uuid4());a=auth(user=user);b=auth(user=user);d=device();client=TestClient(app)
    client.post('/api/account/devices',headers=headers(a),json=d)
    old=account_auth.verifier.verify(a);new=account_auth.verifier.verify(b)
    account_store.revoke(old,d['id'])
    account_store.register(new,d,reauthorize=True)
    assert client.get('/api/account/me',headers=headers(a)).status_code==403
    assert client.post('/api/account/devices/'+d['id']+'/seen',headers=headers(b)).status_code==200


def test_cloud_deployment_does_not_expose_local_sqlite_reports(auth,monkeypatch):
    monkeypatch.setenv('GUARDIAN_CLOUD_MODE','true')
    client=TestClient(app)
    assert client.get('/api/health').status_code==200
    assert client.get('/api/scans').status_code==403
    assert client.post('/api/scans/upload').status_code==403
    assert client.get('/api/account/capabilities').status_code==200


def test_cloud_sanitization_is_idempotent_and_closes_flexible_dictionary_channel():
    original=report();original.assessments={'source_files':{'secret.py':'FULL_SOURCE'},'behavior':{'risk':'High concern','source':'FULL_SOURCE'}}
    original.cli['decision']['policy']={'block_severity':'high','source_files':{'x':'FULL_SOURCE'}}
    clean=prepare_report(original)
    assert prepare_report(clean).model_dump()==clean.model_dump()
    assert 'FULL_SOURCE' not in clean.model_dump_json()
    assert clean.cli['decision']['policy']=={'block_severity':'high'}


def test_jwks_fetch_cache_unknown_key_and_oversize_fail_visible(auth,monkeypatch):
    real_client=httpx.Client;calls=[]
    def transport(request):
        calls.append(str(request.url))
        assert request.url.host=='guardian-test.supabase.co'
        return httpx.Response(200,json={'keys':[JWK]})
    monkeypatch.setattr(account_auth.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(transport),**kwargs))
    verifier=account_auth.JWTVerifier()
    assert verifier.verify(auth()).email=='user@example.test'
    assert verifier.verify(auth()).email=='user@example.test'
    assert len(calls)==1
    def unavailable(request):return httpx.Response(503)
    monkeypatch.setattr(account_auth.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(unavailable),**kwargs))
    with pytest.raises(Exception) as failure: account_auth.JWTVerifier().verify(auth())
    assert failure.value.status_code==503
    monkeypatch.setattr(account_auth.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(lambda request:httpx.Response(200,content=b'x'*131073)),**kwargs))
    with pytest.raises(Exception) as failure: account_auth.JWTVerifier().verify(auth())
    assert failure.value.status_code==503


def test_legacy_hs256_requires_supabase_auth_server_validation(auth,monkeypatch):
    claims=jwt.decode(auth(),options={'verify_signature':False})
    token=jwt.encode(claims,'test-secret-at-least-thirty-two-characters',algorithm='HS256')
    real_client=httpx.Client
    def remote(request):
        assert request.url.path=='/auth/v1/user'
        assert request.headers['Authorization']=='Bearer '+token
        return httpx.Response(200,json={'id':claims['sub']})
    monkeypatch.setattr(account_auth.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(remote),**kwargs))
    assert account_auth.JWTVerifier().verify(token).id==claims['sub']
    monkeypatch.setattr(account_auth.httpx,'Client',lambda **kwargs:real_client(transport=httpx.MockTransport(lambda request:httpx.Response(401)),**kwargs))
    with pytest.raises(Exception) as failure:account_auth.JWTVerifier().verify(token)
    assert failure.value.status_code==401


def test_account_request_size_timestamp_and_session_refresh_revocation(auth,monkeypatch):
    client=TestClient(app);token=auth();d=device()
    assert client.post('/api/account/cli/authorize',content=b'x'*65537).status_code==413
    client.post('/api/account/devices',headers=headers(token),json=d)
    original=report();original.created_at='not-a-timestamp'
    assert client.post('/api/account/scans',headers=headers(token),json={'report':original.model_dump(mode='json'),'device_id':d['id'],'consent':True}).status_code==400
    monkeypatch.setattr(account_api,'supabase_request',lambda *args,**kwargs:{'access_token':token,'refresh_token':'rotated-refresh-token','expires_in':3600})
    body={'refresh_token':'previous-refresh-token','device_id':d['id']}
    assert client.post('/api/account/cli/refresh',json=body).status_code==200
    client.post('/api/account/devices/'+d['id']+'/revoke',headers=headers(token))
    assert client.post('/api/account/cli/refresh',json=body).status_code==403
    assert client.post('/api/account/scans',headers=headers(token),json={'report':report().model_dump(mode='json'),'device_id':d['id'],'consent':True}).status_code==403


@pytest.mark.parametrize('password',['[YOUR-PASSWORD]','%5BYOUR-PASSWORD%5D','your_password'])
def test_placeholder_database_password_is_reported_before_connecting(auth,monkeypatch,password):
    import psycopg
    monkeypatch.setenv('GUARDIAN_DATABASE_URL',f'postgresql://postgres:{password}@db.example.invalid:5432/postgres')
    def unexpected_connect(*args,**kwargs): raise AssertionError('Placeholder must not reach PostgreSQL')
    monkeypatch.setattr(psycopg,'connect',unexpected_connect)
    data={**device(),'state':'s'*43,'code_challenge':'c'*43,'redirect_uri':'http://127.0.0.1:45123/callback'}
    result=TestClient(app).post('/api/account/cli/authorize',json=data)
    assert result.status_code==503
    assert result.headers['x-guardian-error']=='database_password_placeholder'
    assert 'placeholder password' in result.json()['detail']
    assert 'db.example.invalid' not in result.text
