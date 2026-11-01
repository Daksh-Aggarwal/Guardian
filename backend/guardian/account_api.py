"""Supabase account/device/report API, separate from GitHub App authorization."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import urlencode, urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .account_auth import Identity, configured, require_identity, settings, supabase_request, trusted_origin, verifier
from .account_store import account_store
from .models import Report
from .handoff_models import HandoffRequest
from .report_sync import prepare_report

router=APIRouter(prefix='/api/account',tags=['Account'])
_rate_lock=threading.Lock()
_rate=defaultdict(deque)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def challenge(verifier_value):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier_value.encode('ascii')).digest()).rstrip(b'=').decode()


def cli_origins():
    frontend=trusted_origin(os.getenv('GUARDIAN_FRONTEND_URL','http://127.0.0.1:3000'),'Guardian frontend URL')
    backend=trusted_origin(os.getenv('GUARDIAN_PUBLIC_API_URL') or os.getenv('GUARDIAN_API_URL','http://127.0.0.1:8000'),'Guardian API URL')
    return frontend,backend


class DeviceRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id: UUID
    device_name: str=Field(min_length=1,max_length=100)
    operating_system: str=Field(min_length=1,max_length=80)
    cli_version: str=Field(min_length=1,max_length=40)

    @field_validator('device_name','operating_system','cli_version')
    @classmethod
    def text(cls,value):
        if any(ord(c)<32 for c in value): raise ValueError('Control characters are forbidden.')
        return value


class AuthorizeRequest(DeviceRequest):
    state: str=Field(pattern=r'^[A-Za-z0-9_-]{32,128}$')
    code_challenge: str=Field(pattern=r'^[A-Za-z0-9_-]{43}$')
    code_challenge_method: str=Field(default='S256',pattern=r'^S256$')
    redirect_uri: str=Field(max_length=200)

    @field_validator('redirect_uri')
    @classmethod
    def loopback(cls,value):
        try:
            p=urlparse(value)
            valid=p.scheme=='http' and p.hostname=='127.0.0.1' and p.port and 1024<=p.port<=65535 and p.path=='/callback' and not p.query and not p.fragment and not p.username and not p.password
        except ValueError:
            valid=False
        if not valid: raise ValueError('Use an ephemeral http://127.0.0.1:<port>/callback URI.')
        return value


class ExchangeRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    request_id: str=Field(pattern=r'^[A-Za-z0-9_-]{32,128}$')
    auth_code: str=Field(min_length=1,max_length=2048)
    state: str=Field(pattern=r'^[A-Za-z0-9_-]{32,128}$')
    code_verifier: str=Field(pattern=r'^[A-Za-z0-9._~-]{43,128}$')


@router.get('/capabilities')
def capabilities():
    return {'authentication':configured(),'provider':'supabase-github','database_configured':bool(os.getenv('GUARDIAN_DATABASE_URL')) or os.getenv('GUARDIAN_ACCOUNT_STORE')=='sqlite','automatic_sync':False}


@router.get('/me')
def me(user:Identity=Depends(require_identity)):
    return account_store.profile(user)


@router.post('/devices')
def register(device:DeviceRequest,user:Identity=Depends(require_identity)):
    return account_store.register(user,device.model_dump(mode='json'))


@router.get('/devices')
def devices(user:Identity=Depends(require_identity)):
    return account_store.devices(user.id)


@router.post('/devices/{device_id}/seen')
def seen(device_id:UUID,user:Identity=Depends(require_identity)):
    return account_store.touch(user,str(device_id))


@router.post('/devices/{device_id}/revoke')
def revoke(device_id:UUID,user:Identity=Depends(require_identity)):
    return account_store.revoke(user,str(device_id))


@router.get('/overview')
def overview(user:Identity=Depends(require_identity)):
    return account_store.overview(user.id)


@router.get('/scans')
def scans(user:Identity=Depends(require_identity)):
    return account_store.scans(user.id)


@router.get('/scans/{scan_id}')
def report(scan_id:str,user:Identity=Depends(require_identity)):
    return Report.model_validate(account_store.report(user.id,scan_id))


class UploadRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    device_id: UUID
    consent: bool=False
    report: Report


@router.post('/scans')
def upload(body:UploadRequest,user:Identity=Depends(require_identity)):
    if not body.consent: raise HTTPException(400,'Explicit report synchronization consent is required.')
    original=body.report
    if not original.cli or original.cli.get('schema_version')!='1.0' or not original.cli.get('decision',{}).get('decision'):
        raise HTTPException(400,'Expected a versioned Guardian CLI report with its actual policy decision.')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',original.id): raise HTTPException(400,'Invalid report identifier.')
    if len(original.model_dump_json().encode())>8*1024*1024: raise HTTPException(413,'Report exceeds the 8 MiB synchronization limit.')
    try:
        scanned_at=datetime.fromisoformat(original.created_at.replace('Z','+00:00'))
        if scanned_at.tzinfo is None: raise ValueError('Missing timezone')
    except ValueError as error:
        raise HTTPException(400,'Report scan timestamp must be ISO 8601 with a timezone.') from error
    clean=prepare_report(original)
    canonical=json.dumps(clean.model_dump(mode='json'),sort_keys=True,separators=(',',':'))
    summary={severity:sum(f.severity==severity for f in clean.findings) for severity in ('critical','high','medium','low','info')}
    data={'id':clean.id,'project_name':clean.name,'ecosystem':clean.cli.get('ecosystem','npm'),'decision':clean.cli['decision']['decision'],'severity_summary':summary,'report_payload':clean.model_dump(mode='json'),'payload_sha256':sha(canonical),'engine_version':clean.engine_version,'scanned_at':clean.created_at}
    return account_store.upload(user,str(body.device_id),data)


@router.post('/cli/authorize')
def authorize(body:AuthorizeRequest,request:Request):
    settings()
    host=request.client.host if request.client else 'unknown'
    with _rate_lock:
        current=time.monotonic()
        if len(_rate)>1000:
            for key in list(_rate):
                if not _rate[key] or current-_rate[key][-1]>60: del _rate[key]
        history=_rate[host]
        while history and current-history[0]>60: history.popleft()
        if len(history)>=10: raise HTTPException(429,'Too many login requests. Wait one minute.')
        history.append(current)
    frontend,_=cli_origins()
    identifier=secrets.token_urlsafe(32)
    stamp=int(time.time())
    with account_store.connection() as db:
        db.execute('DELETE FROM guardian_cli_authorizations WHERE expires_at<?',(stamp-600,))
        count=db.execute('SELECT COUNT(*) AS count FROM guardian_cli_authorizations WHERE expires_at>? AND consumed_at IS NULL',(stamp,)).fetchone()['count']
        if count>=1000: raise HTTPException(429,'Login queue is full. Retry shortly.')
        db.execute('INSERT INTO guardian_cli_authorizations(id,state,challenge,redirect_uri,device_id,device_name,operating_system,cli_version,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(identifier,body.state,body.code_challenge,body.redirect_uri,str(body.id),body.device_name,body.operating_system,body.cli_version,stamp,stamp+300))
    return {'request_id':identifier,'authorization_url':frontend+'/auth/cli?'+urlencode({'request_id':identifier}),'expires_in':300}


def pending(identifier):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',identifier): raise HTTPException(400,'Invalid authorization request.')
    with account_store.connection() as db:
        row=db.execute('SELECT * FROM guardian_cli_authorizations WHERE id=?',(identifier,)).fetchone()
    if not row or row['expires_at']<int(time.time()) or row['consumed_at'] is not None:
        raise HTTPException(400,'Authorization request expired or was already consumed. Run guardian login again.')
    return dict(row)


@router.get('/cli/requests/{request_id}')
def login_request(request_id:str,response:Response):
    row=pending(request_id)
    url,_=settings()
    _,backend=cli_origins()
    callback=backend+'/api/account/cli/callback/'+request_id
    authorization=url+'/auth/v1/authorize?'+urlencode({'provider':'github','redirect_to':callback,'code_challenge':row['challenge'],'code_challenge_method':'s256','scopes':'read:user user:email'})
    response.headers.update({'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})
    return {'device_name':row['device_name'],'operating_system':row['operating_system'],'expires_at':row['expires_at'],'authorize_url':authorization}


@router.get('/cli/callback/{request_id}')
def callback(request_id:str,code:str=None,error:str=None):
    row=pending(request_id)
    if error or not code or len(code)>2048:
        destination=row['redirect_uri']+'?'+urlencode({'error':'authorization_failed','state':row['state']})
    else:
        with account_store.connection() as db:
            result=db.execute('UPDATE guardian_cli_authorizations SET code_hash=? WHERE id=? AND code_hash IS NULL AND consumed_at IS NULL AND expires_at>=?',(sha(code),request_id,int(time.time())))
            if result.rowcount!=1: raise HTTPException(400,'Authorization callback was already used or expired.')
        destination=row['redirect_uri']+'?'+urlencode({'code':code,'state':row['state']})
    return RedirectResponse(destination,status_code=302,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})


@router.post('/cli/exchange')
def exchange(body:ExchangeRequest,response:Response):
    row=pending(body.request_id)
    if not hmac.compare_digest(row['state'],body.state) or not hmac.compare_digest(row['challenge'],challenge(body.code_verifier)) or not row['code_hash'] or not hmac.compare_digest(row['code_hash'],sha(body.auth_code)):
        raise HTTPException(400,'Authorization state, code or PKCE verification failed.')
    with account_store.connection() as db:
        consumed=db.execute('UPDATE guardian_cli_authorizations SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>=?',(int(time.time()),body.request_id,int(time.time())))
        if consumed.rowcount!=1: raise HTTPException(400,'Authorization code was already consumed.')
    session=supabase_request('token?grant_type=pkce',{'auth_code':body.auth_code,'code_verifier':body.code_verifier})
    access=session.get('access_token','')
    if not access or not session.get('refresh_token'): raise HTTPException(502,'Supabase returned no usable session.')
    user=verifier.verify(access)
    if account_store.session_revoked(user.id,user.session_id): raise HTTPException(403,'This Supabase session has been revoked.')
    device=account_store.register(user,{'id':row['device_id'],'device_name':row['device_name'],'operating_system':row['operating_system'],'cli_version':row['cli_version']},reauthorize=True)
    response.headers['Cache-Control']='no-store'
    return {'access_token':access,'refresh_token':session['refresh_token'],'expires_at':session.get('expires_at',int(time.time())+int(session.get('expires_in',3600))),'user':{'id':user.id,'email':user.email,'display_name':user.display_name},'device':device}


@router.post('/logout')
def logout(request:Request,device_id:UUID,user:Identity=Depends(require_identity)):
    result=account_store.revoke(user,str(device_id))
    # Guardian revocation is authoritative even if the provider is temporarily unavailable.
    try:
        supabase_request('logout?scope=local',access_token=request.headers['authorization'][7:])
    except HTTPException:
        result['provider_logout']='unavailable; Guardian device authorization was revoked'
    return result


class RefreshRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    # Refresh tokens are opaque provider values, not JWTs or fixed-length secrets.
    refresh_token:str=Field(min_length=1,max_length=8192)
    device_id:UUID


@router.post('/cli/refresh')
def refresh(body:RefreshRequest,response:Response):
    session=supabase_request('token?grant_type=refresh_token',{'refresh_token':body.refresh_token})
    user=verifier.verify(session.get('access_token',''))
    if account_store.session_revoked(user.id,user.session_id): raise HTTPException(403,'Device session was revoked.')
    account_store.touch(user,str(body.device_id))
    response.headers['Cache-Control']='no-store'
    return {key:session[key] for key in ('access_token','refresh_token','expires_at','expires_in') if key in session}


@router.post('/scans/{scan_id}/handoff')
def handoff(scan_id:str, body:HandoffRequest, user:Identity=Depends(require_identity)):
    from .handoff import handoff_service
    report=Report.model_validate(account_store.report(user.id,scan_id))
    try:
        return handoff_service.export_bundle(report=report,target=body.target,mode=body.mode,finding_ids=body.finding_ids,project_metadata=None)
    except ValueError as error:
        raise HTTPException(400,str(error)) from error
