"""Opt-in account operations. Local scanner imports no authentication service."""
import base64
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from . import local_reports
from .credential_store import Credentials
from .models import Report
from .report_sync import prepare_report
from .supply_models import AcquisitionError


def api_url():
    value=os.getenv('GUARDIAN_API_URL','http://127.0.0.1:8000').rstrip('/')
    p=urlparse(value)
    if not p.hostname or p.username or p.password or p.path not in {'','/'} or p.query or p.fragment or (p.scheme!='https' and not(p.scheme=='http' and p.hostname in {'localhost','127.0.0.1'})):
        raise AcquisitionError('GUARDIAN_API_URL must be an HTTPS origin; HTTP loopback is allowed for development.')
    return value


def pkce():
    verifier=secrets.token_urlsafe(64)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return verifier,challenge,secrets.token_urlsafe(32)


class CallbackServer(HTTPServer):
    allow_reuse_address=False
    def __init__(self,state):
        self.expected_state=state
        self.result=None
        super().__init__(('127.0.0.1',0),CallbackHandler)
        self.timeout=.5

    def receive(self,timeout=300):
        deadline=time.monotonic()+timeout
        while self.result is None and time.monotonic()<deadline:
            self.handle_request()
        if self.result is None: raise AcquisitionError('Browser login timed out. Run guardian login again.')
        code,error=self.result
        if error: raise AcquisitionError('Browser authorization failed or was cancelled. Run guardian login again.')
        return code


class CallbackHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self,*args):
        pass  # OAuth codes/state must not enter terminal or request logs.

    def do_GET(self):
        parsed=urlparse(self.path)
        query=parse_qs(parsed.query,keep_blank_values=True)
        state=query.get('state',[''])
        valid=(self.headers.get('Host')==f'127.0.0.1:{self.server.server_port}' and parsed.path=='/callback'
               and len(state)==1 and hmac.compare_digest(state[0],self.server.expected_state)
               and set(query).issubset({'state','code','error'}) and (len(query.get('code',[]))==1 or len(query.get('error',[]))==1))
        if valid and not query.get('error') and not (0<len(query['code'][0])<=2048): valid=False
        self.send_response(200 if valid else 400)
        self.send_header('Content-Type','text/plain; charset=utf-8')
        self.send_header('Cache-Control','no-store')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'none'")
        self.end_headers()
        self.wfile.write(b'Authorization received. Return to Guardian in your terminal.' if valid else b'Invalid Guardian callback state.')
        if valid:
            self.server.result=(query.get('code',[None])[0],query.get('error',[None])[0])


class AccountClient:
    def __init__(self,allow_file=False,new_device=False):
        self.base=api_url()
        self.credentials=Credentials(self.base,allow_file,new_device)
        self.session=None

    def request(self,method,path,payload=None,token=None):
        headers={'Authorization':'Bearer '+token} if token else {}
        try:
            with httpx.Client(timeout=20,follow_redirects=False) as client:
                with client.stream(method,self.base+'/api/account'+path,json=payload,headers=headers) as response:
                    raw=bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw)>10*1024*1024: raise AcquisitionError('Account response exceeded its size limit.')
                    if response.status_code>=300:
                        # Server errors contain no trusted arbitrary display text.
                        message={401:'Account session expired. Run guardian login.',403:'Account or device authorization was revoked. Run guardian login.',409:'Report/device identity conflict. Local reports were preserved.',429:'Account request rate limit reached. Retry shortly.',503:'Account service is not configured or temporarily unavailable.'}.get(response.status_code,'Account request failed. Local reports were preserved.')
                        raise AcquisitionError(message,category='account_request_failed',detail=f'HTTP status {response.status_code}.')
                    return json.loads(raw) if raw else {}
        except (httpx.HTTPError,ValueError) as error:
            if isinstance(error,AcquisitionError): raise
            raise AcquisitionError('Account service unavailable. Local scanning and saved reports are unaffected.') from error

    def authenticated(self):
        if self.session is None: self.session=self.credentials.load()
        if not self.session: raise AcquisitionError('Not connected. Run guardian login; local scans do not require login.')
        if self.session.get('expires_at',0)<time.time()+60:
            result=self.request('POST','/cli/refresh',{'refresh_token':self.session['refresh_token'],'device_id':self.session['device']['id']})
            self.session.update(result)
            if not result.get('expires_at'):
                self.session['expires_at']=int(time.time())+int(result.get('expires_in',3600))
            self.credentials.save(self.session)
        return self.session

    def login(self,version,no_browser=False,device_name=None,timeout=300):
        mode=self.credentials.prepare()
        if mode=='file':
            print('Warning: using an explicitly permitted plaintext credential file with private permissions. Protect your Guardian state directory.',file=sys.stderr)
        verifier,challenge,state=pkce()
        with CallbackServer(state) as callback:
            payload={'id':self.credentials.meta['device_id'],'device_name':device_name or 'Guardian CLI ('+platform.system()+')','operating_system':platform.system(),'cli_version':version,'state':state,'code_challenge':challenge,'code_challenge_method':'S256','redirect_uri':f'http://127.0.0.1:{callback.server_port}/callback'}
            authorization=self.request('POST','/cli/authorize',payload)
            url=authorization['authorization_url']
            parsed=urlparse(url)
            if parsed.path!='/auth/cli' or (parsed.scheme!='https' and not(parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1'})) or parsed.username or parsed.password:
                raise AcquisitionError('Account service returned an invalid browser authorization URL.')
            print('Open this Guardian authorization page: '+url,file=sys.stderr)
            if not no_browser: webbrowser.open(url)
            code=callback.receive(timeout)
            result=self.request('POST','/cli/exchange',{'request_id':authorization['request_id'],'auth_code':code,'state':state,'code_verifier':verifier})
        if not result.get('access_token') or not result.get('refresh_token') or result.get('device',{}).get('id')!=self.credentials.meta['device_id']:
            raise AcquisitionError('Account service returned an invalid registered session.')
        self.credentials.save(result)
        self.session=result
        return {'authentication':'Connected','account':result['user']['email'] or result['user']['display_name'],'device':result['device'],'report_sync':'Available','credential_store':mode}

    def status(self,offline=False):
        session=self.credentials.load()
        if not session: return {'authentication':'Local','authenticated':False,'automatic_sync':False,'mode':'local'}
        if offline: return {'authentication':'Stored; not verified offline','account':session['user'],'device':session['device'],'report_sync':'Not checked offline','automatic_sync':False}
        self.session=session
        session=self.authenticated()
        user=self.request('GET','/me',token=session['access_token'])
        self.request('POST','/devices/'+session['device']['id']+'/seen',token=session['access_token'])
        return {'authentication':'Connected','account':user['email'] or user['display_name'],'device':session['device'],'report_sync':'Available','automatic_sync':False}

    def logout(self):
        session=self.credentials.load()
        failure=None
        try:
            if session:
                self.session=session
                session=self.authenticated()
                self.request('POST','/logout?'+urlencode({'device_id':session['device']['id']}),token=session['access_token'])
        except AcquisitionError as error:
            failure=error
        finally:
            self.credentials.clear()
        if failure: raise AcquisitionError('Local credentials removed, but remote revocation could not be confirmed. Revoke this device on the website.') from failure
        return {'authentication':'Local','authenticated':False,'automatic_sync':False,'mode':'local'}

    def devices(self,revoke=None):
        session=self.authenticated()
        if revoke:
            from uuid import UUID
            self.request('POST','/devices/'+str(UUID(revoke))+'/revoke',token=session['access_token'])
        return self.request('GET','/devices',token=session['access_token'])

    def sync(self,reports):
        session=self.authenticated()
        key=hashlib.sha256((self.base+session['user']['id']).encode()).hexdigest()[:20]
        path=local_reports.directory()/('sync-ledger-'+key+'.json')
        ledger=json.loads(path.read_text()) if path.exists() and not path.is_symlink() else {}
        synchronized=[]
        for report in reports:
            clean=prepare_report(report)
            encoded=json.dumps(clean.model_dump(mode='json'),sort_keys=True,separators=(',',':'))
            digest=hashlib.sha256(encoded.encode()).hexdigest()
            if ledger.get(report.id)==digest: continue
            receipt=self.request('POST','/scans',{'device_id':session['device']['id'],'consent':True,'report':clean.model_dump(mode='json')},session['access_token'])
            ledger[report.id]=digest
            local_reports.write_private(path,json.dumps(ledger))
            synchronized.append(receipt['id'])
        return {'status':'synchronized','report_ids':synchronized,'count':len(synchronized),'source_snippets':'withheld','automatic_sync':False}


def saved_reports():
    root=local_reports.directory()
    result=[]
    for path in sorted(root.glob('*.json')):
        if not re.fullmatch(r'[a-f0-9]{32}',path.stem): continue
        if path.is_symlink() or path.stat().st_size>16*1024*1024: raise AcquisitionError('Invalid local report file; synchronization stopped without changing it.')
        result.append(Report.model_validate_json(path.read_text(encoding='utf-8')))
    return result
