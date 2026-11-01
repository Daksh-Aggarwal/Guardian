"""Supabase identity validation. GitHub App installation sessions stay independent."""
import json
import os
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse
from uuid import UUID

import httpx
import jwt
from fastapi import HTTPException, Request

from .environment import load_environment

load_environment()


def trusted_origin(value, name):
    try:
        parsed = urlparse(value)
        valid = (parsed.scheme == 'https' or (parsed.scheme == 'http' and parsed.hostname in {'127.0.0.1', 'localhost'})) and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in {'', '/'} and parsed.port != 0
    except ValueError:
        valid = False
    if not valid:
        raise HTTPException(503, f'{name} must be an HTTPS origin (HTTP loopback is allowed for development).')
    return value.rstrip('/')


def settings():
    url = os.getenv('SUPABASE_URL') or os.getenv('NEXT_PUBLIC_SUPABASE_URL', '')
    key = os.getenv('SUPABASE_PUBLISHABLE_KEY') or os.getenv('NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY', '')
    if not url or not key:
        raise HTTPException(503, 'Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY in Guardian .env, then restart.', headers={'X-Guardian-Error':'auth_not_configured'})
    return trusted_origin(url, 'Supabase URL'), key


def configured():
    try:
        settings()
        return True
    except HTTPException:
        return False


@dataclass(frozen=True)
class Identity:
    id: str
    email: str
    display_name: str
    avatar_url: str
    session_id: str


class JWTVerifier:
    def __init__(self):
        self._lock = threading.Lock()
        self._keys = {}
        self._url = None
        self._fetched = 0.0

    def keys(self, issuer, kid):
        with self._lock:
            now = time.monotonic()
            if self._url != issuer or now-self._fetched > 600 or (kid not in self._keys and now-self._fetched > 30):
                try:
                    with httpx.Client(timeout=5, follow_redirects=False) as client:
                        with client.stream('GET', issuer+'/.well-known/jwks.json') as response:
                            response.raise_for_status()
                            data = bytearray()
                            for block in response.iter_bytes():
                                data.extend(block)
                                if len(data) > 131072:
                                    raise ValueError('JWKS limit')
                    payload = json.loads(data)
                    keys = payload['keys']
                    if not isinstance(keys, list) or len(keys) > 32:
                        raise ValueError('JWKS shape')
                    self._keys = {k['kid']: k for k in keys if isinstance(k, dict) and k.get('kid') and k.get('kty') in {'RSA', 'EC'}}
                    self._url, self._fetched = issuer, now
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                    raise HTTPException(503, 'Supabase signing keys are unavailable. Retry shortly.') from error
            return self._keys.get(kid)

    def verify(self, token):
        url, publishable_key = settings()
        issuer = url+'/auth/v1'
        try:
            if len(token) > 16384:
                raise ValueError('token size')
            header = jwt.get_unverified_header(token)
            if header.get('alg') not in {'RS256', 'ES256', 'HS256'}:
                raise ValueError('unsupported signing key')
            required = ['exp', 'iat', 'sub', 'aud', 'iss', 'session_id']
            if header['alg'] == 'HS256':
                # Supabase recommends Auth-server validation for legacy symmetric keys.
                # No shared JWT secret is distributed to the browser, CLI or this API.
                try:
                    with httpx.Client(timeout=5, follow_redirects=False) as client:
                        with client.stream('GET', issuer+'/user', headers={'Authorization':'Bearer '+token,'apikey':publishable_key}) as response:
                            if response.status_code in {401,403}: raise ValueError('invalid legacy user token')
                            response.raise_for_status()
                            raw = bytearray()
                            for block in response.iter_bytes():
                                raw.extend(block)
                                if len(raw)>262144: raise ValueError('user response limit')
                    remote_user=json.loads(raw)
                except httpx.HTTPError as error:
                    raise HTTPException(503,'Supabase token validation is unavailable.') from error
                claims=jwt.decode(token,options={'verify_signature':False,'verify_exp':True,'verify_iat':True,'verify_aud':True,'verify_iss':True,'require':required},audience='authenticated',issuer=issuer,leeway=5)
                if not isinstance(remote_user,dict) or remote_user.get('id') != claims['sub']: raise ValueError('user identity mismatch')
            else:
                if not isinstance(header.get('kid'),str): raise ValueError('missing signing key')
                raw_key = self.keys(issuer, header['kid'])
                if not raw_key or raw_key.get('alg') not in {None, header['alg']}:
                    raise ValueError('unknown signing key')
                key = jwt.PyJWK.from_dict(raw_key, algorithm=header['alg']).key
                claims = jwt.decode(token, key, algorithms=[header['alg']], audience='authenticated', issuer=issuer,
                                    options={'require': required}, leeway=5)
            if claims.get('role') != 'authenticated':
                raise ValueError('not an authenticated user')
            user_id, session_id = str(UUID(claims['sub'])), str(UUID(claims['session_id']))
            metadata = claims.get('user_metadata') or {}
            if not isinstance(metadata, dict):
                metadata = {}
            return Identity(user_id, str(claims.get('email') or '')[:320],
                            str(metadata.get('user_name') or metadata.get('full_name') or claims.get('email') or 'Guardian user')[:200],
                            str(metadata.get('avatar_url') or '')[:2000], session_id)
        except HTTPException:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as error:
            raise HTTPException(401, 'Supabase access token is invalid or expired. Sign in again.', headers={'WWW-Authenticate': 'Bearer'}) from error


verifier = JWTVerifier()


def require_identity(request: Request):
    header = request.headers.get('authorization', '')
    if not header.startswith('Bearer ') or len(header) > 16400:
        raise HTTPException(401, 'Sign in to Guardian first.', headers={'WWW-Authenticate': 'Bearer'})
    identity = verifier.verify(header[7:])
    from .account_store import account_store
    if account_store.session_revoked(identity.id, identity.session_id):
        raise HTTPException(403, 'This CLI authorization has been revoked. Run guardian login again.')
    return identity


def supabase_request(path, payload=None, access_token=None):
    url, key = settings()
    headers = {'apikey': key}
    if access_token:
        headers['Authorization'] = 'Bearer '+access_token
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            with client.stream('POST', url+'/auth/v1/'+path, json=payload, headers=headers) as response:
                if response.status_code >= 300:
                    raise HTTPException(401, 'Supabase could not complete this authorization. Restart guardian login.')
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 262144:
                        raise HTTPException(502, 'Supabase authorization response exceeded its limit.')
                return json.loads(raw) if raw else {}
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(503, 'Supabase authorization is unavailable. Local scanning still works.') from error
