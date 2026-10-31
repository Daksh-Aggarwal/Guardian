"""Strict SRI validation on compressed bytes, before any archive parsing."""
import base64
import binascii
import hashlib
import hmac
import re
from .models import IntegrityResult

ALGORITHMS = {'sha1':20, 'sha256':32, 'sha384':48, 'sha512':64}

def verify(data, expected, source='lockfile'):
    result = IntegrityResult(source=source, expected=expected if isinstance(expected,str) else None)
    if expected is None or expected == '':
        result.detail = 'No integrity metadata supplied; bytes are not verified against this source.'
        return result
    if not isinstance(expected,str) or len(expected)>4096:
        result.status, result.detail = 'invalid', 'Integrity must be a bounded SRI string.'
        return result
    entries=[]
    for token in expected.split():
        match=re.fullmatch(r'([a-z0-9]+)-([A-Za-z0-9+/]+={0,2})',token)
        if not match:
            result.status,result.detail='invalid','Malformed SRI token; extraction refused.'
            return result
        algorithm,digest=match.groups()
        if algorithm not in ALGORITHMS:
            result.status,result.detail='unsupported','Unsupported SRI algorithm; extraction refused.'
            return result
        try:
            decoded=base64.b64decode(digest,validate=True)
        except (ValueError,binascii.Error):
            decoded=b''
        if len(decoded)!=ALGORITHMS[algorithm]:
            result.status,result.detail='invalid','Invalid digest length or base64; extraction refused.'
            return result
        entries.append((algorithm,decoded))
    if not entries:
        result.status,result.detail='invalid','Empty integrity value; extraction refused.'
        return result
    # SRI selects the strongest supported algorithm, never a weaker fallback.
    strongest=max((a for a,_ in entries),key=lambda a:ALGORITHMS[a])
    digest=hashlib.new(strongest,data).digest()
    result.algorithm=strongest
    result.computed=[strongest+'-'+base64.b64encode(digest).decode()]
    result.status='verified' if any(a==strongest and hmac.compare_digest(digest,d) for a,d in entries) else 'mismatch'
    result.detail=('Downloaded bytes match the supplied digest. This does not establish package safety.' if result.status=='verified' else 'Downloaded bytes do not match the expected digest; extraction refused.')
    return result
