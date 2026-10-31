import httpx
from backend.guardian.intelligence import check_osv
from backend.guardian.models import Dependency
from backend.guardian.engine import assess

def batch(monkeypatch,results):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED','true')
    monkeypatch.setattr(httpx,'post',lambda url,**kw:httpx.Response(200,json={'results':results},request=httpx.Request('POST',url)))

def test_details_severity_vectors_ranges_fixes_and_multiple_advisories(monkeypatch):
    batch(monkeypatch,[{'vulns':[{'id':'TEST-1'},{'id':'TEST-2'}]}])
    def details(url,**kw):
        return httpx.Response(200,json={'id':url.split('/')[-1],'summary':'Published issue','database_specific':{'severity':'HIGH'},'severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],'affected':[{'package':{'name':'alpha','ecosystem':'npm'},'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.1.0'}]}]}],'references':[{'url':'https://example.invalid/advisory'}]},request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx,'get',details)
    found,status,warnings=check_osv([Dependency(name='alpha',version='1.0.0',source='lock')])
    assert len(found)==2 and status=='checked'
    assert found[0].advisory.fixed_versions==['1.1.0']
    assert found[0].advisory.severity=='HIGH' and found[0].advisory.cvss[0]['score'].startswith('CVSS:3.1')
    assert found[0].domain=='vulnerability'
    assert assess(found)[0]=='No elevated signals' # behavior verdict is separate

def test_detail_outage_keeps_batch_match_and_partial_status(monkeypatch):
    batch(monkeypatch,[{'vulns':[{'id':'TEST-1'}]}])
    found,status,warnings=check_osv([Dependency(name='alpha',version='1.0.0',source='lock')])
    assert found and status=='partial' and found[0].advisory.severity is None
    assert found[0].advisory.detail_status=='unavailable'

def test_duplicate_versions_query_once_and_details_cached(monkeypatch):
    batch(monkeypatch,[{'vulns':[{'id':'TEST-1'}]},{'vulns':[{'id':'TEST-1'}]}])
    requests=[]
    def details(url,**kw):
        requests.append(url)
        return httpx.Response(200,json={'id':'TEST-1','affected':[{'package':{'name':'alpha','ecosystem':'npm'}}]},request=httpx.Request('GET',url))
    monkeypatch.setattr(httpx,'get',details)
    deps=[Dependency(name='alpha',version=v,source='lock') for v in ['1.0.0','1.0.0','1.0.1']]
    found,status,_=check_osv(deps)
    assert len(found)==2 and len(requests)==1

def test_detail_package_mismatch_does_not_invent_fix(monkeypatch):
    batch(monkeypatch,[{'vulns':[{'id':'TEST-1'}],'next_page_token':'more'}])
    monkeypatch.setattr(httpx,'get',lambda url,**kw:httpx.Response(200,json={'id':'TEST-1','affected':[{'package':{'name':'other','ecosystem':'npm'},'ranges':[{'events':[{'fixed':'9.0.0'}]}]}]},request=httpx.Request('GET',url)))
    found,status,warnings=check_osv([Dependency(name='alpha',version='1.0.0',source='lock')])
    assert status=='partial' and not found[0].advisory.fixed_versions
    assert any('match' in w for w in warnings)

def test_osv_batch_oversized_response_rejected(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    oversized = b'{"results": []}' + b' ' * (4 * 1024 * 1024 + 1)
    monkeypatch.setattr(httpx, 'post', lambda *a, **kw: httpx.Response(200, content=oversized, request=httpx.Request('POST', a[0])))
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert found == [] and status == 'unavailable'

def test_osv_malformed_batch_structure(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    monkeypatch.setattr(httpx, 'post', lambda *a, **kw: httpx.Response(200, json={'results': 'not a list'}, request=httpx.Request('POST', a[0])))
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert found == [] and status == 'unavailable'

def test_osv_query_result_count_mismatch(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    monkeypatch.setattr(httpx, 'post', lambda *a, **kw: httpx.Response(200, json={'results': [{'vulns': []}, {'vulns': []}]}, request=httpx.Request('POST', a[0])))
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert found == [] and status == 'unavailable'

def test_osv_withdrawn_advisory_ignored(monkeypatch):
    batch(monkeypatch, [{'vulns': [{'id': 'TEST-WITHDRAWN'}]}])
    monkeypatch.setattr(httpx, 'get', lambda url, **kw: httpx.Response(200, json={'id': 'TEST-WITHDRAWN', 'withdrawn': '2023-01-01T00:00:00Z'}, request=httpx.Request('GET', url)))
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert found == []
    assert any('withdrawn' in w for w in warnings)

def test_osv_malformed_cvss_and_references(monkeypatch):
    batch(monkeypatch, [{'vulns': [{'id': 'TEST-MALFORMED'}]}])
    def details(url, **kw):
        return httpx.Response(200, json={
            'id': 'TEST-MALFORMED',
            'severity': [{'type': 'INVALID_TYPE', 'score': 12345}, {'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}],
            'affected': [{
                'package': {'name': 'alpha', 'ecosystem': 'npm'},
                'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': 'bad;version!'}, {'fixed': '1.2.3'}]}]
            }],
            'references': [{'url': 'http://insecure.invalid/ref'}, {'url': 'https://secure.invalid/ref'}, {'url': 'not a url'}]
        }, request=httpx.Request('GET', url))
    monkeypatch.setattr(httpx, 'get', details)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert found[0].advisory.fixed_versions == ['1.2.3']
    assert len(found[0].advisory.cvss) == 1
    assert found[0].advisory.cvss[0]['type'] == 'CVSS_V3'
    assert 'https://secure.invalid/ref' in found[0].references
    assert 'http://insecure.invalid/ref' not in found[0].references

def test_osv_unknown_severity_defaults_to_medium_review(monkeypatch):
    batch(monkeypatch, [{'vulns': [{'id': 'TEST-UNKNOWN-SEV'}]}])
    monkeypatch.setattr(httpx, 'get', lambda url, **kw: httpx.Response(200, json={
        'id': 'TEST-UNKNOWN-SEV',
        'database_specific': {'severity': 'SUPER_CRITICAL_CUSTOM'},
        'affected': [{'package': {'name': 'alpha', 'ecosystem': 'npm'}}]
    }, request=httpx.Request('GET', url)))
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert found[0].advisory.severity is None
    assert found[0].severity == 'medium'

def test_osv_one_query_zero_vulns(monkeypatch):
    batch(monkeypatch, [{'vulns': []}])
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert found == []
    assert status == 'checked'

def test_osv_one_query_one_vuln(monkeypatch):
    batch(monkeypatch, [{'vulns': [{'id': 'TEST-1'}]}])
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert found[0].advisory.id == 'TEST-1'
    assert found[0].package == 'alpha@1.0.0'

def test_osv_one_query_multiple_vulns(monkeypatch):
    batch(monkeypatch, [{'vulns': [{'id': 'TEST-1'}, {'id': 'TEST-2'}, {'id': 'TEST-3'}]}])
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 3
    assert {f.advisory.id for f in found} == {'TEST-1', 'TEST-2', 'TEST-3'}

def test_osv_multiple_queries_different_vuln_counts(monkeypatch):
    batch(monkeypatch, [
        {'vulns': []},
        {'vulns': [{'id': 'TEST-B1'}, {'id': 'TEST-B2'}]},
        {'vulns': [{'id': 'TEST-C1'}]}
    ])
    deps = [
        Dependency(name='dep-a', version='1.0.0', source='lock'),
        Dependency(name='dep-b', version='2.0.0', source='lock'),
        Dependency(name='dep-c', version='3.0.0', source='lock')
    ]
    found, status, warnings = check_osv(deps)
    assert len(found) == 3
    b_finds = [f for f in found if f.package == 'dep-b@2.0.0']
    c_finds = [f for f in found if f.package == 'dep-c@3.0.0']
    assert len(b_finds) == 2
    assert len(c_finds) == 1

def test_osv_non_object_result_entries(monkeypatch):
    batch(monkeypatch, [
        'invalid-non-dict',
        {'vulns': [{'id': 'TEST-GOOD'}]}
    ])
    deps = [
        Dependency(name='dep-bad', version='1.0.0', source='lock'),
        Dependency(name='dep-good', version='2.0.0', source='lock')
    ]
    found, status, warnings = check_osv(deps)
    assert len(found) == 1
    assert found[0].package == 'dep-good@2.0.0'
    assert status == 'partial'
    assert any('Invalid OSV batch entry' in w for w in warnings)

def test_osv_malformed_vulns_arrays(monkeypatch):
    batch(monkeypatch, [{'vulns': 'not-a-list'}])
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert found == []
    assert status == 'partial'
    assert any('Invalid advisory list' in w for w in warnings)

def test_osv_duplicate_or_malformed_vuln_records(monkeypatch):
    batch(monkeypatch, [{'vulns': [
        {'id': 'TEST-DUP'},
        {'id': 'TEST-DUP'},
        'not-a-dict',
        {'id': 'INVALID/ID!'},
        {'id': 'TEST-VALID'}
    ]}])
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 2
    assert {f.advisory.id for f in found} == {'TEST-DUP', 'TEST-VALID'}
    assert status == 'partial'
    assert any('malformed' in w or 'unsupported' in w for w in warnings)

def test_osv_pagination_complete_multiple_pages(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    monkeypatch.setattr(httpx, 'get', lambda url, **kw: httpx.Response(200, json={'id': url.split('/')[-1], 'affected': [{'package': {'name': 'alpha', 'ecosystem': 'npm'}}]}, request=httpx.Request('GET', url)))
    calls = []
    def post(url, **kw):
        calls.append(kw)
        if len(calls) == 1:
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'PAGE-1'}], 'next_page_token': 'page2_tok'}]}, request=httpx.Request('POST', url))
        return httpx.Response(200, json={'results': [{'vulns': [{'id': 'PAGE-2'}]}]}, request=httpx.Request('POST', url))
    monkeypatch.setattr(httpx, 'post', post)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 2
    assert {f.advisory.id for f in found} == {'PAGE-1', 'PAGE-2'}
    assert status == 'checked'
    assert len(calls) == 2
    assert calls[1]['json']['queries'][0]['page_token'] == 'page2_tok'

def test_osv_pagination_repeated_advisory_ids(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    monkeypatch.setattr(httpx, 'get', lambda url, **kw: httpx.Response(200, json={'id': url.split('/')[-1], 'affected': [{'package': {'name': 'alpha', 'ecosystem': 'npm'}}]}, request=httpx.Request('GET', url)))
    calls = []
    def post(url, **kw):
        calls.append(kw)
        if len(calls) == 1:
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'DUP-ADVISORY'}], 'next_page_token': 'p2'}]}, request=httpx.Request('POST', url))
        return httpx.Response(200, json={'results': [{'vulns': [{'id': 'DUP-ADVISORY'}]}]}, request=httpx.Request('POST', url))
    monkeypatch.setattr(httpx, 'post', post)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert status == 'checked'

def test_osv_pagination_empty_subsequent_page(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    monkeypatch.setattr(httpx, 'get', lambda url, **kw: httpx.Response(200, json={'id': url.split('/')[-1], 'affected': [{'package': {'name': 'alpha', 'ecosystem': 'npm'}}]}, request=httpx.Request('GET', url)))
    calls = []
    def post(url, **kw):
        calls.append(kw)
        if len(calls) == 1:
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'VULN-1'}], 'next_page_token': 'p2'}]}, request=httpx.Request('POST', url))
        return httpx.Response(200, json={'results': [{'vulns': []}]}, request=httpx.Request('POST', url))
    monkeypatch.setattr(httpx, 'post', post)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert status == 'checked'

def test_osv_pagination_invalid_page_token(monkeypatch):
    batch(monkeypatch, [{'vulns': [{'id': 'VULN-1'}], 'next_page_token': {'bad': 'token'}}])
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert status == 'partial'
    assert any('invalid page token' in w for w in warnings)

def test_osv_pagination_loop_detected(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    def post(url, **kw):
        return httpx.Response(200, json={'results': [{'vulns': [{'id': 'LOOP-V'}], 'next_page_token': 'same_tok'}]}, request=httpx.Request('POST', url))
    monkeypatch.setattr(httpx, 'post', post)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert status == 'partial'
    assert any('loop' in w for w in warnings)

def test_osv_pagination_page_limit_reached(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    calls = []
    def post(url, **kw):
        page = len(calls) + 1
        calls.append(page)
        return httpx.Response(200, json={'results': [{'vulns': [{'id': f'PAGE-{page}'}], 'next_page_token': f'token_{page}'}]}, request=httpx.Request('POST', url))
    monkeypatch.setattr(httpx, 'post', post)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(calls) == 5
    assert status == 'partial'
    assert any('pagination limit' in w for w in warnings)

def test_osv_pagination_network_failure_after_first_page(monkeypatch):
    monkeypatch.setenv('GUARDIAN_OSV_ENABLED', 'true')
    calls = []
    def post(url, **kw):
        calls.append(url)
        if len(calls) == 1:
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'FIRST-PAGE-VULN'}], 'next_page_token': 'next_tok'}]}, request=httpx.Request('POST', url))
        raise httpx.ConnectError('Network failed on page 2')
    monkeypatch.setattr(httpx, 'post', post)
    found, status, warnings = check_osv([Dependency(name='alpha', version='1.0.0', source='lock')])
    assert len(found) == 1
    assert found[0].advisory.id == 'FIRST-PAGE-VULN'
    assert status == 'partial'
    assert any('pagination request failed' in w for w in warnings)
