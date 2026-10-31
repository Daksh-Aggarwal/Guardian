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
