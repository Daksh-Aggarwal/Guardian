import io
import json
import tarfile
import pytest
from backend.guardian import ingestion

def test_registry_fetches_metadata_and_reads_tar_without_execution(monkeypatch):
    data=io.BytesIO()
    source=b'const token = process.env.NPM_TOKEN;'
    with tarfile.open(fileobj=data,mode='w:gz') as tar:
        entry=tarfile.TarInfo('package/index.js');entry.size=len(source);tar.addfile(entry,io.BytesIO(source))
    urls=[]
    def fake_download(url,limit=ingestion.MAX_UPLOAD):
        urls.append(url)
        if len(urls)==1:return json.dumps({'dist':{'tarball':'https://registry.npmjs.org/test/-/test-1.0.0.tgz'}}).encode()
        return data.getvalue()
    monkeypatch.setattr(ingestion,'download',fake_download)
    files,_=ingestion.registry_package('@scope/test','1.0.0')
    assert urls[0]=='https://registry.npmjs.org/%40scope%2Ftest/1.0.0'
    assert files['package/index.js']==source.decode()

@pytest.mark.parametrize('name,version',[('https://evil.invalid','latest'),('test','../../etc'),('../test','latest')])
def test_registry_rejects_non_package_inputs(name,version):
    with pytest.raises(ValueError):ingestion.registry_package(name,version)
