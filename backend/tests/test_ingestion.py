import io
import tarfile
import zipfile
import pytest
from backend.guardian.ingestion import archive, uploaded, download, MAX_FILE

def zipdata(entries):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w') as z:
        for name,content in entries:
            z.writestr(name,content)
    return data.getvalue()

@pytest.mark.parametrize('name',['../package.json','/package.json','a/../../package.json','a\\package.json','C:/package.json'])
def test_traversal_rejected(name):
    with pytest.raises(ValueError,match='unsafe'):
        archive(zipdata([(name,'{}')]))

def test_large_file_rejected():
    with pytest.raises(ValueError,match='limit'):
        archive(zipdata([('large.js','x'*(MAX_FILE+1))]))

def test_entry_limit():
    with pytest.raises(ValueError,match='500'):
        archive(zipdata([(f'{i}.json','{}') for i in range(501)]))

def test_symlink_rejected():
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w') as z:
        entry=zipfile.ZipInfo('link.js');entry.create_system=3;entry.external_attr=0o120777<<16
        z.writestr(entry,'/etc/passwd')
    with pytest.raises(ValueError,match='links'):
        archive(data.getvalue())

def test_tar_link_rejected():
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:gz') as t:
        entry=tarfile.TarInfo('link');entry.type=tarfile.SYMTYPE;entry.linkname='/etc/passwd';t.addfile(entry)
    with pytest.raises(ValueError,match='links'):
        archive(data.getvalue(),'tar')

def test_unsupported_files_reported():
    files,warnings=archive(zipdata([('package.json','{}'),('image.png','abc')]))
    assert list(files)==['package.json']
    assert 'image.png' in warnings[0]

@pytest.mark.parametrize('url',['http://registry.npmjs.org/a','https://evil.invalid/a','https://registry.npmjs.org:444/a','https://user@registry.npmjs.org/a','https://registry.npmjs.org.evil.invalid/a'])
def test_download_allowlist(url):
    with pytest.raises(ValueError,match='unsupported'):
        download(url)

def test_upload_type_and_json_shape():
    with pytest.raises(ValueError): uploaded('file.exe',b'abc')
    with pytest.raises(ValueError): uploaded('package.json',b'[]')
