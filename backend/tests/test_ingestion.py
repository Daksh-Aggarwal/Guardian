import io
import tarfile
import zipfile
import pytest
from backend.guardian.ingestion import archive, uploaded, download, MAX_FILE, safe_name

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

def test_malformed_zip_and_tar():
    with pytest.raises(ValueError, match='archive format'):
        archive(b'PK\x03\x04corrupted_zip_header_bytes', 'zip')
    with pytest.raises(ValueError, match='archive format'):
        archive(b'\x1f\x8b\x08corrupted_tar_bytes', 'tar')

def test_duplicate_and_normalized_path_collision():
    # Duplicate path in ZIP
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        z.writestr('index.js', 'console.log(1);')
        z.writestr('./index.js', 'console.log(2);')
    with pytest.raises(ValueError, match='duplicate'):
        archive(data.getvalue())

def test_unusual_path_encodings():
    with pytest.raises(ValueError, match='unsafe'):
        archive(zipdata([('index\n.js', 'console.log(1);')]))
    with pytest.raises(ValueError, match='unsafe'):
        archive(zipdata([('~/index.js', 'console.log(1);')]))
    with pytest.raises(ValueError, match='unsafe'):
        archive(zipdata([('index\\file.js', 'console.log(1);')]))
    with pytest.raises(ValueError, match='unsafe'):
        safe_name('index\x00.js')

def test_tar_hard_link_rejected():
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as t:
        entry = tarfile.TarInfo('hardlink.js')
        entry.type = tarfile.LNKTYPE
        entry.linkname = 'target.js'
        t.addfile(entry)
    with pytest.raises(ValueError, match='links and special files'):
        archive(data.getvalue(), 'tar')

def test_zip_special_entries_rejected():
    import stat
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        entry = zipfile.ZipInfo('fifo.js')
        entry.create_system = 3
        entry.external_attr = stat.S_IFIFO << 16
        z.writestr(entry, '')
    with pytest.raises(ValueError, match='links and special files'):
        archive(data.getvalue())

def test_manifest_oversized_and_malformed():
    with pytest.raises(ValueError, match='1 MB'):
        uploaded('package.json', b'{"name":"x"}' + b' ' * (MAX_FILE + 1))
    with pytest.raises(ValueError, match='valid UTF-8 JSON'):
        uploaded('package.json', b'{"name": invalid_json}')
    with pytest.raises(ValueError, match='JSON object'):
        uploaded('package.json', b'"a json string"')

def test_aggregate_decompression_limit():
    from backend.guardian.ingestion import MAX_EXPANDED
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        # 26 files of 1 MB each exceeds 25 MB limit
        chunk = b'x' * (1024 * 1024)
        for i in range(26):
            z.writestr(f'file_{i}.js', chunk)
    with pytest.raises(ValueError, match='expanded limit'):
        archive(data.getvalue())

def test_zip_socket_and_device_rejected():
    import stat
    for s_type in [stat.S_IFSOCK, stat.S_IFBLK, stat.S_IFCHR]:
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as z:
            entry = zipfile.ZipInfo('device.js')
            entry.create_system = 3
            entry.external_attr = s_type << 16
            z.writestr(entry, '')
        with pytest.raises(ValueError, match='links and special files'):
            archive(data.getvalue())

def test_normalized_path_redundant_slashes_and_dots():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        z.writestr('dir/./foo.js', 'console.log(1);')
        z.writestr('dir/foo.js', 'console.log(2);')
    with pytest.raises(ValueError, match='duplicate'):
        archive(data.getvalue())

def test_nested_archive_not_recursively_extracted():
    inner_zip = zipdata([('inner.js', 'console.log("inner");')])
    outer = zipdata([
        ('index.js', 'console.log("outer");'),
        ('nested.zip', inner_zip)
    ])
    files, warnings = archive(outer)
    assert 'index.js' in files
    assert 'nested.zip' not in files
    assert 'inner.js' not in files
    assert any('nested.zip' in w for w in warnings)

def test_tar_devices_and_fifo_rejected():
    for ftype in [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as t:
            entry = tarfile.TarInfo('special.js')
            entry.type = ftype
            t.addfile(entry)
        with pytest.raises(ValueError, match='links and special files'):
            archive(data.getvalue(), 'tar')
