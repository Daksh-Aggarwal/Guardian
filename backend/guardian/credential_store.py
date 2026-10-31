"""OS credential storage, with an explicitly opted-in private-file fallback."""
import hashlib
import json
import os
import stat
from uuid import UUID, uuid4
from types import SimpleNamespace

from . import local_reports
from .supply_models import AcquisitionError


class Credentials:
    def __init__(self, api_url, allow_file=False, new_device=False):
        self.api_url=api_url
        self.namespace=hashlib.sha256(api_url.encode()).hexdigest()[:20]
        self.root=local_reports.directory()
        self.metadata=self.root/f'account-{self.namespace}.json'
        self.file=self.root/f'credentials-{self.namespace}.json'
        self.allow_file=allow_file or os.getenv('GUARDIAN_ALLOW_FILE_CREDENTIALS','false').lower()=='true'
        self.keyring=None
        self.meta=self._read(self.metadata) if self.metadata.exists() else {'device_id':str(uuid4()),'storage':None}
        self.service='Guardian CLI '+self.namespace
        try: UUID(self.meta['device_id'])
        except (KeyError,ValueError,TypeError) as error: raise AcquisitionError('Invalid local device identity. Reconnect with a private Guardian state directory.') from error
        if new_device:
            self.clear()
            self.meta={'device_id':str(uuid4()),'storage':None}

    def _read(self,path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:
            raise AcquisitionError('Credential file is invalid; use the OS credential manager or explicitly reconnect.')
        if os.name!='nt' and stat.S_IMODE(path.stat().st_mode)&0o077:
            raise AcquisitionError('Credential file permissions are too broad; restrict them to 0600 before reconnecting.')
        try:
            value=json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(value,dict): raise ValueError('Expected object')
            return value
        except (ValueError,OSError) as error:
            raise AcquisitionError('Invalid private Guardian credential metadata; reconnect to your account.') from error

    def secure_backend(self):
        try:
            import keyring
            backend=keyring.get_keyring()
            supported=('keyring.backends.macOS','keyring.backends.Windows','keyring.backends.SecretService','keyring.backends.kwallet')
            candidates=backend.backends if type(backend).__module__=='keyring.backends.chainer' else [backend]
            for candidate in candidates:
                if type(candidate).__module__.startswith(supported) and candidate.priority>=1:
                    self.keyring=SimpleNamespace(get_password=candidate.get_password,set_password=candidate.set_password,delete_password=candidate.delete_password,errors=keyring.errors)
                    return self.keyring
            return None
        except Exception:
            # A locked/misconfigured OS backend is unavailable, never a fake keychain.
            return None

    def prepare(self):
        # Explicit opt-in also permits a usable fallback when a keychain is locked.
        if self.allow_file or self.meta.get('storage')=='file':
            self.meta['storage']='file'
        elif self.secure_backend():
            self.meta['storage']='keyring'
        else:
            raise AcquisitionError('No supported OS credential manager. Run guardian login --allow-file-credentials only if you accept a private plaintext credential file.')
        local_reports.write_private(self.metadata,json.dumps(self.meta))
        return self.meta['storage']

    def load(self):
        mode=self.meta.get('storage')
        if mode=='file': return self._read(self.file) if self.file.exists() else None
        if mode!='keyring': return None
        keyring=self.secure_backend()
        if not keyring: raise AcquisitionError('The OS credential manager is unavailable. Unlock it and retry.')
        try:
            value=keyring.get_password(self.service,self.meta['device_id'])
            return json.loads(value) if value else None
        except Exception as error:
            raise AcquisitionError('Could not read Guardian credentials from the OS credential manager.') from error

    def save(self,value):
        mode=self.meta.get('storage') or self.prepare()
        if mode=='file':
            local_reports.write_private(self.file,json.dumps(value))
        else:
            keyring=self.keyring or self.secure_backend()
            if not keyring: raise AcquisitionError('OS credential manager unavailable; session was not saved.')
            try: keyring.set_password(self.service,self.meta['device_id'],json.dumps(value))
            except Exception as error: raise AcquisitionError('OS credential manager refused to save the session. Unlock it or explicitly reconnect with --allow-file-credentials.') from error
        local_reports.write_private(self.metadata,json.dumps(self.meta))

    def clear(self):
        if self.meta.get('storage')=='file':
            if self.file.is_symlink(): raise AcquisitionError('Refusing to remove a symbolic credential link.')
            self.file.unlink(missing_ok=True)
        elif self.meta.get('storage')=='keyring':
            keyring=self.secure_backend()
            if not keyring: raise AcquisitionError('Unlock the OS credential manager to remove local credentials.')
            try: keyring.delete_password(self.service,self.meta['device_id'])
            except keyring.errors.PasswordDeleteError: pass
