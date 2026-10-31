"""Private per-user reports. No account, source cache or automatic network sync."""
import json
import os
import tempfile
from pathlib import Path
from .models import Report


def directory():
    override = os.getenv('GUARDIAN_HOME')
    if override:
        path = Path(override).expanduser()
    elif os.name == 'nt':
        path = Path(os.getenv('LOCALAPPDATA', str(Path.home()))) / 'Guardian'
    else:
        path = Path(os.getenv('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'guardian'
    if path.is_symlink():
        raise ValueError('Guardian report directory must not be a symbolic link.')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def write_private(path, text):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing to overwrite a symbolic link.')
    fd, tmp = tempfile.mkstemp(prefix='.guardian-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save(report):
    root = directory()
    target = root / (report.id + '.json')
    write_private(target, report.model_dump_json(indent=2))
    write_private(root / 'latest.json', json.dumps({'id': report.id}))
    return target


def latest():
    root = directory()
    pointer = root / 'latest.json'
    if not pointer.exists():
        raise ValueError('No local report yet. Run guardian check or guardian audit.')
    identifier = json.loads(pointer.read_text(encoding='utf-8'))['id']
    if not isinstance(identifier, str) or not identifier.isalnum() or len(identifier) > 64:
        raise ValueError('Invalid local report identifier.')
    target = root / (identifier + '.json')
    if target.is_symlink() or target.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Invalid local report file.')
    return Report.model_validate_json(target.read_text(encoding='utf-8'))
