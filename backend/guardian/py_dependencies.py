"""Python manifest parsing and dependency resolution for requirements.txt, pyproject.toml, and poetry.lock."""
import re
import tomllib
from pathlib import PurePosixPath
from .models import Dependency, PackageInspection, IntegrityResult

EXACT = re.compile(r'^\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
MAX_DISCOVERED = 2000

def parse_requirements_line(line: str):
    line = line.split('#')[0].strip()
    if not line or line.startswith('-'):
        return None
    # Strip environment markers (e.g. ; python_version >= '3.8')
    line = line.split(';')[0].strip()
    # Strip parentheses e.g. charset-normalizer (<4,>=2)
    cleaned = re.sub(r'[\(\)]', '', line).strip()
    match = re.match(r'^([A-Za-z0-9_.-]+)(?:\[.*?\])?\s*(===|==|>=|<=|~=|>|<|!=)?\s*(.*)$', cleaned)
    if not match:
        return None
    name, op, ver = match.groups()
    name = name.strip()
    op = (op or '').strip()
    ver = (ver or '').strip()
    if op in ('==', '==='):
        # Extract version if exact
        v = ver.split(',')[0].strip()
        return name, v
    if op and ver:
        return name, f'{op}{ver}'
    return name, 'unresolved'

def parse_requirements_txt(content: str, path: str = 'requirements.txt'):
    dependencies = []
    inspections = []
    lines = content.splitlines()
    for index, raw_line in enumerate(lines):
        parsed = parse_requirements_line(raw_line)
        if not parsed:
            continue
        name, ver = parsed
        is_exact = bool(EXACT.fullmatch(ver))
        dep = Dependency(name=name, version=ver, direct=True, source=path, ecosystem='pypi')
        dependencies.append(dep)
        inspection = PackageInspection(
            name=name,
            version=ver,
            location=f'{path}:{index+1}',
            direct=True,
            status='uninspected' if is_exact else 'unresolved',
            reason='Awaiting bounded source inspection.' if is_exact else 'Non-exact version specifier.'
        )
        inspections.append(inspection)
    return dependencies, inspections

def parse_pyproject_toml(content: str, path: str = 'pyproject.toml'):
    dependencies = []
    inspections = []
    pkg_name = 'Uploaded Python project'
    pkg_version = 'unversioned'
    try:
        data = tomllib.loads(content)
    except Exception:
        return dependencies, inspections, pkg_name, pkg_version

    # Standard PEP 621 metadata
    project = data.get('project', {})
    if isinstance(project, dict):
        pkg_name = str(project.get('name', pkg_name))
        pkg_version = str(project.get('version', pkg_version))
        for raw in project.get('dependencies', []):
            if isinstance(raw, str):
                parsed = parse_requirements_line(raw)
                if parsed:
                    name, ver = parsed
                    dependencies.append(Dependency(name=name, version=ver, direct=True, source=path, ecosystem='pypi'))
                    inspections.append(PackageInspection(name=name, version=ver, location=f'{path}:{name}', direct=True, status='unresolved', reason='Awaiting lockfile resolution.'))

    # Poetry support
    poetry = data.get('tool', {}).get('poetry', {})
    if isinstance(poetry, dict):
        if pkg_name == 'Uploaded Python project':
            pkg_name = str(poetry.get('name', pkg_name))
            pkg_version = str(poetry.get('version', pkg_version))
        poetry_deps = poetry.get('dependencies', {})
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == 'python':
                    continue
                ver = spec if isinstance(spec, str) else (spec.get('version', 'unresolved') if isinstance(spec, dict) else 'unresolved')
                dependencies.append(Dependency(name=name, version=str(ver), direct=True, source=path, ecosystem='pypi'))
                inspections.append(PackageInspection(name=name, version=str(ver), location=f'{path}:{name}', direct=True, status='unresolved', reason='Awaiting lockfile resolution.'))

    return dependencies, inspections, pkg_name, pkg_version

def parse_poetry_lock(content: str, path: str = 'poetry.lock'):
    dependencies = []
    inspections = []
    expected_digests = {}
    warnings = []
    try:
        data = tomllib.loads(content)
    except Exception as e:
        return [], [], {}, [f'Failed to parse poetry.lock: {e}']

    packages = data.get('package', [])
    if not isinstance(packages, list):
        return [], [], {}, ['poetry.lock packages must be a list.']

    for index, p in enumerate(packages[:MAX_DISCOVERED]):
        if not isinstance(p, dict):
            continue
        name = p.get('name')
        ver = p.get('version', 'unresolved')
        if not name:
            continue
        category = p.get('category', 'main')
        direct = (category == 'main')
        location = f'{path}:{name}@{ver}'
        dep = Dependency(name=name, version=str(ver), direct=direct, source=path, ecosystem='pypi')
        dependencies.append(dep)

        # Integrity
        files = p.get('files', [])
        expected_sri = None
        if isinstance(files, list):
            for f in files:
                if isinstance(f, dict) and 'hash' in f:
                    h = f['hash']
                    if h.startswith('sha256:'):
                        import base64
                        raw_hex = h.split('sha256:')[1]
                        if len(raw_hex) == 64:
                            expected_sri = 'sha256-' + base64.b64encode(bytes.fromhex(raw_hex)).decode()
                            break
        if expected_sri:
            expected_digests[location] = expected_sri

        node = PackageInspection(
            name=name,
            version=str(ver),
            location=location,
            direct=direct,
            status='uninspected' if EXACT.fullmatch(str(ver)) else 'unresolved',
            reason='Awaiting bounded source inspection.' if EXACT.fullmatch(str(ver)) else 'Non-exact version.',
            integrity=IntegrityResult(expected=expected_sri, source='lockfile') if expected_sri else IntegrityResult()
        )
        # Child dependencies in poetry.lock
        sub_deps = p.get('dependencies', {})
        if isinstance(sub_deps, dict):
            for sub_name in sub_deps:
                node.dependencies.append(f'{path}:{sub_name}')
        inspections.append(node)

    return dependencies, inspections, expected_digests, warnings

def parse_python_manifests(files: dict, manifest_paths: list):
    dependencies = []
    findings = []
    coverage = []
    pkg_name = None
    pkg_version = None

    for path in manifest_paths:
        content = files.get(path, '')
        name = PurePosixPath(path).name
        if name == 'requirements.txt':
            deps, _ = parse_requirements_txt(content, path)
            dependencies.extend(deps)
        elif name == 'pyproject.toml':
            deps, _, p_name, p_ver = parse_pyproject_toml(content, path)
            dependencies.extend(deps)
            if not pkg_name and p_name != 'Uploaded Python project':
                pkg_name, pkg_version = p_name, p_ver
        elif name == 'poetry.lock':
            deps, _, _, lock_warnings = parse_poetry_lock(content, path)
            dependencies.extend(deps)
            coverage.extend(lock_warnings)

    return pkg_name, pkg_version, dependencies, findings, coverage
