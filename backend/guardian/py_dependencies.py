"""Python manifest parsing and dependency resolution for requirements.txt, pyproject.toml, and poetry.lock."""
import re
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from pathlib import PurePosixPath
from .models import Dependency, PackageInspection, IntegrityResult
from .intelligence import is_exact_resolved_version

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
        is_exact = is_exact_resolved_version(ver, 'pypi')
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

        # PEP 621 optional-dependencies
        opt_deps = project.get('optional-dependencies', {})
        if isinstance(opt_deps, dict):
            for group_name, raw_list in opt_deps.items():
                if isinstance(raw_list, list):
                    for raw in raw_list:
                        if isinstance(raw, str):
                            parsed = parse_requirements_line(raw)
                            if parsed:
                                name, ver = parsed
                                dependencies.append(Dependency(name=name, version=ver, direct=False, source=f'{path} [{group_name}]', ecosystem='pypi'))
                                inspections.append(PackageInspection(name=name, version=ver, location=f'{path}:{name}', direct=False, status='unresolved', reason=f"Optional group '{group_name}' awaiting lockfile resolution."))

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

        # Poetry dependency groups (tool.poetry.group.<group>.dependencies)
        groups = poetry.get('group', {})
        if isinstance(groups, dict):
            for group_name, group_data in groups.items():
                if isinstance(group_data, dict):
                    grp_deps = group_data.get('dependencies', {})
                    if isinstance(grp_deps, dict):
                        for name, spec in grp_deps.items():
                            if name.lower() == 'python':
                                continue
                            ver = spec if isinstance(spec, str) else (spec.get('version', 'unresolved') if isinstance(spec, dict) else 'unresolved')
                            dependencies.append(Dependency(name=name, version=str(ver), direct=False, source=f'{path} [poetry: {group_name}]', ecosystem='pypi'))
                            inspections.append(PackageInspection(name=name, version=str(ver), location=f'{path}:{name}', direct=False, status='unresolved', reason=f"Poetry group '{group_name}' awaiting lockfile resolution."))

        # Legacy Poetry dev-dependencies
        dev_deps = poetry.get('dev-dependencies', {})
        if isinstance(dev_deps, dict):
            for name, spec in dev_deps.items():
                if name.lower() == 'python':
                    continue
                ver = spec if isinstance(spec, str) else (spec.get('version', 'unresolved') if isinstance(spec, dict) else 'unresolved')
                dependencies.append(Dependency(name=name, version=str(ver), direct=False, source=f'{path} [poetry: dev]', ecosystem='pypi'))
                inspections.append(PackageInspection(name=name, version=str(ver), location=f'{path}:{name}', direct=False, status='unresolved', reason='Poetry dev dependency awaiting lockfile resolution.'))

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

    # Pre-index package versions for graph reference resolution: name -> version
    pkg_version_map = {}
    for p in packages:
        if isinstance(p, dict) and p.get('name'):
            pkg_version_map[p['name']] = str(p.get('version', 'unresolved'))

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

        # Integrity: collect all available sha256 digests
        files = p.get('files', [])
        sris = []
        if isinstance(files, list):
            import base64
            for f in files:
                if isinstance(f, dict) and 'hash' in f:
                    h = f['hash']
                    if h.startswith('sha256:'):
                        raw_hex = h.split('sha256:')[1]
                        if len(raw_hex) == 64:
                            sris.append('sha256-' + base64.b64encode(bytes.fromhex(raw_hex)).decode())
        expected_sri = ' '.join(sris) if sris else None
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
        # Child dependencies in poetry.lock resolved to actual package record locations
        sub_deps = p.get('dependencies', {})
        if isinstance(sub_deps, dict):
            for sub_name in sub_deps:
                sub_ver = pkg_version_map.get(sub_name)
                if sub_ver:
                    node.dependencies.append(f'{path}:{sub_name}@{sub_ver}')
                else:
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
            for line in content.splitlines():
                stripped = line.split('#')[0].strip()
                if not stripped:
                    continue
                if stripped.startswith(('-r ', '--requirement ')):
                    coverage.append(f"Nested requirement directive '{stripped}' is omitted; dependencies were not recursively followed.")
                elif stripped.startswith(('-e ', '--editable ')):
                    coverage.append(f"Editable installation '{stripped}' is not supported in static inspection.")
                elif stripped.startswith(('-f ', '-i ', '--extra-index-url', '--index-url', '--find-links')):
                    coverage.append(f"Package index/find directive '{stripped.split()[0]}' is omitted.")
                elif '@' in stripped and any(p in stripped for p in ('http://', 'https://', 'git+', 'hg+', 'svn+')):
                    coverage.append(f"Direct URL/VCS requirement '{stripped}' is omitted from dependencies.")
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
