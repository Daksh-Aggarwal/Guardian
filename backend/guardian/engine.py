import ast
import json
import re
import subprocess
from pathlib import Path
from uuid import uuid4
import yaml
from .models import Dependency, Evidence, Finding, DataFlow
from .config import parser_limits

ROOT = Path(__file__).resolve().parents[2]
POPULAR = ['react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'typescript', 'webpack', 'vite', 'next', 'eslint', 'prettier', 'dotenv', 'zod', 'mongoose', 'debug', 'moment', 'cross-env', 'cookie', 'minimist', 'yargs', 'jquery', 'request', 'uuid']
RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
LIFECYCLE_STAGES = ['preinstall', 'install', 'postinstall', 'prepare', 'preuninstall', 'uninstall', 'postuninstall', 'prepack', 'postpack', 'prepublish', 'prepublishOnly']
MINING_PACKAGES = {'stratum-client', 'coinhive', 'node-cryptonight', 'cryptonight-hashing', 'xmrig'}
BINARY_EXTENSIONS = {'.node', '.dll', '.so', '.dylib', '.exe', '.pyd', '.wasm'}
PROMPT_INJECTION_RE = re.compile(
    r'(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|'
    r'system\s*prompt\s*override|'
    r'<\s*(?:system|instructions|important|tool_call)\s*>.*?(?:curl|wget|bash|sh\s+-c|exec|eval|\.env|id_rsa)|'
    r'important\s+for\s+ai\s+(?:agents?|assistants?)\s*:.*?(?:run|execute|curl|wget|fetch))',
    re.IGNORECASE | re.DOTALL,
)
PY_PRIVATE_FILE_RE = re.compile(
    r'(\.ssh/|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.aws/credentials|\.kube/config|kubeconfig|\.docker/config\.json|\.git-credentials|\.netrc|(?:^|[/\\])\.env(?:\.[a-z0-9_]+)?$)',
    re.IGNORECASE,
)

def finding(rule, title, category, severity, confidence, observed, explanation, implication, recommendation, evidence, references=None):
    return Finding(id=uuid4().hex[:12], rule=rule, title=title, category=category, severity=severity, confidence=confidence, observed=observed, explanation=explanation, implication=implication, recommendation=recommendation, evidence=evidence, references=references or [], limitations=["Static evidence does not establish runtime execution or malicious intent."])

def distance(a, b):
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        nxt = [i + 1]
        for j, cb in enumerate(b):
            nxt.append(min(nxt[-1] + 1, row[j + 1] + 1, row[j] + (ca != cb)))
        row = nxt
    return row[-1]

def typo(name):
    if name in POPULAR or name.startswith('@'):
        return None
    normalized = name.translate(str.maketrans({'0': 'o', '1': 'l', '3': 'e', '5': 's'}))
    return next((p for p in POPULAR if len(p) >= 4 and (distance(name, p) == 1 or normalized == p)), None)

def _analyze_python_ast(path, content, findings, reverse_shell_only=False):
    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError:
        return
    lines = content.splitlines()
    def _snip(lineno):
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()[:500]
        return ''

    has_cred_source = []
    has_net_sink = []
    has_decode = []
    has_dynamic = []
    has_socket = []
    has_shell = []

    for node in ast.walk(tree):
        lineno = getattr(node, 'lineno', 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if PY_PRIVATE_FILE_RE.search(node.value):
                has_cred_source.append(Evidence(file=path, line=lineno, snippet=_snip(lineno), detail=f'Sensitive file path {node.value[:80]}'))
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == 'os' and node.attr == 'environ':
                has_cred_source.append(Evidence(file=path, line=lineno, snippet=_snip(lineno), detail='os.environ access'))
        if isinstance(node, ast.Call):
            func_name = ''
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    func_name = f'{node.func.value.id}.{node.func.attr}'
                else:
                    func_name = node.func.attr

            if func_name in {'eval', 'exec', 'compile', '__import__', 'pickle.loads', 'marshal.loads', 'ctypes.CDLL', 'ctypes.windll'}:
                ev = Evidence(file=path, line=lineno, snippet=_snip(lineno), detail=f'Python dynamic execution via {func_name}')
                has_dynamic.append(ev)
                if not reverse_shell_only: findings.append(finding('DYNAMIC_EXECUTION', 'Builds or runs code dynamically', 'Dynamic code', 'medium' if 'pickle' in func_name or 'marshal' in func_name else 'low', 'high', ev.detail, 'The Python source executes code dynamically or deserializes executable objects.', 'Dynamic code execution or unsafe deserialization can conceal arbitrary payloads.', 'Inspect the input to the dynamic execution call.', [ev]))
            if func_name in {'base64.b64decode', 'b64decode', 'zlib.decompress', 'codecs.decode', 'bytes.fromhex'}:
                has_decode.append(Evidence(file=path, line=lineno, snippet=_snip(lineno), detail=f'Decoded content via {func_name}'))
            if func_name in {'os.system', 'os.popen'} or func_name.startswith('subprocess.') or func_name in {'Popen', 'run', 'call', 'check_output'}:
                ev = Evidence(file=path, line=lineno, snippet=_snip(lineno), detail=f'Python process execution via {func_name}')
                has_shell.append(ev)
                if not reverse_shell_only: findings.append(finding('PROCESS_EXECUTION', 'Starts an operating-system process', 'Execution', 'low', 'high', ev.detail, 'The Python source spawns an operating-system process.', 'The child process runs with the caller’s permissions.', 'Review the command and arguments passed to the process call.', [ev]))
            if func_name in {'socket.socket', 'socket.create_connection'} or func_name.endswith('.connect'):
                has_socket.append(Evidence(file=path, line=lineno, snippet=_snip(lineno), detail=f'Socket connection via {func_name}'))
            if func_name.startswith(('requests.', 'urllib.request.', 'httpx.', 'aiohttp.')) or func_name in {'urlopen', 'Request'}:
                has_net_sink.append(Evidence(file=path, line=lineno, snippet=_snip(lineno), detail=f'Outbound network call via {func_name}'))

    if reverse_shell_only:
        if has_socket and has_shell:
            findings.append(finding('REVERSE_SHELL', 'Establishes a reverse shell or interactive socket pipe', 'Execution', 'critical', 'high', 'Python module combines raw socket connection with subprocess execution', 'The Python file opens a socket connection and spawns a subprocess in the same module.', 'An attacker may gain interactive remote command execution.', 'Do not install or import this package; isolate affected hosts.', (has_socket + has_shell)[:6]))
        return

    if has_cred_source and has_net_sink:
        findings.append(finding('SENSITIVE_TRANSMISSION', 'Sensitive data reaches a network request', 'Data exposure', 'high', 'medium', 'Python module accesses environment/credentials and performs outbound network requests', 'The Python file accesses sensitive environment or credential paths and makes outbound HTTP requests.', 'This may exfiltrate credentials or tokens during package import, build, or runtime.', 'Inspect the destination URL and payload in the Python module.', (has_cred_source + has_net_sink)[:6]))
    if has_decode and has_dynamic:
        findings.append(finding('OBFUSCATED_EXECUTION', 'Decoded content reaches dynamic execution', 'Obfuscation', 'medium', 'medium', 'Python module decodes base64/zlib data and invokes eval/exec', 'The Python file combines payload decoding/decompression with dynamic code execution.', 'This pattern is widely used to conceal malicious payloads in Python packages.', 'Decode and inspect the payload statically without executing the module.', (has_decode + has_dynamic)[:6]))
    if has_socket and has_shell:
        findings.append(finding('REVERSE_SHELL', 'Establishes a reverse shell or interactive socket pipe', 'Execution', 'critical', 'high', 'Python module combines raw socket connection with subprocess execution', 'The Python file opens a socket connection and spawns a subprocess in the same module.', 'An attacker may gain interactive remote command execution.', 'Do not install or import this package; isolate affected hosts.', (has_socket + has_shell)[:6]))

def analyze(files, limits=None, timeout=20):
    findings, dependencies, coverage, count = [], [], [], 0
    name, version = 'Uploaded project', 'unversioned'
    manifests = sorted(
        (p for p in files if Path(p).name in {'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'}),
        key=lambda p: (len(Path(p).parts), Path(p).name != 'package.json', p)
    )
    lifecycle_scripts = []
    for index, path in enumerate(manifests):
        try:
            p_name = Path(path).name
            if p_name.endswith('.json'):
                manifest = json.loads(files[path])
            elif p_name in {'pnpm-lock.yaml', 'yarn.lock'}:
                manifest = yaml.safe_load(files[path])
            else:
                continue

            if not isinstance(manifest, dict):
                raise ValueError('Manifest must be an object')
            if index == 0 and p_name == 'package.json':
                name, version = str(manifest.get('name', name)), str(manifest.get('version', version))
            desc = str(manifest.get('description', ''))
            if desc and PROMPT_INJECTION_RE.search(desc):
                ev = Evidence(file=path, line=1, snippet=desc[:500], detail='Adversarial prompt-injection pattern in manifest description')
                findings.append(finding('AGENT_PROMPT_INJECTION', 'Contains prompt-injection instructions targeting AI agents', 'AI security', 'medium', 'medium', ev.detail, 'The package metadata contains instructions designed to override AI coding assistant or agent behavior.', 'AI agents reading package metadata may be tricked into running commands or exfiltrating secrets.', 'Treat package metadata as untrusted data and do not feed unverified descriptions into privileged agent loops.', [ev]))
            scripts = manifest.get('scripts', {})
            if not isinstance(scripts, dict):
                raise ValueError('scripts must be an object')
            for stage in LIFECYCLE_STAGES:
                command = scripts.get(stage)
                if not command:
                    continue
                if not isinstance(command, str):
                    raise ValueError('Script commands must be strings')
                remote = bool(re.search(r'\b(curl|wget|Invoke-WebRequest|iwr)\b.*https?://', command, re.IGNORECASE))
                execution = bool(re.search(r'\|\s*(sh|bash|zsh|pwsh|powershell)|\beval\b|\bnode\s+-e\b|\bpython3?\s+-c\b', command, re.IGNORECASE))
                loader_evasion = bool(re.search(r'\b(bun\s+run|bunx|powershell(?:\.exe)?\s+-(?:enc|EncodedCommand|w\s+hidden)|nohup\b|--detached\b|base64\s+-d\b)', command, re.IGNORECASE))
                evidence = Evidence(file=path, line=next((i+1 for i,l in enumerate(files[path].splitlines()) if '"'+stage+'"' in l), 1), snippet=command[:500], detail=stage + ' lifecycle command')
                findings.append(finding('INSTALL_SCRIPT', 'Runs code during installation', 'Installation', 'info', 'high', f'{stage}: {command[:200]}', 'This package can run a command automatically when it is installed or unpacked. Many legitimate packages do this.', 'The command runs with the permissions of the person installing the package.', 'Review this command and its referenced files before installation. Consider npm install --ignore-scripts.', [evidence]))
                lifecycle_scripts.append((stage, command, evidence, path))
                if remote:
                    findings.append(finding('INSTALL_REMOTE', 'Installation downloads a remote payload', 'Execution', 'high' if execution else 'medium', 'high', 'An installation command downloads from a remote URL' + (' and pipes to a shell.' if execution else '.'), 'The installer retrieves code or data from outside the package.' + (' It sends the download directly to a command interpreter.' if execution else ''), 'Remote content can change independently of the package and may run with your permissions.', 'Do not run the installer until you have verified the remote source and command. Prefer a reviewed, pinned artifact.', [evidence]))
                if loader_evasion:
                    findings.append(finding('INSTALL_LOADER', 'Lifecycle script uses an alternative runtime or detached loader', 'Installation', 'medium', 'high', f'{stage} invokes loader: {command[:200]}', 'The lifecycle script uses an alternative runtime (such as bun), encoded PowerShell, base64 decoding, or background detachment.', 'Attackers frequently use alternative runtimes or detached loaders in lifecycle scripts to bypass Node.js runtime monitors.', 'Inspect the target script and loader arguments before running package installation.', [evidence]))
            for field in ['dependencies', 'devDependencies', 'optionalDependencies']:
                group = manifest.get(field, {})
                if isinstance(group, dict):
                    for dep, spec in group.items():
                        if isinstance(spec, str):
                            dependencies.append(Dependency(name=dep, version=spec, direct=True, source=path))
                        elif isinstance(spec, dict) and 'version' in spec:  # lockfile v1
                            dependencies.append(Dependency(name=dep, version=str(spec['version']), direct=False, source=path))
                        if dep.lower() in MINING_PACKAGES:
                            ev = Evidence(file=path, line=1, snippet=f'"{dep}": "{spec}"', detail=f'Cryptomining dependency {dep}')
                            findings.append(finding('CRYPTOMINING', 'References cryptomining pools or mining libraries', 'Resource abuse', 'high', 'high', ev.detail, 'The manifest declares a known cryptocurrency mining library as a dependency.', 'This package may consume host CPU/GPU resources for unauthorized cryptocurrency mining.', 'Remove the mining dependency and audit how the package was introduced.', [ev]))
                elif group is not None and field in manifest:
                    raise ValueError(field + ' must be an object')
            packages = manifest.get('packages', {})
            if isinstance(packages, dict):
                direct_names = set(packages.get('', {}).get('dependencies', {})) if isinstance(packages.get('', {}), dict) else set()
                for location, package in packages.items():
                    if location and isinstance(package, dict) and package.get('version'):
                        dep = package.get('name') or location.split('node_modules/')[-1]
                        dependencies.append(Dependency(name=dep, version=str(package['version']), direct=dep in direct_names, source=path))
                    elif location and isinstance(package, dict) and '@' in location:
                        from .dependencies import _parse_pnpm_key
                        dep_name, dep_ver = _parse_pnpm_key(location, package)
                        dependencies.append(Dependency(name=dep_name, version=dep_ver, direct=False, source=path))

            if '__metadata' in manifest:
                from .dependencies import _parse_yarn_descriptor
                for yk, yv in manifest.items():
                    if yk != '__metadata' and isinstance(yv, dict) and yv.get('version'):
                        descriptors = [_parse_yarn_descriptor(d) for d in yk.split(',')]
                        primary_name = descriptors[0][0]
                        dependencies.append(Dependency(name=primary_name, version=str(yv['version']), direct=False, source=path))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError(f'Invalid manifest {path}: {error}')
    py_manifests = sorted(
        (p for p in files if Path(p).name in {'requirements.txt', 'pyproject.toml', 'poetry.lock', 'Pipfile', 'Pipfile.lock'}),
        key=lambda p: (len(Path(p).parts), p)
    )
    if py_manifests:
        from .py_dependencies import parse_python_manifests
        p_name, p_ver, p_deps, p_findings, p_coverage = parse_python_manifests(files, py_manifests)
        if name == 'Uploaded project' and p_name:
            name, version = p_name, p_ver
        dependencies.extend(p_deps)
        findings.extend(p_findings)
        coverage.extend(p_coverage)
    if not manifests and not py_manifests:
        coverage.append('No npm manifest was found; package identity and dependencies are unknown.')
    unique = {(d.name, d.version, getattr(d, 'ecosystem', 'npm')): d for d in dependencies}
    dependencies = list(unique.values())
    from .py_engine import typo_pypi
    for dep, path in [(name, manifests[0] if manifests else (py_manifests[0] if py_manifests else 'project'))] + [(d.name, d.source) for d in dependencies]:
        similar = typo(dep)
        if not similar:
            similar = typo_pypi(dep)
        if similar and not any(f.rule == 'TYPO' and f.observed == dep for f in findings):
            findings.append(finding('TYPO', f'Name resembles {similar}', 'Package identity', 'medium', 'low', dep, f'“{dep}” is very close to the name of the popular package “{similar}”. This can also be a coincidence.', 'A mistyped name could install a different author’s package. Similarity alone is not evidence of malicious intent.', 'Confirm the intended package name, publisher, and repository before installation.', [Evidence(file=path, snippet=dep, detail=f'Curated-name comparison with {similar}; edit distance {distance(dep, similar)}')]))
    sources = {p: c for p, c in files.items() if Path(p).suffix in {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'}}
    parsed = []
    if sources:
        try:
            result = subprocess.run(['node', '--max-old-space-size=256', str(ROOT / 'scripts/parse.cjs')], input=json.dumps({"files":sources,"limits":limits or parser_limits()}), text=True, capture_output=True, timeout=timeout, cwd=ROOT)
            if result.returncode:
                raise ValueError('Parser exited unsuccessfully')
            parsed = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            coverage.append('JavaScript parser unavailable or resource limit reached. Source behavior analysis is incomplete.')
    py_sources = {p: c for p, c in files.items() if Path(p).suffix in {'.py', '.pyw'}}
    if py_sources:
        from .py_engine import analyze_python
        py_findings, py_coverage, py_count = analyze_python(py_sources, timeout=timeout)
        findings.extend(py_findings)
        coverage.extend(py_coverage)
        count += py_count

    if not sources and not py_sources:
        coverage.append('Manifest-only scan: package source behavior has not been inspected.')
    rules = {
        'credential': ('CREDENTIAL_ACCESS', 'Reads environment or credential information', 'Data access', 'info', 'The source accesses environment variables or references a sensitive file.', 'Applications often use this for configuration. It becomes more concerning if private information is sent elsewhere.', 'Check which values are read and whether the package needs them.'),
        'network': ('NETWORK', 'Makes an outbound network request', 'Network', 'info', 'The source makes a network request.', 'Network access is common and is not by itself evidence of harm.', 'Verify that the destination and transmitted data match the package’s purpose.'),
        'exfiltration': ('SENSITIVE_TRANSMISSION', 'Sensitive data reaches a network request', 'Data exposure', 'high', 'Sensitive information appears in the arguments of a network request, directly or through a local variable.', 'This may send secrets outside your computer. Legitimate authentication can have the same pattern; intent and destination require review.', 'Inspect the destination and request payload. Avoid running the package with real credentials until reviewed.'),
        'info-exfiltration': ('HOST_INFO_EXFILTRATION', 'Host fingerprint data reaches a network request', 'Data exposure', 'medium', 'Host environment information (such as hostname, home directory, username, or DNS servers) flows to an outbound network request.', 'Malicious packages frequently beacon host identification telemetry to an external server during installation or import.', 'Verify whether outbound telemetry is expected and inspect the destination server.'),
        'dynamic': ('DYNAMIC_EXECUTION', 'Builds or runs code dynamically', 'Dynamic code', 'low', 'The source calls eval, Function, or vm execution APIs.', 'This can make behavior harder to review. Some legitimate tools also generate code.', 'Inspect the input to the dynamic execution call.'),
        'encoding': ('ENCODED_CONTENT', 'Decodes encoded content', 'Obfuscation', 'info', 'The source decodes base64/hexadecimal data, decompresses buffers, or decrypts ciphertexts.', 'Encoding is common for data handling. Decoding followed by code execution deserves closer inspection.', 'Review the decoded content without executing it.'),
        'execution': ('PROCESS_EXECUTION', 'Starts an operating-system process', 'Execution', 'low', 'The source calls a child-process API.', 'The new process can act with the caller’s permissions. Build tools commonly do this.', 'Review the command and inputs, especially input supplied by others.'),
        'remote': ('REMOTE_PAYLOAD', 'Downloads a payload through a shell', 'Execution', 'medium', 'A child-process command uses curl or wget with a remote URL.', 'The remote content may change and could contain executable code.', 'Verify and pin the remote content; inspect whether it is subsequently executed.'),
        'filesystem': ('FILESYSTEM', 'Reads or writes local files', 'Data access', 'info', 'The source uses a file-system API.', 'File access is ordinary but can expose or modify sensitive files depending on the path.', 'Check the paths and whether access is necessary.'),
        'reverse-shell': ('REVERSE_SHELL', 'Establishes a reverse shell or interactive socket pipe', 'Execution', 'critical', 'The source connects a raw network socket and spawns or pipes an interactive shell process.', 'This pattern provides an external party with interactive command execution on the host.', 'Do not install or execute this package. Isolate any machine where it was run and rotate credentials.'),
        'c2-execution': ('REMOTE_CODE_C2', 'Executes commands or code fetched from a remote server', 'Execution', 'critical', 'Data received from an outbound HTTP or DNS request is passed directly into process execution or dynamic code evaluation.', 'Remote command-and-control (C2) execution allows arbitrary unreviewed code to run on the host.', 'Block network access to the remote endpoint and do not execute the package.'),
        'staged-dropper': ('STAGED_PAYLOAD_DROPPER', 'Downloads, writes, and executes a staged payload', 'Execution', 'high', 'The module performs an outbound network request, writes to the file system, and spawns an operating-system process.', 'Staged droppers fetch secondary binaries or scripts at runtime to evade static signature checks.', 'Inspect the downloaded artifact, target file path, and spawned command.'),
        'dns-tunneling': ('DNS_TUNNELING', 'Exfiltrates host or credential data via DNS queries', 'Data exposure', 'high', 'Host environment data, file contents, or encoded secrets are embedded into DNS resolution calls.', 'DNS tunneling bypasses outbound HTTP firewalls to exfiltrate data to attacker-controlled nameservers.', 'Inspect the domain names constructed in DNS queries and block unauthorized nameserver lookups.'),
        'cryptomining': ('CRYPTOMINING', 'References cryptomining pools or mining libraries', 'Resource abuse', 'high', 'The source references Stratum mining protocols, known mining pools, or cryptocurrency miner binaries.', 'Unauthorized cryptominers hijack CPU and GPU resources and degrade system availability.', 'Remove the package and terminate any unauthorized miner processes.'),
        'persistence': ('PERSISTENCE_MECHANISM', 'Installs host persistence or starts a background server listener', 'Persistence', 'high', 'The code modifies startup profiles, cron jobs, systemd units, Git hooks, or binds a persistent server port.', 'Persistence mechanisms ensure malicious code survives reboot or re-executes during developer workflows.', 'Audit system cron jobs, shell profiles, Git hooks, and listening ports on any host where this package ran.'),
        'cloud-metadata': ('CLOUD_METADATA_ACCESS', 'Queries cloud instance metadata service', 'Credential access', 'high', 'The code requests cloud metadata endpoints (such as 169.254.169.254 or metadata.google.internal).', 'Cloud metadata services expose temporary IAM role credentials and instance identity tokens.', 'Block untrusted workloads from reaching instance metadata endpoints (use IMDSv2 hop limits) and rotate IAM credentials.'),
        'self-propagation': ('SELF_PROPAGATION', 'Publishes packages or modifies CI/CD workflows automatically', 'Supply chain worm', 'critical', 'The source invokes package publishing commands (npm publish, twine upload), repository pushes, or writes GitHub Actions workflows.', 'Self-propagating supply-chain worms use stolen maintainer tokens to infect downstream packages and repositories.', 'Revoke npm, PyPI, and GitHub tokens immediately and audit recent package publications and workflow commits.'),
        'defense-impairment': ('DEFENSE_EVASION_TLS', 'Disables TLS verification or weakens host security controls', 'Defense evasion', 'medium', 'The source disables TLS certificate validation (NODE_TLS_REJECT_UNAUTHORIZED=0 or rejectUnauthorized: false) or impairs host defenses.', 'Disabling TLS verification allows man-in-the-middle interception and enables connections to self-signed C2 infrastructure.', 'Restore strict TLS verification and review all outbound network destinations.'),
        'conditional-evasion': ('ENV_GATED_EXECUTION', 'Gates execution or exfiltration on specific host or CI conditions', 'Defense evasion', 'medium', 'Sensitive process execution, dynamic evaluation, or exfiltration occurs inside a conditional check on OS platform, hostname, or CI environment.', 'Conditional execution is used to evade analysis sandboxes or target only production CI/CD runners and specific operating systems.', 'Inspect both branches of the environment condition to understand the gated behavior.'),
        'destructive-fs': ('DESTRUCTIVE_FS', 'Deletes or corrupts sensitive or root filesystem paths', 'Impact', 'high', 'The source invokes recursive or targeted file deletion on root, home, or parent traversal paths.', 'Destructive filesystem operations (wipers/protestware) can permanently destroy source code and host data.', 'Do not execute this package; restore affected systems from verified backups.'),
    }
    file_findings_map = {}
    for item in parsed:
        if item['error']:
            coverage.append(f"Could not parse {item['file']}: {item['error']}")
            continue
        count += 1
        coverage.extend(item.get('coverage', []))
        grouped = {}
        for event in item['events']:
            kind = event['kind']
            if kind in {'encoded-execution'}:
                continue
            evidence = Evidence(file=item['file'], **{k:event[k] for k in ['line','column','snippet','detail']})
            if kind == 'exfiltration':
                rule, title, category, severity, explanation, implication, action = rules[kind]
                auth = event.get('context') == 'authentication'
                f = finding(rule, 'Sensitive data used in authentication' if auth else title, category, 'medium' if auth else severity, 'medium', event['detail'],
                    'A static path connects a private value to an authentication header. This is often intentional, but the destination still needs review.' if auth else 'A static path connects a sensitive source to an outbound request, through the recorded variables or function calls.',
                    implication, action, [evidence])
                f.data_flows = [DataFlow.model_validate(flow) for flow in event.get('flows', [])]
                f.limitations = ['Statically inferred path; not proof of runtime execution or malicious intent.']
                if any(step.kind == 'unknown-call' for flow in f.data_flows for step in flow.steps):
                    f.confidence = 'low'
                    f.limitations.append('An unmodeled transformation occurs on this path; it may remove or change the data.')
                findings.append(f)
                file_findings_map.setdefault(item['file'], []).append(f)
            else:
                grouped.setdefault(kind, []).append(evidence)
        if len(item['events']) >= 250:
            coverage.append(f"Evidence capped at 250 observations in {item['file']}.")
        for kind, evidence in grouped.items():
            if kind not in rules:
                continue
            rule, title, category, severity, explanation, implication, action = rules[kind]
            f = finding(rule, title, category, severity, 'high', evidence[0].detail, explanation, implication, action, evidence[:12])
            findings.append(f)
            file_findings_map.setdefault(item['file'], []).append(f)
        if any(e['kind'] == 'encoded-execution' for e in item['events']):
            f = finding('OBFUSCATED_EXECUTION', 'Decoded content reaches dynamic execution', 'Obfuscation', 'medium', 'medium', 'A decoded value is passed to eval or a Function constructor.', 'A static value connection links decoding to dynamic code execution.', 'This may conceal behavior, but can also be legitimate. Runtime execution has not been proven.', 'Inspect the decoded input without executing it.', grouped.get('encoding', [])[:3] + grouped.get('dynamic', [])[:3])
            findings.append(f)
            file_findings_map.setdefault(item['file'], []).append(f)

    # Correlate lifecycle scripts with the JS files they invoke (DistillGuard install-time attack chain)
    for stage, command, script_ev, manifest_path in lifecycle_scripts:
        for src_file, src_findings in file_findings_map.items():
            base_name = Path(src_file).name
            if base_name in command or src_file in command:
                elevated_src = [sf for sf in src_findings if RANK[sf.severity] >= RANK['medium']]
                has_net_and_exec = any(sf.rule == 'NETWORK' for sf in src_findings) and any(sf.rule in {'PROCESS_EXECUTION', 'DYNAMIC_EXECUTION'} for sf in src_findings)
                if elevated_src or has_net_and_exec:
                    chain_ev = [script_ev] + [ sf.evidence[0] for sf in (elevated_src or src_findings) if sf.evidence ][:3]
                    findings.append(finding(
                        'INSTALL_SCRIPT_CHAIN',
                        'Lifecycle script executes a file with elevated risk behavior',
                        'Installation',
                        'high',
                        'high',
                        f'{stage} invokes {src_file} which triggers {", ".join( sorted({sf.rule for sf in (elevated_src or src_findings)}) )}',
                        'An automatic lifecycle hook executes a local script that performs sensitive data transmission, remote code execution, obfuscation, or process spawning.',
                        'Because lifecycle hooks run automatically during package installation, any dangerous behavior in the target script executes immediately on the host.',
                        'Do not install this package without --ignore-scripts. Inspect the referenced lifecycle script and all behaviors it triggers.',
                        chain_ev,
                    ))

    # Cross-ecosystem & Python / Native / AI Agent analyzers
    for path, content in files.items():
        p = Path(path)
        suffix = p.suffix.lower()
        fname = p.name.lower()

        # 1. Python startup hooks (.pth, .start, sitecustomize.py, usercustomize.py) — INC-015 LiteLLM, DET-004, PKG-START-001
        if suffix == '.pth':
            for idx, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(('import ', 'import\t')):
                    ev = Evidence(file=path, line=idx, snippet=stripped[:500], detail='Executable import line in Python .pth file')
                    findings.append(finding('PYTHON_STARTUP_HOOK', 'Executes arbitrary code on every Python interpreter startup', 'Persistence', 'critical', 'high', ev.detail, 'Python .pth files in site-packages execute lines beginning with "import" every time the Python interpreter starts.', 'This provides automatic, invisible code execution across all Python invocations in the environment (as seen in the LiteLLM supply-chain incident).', 'Remove the malicious .pth file immediately and rebuild the virtual environment.', [ev]))
        elif suffix == '.start' or fname in {'sitecustomize.py', 'usercustomize.py'}:
            ev = Evidence(file=path, line=1, snippet=content[:300], detail=f'Python interpreter startup hook {p.name}')
            findings.append(finding('PYTHON_STARTUP_HOOK', 'Executes arbitrary code on every Python interpreter startup', 'Persistence', 'critical', 'high', ev.detail, f'The package includes {p.name}, which Python executes automatically during interpreter initialization.', 'Any code inside this startup hook runs silently before user scripts whenever Python starts.', 'Inspect or remove the startup customization file before installing the package.', [ev]))

        # 2. Python build hooks (setup.py, pyproject.toml) — PKG-EXEC-001, INC-014, INC-017
        if fname == 'setup.py':
            if re.search(r'\b(subprocess|os\.system|os\.popen|urllib|requests|socket|eval|exec|b64decode)\b', content):
                ev = Evidence(file=path, line=1, snippet=content[:400], detail='setup.py invokes process, network, or dynamic execution APIs')
                findings.append(finding('PYTHON_BUILD_HOOK', 'Python build script executes commands or network calls during installation', 'Installation', 'high', 'high', ev.detail, 'setup.py contains process execution, network access, or dynamic code execution during package build/installation.', 'Executing setup.py runs arbitrary code with the installer’s permissions.', 'Use binary wheels (--only-binary :all:) or audit setup.py before installing.', [ev]))
            if path not in py_sources:
                count += 1
                _analyze_python_ast(path, content, findings)
            else:
                _analyze_python_ast(path, content, findings, reverse_shell_only=True)
        elif suffix == '.py' and fname not in {'sitecustomize.py', 'usercustomize.py'}:
            if path not in py_sources:
                count += 1
                _analyze_python_ast(path, content, findings)
            else:
                _analyze_python_ast(path, content, findings, reverse_shell_only=True)
        elif fname == 'pyproject.toml':
            if re.search(r'(?:custom_build|build-backend\s*=\s*["\'](?!setuptools\.build_meta|flit_core|hatchling|poetry\.core|maturin)[^"\']+["\'])', content):
                ev = Evidence(file=path, line=1, snippet=content[:400], detail='Non-standard or custom build backend in pyproject.toml')
                findings.append(finding('PYTHON_BUILD_HOOK', 'Python build configuration specifies a custom build hook', 'Installation', 'medium', 'medium', ev.detail, 'pyproject.toml configures a custom or non-standard build backend that runs during wheel building.', 'Custom build backends execute arbitrary Python code during pip build.', 'Verify the build-system backend in pyproject.toml before building from source.', [ev]))

        # 3. Pre-compiled native binaries or shared libraries — PKG-NATIVE-001, INC-018 Miasma/Hades
        if suffix in BINARY_EXTENSIONS or content.startswith(('\x7fELF', 'MZ\x90\x00', '\xcf\xfa\xed\xfe', '\x00asm')):
            ev = Evidence(file=path, line=1, snippet=f'Binary artifact: {path}', detail=f'Bundled native binary or shared object ({p.name})')
            findings.append(finding('NATIVE_BINARY', 'Bundles a pre-compiled native binary or shared library', 'Binary artifact', 'medium', 'high', ev.detail, 'The package contains a pre-compiled native addon, executable, or shared library that cannot be inspected by JavaScript/Python AST parsers.', 'Compiled binaries (.node, .so, .dll, .pyd, .exe) can conceal C2 payloads, credential stealers, or rootkits (such as the Miasma/Hades native wheel attacks).', 'Verify the provenance of the native binary and inspect it with binary analysis tools before execution.', [ev]))

        # 4. AI / Coding Agent prompt injection in documentation — PKG-AI-001, DET-015
        if suffix == '.md' and PROMPT_INJECTION_RE.search(content):
            ev = Evidence(file=path, line=1, snippet=content[:500], detail=f'Adversarial prompt-injection pattern in {p.name}')
            findings.append(finding('AGENT_PROMPT_INJECTION', 'Contains prompt-injection instructions targeting AI agents', 'AI security', 'medium', 'medium', ev.detail, 'Documentation in this package contains directives structured to hijack AI coding assistants or MCP agents.', 'When an AI agent reads this file during code review or installation, it may follow embedded instructions to run shell commands or leak secrets.', 'Do not allow autonomous coding agents with shell or network access to process untrusted package documentation.', [ev]))

    coverage.append('Static analysis only: no package code was executed. Bounded calls and static local ESM/CommonJS imports are supported; runtime reachability is not proven.')
    coverage.append('Only module initialization and directly invoked function paths are evaluated. Uncalled exported functions, callbacks, loops, and dynamic module resolution may be uninspected.')
    findings.sort(key=lambda f: RANK[f.severity], reverse=True)
    return name, version, findings, dependencies, coverage, count

def assess(findings, coverage_incomplete=False, source_coverage_incomplete=None):
    if source_coverage_incomplete is None:
        source_coverage_incomplete = coverage_incomplete
    behavioral_findings = [f for f in findings if f.domain == 'behavior' and f.rule != 'OSV']
    strongest = max((RANK[f.severity] for f in behavioral_findings), default=0)
    risk = {0:'No elevated signals', 1:'Review suggested', 2:'Review recommended', 3:'High concern', 4:'Critical concern'}[strongest]
    elevated = [f for f in behavioral_findings if RANK[f.severity] == strongest and strongest > 0]
    if elevated:
        suffix = ' Note that source inspection was incomplete; check coverage details.' if source_coverage_incomplete else ''
        rationale = 'Highest-priority evidence: ' + '; '.join(dict.fromkeys(f.title for f in elevated)) + '. This is a review priority, not a malware verdict.' + suffix
    else:
        rationale = 'No elevated signals were detected in the inspected source code. However, source inspection was incomplete; review coverage limitations before making a trust decision.' if source_coverage_incomplete else 'No elevated signals were detected in the inspected content. This does not establish that the package is safe.'
    return risk, rationale
