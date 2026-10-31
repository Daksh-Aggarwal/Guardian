import json
import re
import subprocess
from pathlib import Path
from uuid import uuid4
from .models import Dependency, Evidence, Finding, DataFlow
from .config import parser_limits

ROOT = Path(__file__).resolve().parents[2]
POPULAR = ['react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'typescript', 'webpack', 'vite', 'next', 'eslint', 'prettier', 'dotenv', 'zod', 'mongoose', 'debug', 'moment', 'cross-env', 'cookie', 'minimist', 'yargs', 'jquery', 'request', 'uuid']
RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

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

def analyze(files, limits=None, timeout=20):
    findings, dependencies, coverage = [], [], []
    name, version = 'Uploaded project', 'unversioned'
    manifests = sorted((p for p in files if Path(p).name in {'package.json', 'package-lock.json'}), key=lambda p: (len(Path(p).parts), Path(p).name != 'package.json', p))
    for index, path in enumerate(manifests):
        try:
            manifest = json.loads(files[path])
            if not isinstance(manifest, dict):
                raise ValueError('Manifest must be an object')
            if index == 0:
                name, version = str(manifest.get('name', name)), str(manifest.get('version', version))
            scripts = manifest.get('scripts', {})
            if not isinstance(scripts, dict):
                raise ValueError('scripts must be an object')
            for stage in ['preinstall', 'install', 'postinstall', 'prepare']:
                command = scripts.get(stage)
                if not command:
                    continue
                if not isinstance(command, str):
                    raise ValueError('Script commands must be strings')
                remote = bool(re.search(r'\b(curl|wget)\b.*https?://', command))
                execution = bool(re.search(r'\|\s*(sh|bash)|\beval\b|\bnode\s+-e', command))
                evidence = Evidence(file=path, line=next((i+1 for i,l in enumerate(files[path].splitlines()) if '"'+stage+'"' in l), 1), snippet=command[:500], detail=stage + ' lifecycle command')
                findings.append(finding('INSTALL_SCRIPT', 'Runs code during installation', 'Installation', 'info', 'high', f'{stage}: {command[:200]}', 'This package can run a command automatically when it is installed. Many legitimate packages do this.', 'The command runs with the permissions of the person installing the package.', 'Review this command and its referenced files before installation. Consider npm install --ignore-scripts.', [evidence]))
                if remote:
                    findings.append(finding('INSTALL_REMOTE', 'Installation downloads a remote payload', 'Execution', 'high' if execution else 'medium', 'high', 'An installation command downloads from a remote URL' + (' and pipes to a shell.' if execution else '.'), 'The installer retrieves code or data from outside the package.' + (' It sends the download directly to a command interpreter.' if execution else ''), 'Remote content can change independently of the package and may run with your permissions.', 'Do not run the installer until you have verified the remote source and command. Prefer a reviewed, pinned artifact.', [evidence]))
            for field in ['dependencies', 'devDependencies', 'optionalDependencies']:
                group = manifest.get(field, {})
                if not isinstance(group, dict):
                    raise ValueError(field + ' must be an object')
                for dep, spec in group.items():
                    if isinstance(spec, str):
                        dependencies.append(Dependency(name=dep, version=spec, direct=True, source=path))
                    elif isinstance(spec, dict) and 'version' in spec:  # lockfile v1
                        dependencies.append(Dependency(name=dep, version=str(spec['version']), direct=False, source=path))
            packages = manifest.get('packages', {})
            if not isinstance(packages, dict):
                raise ValueError('packages must be an object')
            direct_names = set(packages.get('', {}).get('dependencies', {})) if isinstance(packages.get('', {}), dict) else set()
            for location, package in packages.items():
                if location and isinstance(package, dict) and package.get('version'):
                    dep = package.get('name') or location.split('node_modules/')[-1]
                    dependencies.append(Dependency(name=dep, version=str(package['version']), direct=dep in direct_names, source=path))
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError(f'Invalid manifest {path}: {error}')
    if not manifests:
        coverage.append('No npm manifest was found; package identity and dependencies are unknown.')
    unique = {(d.name, d.version): d for d in dependencies}
    dependencies = list(unique.values())
    for dep, path in [(name, manifests[0] if manifests else 'project')] + [(d.name, d.source) for d in dependencies]:
        similar = typo(dep)
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
    else:
        coverage.append('Manifest-only scan: package source behavior has not been inspected.')
    rules = {
        'credential': ('CREDENTIAL_ACCESS', 'Reads environment or credential information', 'Data access', 'info', 'The source accesses environment variables or references a sensitive file.', 'Applications often use this for configuration. It becomes more concerning if private information is sent elsewhere.', 'Check which values are read and whether the package needs them.'),
        'network': ('NETWORK', 'Makes an outbound network request', 'Network', 'info', 'The source makes a network request.', 'Network access is common and is not by itself evidence of harm.', 'Verify that the destination and transmitted data match the package’s purpose.'),
        'exfiltration': ('SENSITIVE_TRANSMISSION', 'Sensitive data reaches a network request', 'Data exposure', 'high', 'Sensitive information appears in the arguments of a network request, directly or through a local variable.', 'This may send secrets outside your computer. Legitimate authentication can have the same pattern; intent and destination require review.', 'Inspect the destination and request payload. Avoid running the package with real credentials until reviewed.'),
        'dynamic': ('DYNAMIC_EXECUTION', 'Builds or runs code dynamically', 'Dynamic code', 'low', 'The source calls eval or constructs a function from data.', 'This can make behavior harder to review. Some legitimate tools also generate code.', 'Inspect the input to the dynamic execution call.'),
        'encoding': ('ENCODED_CONTENT', 'Decodes encoded content', 'Obfuscation', 'info', 'The source decodes base64 or hexadecimal data.', 'Encoding is common for data handling. Decoding followed by code execution deserves closer inspection.', 'Review the decoded content without executing it.'),
        'execution': ('PROCESS_EXECUTION', 'Starts an operating-system process', 'Execution', 'low', 'The source calls a child-process API.', 'The new process can act with the caller’s permissions. Build tools commonly do this.', 'Review the command and inputs, especially input supplied by others.'),
        'remote': ('REMOTE_PAYLOAD', 'Downloads a payload through a shell', 'Execution', 'medium', 'A child-process command uses curl or wget with a remote URL.', 'The remote content may change and could contain executable code.', 'Verify and pin the remote content; inspect whether it is subsequently executed.'),
        'filesystem': ('FILESYSTEM', 'Reads or writes local files', 'Data access', 'info', 'The source uses a file-system API.', 'File access is ordinary but can expose or modify sensitive files depending on the path.', 'Check the paths and whether access is necessary.'),
    }
    count = 0
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
            else:
                grouped.setdefault(kind, []).append(evidence)
        if len(item['events']) >= 250:
            coverage.append(f"Evidence capped at 250 observations in {item['file']}.")
        for kind, evidence in grouped.items():
            if kind not in rules:
                continue
            rule, title, category, severity, explanation, implication, action = rules[kind]
            findings.append(finding(rule, title, category, severity, 'high', evidence[0].detail, explanation, implication, action, evidence[:12]))
        if any(e['kind'] == 'encoded-execution' for e in item['events']):
            findings.append(finding('OBFUSCATED_EXECUTION', 'Decoded content reaches dynamic execution', 'Obfuscation', 'medium', 'medium', 'A decoded value is passed to eval or a Function constructor.', 'A static value connection links decoding to dynamic code execution.', 'This may conceal behavior, but can also be legitimate. Runtime execution has not been proven.', 'Inspect the decoded input without executing it.', grouped.get('encoding', [])[:3] + grouped.get('dynamic', [])[:3]))
    coverage.append('Static analysis only: no package code was executed. Bounded calls and static local ESM/CommonJS imports are supported; runtime reachability is not proven.')
    coverage.append('Only module initialization and directly invoked function paths are evaluated. Uncalled exported functions, callbacks, loops, and dynamic module resolution may be uninspected.')
    findings.sort(key=lambda f: RANK[f.severity], reverse=True)
    return name, version, findings, dependencies, coverage, count

def assess(findings, coverage_incomplete=False):
    findings = [f for f in findings if f.domain == 'behavior' and f.rule != 'OSV']
    strongest = max((RANK[f.severity] for f in findings), default=0)
    risk = {0:'No elevated signals', 1:'Review suggested', 2:'Review recommended', 3:'High concern', 4:'Critical concern'}[strongest]
    elevated = [f for f in findings if RANK[f.severity] == strongest and strongest > 0]
    if elevated:
        suffix = ' Note that dependency or source coverage was incomplete; check coverage details.' if coverage_incomplete else ''
        rationale = 'Highest-priority evidence: ' + '; '.join(dict.fromkeys(f.title for f in elevated)) + '. This is a review priority, not a malware verdict.' + suffix
    else:
        rationale = 'No elevated signals were detected in the inspected source code. However, dependency inspection or source coverage was incomplete; review coverage limitations before making a trust decision.' if coverage_incomplete else 'No elevated signals were detected in the inspected content. This does not establish that the package is safe.'
    return risk, rationale
