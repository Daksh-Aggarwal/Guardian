"""Native Python AST static security analyzer for PyPI and Python packages."""
import ast
import re
import time
from pathlib import PurePosixPath
from typing import Dict, List, Tuple
from .models import Evidence, Finding, DataFlow, FlowStep
from .engine import finding, distance

POPULAR_PYPI = [
    'requests', 'urllib3', 'numpy', 'pandas', 'scipy', 'matplotlib',
    'flask', 'django', 'fastapi', 'pydantic', 'boto3', 'botocore',
    'pytest', 'setuptools', 'wheel', 'pip', 'virtualenv', 'black',
    'cryptography', 'sqlalchemy', 'jinja2', 'click', 'rich', 'tqdm',
    'celery', 'redis', 'pillow', 'psycopg2', 'beautifulsoup4', 'lxml',
    'scikit-learn', 'torch', 'tensorflow', 'httpx', 'aiohttp', 'pytz'
]

SENSITIVE_PATHS = {
    '.env', '.aws/credentials', '.ssh/id_rsa', '/etc/shadow', '/etc/passwd'
}

RULES = {
    'credential': (
        'CREDENTIAL_ACCESS',
        'Reads environment or credential information',
        'Data access',
        'info',
        'The Python source accesses environment variables or references a sensitive file.',
        'Applications often use this for configuration. It becomes more concerning if private information is transmitted elsewhere.',
        'Check which values are read and whether the package needs them.'
    ),
    'network': (
        'NETWORK',
        'Makes an outbound network request',
        'Network',
        'info',
        'The Python source makes a network request using requests, urllib, httpx, or socket.',
        'Network access is common and is not by itself evidence of harm.',
        'Verify that the destination and transmitted data match the package’s purpose.'
    ),
    'exfiltration': (
        'SENSITIVE_TRANSMISSION',
        'Sensitive data reaches a network request',
        'Data exposure',
        'high',
        'Sensitive information (environment variables or credentials) appears in the arguments of a network request.',
        'This may send secrets outside your computer. Verify the destination and intended use before running.',
        'Inspect the destination and request payload. Avoid running the package with real credentials until reviewed.'
    ),
    'dynamic': (
        'DYNAMIC_EXECUTION',
        'Builds or runs code dynamically',
        'Dynamic code',
        'low',
        'The Python source calls eval(), exec(), compile(), or __import__().',
        'Dynamic code execution can make behavior harder to review and may conceal malicious payloads.',
        'Inspect the input passed to the dynamic execution call.'
    ),
    'encoding': (
        'ENCODED_CONTENT',
        'Decodes encoded content',
        'Obfuscation',
        'info',
        'The source decodes base64, hex, or compressed data.',
        'Encoding is common for binary asset handling, but decoding followed by code execution deserves closer inspection.',
        'Review the decoded content without executing it.'
    ),
    'obfuscated_execution': (
        'OBFUSCATED_EXECUTION',
        'Decoded content reaches dynamic execution',
        'Obfuscation',
        'medium',
        'A decoded or decompressed value is passed directly to exec() or eval().',
        'This pattern is frequently used to conceal executable payloads from static code scanners.',
        'Inspect the decoded input without executing it. Do not install until validated.'
    ),
    'execution': (
        'PROCESS_EXECUTION',
        'Starts an operating-system process',
        'Execution',
        'low',
        'The Python source calls subprocess APIs or os.system/popen.',
        'The spawned process can execute commands with the caller’s local permissions.',
        'Review the command line, especially if any parts are built from external input.'
    ),
    'filesystem': (
        'FILESYSTEM',
        'Reads or writes local files',
        'Data access',
        'info',
        'The source uses file-system APIs (open, os.remove, shutil).',
        'File access is ordinary but can expose or modify sensitive files depending on the path.',
        'Check file paths and verify whether file modifications are expected.'
    ),
    'install_script': (
        'INSTALL_SCRIPT',
        'Runs code during package setup',
        'Installation',
        'info',
        'setup.py executes processes or network requests at installation time.',
        'Installation commands execute automatically with user privileges when installing via pip.',
        'Review setup.py lifecycle scripts before installing.'
    ),
}

def typo_pypi(name: str):
    if not name or name in POPULAR_PYPI:
        return None
    normalized = name.lower().translate(str.maketrans({'0': 'o', '1': 'l', '3': 'e', '5': 's'}))
    return next((p for p in POPULAR_PYPI if len(p) >= 4 and (distance(name.lower(), p) == 1 or normalized == p)), None)

def _get_call_name(node: ast.Call) -> str:
    """Helper to extract dotted call path (e.g. 'requests.post', 'os.getenv', 'subprocess.run')."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = [node.func.attr]
        curr = node.func.value
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return '.'.join(reversed(parts))
    return ''


def _direct_environment_source(node):
    """Recognize an actual environment expression within a network argument.

    This deliberately does not correlate an unrelated environment read elsewhere
    in the module with a public network request.
    """
    if isinstance(node, ast.Attribute):
        return isinstance(node.value, ast.Name) and node.value.id == 'os' and node.attr == 'environ'
    if isinstance(node, ast.Call):
        return _get_call_name(node) in {'os.getenv', 'os.environ.get'}
    return False

class PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, lines: List[str]):
        self.filename = filename
        self.lines = lines
        self.observations = []
        self.env_vars = set()  # Tracks local variables loaded from os.environ / os.getenv
        self.is_setup_file = PurePosixPath(filename).name in ('setup.py', 'setup.cfg')

    def _evidence(self, node: ast.AST, detail: str) -> Evidence:
        line = getattr(node, 'lineno', 1)
        col = getattr(node, 'col_offset', 0) + 1
        snippet = self.lines[line - 1].strip() if 0 <= line - 1 < len(self.lines) else ''
        return Evidence(file=self.filename, line=line, column=col, snippet=snippet[:500], detail=detail[:300])

    def visit_Assign(self, node: ast.Assign):
        # Track if assigning from os.getenv or os.environ to detect exfiltration
        if isinstance(node.value, ast.Call):
            call_name = _get_call_name(node.value)
            if call_name in ('os.getenv', 'os.environ.get') or (isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'getenv'):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.env_vars.add(target.id)
        elif isinstance(node.value, ast.Subscript):
            if isinstance(node.value.value, (ast.Name, ast.Attribute)):
                val_name = _get_call_name(ast.Call(func=node.value.value, args=[], keywords=[]))
                if 'environ' in val_name:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.env_vars.add(target.id)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            val = node.value.strip()
            for sensitive in SENSITIVE_PATHS:
                if sensitive in val:
                    self.observations.append(('credential', self._evidence(node, f'Reference to sensitive path: {val}'), None))
                    break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if len(self.observations) >= 250:
            return
        call_name = _get_call_name(node)

        # 1. Credential Access
        if call_name in ('os.getenv', 'os.environ.get') or call_name.endswith('.getenv'):
            arg_str = ''
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                arg_str = f" ('{node.args[0].value}')"
            self.observations.append(('credential', self._evidence(node, f'Accesses environment variable via {call_name}{arg_str}'), None))

        # 2. Dynamic Execution
        elif call_name in ('eval', 'exec', 'compile', '__import__', 'importlib.import_module'):
            # Check for Obfuscated Execution: eval(base64.b64decode(...)) or exec(base64...)
            has_decode_arg = False
            for arg in node.args:
                if isinstance(arg, ast.Call):
                    nested_name = _get_call_name(arg)
                    if any(dec in nested_name for dec in ('b64decode', 'fromhex', 'decompress', 'decode')):
                        has_decode_arg = True
                        break
            if has_decode_arg:
                self.observations.append(('obfuscated_execution', self._evidence(node, f'Decoded payload passed directly to {call_name}()'), None))
            else:
                self.observations.append(('dynamic', self._evidence(node, f'Dynamic code evaluation with {call_name}()'), None))

        # 3. Encoded Content
        elif any(dec in call_name for dec in ('base64.b64decode', 'base64.urlsafe_b64decode', 'bytes.fromhex', 'codecs.decode', 'zlib.decompress')):
            self.observations.append(('encoding', self._evidence(node, f'Decodes encoded content with {call_name}()'), None))

        # 4. Process Execution
        elif any(proc in call_name for proc in ('subprocess.run', 'subprocess.Popen', 'subprocess.call', 'subprocess.check_call', 'subprocess.check_output', 'os.system', 'os.popen')):
            if self.is_setup_file:
                self.observations.append(('install_script', self._evidence(node, f'setup.py spawns subprocess: {call_name}()'), None))
            self.observations.append(('execution', self._evidence(node, f'Spawns OS child process via {call_name}()'), None))

        # 5. Network Requests
        elif any(net in call_name for net in (
            'requests.get', 'requests.post', 'requests.put', 'requests.delete', 'requests.request', 'requests.patch',
            'urllib.request.urlopen', 'httpx.get', 'httpx.post', 'httpx.Client', 'httpx.AsyncClient',
            'aiohttp.ClientSession', 'socket.socket', 'socket.create_connection'
        )):
            if self.is_setup_file:
                self.observations.append(('install_script', self._evidence(node, f'setup.py initiates network connection: {call_name}()'), None))

            # Exfiltration check: do network arguments reference known environment variables?
            exfil_var = None
            source_node = None
            all_exprs = list(node.args) + [kw.value for kw in node.keywords]
            for expr in all_exprs:
                for sub in ast.walk(expr):
                    if isinstance(sub, ast.Name) and sub.id in self.env_vars:
                        exfil_var = sub.id
                        source_node = sub
                        break
                    if _direct_environment_source(sub):
                        exfil_var = _get_call_name(sub) if isinstance(sub, ast.Call) else 'os.environ'
                        source_node = sub
                        break
                if exfil_var:
                    break

            if exfil_var:
                ev = self._evidence(node, f'Sensitive credential ({exfil_var}) passed to network call {call_name}()')
                source_ev = self._evidence(source_node, f'Credential {exfil_var} read in network argument')
                flow = DataFlow(
                    context='payload',
                    steps=[
                        FlowStep(file=self.filename, line=source_ev.line, column=source_ev.column, snippet=source_ev.snippet, detail=source_ev.detail, kind='source', binding=exfil_var),
                        FlowStep(file=self.filename, line=ev.line, column=ev.column, snippet=ev.snippet, detail=f'Credential passed to {call_name}', kind='sink', binding=call_name)
                    ]
                )
                self.observations.append(('exfiltration', ev, flow))
            else:
                self.observations.append(('network', self._evidence(node, f'Outbound network request via {call_name}()'), None))

        # 6. Filesystem Access
        elif call_name in ('open', 'os.remove', 'os.unlink', 'shutil.rmtree') or call_name.endswith('.write_text') or call_name.endswith('.write_bytes'):
            self.observations.append(('filesystem', self._evidence(node, f'File-system interaction via {call_name}()'), None))

        self.generic_visit(node)

def analyze_python(files: Dict[str, str], timeout: float = 20.0) -> Tuple[List[Finding], List[str], int]:
    """Analyzes a collection of Python source files using native AST parsing."""
    findings = []
    coverage = []
    file_count = 0
    grouped_evidence: Dict[str, List[Evidence]] = {}
    exfiltration_findings = []

    deadline = time.monotonic() + timeout

    for filepath, content in files.items():
        if time.monotonic() > deadline:
            coverage.append('Python AST analyzer reached deadline timeout; analysis was truncated.')
            break
        if not filepath.endswith(('.py', '.pyw')):
            continue

        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError as e:
            coverage.append(f'Could not parse Python source {filepath}: SyntaxError on line {e.lineno}')
            continue
        except Exception as e:
            coverage.append(f'Could not parse Python source {filepath}: {e}')
            continue

        file_count += 1
        lines = content.splitlines()
        visitor = PythonSecurityVisitor(filepath, lines)
        visitor.visit(tree)

        if len(visitor.observations) >= 250:
            coverage.append(f'Evidence capped at 250 observations in {filepath}.')

        for kind, evidence, flow in visitor.observations:
            if kind == 'exfiltration' and flow:
                rule, title, category, severity, explanation, implication, action = RULES[kind]
                f = finding(
                    rule, title, category, severity, 'high', evidence.detail,
                    explanation, implication, action, [evidence]
                )
                f.data_flows = [flow]
                f.limitations = ['Statically inferred path; not proof of runtime execution or malicious intent.']
                exfiltration_findings.append(f)
            else:
                grouped_evidence.setdefault(kind, []).append(evidence)

    # Convert grouped observations into Guardian findings
    for kind, evidences in grouped_evidence.items():
        if kind not in RULES:
            continue
        rule, title, category, severity, explanation, implication, action = RULES[kind]
        f = finding(
            rule, title, category, severity, 'high', evidences[0].detail,
            explanation, implication, action, evidences[:12]
        )
        findings.append(f)

    findings.extend(exfiltration_findings)

    coverage.append('Python AST static analysis only: no package code was executed. Runtime reachability is not proven.')
    return findings, coverage, file_count
