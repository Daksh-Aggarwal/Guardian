"""Guardian local CLI. Account uploads require explicit sync; installers receive only approved plans."""
import argparse
import hashlib
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from .environment import load_environment

load_environment()

from . import local_reports
from .core import analyze_plan
from .ingestion import EXTENSIONS, MAX_FILE, MAX_FILES, MAX_EXPANDED
from .terminal_ui import Terminal, report_text, safe
from .policy import Policy
from .supply_models import Artifact, Plan, AcquisitionError, IntegrityError, InstallError

VERSION = '0.2.0'
# Stable exit codes: security block, review, acquisition, integrity, internal, install.
EXIT_BLOCK, EXIT_REVIEW, EXIT_ACQUIRE, EXIT_INTEGRITY, EXIT_INTERNAL, EXIT_INSTALL = 2, 3, 4, 5, 6, 7

@contextmanager
def installation_guard(project):
    path = project / '.guardian-install.lock'
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise InstallError('Another Guardian installation holds .guardian-install.lock. If a prior process crashed, verify it has stopped before removing that lock.') from error
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        path.unlink()


def presentation_options(parser, root=False):
    default='auto' if root else argparse.SUPPRESS
    parser.add_argument('--color', choices=('auto','always','never'), default=default, help='Terminal color mode (NO_COLOR is respected).')
    parser.add_argument('--no-color', dest='color', action='store_const', const='never', default=argparse.SUPPRESS, help='Disable terminal colors.')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--banner', action='store_true', default=None if root else argparse.SUPPRESS, help='Show the DevGuardian ASCII banner.')
    group.add_argument('--no-banner', dest='banner', action='store_false', default=argparse.SUPPRESS, help='Suppress the welcome banner.')


def parser():
    result = argparse.ArgumentParser(prog='guardian', description='Local npm + PyPI pre-installation static security analysis.')
    result.add_argument('--version', action='version', version='DevGuardian ' + VERSION)
    presentation_options(result,root=True)
    commands = result.add_subparsers(dest='command', required=True)
    for command in ('install', 'check', 'audit', 'report', 'login', 'logout', 'status', 'sync', 'devices'):
        sub = commands.add_parser(command)
        presentation_options(sub)
        if command in ('install', 'check'):
            sub.add_argument('packages', nargs='*')
        if command == 'login':
            sub.add_argument('--allow-file-credentials', action='store_true', help='Explicitly use private plaintext credentials instead of the OS keychain.')
            sub.add_argument('--no-browser', action='store_true', help='Print the login URL for manual opening.')
            sub.add_argument('--device-name', help='Name shown in the account dashboard.')
            sub.add_argument('--new-device', action='store_true', help='Create a new device identity when switching accounts.')
        if command == 'devices':
            sub.add_argument('--revoke', metavar='DEVICE_ID', help='Revoke one of your registered devices.')
        if command == 'report':
            sub.add_argument('--sync', action='store_true', help='Explicitly synchronize the latest sanitized report.')
        sub.add_argument('--ecosystem', choices=('npm', 'pypi'))
        sub.add_argument('--json', action='store_true', help='Emit only a JSON report or error.')
        sub.add_argument('--output', type=Path, help='Export JSON to this file (private permissions).')
        sub.add_argument('--no-sync', action='store_true', help='Keep reports local (also the default).')
        sub.add_argument('--offline', action='store_true', help='Inspect local artifacts or project source; do not access registries.')
        sub.add_argument('--force', action='store_true', help='Explicitly override findings only; integrity/coverage failures remain non-overridable.')
        sub.add_argument('--yes', action='store_true', help='Acknowledge WARN or an explicit --force findings override.')
        sub.add_argument('--verbose', action='store_true', help='Include coverage limitations in terminal output.')
        sub.add_argument('--policy', type=Path, help='Explicit JSON installation policy file.')
    return result


def ecosystem(project, explicit, specs):
    prefixes = {s.split(':', 1)[0] for s in specs if s.startswith(('npm:', 'pypi:'))}
    if len(prefixes) > 1 or (explicit and prefixes and explicit not in prefixes):
        raise AcquisitionError('Mixed ecosystems require separate commands.')
    if explicit or prefixes:
        return explicit or next(iter(prefixes))
    detected = []
    if (project / 'package.json').is_file():
        detected.append('npm')
    if any((project / n).is_file() for n in ('pyproject.toml', 'requirements.txt', 'poetry.lock', 'Pipfile')):
        detected.append('pypi')
    if len(detected) != 1:
        raise AcquisitionError('Ecosystem is ambiguous. Select --ecosystem npm or --ecosystem pypi (or use npm:/pypi: prefix).')
    return detected[0]


def project_artifact(project, eco):
    files, size = {}, 0
    excluded = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', '.next', '.guardian', '.aws', '.ssh'}
    for root, directories, names in os.walk(project, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in excluded and not (Path(root) / d).is_symlink())
        for name in sorted(names):
            path = Path(root) / name
            relative = path.relative_to(project).as_posix()
            if (path.is_symlink() or name.startswith('.env') or name in {'.npmrc', '.pypirc', '.netrc', '.git-credentials'}
                    or name.startswith(('id_rsa', 'id_ed25519')) or path.suffix in {'.pem', '.key', '.p12', '.pfx'} or path.suffix not in EXTENSIONS):
                continue
            if path.stat().st_size > MAX_FILE or len(files) >= MAX_FILES:
                raise AcquisitionError('Project exceeds bounded local source limits; use a smaller project.')
            data = path.read_bytes()
            size += len(data)
            if len(data) > MAX_FILE or size > MAX_EXPANDED:
                raise AcquisitionError('Project source exceeds expanded size limit.')
            try:
                files[relative] = data.decode('utf-8')
            except UnicodeDecodeError:
                raise AcquisitionError('Project contains a non-UTF-8 source file; inspection is incomplete.')
    if not files:
        raise AcquisitionError('No supported local project source files found.')
    raw = json.dumps(files, sort_keys=True).encode()
    return Artifact(eco, project.name, 'local', project.name, raw, files,
                    hashlib.sha256(raw).hexdigest(), False, kind='project')


def terminal(report, verbose=False, color='auto', width=None):
    return report_text(report,verbose,color,width)


def emit(report, args):
    target = local_reports.save(report)
    if args.output:
        local_reports.write_private(args.output, report.model_dump_json(indent=2))
    if args.json:
        print(report.model_dump_json())
    else:
        print(terminal(report, args.verbose, args.color))
        print(Terminal(color=args.color).line(f'Report saved locally: {target}',tone='muted'))


def execute(args):
    if args.command in ('login', 'logout', 'status', 'devices', 'sync') or (args.command == 'report' and args.sync):
        from .connected import AccountClient, saved_reports
        if args.offline and args.command != 'status':
            raise AcquisitionError('This account operation requires network access; local check/audit/report still work offline.')
        if args.no_sync and (args.command == 'sync' or getattr(args, 'sync', False)):
            raise AcquisitionError('Choose synchronization or --no-sync, not both.')
        client = AccountClient(getattr(args,'allow_file_credentials',False),getattr(args,'new_device',False))
        if args.command == 'login':
            result=client.login(VERSION,args.no_browser,args.device_name)
        elif args.command == 'logout':
            result=client.logout()
        elif args.command == 'status':
            result=client.status(args.offline)
        elif args.command == 'devices':
            result=client.devices(args.revoke)
        elif args.command == 'report':
            report=local_reports.latest()
            if args.output: local_reports.write_private(args.output,report.model_dump_json(indent=2))
            result=client.sync([report])
        else:
            result=client.sync(saved_reports())
        if args.json:
            print(json.dumps(result))
        else:
            print(Terminal(color=args.color).account(args.command,result))
        return 0
    if args.command == 'report':
        report = local_reports.latest()
        if args.output:
            local_reports.write_private(args.output, report.model_dump_json(indent=2))
        print(report.model_dump_json() if args.json else terminal(report, args.verbose, args.color))
        return 0
    project = Path.cwd()
    specs = getattr(args, 'packages', [])
    eco = ecosystem(project, args.ecosystem, specs)
    specs = [s.split(':', 1)[1] if s.startswith(('npm:', 'pypi:')) else s for s in specs]
    if eco == 'npm':
        from . import npm_adapter as adapter
    else:
        from . import pypi_adapter as adapter
    local = [Path(s) for s in specs if Path(s).is_file()]
    if local:
        if len(local) != len(specs) or args.command == 'install':
            raise AcquisitionError('Local artifact inputs support check only; installation requires a verified registry plan.')
        artifacts = [adapter.acquire_local(p) for p in local]
        plan = Plan(eco, artifacts, [a.identity for a in artifacts], complete=False,
                    limitations=['Local artifact dependency graph and registry provenance are not verified.'])
    elif args.command == 'audit' and args.offline:
        artifact = project_artifact(project, eco)
        plan = Plan(eco, [artifact], [artifact.identity], complete=False,
                    limitations=['Offline audit inspects project source only; dependencies and registry integrity are unverified.'])
    else:
        if args.command == 'check' and not specs:
            raise AcquisitionError('Specify a package or local artifact; use guardian audit for the current project.')
        if not args.json:
            print(Terminal(sys.stderr,args.color).line(f'[resolve] Resolving and acquiring {eco} dependencies...',tone='brand'),file=sys.stderr)
        plan = adapter.resolve(specs, project, offline=args.offline)
        if args.command == 'audit':
            artifact = project_artifact(project, eco)
            # Local project provenance is disclosed; its code still participates in policy.
            plan.artifacts.insert(0, artifact)
    if not args.json:
        print(Terminal(sys.stderr,args.color).line(f'[scan] Analysing {len(plan.artifacts)} unique artifacts...',tone='brand'),file=sys.stderr)
    report = analyze_plan(plan, Policy.load(args.policy) if args.policy else None)
    decision = report.cli['decision']
    result = 0
    if decision['decision'] == 'BLOCK':
        result = EXIT_BLOCK
    elif decision['decision'] in ('WARN', 'REVIEW'):
        result = EXIT_REVIEW
    if args.command == 'install':
        allowed = decision['decision'] == 'ALLOW'
        if decision['overridable'] and ((decision['decision'] == 'WARN' and args.yes) or (args.force and args.yes)):
            allowed = True
            report.cli['overrides'].append({'decision': decision['decision'], 'force': args.force,
                                            'acknowledged': True, 'timestamp': report.created_at})
        if allowed:
            # Persist the approval before any mutation; failed installs also remain auditable.
            report.cli['installation'] = {'status': 'approved'}
            local_reports.save(report)
            try:
                with installation_guard(project):
                    adapter.install(plan, project)
                report.cli['installation'] = {'status': 'installed', 'artifact_sha256': [a.sha256 for a in plan.artifacts]}
                result = 0
            except (InstallError, AcquisitionError, OSError) as error:
                report.cli['installation'] = {'status': 'failed', 'reason': str(error)}
                result = EXIT_INTEGRITY if isinstance(error, IntegrityError) else EXIT_INSTALL
        else:
            report.cli['installation'] = {'status': 'blocked before installation'}
    emit(report, args)
    return result


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    command_parser=parser()
    if not argv:
        if Terminal().interactive:print(Terminal().banner(VERSION))
        command_parser.print_help()
        return 0
    if ('--help' in argv or '-h' in argv) and '--json' not in argv and '--no-banner' not in argv:
        mode='auto'
        for i,argument in enumerate(argv):
            if argument=='--no-color':mode='never'
            elif argument.startswith('--color='):mode=argument.split('=',1)[1]
            elif argument=='--color' and i+1<len(argv):mode=argv[i+1]
        if Terminal().interactive or '--banner' in argv:print(Terminal(color=mode).banner(VERSION))
    args = command_parser.parse_args(argv)
    if not args.json and (args.banner is True or (args.banner is None and args.command=='login' and Terminal().interactive)):
        print(Terminal(color=args.color).banner(VERSION))
    try:
        return execute(args)
    except (IntegrityError, AcquisitionError, InstallError, ValueError, OSError) as error:
        code = EXIT_INTEGRITY if isinstance(error, IntegrityError) else (EXIT_INSTALL if isinstance(error, InstallError) else EXIT_ACQUIRE)
        message = str(error)
        diagnostic = error.diagnostic() if isinstance(error, AcquisitionError) else None
        if args.json:
            print(json.dumps({'error': message, 'exit_code': code, **({'diagnostic': diagnostic} if diagnostic else {})}))
        else:
            if diagnostic:
                message = f"[{diagnostic['category']}] " + message
                if diagnostic.get('package'):
                    message += ' Package: ' + diagnostic['package'] + '.'
                if 'limit' in diagnostic:
                    message += f" Limit: {diagnostic['limit']}; encountered: {diagnostic.get('encountered', 'unknown')}."
            ui=Terminal(sys.stderr,args.color)
            print(ui.heading('DevGuardian / Error'),file=sys.stderr)
            print(ui.line(message,tone='BLOCK'),file=sys.stderr)
            if args.verbose and diagnostic:
                for key, value in diagnostic.items():
                    clean = safe(value)
                    print(Terminal(sys.stderr,args.color).line(f'{key}: {clean}',indent=2),file=sys.stderr)
            if isinstance(error, AcquisitionError) and args.command in {'install','check','audit'}:
                print('No installation was attempted.', file=sys.stderr)
        return code
    except Exception as error:
        message = f'Internal error ({type(error).__name__}); installation did not report success.'
        print(json.dumps({'error': message, 'exit_code': EXIT_INTERNAL}) if args.json else 'Guardian: ' + message, file=sys.stderr if not args.json else sys.stdout)
        return EXIT_INTERNAL


if __name__ == '__main__':
    sys.exit(main())
