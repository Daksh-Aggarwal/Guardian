"""Presentation contracts: actual verdicts, clean pipes, bounded layout and inert input."""
import io
import json
import re

import pytest

from backend.guardian import cli, local_reports
from backend.guardian.terminal_ui import Terminal, report_text
from backend.tests.test_accounts import report


class TTY(io.StringIO):
    def isatty(self):return True


def test_icon_palette_and_banner_modes(monkeypatch):
    monkeypatch.delenv('NO_COLOR',raising=False);monkeypatch.setenv('TERM','xterm-256color')
    monkeypatch.setenv('WT_SESSION','test')
    ui=Terminal(TTY(),width=80)
    art=ui.banner('0.2.0')
    assert 'DevGuardian' in art and '48;2;77;84;215' in art and '\x1b[97m' in art
    assert '\\/' in art
    monkeypatch.setenv('NO_COLOR','')
    assert '\x1b' not in Terminal(TTY(),color='always').banner('0.2.0')
    monkeypatch.delenv('NO_COLOR');monkeypatch.setenv('TERM','dumb')
    assert '\x1b' not in Terminal(TTY(),color='always').banner('0.2.0')
    assert '\x1b' not in Terminal(io.StringIO()).banner('0.2.0')


@pytest.mark.parametrize('width',[24,40,60,72,80,110])
def test_banner_and_reports_fit_narrow_terminals(width):
    r=report();r.name='extremely-long-package-name-'*8
    output=report_text(r,True,color='never',width=width)
    assert max(map(len,output.splitlines()))<=width
    art=Terminal(io.StringIO(),width=width).banner('0.2.0')
    assert max(map(len,art.splitlines()))<=width
    assert 'Decision: BLOCK' in output and 'Summary' in output


def test_summary_preserves_finding_counts_coverage_and_failed_override():
    r=report();r.cli['overrides']=[{'force':True,'decision':'BLOCK'}]
    r.cli['installation']={'status':'failed','reason':'disk full'}
    before=r.model_dump_json()
    output=report_text(r,color='never',width=110)
    assert '1 high' in output and '0 critical' in output
    assert 'Installation: failed' in output and 'disk full' in output
    assert 'original decision preserved' in output and 'Decision: BLOCK' in output
    assert 'source incomplete' in output and 'Vulnerability intelligence: not checked' in output
    assert r.model_dump_json()==before


def test_untrusted_evidence_cannot_inject_ansi_even_when_color_enabled(monkeypatch):
    monkeypatch.delenv('NO_COLOR',raising=False);monkeypatch.setenv('TERM','xterm');monkeypatch.setenv('WT_SESSION','test')
    r=report();r.findings[0].title='evil\x1b]52;c;clipboard\x07\r\u202eattack'
    output=report_text(r,color='always')
    clean=re.sub(r'\x1b\[[0-9;]*m','',output)
    assert '\x1b' not in clean and '\x07' not in clean and '\r' not in clean and '\u202e' not in clean


def test_json_is_clean_even_with_forced_banner_and_color(monkeypatch,tmp_path,capsys):
    monkeypatch.setenv('GUARDIAN_HOME',str(tmp_path));local_reports.save(report())
    assert cli.main(['--banner','--color','always','report','--json'])==0
    result=capsys.readouterr()
    assert json.loads(result.out)['cli']['decision']['decision']=='BLOCK'
    assert '\x1b' not in result.out and 'DevGuardian' not in result.out and not result.err


def test_report_plain_mode_and_account_text_are_safe(monkeypatch,tmp_path,capsys):
    monkeypatch.setenv('GUARDIAN_HOME',str(tmp_path));local_reports.save(report())
    assert cli.main(['report','--no-color','--no-banner'])==0
    output=capsys.readouterr().out
    assert 'Summary' in output and '\x1b' not in output and '/\\' not in output
    account=Terminal(color='never').account('status',{'authentication':'Connected','account':'user\x1b[2J','device':{'device_name':'terminal\rspoof'}})
    assert '\x1b' not in account and '\r' not in account


def test_presentation_flags_work_before_and_after_subcommand():
    for argv in (['--no-color','status'],['status','--no-color'],['--no-banner','status'],['status','--no-banner']):
        args=cli.parser().parse_args(argv)
        assert args.color=='never' if '--no-color' in argv else args.banner is False


def test_no_arguments_shows_help_without_scanning(capsys):
    assert cli.main([])==0
    assert 'usage: guardian' in capsys.readouterr().out


@pytest.mark.parametrize('verdict',['ALLOW','WARN','BLOCK','REVIEW'])
def test_summary_keeps_actual_decision_without_safety_claims(verdict):
    r=report();r.cli['decision']['decision']=verdict;r.findings=[]
    output=report_text(r,color='never')
    assert output.count('Decision: '+verdict)==2
    assert 'Coverage still matters' in output and 'cannot prove a package safe' in output


def test_banner_is_occasional_and_json_always_wins(monkeypatch,tmp_path):
    from backend.guardian.connected import AccountClient
    monkeypatch.setenv('GUARDIAN_HOME',str(tmp_path))
    monkeypatch.setattr(AccountClient,'login',lambda *a,**kw:{'authentication':'Connected'})
    monkeypatch.setattr(AccountClient,'status',lambda *a,**kw:{'authentication':'Local'})
    output=TTY();monkeypatch.setattr('sys.stdout',output)
    assert cli.main(['login'])==0
    assert output.getvalue().count('Local analysis. Deliberate decisions.')==1
    output.seek(0);output.truncate(0)
    assert cli.main(['status'])==0
    assert 'Deliberate decisions' not in output.getvalue()
    output.seek(0);output.truncate(0)
    assert cli.main(['login','--no-banner'])==0
    assert 'Deliberate decisions' not in output.getvalue()
    output.seek(0);output.truncate(0)
    assert cli.main(['login','--json','--banner'])==0
    assert json.loads(output.getvalue())['authentication']=='Connected'


def test_json_errors_ignore_presentation_flags(capsys):
    assert cli.main(['login','--offline','--json','--banner','--color','always'])==cli.EXIT_ACQUIRE
    captured=capsys.readouterr()
    assert json.loads(captured.out)['exit_code']==cli.EXIT_ACQUIRE
    assert '\x1b' not in captured.out and not captured.err
