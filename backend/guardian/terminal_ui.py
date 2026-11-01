"""Dependency-free terminal presentation. Untrusted text never supplies ANSI codes."""
import os
import shutil
import sys
import textwrap
import unicodedata
from collections import Counter


def safe(value):
    return ''.join(c if c.isprintable() and unicodedata.category(c) not in {'Cf','Cs'} else '?' for c in str(value))


class Terminal:
    COLORS = {'brand':'38;2;77;84;215','muted':'90','strong':'1','ALLOW':'32','WARN':'33','BLOCK':'31','REVIEW':'33','critical':'31','high':'31','medium':'33','low':'36','info':'90'}

    def __init__(self, stream=None, color='auto', width=None):
        self.stream = stream if stream is not None else sys.stdout
        self.width = max(24, min(width or shutil.get_terminal_size((80,24)).columns, 110))
        self.interactive = bool(getattr(self.stream,'isatty',lambda:False)())
        self.color = color != 'never' and 'NO_COLOR' not in os.environ and os.getenv('TERM') != 'dumb' and (color=='always' or self.interactive)
        if os.name=='nt' and not (os.getenv('WT_SESSION') or os.getenv('ANSICON')):
            self.color=False

    def paint(self, text, tone='strong'):
        text=safe(text)
        return '\x1b['+self.COLORS.get(tone,'0')+'m'+text+'\x1b[0m' if self.color else text

    def line(self, text='', indent=0, tone=None):
        lines=textwrap.wrap(safe(text),width=self.width-indent,replace_whitespace=False,break_long_words=True,break_on_hyphens=False) or ['']
        return '\n'.join(' '*indent+(self.paint(line,tone) if tone else line) for line in lines)

    def heading(self,title):
        return self.line(title,tone='strong')+'\n'+self.paint('-'*min(self.width,len(title)+6),'muted')

    def banner(self,version):
        if self.width<40:return self.line('DevGuardian / '+version,tone='brand')+'\n'
        shield=['     /\\     ',"  .-'  '-.  ",'  |    / |  ','  | \\/   |  ','   \\    /   ','    \\  /    ','     \\/     ']
        glyphs={
            'D':[' __ ','|  \\','|  |','|  |','|__/'],
            'E':[' ___','|   ','|__ ','|   ','|___'],
            'V':['    ','\\  /','\\  /',' \\/ ','    '],
            'G':[' __ ','/   ','| __','|  |','\\__/'],
            'U':['    ','|  |','|  |','|  |','\\__/'],
            'A':[' /\\ ','/  \\','|__|','|  |','|  |'],
            'R':[' __ ','|  \\','|__/','| \\ ','|  \\'],
            'I':[' ___','  | ','  | ','  | ',' _|_'],
            'N':['    ','|\\ |','| \\|','|  |','|  |'],
        }
        word=[' '.join(glyphs[c][i] for c in 'DEVGUARDIAN') for i in range(5)]
        right=['DevGuardian  /  '+safe(version)]+word+['Local analysis. Deliberate decisions.'] if self.width>=72 else ['DevGuardian','v'+safe(version),'','Local package','security.','','']
        lines=[]
        for left,label in zip(shield,right):
            # The icon's exact indigo background and white shield strokes.
            icon='\x1b[48;2;77;84;215m\x1b[97m'+left+'\x1b[0m' if self.color else left
            lines.append(icon+'  '+(self.paint(label,'brand') if self.width>=72 else self.paint(label)))
        return '\n'+'\n'.join(lines)+'\n'

    def account(self,command,result):
        if command=='devices':
            lines=[self.heading('DevGuardian / Devices')]
            if not result:lines.append(self.line('No devices yet. Run guardian login.'))
            for device in result:
                lines.extend(['',self.line(device['device_name'],tone='strong'),self.line(device['id'],indent=2),self.line(device['operating_system']+' / CLI '+device.get('cli_version','unknown'),indent=2),self.line('Status: '+('Revoked' if device.get('revoked_at') else 'Authorized'),indent=2)])
                if device.get('last_seen_at'):lines.append(self.line('Last seen: '+device['last_seen_at'],indent=2))
            return '\n'.join(lines)
        if result.get('status')=='synchronized':
            return '\n'.join([self.heading('DevGuardian / Sync'),self.line(f"Synchronized {result['count']} report(s).",tone='ALLOW'),self.line('Source snippets withheld. Local reports preserved.',tone='muted')])
        lines=[self.heading('DevGuardian / '+('Signed out' if command=='logout' else 'Status'))]
        for label,key in [('Authentication','authentication'),('Account','account'),('Device','device'),('Report sync','report_sync')]:
            value=result.get(key)
            if isinstance(value,dict):value=value.get('device_name') or value.get('email') or value.get('display_name') or value.get('id')
            if value:lines.append(self.line(label+': '+str(value)))
        if not result.get('report_sync'):lines.append(self.line('Report sync: Sign in with guardian login'))
        lines.append(self.line('Automatic synchronization: disabled',tone='muted'))
        return '\n'.join(lines)


def report_text(report,verbose=False,color='auto',width=None):
    ui=Terminal(color=color,width=width)
    cli=report.cli or {};decision=cli.get('decision',{});verdict=decision.get('decision','REVIEW')
    lines=[ui.heading('DevGuardian / Security report'),ui.line(report.name+'@'+report.version,tone='strong'),ui.line('Decision: '+verdict,tone=verdict),ui.line('Behavioral assessment: '+report.risk)]
    if cli.get('location_count'):
        lines.extend([ui.line(f"Found {cli['location_count']} installation locations."),ui.line(f"Found {cli['unique_artifacts']} unique package artifacts.")])
    if cli.get('packages'):
        lines.extend(['',ui.heading('Packages')])
        for p in cli['packages']:lines.append(ui.line(p['decision']+'  '+p['identity'],indent=2,tone=p['decision']))
    for reason in dict.fromkeys(decision.get('reasons',[])+decision.get('review_reasons',[])):
        lines.append(ui.line('- '+reason,indent=2))
    lines.extend(['',ui.heading('Findings')])
    shown=0
    for f in report.findings:
        if f.severity=='info' and not verbose:continue
        shown+=1
        lines.extend(['',ui.line(f.severity.upper()+' / '+f.confidence+' confidence / '+f.title,tone=f.severity),ui.line((f.package or report.name)+' | '+f.rule,indent=2)])
        for ev in (f.evidence if verbose else f.evidence[:1]):
            lines.append(ui.line(f'{ev.file}:{ev.line}:{ev.column}: {ev.detail}',indent=2))
    if not shown:lines.append(ui.line('No actionable findings reported.' if report.findings else 'No findings reported. Coverage still matters.'))
    info=sum(f.severity=='info' for f in report.findings)
    if info and not verbose:lines.append(ui.line(f'{info} informational finding(s); use --verbose to include them.',tone='muted'))
    status=cli.get('installation',{}).get('status','not attempted')
    counts=Counter(f.severity for f in report.findings)
    lines.extend(['',ui.heading('Summary'),ui.line('Decision: '+verdict,tone=verdict),ui.line('Findings: '+str(len(report.findings))+' total | '+' / '.join(f'{counts[s]} {s}' for s in ('critical','high','medium','low','info'))),ui.line('Source: '+str(report.files_analyzed)+' files analyzed'),ui.line('Vulnerability intelligence: '+report.intelligence)])
    assessments=report.assessments or {}
    if assessments.get('acquisition'):
        lines.append(ui.line('Acquisition: '+assessments['acquisition']['status']))
    if assessments.get('inspection'):
        inspection=assessments['inspection']
        lines.append(ui.line('Source inspection: '+inspection.get('source_status',inspection.get('status','unknown'))))
        if inspection.get('dependency_resolution_status'):
            lines.append(ui.line('Dependency resolution: '+inspection['dependency_resolution_status']))
    if assessments.get('integrity'):
        lines.append(ui.line('Artifact integrity: '+assessments['integrity']['root_status']))
    lock_results=[n.integrity for n in report.inspections if n.integrity and n.integrity.source=='lockfile']
    if lock_results:
        lines.append(ui.line(f'Lockfile integrity: {sum(r.status=="verified" for r in lock_results)}/{len(lock_results)} artifacts verified'))
    if report.root_integrity:lines.append(ui.line('Root integrity: '+report.root_integrity.status))
    if report.inspection_summary:
        s=report.inspection_summary
        lines.append(ui.line(f'Dependencies: {s.inspected}/{s.total} inspected; {s.skipped} skipped; {s.unavailable} unavailable; {s.unresolved} unresolved; {s.integrity_failed} integrity failed; {s.not_attempted} not attempted'))
    lines.append(ui.line('Installation: '+status))
    if cli.get('installation',{}).get('reason'):lines.append(ui.line(cli['installation']['reason'],indent=2))
    if cli.get('overrides'):lines.append(ui.line('Explicit policy override recorded; original decision preserved.',tone='WARN'))
    if report.coverage:
        lines.append(ui.line(f'Coverage notes: {len(report.coverage)}'+('' if verbose else ' (use --verbose for all)')))
        for note in report.coverage if verbose else report.coverage[:2]:lines.append(ui.line('- '+note,indent=2))
    next_step={'BLOCK':'Review the blocking findings before installing.','REVIEW':'Resolve coverage or integrity limitations before installing.','WARN':'Review the warnings before choosing to install.','ALLOW':'No policy blockers found within inspected coverage.'}.get(verdict,'Review the report before installing.')
    lines.extend(['',ui.line('Next: '+next_step),ui.line('No lifecycle scripts or Python build backends were executed by Guardian.',tone='muted'),ui.line('Static analysis cannot prove a package safe.',tone='muted')])
    return '\n'.join(lines)
