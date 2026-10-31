"""Bounded lockfile graph traversal and per-scan npm retrieval cache."""
import base64
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import quote
from . import ingestion
from .config import Budget
from .integrity import verify
from .models import IntegrityResult, PackageInspection, InspectionSummary, Evidence

EXACT = re.compile(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')
MAX_DISCOVERED = 2000

class BudgetExceeded(ValueError):
    pass

@dataclass
class Retrieved:
    files: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    integrity: IntegrityResult = field(default_factory=IntegrityResult)
    registry_integrity: IntegrityResult = field(default_factory=IntegrityResult)
    metadata: dict = field(default_factory=dict)
    raw: bytes = b''

class RegistrySession:
    """Serial HTTP is intentional: one request per scan, two scans globally."""
    def __init__(self, budget=None):
        self.budget=budget or Budget.from_env()
        self.started=time.monotonic()
        self.requests=0
        self.bytes=0
        self.expanded=0
        self.metadata={}
        self.tarballs={}
        self.errors={}
        self.contents={}

    def remaining(self):
        return self.budget.seconds-(time.monotonic()-self.started)

    def fetch(self,url):
        if self.remaining()<=0 or self.requests>=self.budget.requests or self.bytes>=self.budget.bytes:
            raise BudgetExceeded('Registry time, request, or aggregate download budget reached.')
        self.requests+=1
        data=ingestion.download(url, min(ingestion.MAX_UPLOAD,self.budget.bytes-self.bytes), timeout=min(8,self.remaining()))
        self.bytes+=len(data)
        return data

    def retrieve(self,name,version,expected=None,strict=True):
        ingestion.validate_package(name,version)
        key=(name,version)
        if key in self.errors:
            raise ValueError(self.errors[key])
        try:
            if key not in self.metadata:
                url='https://registry.npmjs.org/'+quote(name,safe='')+'/'+quote(version,safe='')
                metadata=json.loads(self.fetch(url))
                if not isinstance(metadata,dict):raise ValueError('Registry metadata must be an object.')
                if strict and (metadata.get('name')!=name or (EXACT.fullmatch(version) and metadata.get('version')!=version)):
                    raise ValueError('Registry package identity does not match the requested name/version.')
                self.metadata[key]=metadata
            metadata=self.metadata[key]
            dist=metadata.get('dist',{})
            if not isinstance(dist,dict) or not dist.get('tarball'):raise ValueError('No registry tarball is available.')
            if key not in self.tarballs:self.tarballs[key]=self.fetch(dist['tarball'])
            data=self.tarballs[key]
            registry_expected=dist.get('integrity')
            if not registry_expected and isinstance(dist.get('shasum'),str):
                if re.fullmatch(r'[0-9a-fA-F]{40}',dist['shasum']):registry_expected='sha1-'+base64.b64encode(bytes.fromhex(dist['shasum'])).decode()
                else:registry_expected='invalid-shasum'
            result=Retrieved(metadata=metadata,raw=data,integrity=verify(data,expected,'lockfile'),registry_integrity=verify(data,registry_expected,'registry'))
            checks=[result.integrity,result.registry_integrity]
            if any(c.status not in {'missing','verified'} for c in checks):
                result.warnings.append('Integrity verification failed or is unsupported. Tarball was not extracted or analyzed.')
                return result
            if self.remaining()<=0:raise BudgetExceeded('Dependency time budget reached before extraction.')
            if key not in self.contents:
                self.contents[key]=ingestion.archive(data,'tar')
                self.expanded+=sum(len(c.encode('utf-8')) for c in self.contents[key][0].values())
            result.files,cached_warnings=self.contents[key]
            result.warnings=list(cached_warnings)
            if self.expanded>self.budget.expanded:raise BudgetExceeded('Aggregate extracted source budget reached.')
            if result.integrity.status=='missing':result.warnings.append('Lockfile integrity is missing; no lockfile digest was verified.')
            if result.registry_integrity.status=='missing':result.warnings.append('Registry integrity is missing; published bytes could not be verified.')
            return result
        except BudgetExceeded:
            raise
        except Exception as error:
            self.errors[key]=str(error) if isinstance(error,ValueError) else 'Registry download unavailable or timed out.'
            raise ValueError(self.errors[key]) from error


def declarations(value):
    out={}
    for key in ('dependencies','devDependencies','optionalDependencies'):
        if isinstance(value.get(key),dict):out.update(value[key])
    return out


def lock_graph(files):
    """Resolve lockfile locations with Node's nearest node_modules lookup."""
    warnings=[]
    paths=sorted((p for p in files if PurePosixPath(p).name=='package-lock.json'),key=lambda p:(len(PurePosixPath(p).parts),p))
    if not paths:
        manifests=sorted((p for p in files if PurePosixPath(p).name=='package.json'),key=lambda p:(len(PurePosixPath(p).parts),p))
        root=json.loads(files[manifests[0]]) if manifests else {}
        nodes=[PackageInspection(name=n,version=str(v),location='manifest:'+n,direct=True,status='unresolved',reason='No lockfile exact resolution available.') for n,v in list(declarations(root).items())[:MAX_DISCOVERED]]
        return nodes,{},['No modern lockfile: declared dependency source is uninspected.'] if nodes else []
    path=paths[0]; lock=json.loads(files[path]); packages=lock.get('packages')
    if not isinstance(packages,dict):
        return [],{},['Lockfile v1 has no modern packages graph; recursive inspection is unavailable.']
    if len(paths)>1:warnings.append('Only the shallowest package-lock.json graph is inspected; other project lockfiles are uninspected.')
    if len(packages)>MAX_DISCOVERED+1:warnings.append(f'Dependency graph inventory capped at {MAX_DISCOVERED} locations.')
    records={loc:p for loc,p in list(packages.items())[:MAX_DISCOVERED+1] if loc and isinstance(p,dict)}
    root=packages.get('',{})
    if not root:
        manifest_path=str(PurePosixPath(path).parent/'package.json')
        root=json.loads(files[manifest_path]) if manifest_path in files else {}
    def resolve(parent,name):
        current=parent
        while True:
            candidate=(current+'/' if current else '')+'node_modules/'+name
            if candidate in records:return candidate
            if not current:break
            current=current.rsplit('/node_modules/',1)[0] if '/node_modules/' in current else ''
        return None
    nodes={loc:PackageInspection(name=p.get('name') or loc.split('node_modules/')[-1],version=str(p.get('version','unresolved')),location=loc,direct=False,status='unresolved',reason='Not reachable from the root dependency declarations.') for loc,p in records.items()}
    queue=deque(); seen=set(); expected={}
    for name,spec in declarations(root).items():
        loc=resolve('',name)
        if loc:
            nodes[loc].direct=True;queue.append((loc,1))
        else:
            loc='unresolved:'+name
            nodes[loc]=PackageInspection(name=name,version=str(spec),location=loc,direct=True,status='unresolved',reason='Root dependency has no matching lockfile entry.')
    while queue:
        loc,depth=queue.popleft()
        if loc in seen:continue
        seen.add(loc);node=nodes[loc];node.depth=depth;entry=records[loc]
        expected[loc]=entry.get('integrity')
        node.integrity=IntegrityResult(expected=entry.get('integrity') if isinstance(entry.get('integrity'),str) else None,source='lockfile')
        if entry.get('link') or not EXACT.fullmatch(node.version):
            node.status='unresolved';node.reason='Workspace/link or non-exact version is not registry-resolvable.'
        else:node.status='uninspected';node.reason='Awaiting bounded source inspection.'
        for name,spec in declarations(entry).items():
            target=resolve(loc,name)
            if target:
                node.dependencies.append(target)
                if target in seen:warnings.append(f'Reused/cyclic dependency edge: {loc} → {target}; visited once.')
                else:queue.append((target,depth+1))
            elif len(nodes)<MAX_DISCOVERED:
                missing=loc+'/unresolved:'+name
                nodes[missing]=PackageInspection(name=name,version=str(spec),location=missing,direct=False,depth=depth+1,status='unresolved',reason='Transitive dependency has no matching lockfile entry.')
                node.dependencies.append(missing)
    return list(nodes.values()),expected,warnings


def inspect_dependencies(files, analyzer, profile='fast', session=None, cancel=None):
    session=session or RegistrySession(Budget.from_env(profile))
    started=time.monotonic();nodes,expected,warnings=lock_graph(files);findings=[];file_count=0;analyzed={};attempts=set()
    from .engine import finding
    for node in sorted(nodes,key=lambda n:n.depth if n.depth is not None else 9999):
        if node.status!='uninspected':continue
        if cancel and cancel.is_set():node.status='skipped';node.reason='Scan cancelled.';continue
        key=(node.name,node.version)
        if node.depth>session.budget.depth or (key not in attempts and len(attempts)>=session.budget.packages) or session.remaining()<=0:
            node.status='skipped';node.reason='Dependency depth, package count, or time budget reached.';continue
        attempts.add(key)
        try:
            result=session.retrieve(*key,expected.get(node.location))
            node.integrity=result.integrity;node.registry_integrity=result.registry_integrity
            failures=[x for x in [result.integrity,result.registry_integrity] if x.status not in {'verified','missing'}]
            if failures:
                node.status='integrity_failed';node.reason='Tarball was not extracted because integrity verification failed.'
                f=finding('PACKAGE_INTEGRITY',f'{node.name}: integrity could not be verified','Package integrity','high','high',node.reason,'The downloaded file did not pass its supplied integrity check. Guardian did not inspect its contents.','The bytes may be different, damaged, or described by unsupported metadata. This does not establish malicious behavior.','Do not use these bytes; verify the lockfile, registry metadata, and package publisher.',[Evidence(file=node.location,snippet=x.expected or '',detail=x.detail) for x in failures]);f.domain='integrity';f.package=f'{node.name}@{node.version}';findings.append(f);node.finding_ids=[f.id];continue
            if key not in analyzed:
                if session.remaining()<=0:raise BudgetExceeded('Time budget reached before source analysis.')
                prefix=f'dependencies/{node.name}@{node.version}/'
                namespaced={prefix+p:c for p,c in result.files.items()}
                analyzed[key]=analyzer(namespaced,timeout=max(.1,min(20,session.remaining())))
                _,_,package_findings,_,package_coverage,count=analyzed[key]
                for f in package_findings:f.package=f'{node.name}@{node.version}'
                findings.extend(package_findings);file_count+=count
                warnings.extend(f'{node.name}@{node.version}: {w}' for w in package_coverage if not w.startswith('Static analysis only'))
            package_findings=analyzed[key][2]
            node.finding_ids=[f.id for f in package_findings]
            node.status='inspected';node.reason='Bounded static inspection completed; check source coverage limitations.'
            warnings.extend(f'{node.name}@{node.version}: {w}' for w in result.warnings)
        except BudgetExceeded as error:
            node.status='skipped';node.reason=str(error)
        except Exception:
            node.status='unavailable';node.reason='Registry metadata, tarball, or source inspection unavailable; package is uninspected.'
    summary=InspectionSummary(total=len(nodes),direct=sum(n.direct for n in nodes),transitive=sum(not n.direct for n in nodes),inspected=sum(n.status=='inspected' for n in nodes),skipped=sum(n.status=='skipped' for n in nodes),unavailable=sum(n.status in {'unavailable','unresolved','uninspected','integrity_failed'} for n in nodes),packages_with_findings=sum(bool(n.finding_ids) for n in nodes),profile=profile,registry_requests=session.requests,downloaded_bytes=session.bytes,elapsed_ms=int((time.monotonic()-started)*1000))
    if summary.inspected<summary.total:warnings.append(f'Dependency inspection incomplete: {summary.inspected}/{summary.total} locations inspected; skipped/unavailable packages are not evidence of safety.')
    return nodes,summary,findings,warnings,file_count
