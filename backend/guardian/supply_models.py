"""Acquisition boundary: immutable bytes and normalized metadata, never executable input."""
from dataclasses import dataclass, field
from typing import Dict, List


class AcquisitionError(ValueError):
    """Safe diagnostics only; exception causes may contain private upstream details."""
    def __init__(self, message, *, category='acquisition_failure', operation=None,
                 package=None, budget=None, limit=None, encountered=None, detail=None,
                 bytes_received=0):
        super().__init__(message)
        self.category, self.operation, self.package = category, operation, package
        self.budget, self.limit, self.encountered = budget, limit, encountered
        self.detail, self.bytes_received = detail, bytes_received

    def diagnostic(self):
        return {key: value for key, value in {
            'category': self.category, 'operation': self.operation, 'package': self.package,
            'budget': self.budget, 'limit': self.limit, 'encountered': self.encountered,
            'detail': self.detail}.items() if value is not None}


class IntegrityError(AcquisitionError):
    def __init__(self, message, **kwargs):
        kwargs.setdefault('category', 'integrity_mismatch')
        super().__init__(message, **kwargs)


class InstallError(ValueError):
    pass


@dataclass
class Artifact:
    ecosystem: str
    name: str
    version: str
    filename: str
    raw: bytes
    files: Dict[str, str]
    sha256: str
    verified: bool
    warnings: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    direct: bool = True
    kind: str = ''

    @property
    def identity(self):
        return f'{self.ecosystem}:{self.name}@{self.version}'


@dataclass
class Plan:
    ecosystem: str
    artifacts: List[Artifact]
    roots: List[str]
    complete: bool = True
    limitations: List[str] = field(default_factory=list)
    installer_data: dict = field(default_factory=dict)
    locations: List[dict] = field(default_factory=list)
    budgets: dict = field(default_factory=dict)
    acquisition: dict = field(default_factory=dict)
