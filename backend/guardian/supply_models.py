"""Acquisition boundary: immutable bytes and normalized metadata, never executable input."""
from dataclasses import dataclass, field
from typing import Dict, List


class AcquisitionError(ValueError):
    pass


class IntegrityError(AcquisitionError):
    pass


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
