"""Operator-controlled budgets, clamped to hard ceilings; no unbounded client input."""
import os
from dataclasses import dataclass

def integer(name, default, ceiling, minimum=1):
    try:
        return max(minimum, min(ceiling, int(os.getenv(name, default))))
    except ValueError:
        return default

@dataclass(frozen=True)
class Budget:
    profile: str = 'fast'
    packages: int = 6
    depth: int = 2
    seconds: int = 25
    requests: int = 14
    bytes: int = 20 * 1024 * 1024
    expanded: int = 40 * 1024 * 1024

    @classmethod
    def from_env(cls, profile='fast'):
        deep = profile == 'deep'
        return cls(profile, integer('GUARDIAN_MAX_PACKAGES', 20 if deep else 6, 40, 0),
                   integer('GUARDIAN_MAX_DEPTH', 4 if deep else 2, 6, 0),
                   integer('GUARDIAN_DEPENDENCY_SECONDS', 60 if deep else 25, 120),
                   integer('GUARDIAN_REGISTRY_REQUESTS', 42 if deep else 14, 82),
                   integer('GUARDIAN_DOWNLOAD_MB', 50 if deep else 20, 100)*1024*1024,
                   integer('GUARDIAN_EXPANDED_MB', 80 if deep else 40, 150)*1024*1024)

def parser_limits():
    return {'maxNodes':integer('GUARDIAN_AST_NODES',100000,300000),
            'maxSteps':integer('GUARDIAN_FLOW_STEPS',100000,400000),
            'maxCalls':integer('GUARDIAN_FLOW_CALLS',300,2000),
            'maxDepth':integer('GUARDIAN_CALL_DEPTH',8,16),
            'maxModules':integer('GUARDIAN_MODULES',100,300),
            'maxPaths':12, 'maxTrace':24}


@dataclass(frozen=True)
class ArchiveLimits:
    """Per-artifact ceilings. Upload defaults/ceilings never inherit registry settings."""
    profile: str
    entries: int
    compressed: int
    expanded: int
    file: int
    sources: int
    seconds: int
    analysis_seconds: int

    @classmethod
    def from_env(cls, profile):
        # Byte values below are MiB. Each (default, hard ceiling) is independent.
        settings = {
            'upload': ((500,500),(10,10),(25,25),(1,1),(500,500),(15,30),(20,20)),
            'npm': ((10000,20000),(20,50),(80,200),(1,4),(5000,10000),(20,60),(30,60)),
            'wheel': ((10000,20000),(30,100),(100,300),(5,20),(5000,10000),(20,60),(30,60)),
            'sdist': ((10000,20000),(20,50),(80,200),(2,8),(5000,10000),(20,60),(30,60)),
        }
        fields = ('ENTRIES','COMPRESSED_MB','EXPANDED_MB','FILE_MB','SOURCES','SECONDS','ANALYSIS_SECONDS')
        values = [integer(f'GUARDIAN_{profile.upper()}_ARCHIVE_{name}', default, ceiling)
                  for name, (default, ceiling) in zip(fields, settings[profile])]
        for index in (1,2,3):
            values[index] *= 1024 * 1024
        return cls(profile, *values)


@dataclass(frozen=True)
class NpmBudget:
    """CLI graph budget, independent of bounded website scan profiles."""
    artifacts: int = 256
    locations: int = 2048
    depth: int = 32
    requests: int = 512
    seconds: int = 180
    bytes: int = 128 * 1024 * 1024
    expanded: int = 256 * 1024 * 1024
    analysis_seconds: int = 180
    profile: str = 'cli'

    @classmethod
    def from_env(cls):
        return cls(
            integer('GUARDIAN_NPM_UNIQUE_ARTIFACTS',256,1024),
            integer('GUARDIAN_NPM_LOCATIONS',2048,10000),
            integer('GUARDIAN_NPM_DEPTH',32,64),
            integer('GUARDIAN_NPM_REQUESTS',512,2048),
            integer('GUARDIAN_NPM_SECONDS',180,600),
            integer('GUARDIAN_NPM_DOWNLOAD_MB',128,512)*1024*1024,
            integer('GUARDIAN_NPM_EXPANDED_MB',256,1024)*1024*1024,
            integer('GUARDIAN_NPM_ANALYSIS_SECONDS',180,600))
