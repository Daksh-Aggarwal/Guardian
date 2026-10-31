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
