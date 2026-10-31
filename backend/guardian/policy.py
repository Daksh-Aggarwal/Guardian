"""Installation policy is independent of detection; overrides never repair coverage."""
from dataclasses import asdict, dataclass
from .engine import RANK


@dataclass(frozen=True)
class Policy:
    block_severity: str = 'high'
    block_confidence: str = 'medium'
    require_intelligence: bool = False

    @classmethod
    def load(cls, path):
        import json
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or set(data) - {'block_severity', 'block_confidence', 'require_intelligence'}:
            raise ValueError('Policy accepts block_severity, block_confidence, require_intelligence only.')
        result = cls(**data)
        if result.block_severity not in RANK or result.block_confidence not in {'low', 'medium', 'high'} or type(result.require_intelligence) is not bool:
            raise ValueError('Invalid installation policy thresholds.')
        return result


def evaluate(findings, *, verified, complete, limitations, intelligence='not checked', policy=None):
    policy = policy or Policy()
    confidence = {'low': 0, 'medium': 1, 'high': 2}
    blockers = [f for f in findings if RANK[f.severity] >= RANK[policy.block_severity]
                and confidence[f.confidence] >= confidence[policy.block_confidence]]
    review = list(limitations)
    if not verified:
        review.append('Artifact integrity could not be verified against trusted metadata.')
    if not complete:
        review.append('Package source or dependency graph was not fully analysed.')
    if policy.require_intelligence and intelligence != 'checked':
        review.append('Policy requires available vulnerability intelligence.')
    warnings = [f for f in findings if f.severity != 'info' and f not in blockers]
    decision = 'BLOCK' if blockers else ('REVIEW' if review else ('WARN' if warnings else 'ALLOW'))
    return {
        'decision': decision,
        'reasons': [f'{f.rule}: {f.title}' for f in blockers] + review + [f'{f.rule}: {f.title}' for f in warnings],
        'blocking_finding_ids': [f.id for f in blockers],
        'review_reasons': review,
        'overridable': bool(verified and complete and not review),
        'policy': asdict(policy),
    }
