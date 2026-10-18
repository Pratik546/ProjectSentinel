"""Deterministic risk scoring."""
from collections import Counter
from .models import Finding, Severity

WEIGHTS = {Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}

def score_findings(findings: list[Finding]) -> int:
    """Return a bounded 0-100 risk score; duplicate IDs count once."""
    unique = {f.finding_id or (f.rule_id, f.path, f.line, f.message): f for f in findings}
    return min(100, sum(WEIGHTS[f.severity] for f in unique.values()))

def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.name.lower() for f in findings)
    return {level: counts.get(level, 0) for level in ("critical", "high", "medium", "low", "info")}
