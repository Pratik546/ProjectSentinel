"""Deterministic risk scoring."""
from collections import Counter
from .models import Finding, ScanResult, Severity

WEIGHTS = {Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}

def score_findings(findings: list[Finding]) -> int:
    """Return a bounded 0-100 risk score; duplicate IDs count once."""
    unique = {f.finding_id or (f.rule_id, f.path, f.line, f.message): f for f in findings}
    return min(100, sum(WEIGHTS[f.severity] for f in unique.values()))

def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.name.lower() for f in findings)
    return {level: counts.get(level, 0) for level in ("critical", "high", "medium", "low", "info")}

def release_gate(result: ScanResult) -> dict[str, object]:
    """Return an explainable release decision; never represents it as certification."""
    counts = severity_counts(result.findings)
    failed = [name for name, status in result.module_status.items() if status in {"failed", "partial"}]
    not_run = [name for name, status in result.module_status.items() if status == "not run"]
    unverified = sum(f.rule_id == "SCOPE-UNVERIFIED" for f in result.findings)
    skipped = len(result.skipped)
    reasons: list[str] = []
    if counts["critical"]: reasons.append(f"{counts['critical']} critical finding(s)")
    if counts["high"]: reasons.append(f"{counts['high']} high-priority finding(s)")
    if unverified: reasons.append(f"{unverified} requirement(s) lack verification evidence")
    if skipped: reasons.append(f"{skipped} file(s) were skipped by scan limits or safety rules")
    if failed: reasons.append("failed checks: " + ", ".join(failed))
    if not_run: reasons.append("not-run checks: " + ", ".join(not_run))
    if failed or counts["critical"]:
        status, label = "BLOCKED", "Do not release yet"
    elif counts["high"] or unverified or not_run or skipped:
        status, label = "REVIEW", "Review before release"
    else:
        status, label = "VERIFY", "No blockers detected by enabled checks"
    next_steps = [f.remediation for f in sorted(result.findings, key=lambda item: (-int(item.severity), -int(item.confidence), item.path)) if f.actionable and f.remediation][:5]
    return {"status": status, "label": label, "reasons": reasons, "next_steps": next_steps, "confirmed_high_or_critical": counts["critical"] + counts["high"], "unverified_requirements": unverified, "modules_failed": failed, "modules_not_run": not_run}
