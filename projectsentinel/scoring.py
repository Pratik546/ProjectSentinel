"""Deterministic risk scoring and release verification planning.

The scanner deliberately stops at evidence gathering.  Verification plans keep
that boundary explicit: they describe the manual and automated checks a
release owner should perform, but they never imply that a check has run.
Automated commands are accepted only when an adapter has supplied one; this
module never invents a command or executes one.
"""
from collections import Counter
import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import Finding, ScanResult, Severity
from .security import redact

WEIGHTS = {Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}


_CHECK_TEMPLATES: dict[str, dict[str, Any]] = {
    "CRASH-ERROR": {
        "manual": {
            "title": "Reproduce and triage the reported crash/log error",
            "steps": [
                "Reproduce the error in the target engine, platform, or toolchain.",
                "Inspect the surrounding stack trace and record the observed root cause.",
            ],
            "pass_criteria": "The error is no longer reproduced, or an accepted known-issue record and mitigation are attached.",
        },
        "automated": {
            "title": "Add or run a regression check for the error signature",
            "steps": [
                "Add a focused regression test for the reproduced behavior.",
                "Run the repository's approved test command and retain its result.",
            ],
            "pass_criteria": "The regression test passes and the retained result identifies the tested revision.",
        },
    },
    "CODE-SYNTAX": {
        "manual": {
            "title": "Review the source location and intended syntax",
            "steps": ["Open the reported source location and correct the syntax while preserving intended behavior."],
            "pass_criteria": "The source parses with the project's language tooling and the change has been reviewed.",
        },
        "automated": {
            "title": "Run the language parser or compiler",
            "steps": ["Run the language's parser/compiler or the project's normal build check."],
            "pass_criteria": "The parser/compiler exits successfully with no syntax errors.",
        },
    },
    "CODE-MERGE-CONFLICT": {
        "manual": {
            "title": "Resolve the merge-conflict marker",
            "steps": ["Review the conflicting source section, choose the intended implementation, and remove all conflict markers."],
            "pass_criteria": "The source contains no unresolved conflict markers and the resolution is reviewed.",
        },
        "automated": {
            "title": "Run the repository integrity and build checks",
            "steps": ["Run the repository's approved conflict-marker, build, and test checks."],
            "pass_criteria": "Integrity/build checks pass without conflict-marker or compilation errors.",
        },
    },
    "TRUST-SECRET": {
        "manual": {
            "title": "Rotate and remove the possible credential",
            "steps": [
                "Confirm whether the redacted value is a real credential with the owning team.",
                "Revoke or rotate it, remove it from source, and move configuration to an approved secret store.",
            ],
            "pass_criteria": "The credential is revoked/rotated, source history is handled per policy, and the replacement is not committed.",
        },
        "automated": {
            "title": "Re-run an approved secret scan",
            "steps": ["Run the repository's approved secret scanner against the changed files and relevant history."],
            "pass_criteria": "The approved scanner reports no unreviewed credential match.",
        },
    },
    "SCOPE-UNVERIFIED": {
        "manual": {
            "title": "Complete the release requirement verification",
            "steps": ["Perform the requirement's stated check and attach a test result, screenshot, log, or reviewer reference."],
            "pass_criteria": "The requirement has an explicit accepted status and a traceable evidence reference.",
        },
        "automated": {
            "title": "Run the requirement's linked automated check when available",
            "steps": ["Run the automated check linked by the requirement or record why this requirement requires manual evidence."],
            "pass_criteria": "The linked check passes and its result is attached to the requirement record.",
        },
    },
    "SCOPE-SCHEMA": {
        "manual": {
            "title": "Correct the release requirements evidence document",
            "steps": ["Review the requirements input and provide an object containing a requirements array with id and description."],
            "pass_criteria": "The requirements document validates against the documented schema.",
        },
        "automated": {
            "title": "Validate the requirements schema",
            "steps": ["Run the local requirements-schema validation check."],
            "pass_criteria": "Schema validation exits successfully and reports no malformed requirement entries.",
        },
    },
}


def _finding_sort_key(finding: Finding) -> tuple[int, int, str, str, int]:
    return (-int(finding.severity), -int(finding.confidence), finding.path, finding.rule_id, finding.line or 0)


def _metadata_checks(finding: Finding) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Read optional adapter-provided verification details without trusting them as results."""
    metadata = finding.metadata if isinstance(finding.metadata, Mapping) else {}
    raw = metadata.get("verification_plan", metadata.get("verification"))
    manual: dict[str, Any] | None = None
    automated: dict[str, Any] | None = None
    if isinstance(raw, Mapping):
        for key, target in (("manual", "manual"), ("manual_check", "manual"), ("automated", "automated"), ("automated_check", "automated")):
            value = raw.get(key)
            if isinstance(value, Mapping):
                if target == "manual":
                    manual = dict(value)
                else:
                    automated = dict(value)
    command = metadata.get("verification_command", metadata.get("test_command"))
    if command and automated is None:
        automated = {"command": command}
    return manual, automated


def _adapter_command_for_finding(result: ScanResult | None, finding: Finding) -> tuple[str | list[str] | None, str | None]:
    """Match a real adapter proposal to a source finding when evidence overlaps."""
    if result is None or not finding.path:
        return None, None
    _ensure_adapter_metadata(result)
    metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
    raw = metadata.get("adapter_commands", [])
    if not isinstance(raw, list):
        return None, None
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        evidence = item.get("evidence", ())
        if isinstance(evidence, str):
            evidence = (evidence,)
        if finding.path not in evidence:
            continue
        command = _normalise_command(item.get("command"))
        if command is not None:
            return command, str(item.get("name", "adapter"))
    # A language adapter can still be relevant to a code finding when the
    # adapter evidence names the project marker rather than the finding file.
    if not finding.rule_id.startswith("CODE-"):
        return None, None
    suffix = Path(finding.path).suffix.lower()
    language_by_suffix = {
        ".cs": "C#", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
        ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
        ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin",
        ".rs": "Rust", ".swift": "Swift", ".dart": "Dart",
    }
    language = language_by_suffix.get(suffix)
    for item in raw:
        if not isinstance(item, Mapping) or str(item.get("name", "")) != language:
            continue
        command = _normalise_command(item.get("command"))
        if command is not None:
            return command, language
    return None, None


def _normalise_command(value: Any) -> str | list[str] | None:
    """Keep adapter commands serialisable while avoiding fabricated commands."""
    if isinstance(value, str) and value.strip():
        return redact(value.strip())
    if isinstance(value, (list, tuple)) and value and all(isinstance(item, str) and item.strip() for item in value):
        return [redact(item.strip()) for item in value]
    return None


def _adapter_statuses(source: ScanResult | Mapping[str, Any]) -> list[dict[str, Any]]:
    if isinstance(source, ScanResult):
        _ensure_adapter_metadata(source)
    metadata = source.metadata if isinstance(source, ScanResult) else source
    raw = metadata.get(
        "adapter_status",
        metadata.get("adapter_statuses", metadata.get("adapter_results", metadata.get("adapters", []))),
    )
    if isinstance(raw, Mapping):
        values = []
        for name, value in sorted(raw.items(), key=lambda item: str(item[0])):
            if isinstance(value, Mapping):
                item = {"name": str(name), **dict(value)}
            else:
                item = {"name": str(name), "status": str(value)}
            values.append(item)
        return values
    if isinstance(raw, list):
        values = []
        for item in raw:
            if isinstance(item, Mapping):
                values.append(dict(item))
            elif isinstance(item, str):
                values.append({"name": item})
            elif hasattr(item, "adapter"):
                values.append({
                    "name": str(getattr(item, "adapter")),
                    "status": str(getattr(item, "state", "recorded")),
                    "evidence": getattr(item, "evidence", {}),
                    "limitations": getattr(item, "limitations", []),
                })
        return values
    return []


def adapter_statuses(source: ScanResult | Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return real adapter records from scan metadata, or an empty list.

    The empty result is intentional: a missing adapter record is not reported as
    an installed, healthy, or unavailable adapter.
    """
    return _adapter_statuses(source)


def _ensure_adapter_metadata(result: ScanResult) -> None:
    """Record real language-adapter discovery for reports outside Streamlit.

    Discovery only walks the already-selected project root and checks PATH for
    adapter executables.  It never invokes a command.  The UI may populate the
    same metadata earlier; in that case this function preserves that receipt.
    """
    metadata = result.metadata
    if metadata.get("adapter_status") or metadata.get("adapter_statuses"):
        return
    try:
        from .adapters import discover_adapters

        discovery = discover_adapters(result.root, check_executables=True)
    except (ImportError, OSError, ValueError):
        return
    statuses: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    for proposal in discovery.proposals:
        item = {
            "name": proposal.language,
            "status": proposal.status.value,
            "executable": proposal.executable,
            "command": list(proposal.command),
            "reason": proposal.reason,
            "evidence": list(proposal.evidence),
        }
        statuses.append(item)
        if proposal.status.value == "proposed":
            commands.append(item)
    for skipped in discovery.skipped:
        statuses.append({"name": skipped.language, "status": skipped.status.value, "reason": skipped.reason})
    if statuses:
        metadata["adapter_status"] = statuses
    if commands:
        metadata["adapter_commands"] = commands


def _check_from_template(kind: str, finding: Finding, template: Mapping[str, Any]) -> dict[str, Any]:
    check_id = hashlib.sha256(f"{finding.finding_id}|{kind}".encode("utf-8")).hexdigest()[:16]
    value = dict(template)
    value.setdefault("title", f"{kind.title()} verification for {finding.title}")
    value.setdefault("steps", [])
    value.setdefault("pass_criteria", "Attach evidence that the check passed or record an accepted exception.")
    value["kind"] = kind
    value["type"] = kind
    value["verification_type"] = kind
    value["check_id"] = f"verify-{check_id}"
    value["status"] = "pending" if kind == "manual" else "not_run"
    value["available"] = False if kind == "automated" else None
    value["command"] = _normalise_command(value.get("command"))
    if kind == "automated" and value["command"] is not None:
        value["available"] = True
    return value


def generate_verification_plan(source: ScanResult | Iterable[Finding]) -> list[dict[str, Any]]:
    """Generate deterministic manual/automated checks from findings.

    ``source`` may be a :class:`ScanResult` or a finding iterable.  Each plan
    item retains the finding identity and evidence context, and contains a
    ``manual`` and ``automated`` check.  Adapter-provided commands are shown as
    available but remain ``not_run`` until an explicitly enabled runner uses
    them.
    """
    result = source if isinstance(source, ScanResult) else None
    findings = result.findings if result is not None else list(source)
    plan: list[dict[str, Any]] = []
    for finding in sorted(findings, key=_finding_sort_key):
        template = _CHECK_TEMPLATES.get(finding.rule_id, {})
        manual_template = dict(template.get("manual", {}))
        automated_template = dict(template.get("automated", {}))
        explicit_manual, explicit_automated = _metadata_checks(finding)
        if explicit_manual:
            manual_template.update(explicit_manual)
        if explicit_automated:
            automated_template.update(explicit_automated)
        if not manual_template:
            manual_template = {
                "title": f"Review and verify {finding.title}",
                "steps": [finding.remediation or "Review the retained evidence and perform the recommended release check."],
                "pass_criteria": "The evidence is resolved or an accepted exception is recorded.",
            }
        if not automated_template:
            automated_template = {
                "title": f"Re-run the automated check related to {finding.title}",
                "steps": ["Run the project's approved automated check for this evidence, if one exists."],
                "pass_criteria": "The approved check passes, or a documented manual exception is accepted.",
            }
        adapter_command, adapter_name = _adapter_command_for_finding(result, finding)
        if adapter_command is not None and "command" not in automated_template:
            automated_template["command"] = adapter_command
            automated_template["adapter"] = adapter_name
        manual = _check_from_template("manual", finding, manual_template)
        automated = _check_from_template("automated", finding, automated_template)
        plan.append({
            "plan_id": f"plan-{finding.finding_id}",
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "module": finding.module,
            "path": finding.path,
            "line": finding.line,
            "title": finding.title,
            "priority": finding.severity.name.title(),
            "confidence": finding.confidence.name.title(),
            "evidence": redact(finding.evidence or ""),
            "manual": manual,
            "automated": automated,
            "manual_check": manual,
            "automated_check": automated,
            # ``checks`` is convenient for tabular consumers while the named
            # fields keep the manual/automated distinction obvious in JSON.
            "checks": [manual, automated],
        })
    return plan


# Short aliases make the generator easy to discover for integrations without
# creating a second implementation.
verification_plan = generate_verification_plan
build_verification_plan = generate_verification_plan


def verification_plan_summary(plan: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Return counts derived from a generated plan, never simulated results."""
    items = list(plan)
    checks = [check for item in items for check in item.get("checks", []) if isinstance(check, Mapping)]
    return {
        "findings": len(items),
        "checks": len(checks),
        "manual_checks": sum(check.get("kind") == "manual" for check in checks),
        "automated_checks": sum(check.get("kind") == "automated" for check in checks),
        "automated_available": sum(check.get("kind") == "automated" and check.get("available") is True for check in checks),
    }

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
    next_steps = [f.remediation for f in sorted(result.findings, key=_finding_sort_key) if f.actionable and f.remediation][:5]
    plan = generate_verification_plan(result)
    plan_counts = verification_plan_summary(plan)
    return {
        "status": status,
        "label": label,
        "reasons": reasons,
        "next_steps": next_steps,
        "confirmed_high_or_critical": counts["critical"] + counts["high"],
        "unverified_requirements": unverified,
        "modules_failed": failed,
        "modules_not_run": not_run,
        "verification_plan_count": plan_counts["findings"],
        "verification_check_count": plan_counts["checks"],
    }
