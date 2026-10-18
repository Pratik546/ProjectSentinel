"""Small shared helpers for read-only adapters."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..models import Confidence, FileRecord, Finding, Severity
from ..security import redact


def make_finding(
    rule: str,
    title: str,
    severity: Severity,
    path: str,
    message: str,
    line: int | None = None,
    evidence: str | None = None,
    *,
    module: str,
    confidence: Confidence = Confidence.MEDIUM,
    remediation: str = "Review the evidence and verify the recommended change before release.",
    why: str = "This evidence may increase release risk.",
    metadata: dict[str, Any] | None = None,
    actionable: bool = True,
) -> Finding:
    canonical = f"{rule}\0{path}\0{line or ''}\0{message}"
    return Finding(
        rule_id=rule,
        title=title,
        severity=severity,
        path=path,
        message=redact(message),
        line=line,
        evidence=redact(evidence) if evidence else None,
        finding_id=hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16],
        module=module,
        confidence=confidence,
        why_it_matters=why,
        remediation=remediation,
        actionable=actionable,
        metadata=metadata or {},
    )


def record_bytes(record: FileRecord) -> bytes:
    """Return bounded bytes already held by the scanner, never execute a file."""
    if record.data is not None:
        return record.data
    return (record.text or "").encode("utf-8", errors="replace")


def is_named(record: FileRecord, *names: str) -> bool:
    return Path(record.path).name.lower() in {name.lower() for name in names}
