"""Typed, portable data contracts shared by every audit module."""
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from typing import Any

class Severity(IntEnum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4

class Confidence(IntEnum):
    LOW = 1; MEDIUM = 2; HIGH = 3

@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    text: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    # Binary evidence is retained only for bounded, non-text artifacts that
    # have a validator.  It is intentionally not included in reports.
    data: bytes | None = None

@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    path: str = ""
    message: str = ""
    line: int | None = None
    evidence: str | None = None
    finding_id: str = ""
    module: str = ""
    confidence: Confidence = Confidence.MEDIUM
    why_it_matters: str = ""
    remediation: str = ""
    actionable: bool = True
    related_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_id:
            import hashlib
            raw = f"{self.rule_id}|{self.path}|{self.line or 0}|{self.title}"
            object.__setattr__(self, "finding_id", hashlib.sha256(raw.encode()).hexdigest()[:16])
        if not self.module:
            object.__setattr__(self, "module", self.rule_id.split("-", 1)[0].lower())

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.name.title()
        value["confidence"] = self.confidence.name.title()
        value["related_ids"] = list(self.related_ids)
        return value

@dataclass
class ScanResult:
    root: Path
    files: list[FileRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    module_status: dict[str, str] = field(default_factory=dict)
    started_at: str = ""
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def project_types(self) -> list[str]:
        return list(self.metadata.get("project_types", []))

    @property
    def score(self) -> int:
        from .scoring import score_findings
        return score_findings(self.findings)

    @property
    def highest_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def files_inspected(self) -> int:
        return len(self.files)
