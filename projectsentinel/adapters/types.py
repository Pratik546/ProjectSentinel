"""Typed contracts returned by ProjectSentinel's optional offline adapters."""
from dataclasses import dataclass, field
from typing import Any, Literal

from ..models import Finding

AdapterState = Literal[
    "not_applicable",
    "inspected",
    "structural_evidence",
    "unsupported",
    "malformed",
    "error",
]


@dataclass
class AdapterResult:
    """A result that distinguishes evidence from a product-level assertion."""

    adapter: str
    state: AdapterState
    findings: list[Finding] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    @property
    def inspected(self) -> bool:
        return self.state in {"inspected", "structural_evidence", "malformed"}

    @property
    def status(self) -> AdapterState:
        """Compatibility spelling for callers that use status terminology."""
        return self.state


@dataclass
class MobileManifestResult(AdapterResult):
    platform: str = ""
    manifest_path: str = ""
    permissions: tuple[str, ...] = ()


@dataclass
class BuildValidationResult(AdapterResult):
    engine: str = ""
    log_paths: tuple[str, ...] = ()
    passed: bool | None = None


@dataclass
class DependencyDatabaseResult(AdapterResult):
    database_path: str = ""
    advisories_loaded: int = 0
    dependencies_checked: int = 0


@dataclass(frozen=True)
class CrashLogRecord:
    path: str
    format: str
    signatures: tuple[str, ...]
    occurrences: int
    first_line: int | None = None


@dataclass
class CrashImportResult(AdapterResult):
    logs: tuple[CrashLogRecord, ...] = ()


@dataclass
class AssetValidationResult(AdapterResult):
    engine: str = ""
    assets_checked: int = 0


@dataclass
class ModelValidationResult(AdapterResult):
    model_format: str = ""
    model_path: str = ""
    validation_status: str = "unverified"
