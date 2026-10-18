"""Optional local advisory database support with exact-version evidence only."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..models import Confidence, FileRecord, Finding, Severity
from ..parsers import parse_requirements
from ..security import read_bounded
from ._common import make_finding
from .types import DependencyDatabaseResult


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    source: str


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    package: str
    ecosystem: str
    affected_versions: tuple[str, ...]
    summary: str
    source: str


@dataclass
class LocalVulnerabilityDatabase:
    source: str
    advisories: tuple[Advisory, ...] = ()
    error: str | None = None

    @property
    def loaded(self) -> bool:
        return self.error is None


def _str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if item is not None)
    if value is None:
        return ()
    return (str(value),)


def _advisories(data: Any, source: str) -> list[Advisory]:
    rows: list[Advisory] = []
    candidates = data.get("vulnerabilities", []) if isinstance(data, dict) else data
    if isinstance(data, dict) and isinstance(data.get("advisories"), list):
        candidates = data["advisories"]
    if isinstance(data, dict) and isinstance(data.get("packages"), dict):
        candidates = []
        for package, versions in data["packages"].items():
            if isinstance(versions, dict):
                for version, entries in versions.items():
                    for entry in entries if isinstance(entries, list) else [entries]:
                        if isinstance(entry, dict):
                            candidates.append({**entry, "package": package, "versions": [version]})
    elif isinstance(data, dict) and not any(key in data for key in ("vulnerabilities", "advisories")):
        # Small hand-maintained indexes are useful in offline CI fixtures:
        # {"package": {"version": [{"id": "..."}]}}.
        candidates = []
        for package, versions in data.items():
            if not isinstance(versions, dict):
                continue
            for version, entries in versions.items():
                for entry in entries if isinstance(entries, list) else [entries]:
                    if isinstance(entry, dict):
                        candidates.append({**entry, "package": package, "versions": [version]})
    if isinstance(data, dict) and not isinstance(candidates, list):
        candidates = []
    expanded: list[dict[str, Any]] = []
    for item in candidates if isinstance(candidates, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("affected"), list):
            if isinstance(item, dict):
                expanded.append(item)
            continue
        # OSV records commonly put package identity and explicit affected
        # versions under each affected entry.  Range events are not reduced to
        # claims here; only the database's explicit version list is accepted.
        for affected in item["affected"]:
            if not isinstance(affected, dict):
                continue
            package = affected.get("package") or item.get("package") or item.get("name")
            versions = affected.get("versions") or affected.get("affected_versions")
            expanded.append({**item, **affected, "package": package, "versions": versions})
    for index, item in enumerate(expanded, 1):
        if not isinstance(item, dict):
            continue
        package = item.get("package") or item.get("name")
        if isinstance(package, dict):
            ecosystem = str(package.get("ecosystem", ""))
            package = package.get("name")
        else:
            ecosystem = str(item.get("ecosystem", ""))
        package = str(package or "").strip()
        versions = item.get("versions") or item.get("affected_versions") or item.get("affectedVersions")
        if not package or not versions:
            # OSV range events are intentionally not converted into a claim;
            # exact affected versions are required for offline matching.
            continue
        advisory_id = str(item.get("id") or item.get("advisory") or item.get("cve") or f"LOCAL-{index}")
        rows.append(Advisory(advisory_id, package.lower(), ecosystem.lower(), _str_tuple(versions), str(item.get("summary") or item.get("details") or "Local advisory match"), source))
    return rows


def load_database(source: str | Path | Mapping[str, Any] | None, *, max_bytes: int = 10_000_000) -> LocalVulnerabilityDatabase | None:
    if source is None:
        return None
    if isinstance(source, Mapping):
        return LocalVulnerabilityDatabase("<mapping>", tuple(_advisories(source, "<mapping>")))
    path = Path(source).expanduser()
    if path.is_symlink():
        return LocalVulnerabilityDatabase(str(path), error="symlinked advisory database was not read")
    try:
        data = json.loads(read_bounded(path, max_bytes).decode("utf-8"))
        return LocalVulnerabilityDatabase(str(path), tuple(_advisories(data, str(path))))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return LocalVulnerabilityDatabase(str(path), error=f"could not load local advisory database: {exc}")


def _dependencies(files: list[FileRecord]) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for record in files:
        name = Path(record.path).name.lower()
        if not record.text:
            continue
        if name.startswith("requirements") and name.endswith(".txt"):
            for spec in parse_requirements(record.text):
                match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([0-9][^\s;]*)", spec)
                if match:
                    dependencies.append(Dependency(match.group(1).lower(), match.group(2), "pypi", record.path))
                else:
                    package = re.match(r"^([A-Za-z0-9_.-]+)", spec)
                    if package:
                        dependencies.append(Dependency(package.group(1).lower(), None, "pypi", record.path))
        elif name == "package-lock.json":
            try:
                data = json.loads(record.text)
                packages = data.get("packages", {}) if isinstance(data, dict) else {}
                for package_path, info in packages.items():
                    if not isinstance(info, dict) or not info.get("version"):
                        continue
                    package_name = package_path.rsplit("node_modules/", 1)[-1]
                    if package_name and package_name != package_path:
                        dependencies.append(Dependency(package_name.lower(), str(info["version"]), "npm", record.path))
            except (ValueError, TypeError):
                continue
    unique = {(item.name, item.version, item.ecosystem, item.source): item for item in dependencies}
    return list(unique.values())


def analyze_dependencies(files: list[FileRecord], vulnerability_database: str | Path | Mapping[str, Any] | None = None) -> DependencyDatabaseResult:
    dependencies = _dependencies(files)
    database = load_database(vulnerability_database)
    findings: list[Finding] = []
    if database is None:
        if dependencies:
            findings.append(
                make_finding(
                    "TRUST-AUDIT-LIMIT",
                    "Dependency vulnerability intelligence was not checked",
                    Severity.INFO,
                    "",
                    "Dependencies were parsed locally, but no optional local advisory database was supplied. No vulnerability claim is made.",
                    module="TrustTrail",
                    confidence=Confidence.HIGH,
                    actionable=False,
                    remediation="Supply a reviewed local advisory database or review dependencies against an authorized advisory source as a separate release step.",
                    metadata={"dependencies_checked": len(dependencies), "advisory_database": None, "claims": []},
                )
            )
        return DependencyDatabaseResult(adapter="dependencies", state="not_applicable" if not dependencies else "inspected", findings=findings, dependencies_checked=len(dependencies), limitations=["No remote advisory service is contacted; no vulnerability claim is made without local advisory evidence."])
    if database.error:
        database_label = Path(database.source).name if not database.source.startswith("<") else database.source
        findings.append(
            make_finding(
                "TRUST-DEPENDENCY-DB",
                "Local dependency advisory database could not be loaded",
                Severity.MEDIUM,
                database_label,
                database.error,
                module="TrustTrail",
                confidence=Confidence.HIGH,
                remediation="Provide a readable, reviewed JSON advisory database or continue with manual dependency review.",
                metadata={"advisory_database": database_label, "claims": []},
            )
        )
        return DependencyDatabaseResult(adapter="dependencies", state="error", findings=findings, database_path=database.source, dependencies_checked=len(dependencies), limitations=["An unreadable database cannot provide vulnerability evidence."])

    findings.append(
        make_finding(
            "TRUST-DEPENDENCY-DB",
            "Local dependency advisory database loaded",
            Severity.INFO,
            Path(database.source).name if not database.source.startswith("<") else database.source,
            f"Loaded {len(database.advisories)} exact-version advisory record(s) from a local database; only exact package/version matches are reported.",
            module="TrustTrail",
            confidence=Confidence.HIGH,
            actionable=False,
            metadata={"advisories_loaded": len(database.advisories), "dependencies_checked": len(dependencies), "claims": []},
        )
    )
    matches = 0
    for dependency in dependencies:
        if dependency.version is None:
            continue
        for advisory in database.advisories:
            if advisory.package != dependency.name or advisory.ecosystem and advisory.ecosystem != dependency.ecosystem:
                continue
            if dependency.version not in advisory.affected_versions:
                continue
            matches += 1
            findings.append(
                make_finding(
                    "TRUST-VULNERABILITY",
                    "Local advisory matches dependency",
                    Severity.HIGH,
                    dependency.source,
                    f"Local advisory {advisory.advisory_id} lists {dependency.name} {dependency.version} as affected. This claim is limited to the supplied database evidence.",
                    evidence=f"{advisory.advisory_id}: {advisory.summary}",
                    module="TrustTrail",
                    confidence=Confidence.HIGH,
                    remediation="Review the advisory, upgrade or replace the dependency, and record the resulting release decision.",
                    metadata={"advisory_id": advisory.advisory_id, "package": dependency.name, "version": dependency.version, "ecosystem": dependency.ecosystem, "database": Path(advisory.source).name if not advisory.source.startswith("<") else advisory.source, "evidence_basis": "exact local advisory match"},
                )
            )
    return DependencyDatabaseResult(adapter="dependencies", state="inspected", findings=findings, evidence={"advisories_loaded": len(database.advisories), "matches": matches}, database_path=database.source, advisories_loaded=len(database.advisories), dependencies_checked=len(dependencies), limitations=["Only exact versions listed by the local database are matched; freshness, transitive resolution, exploitability, and patched-version selection were not evaluated."])


check_dependencies = analyze_dependencies
