"""Read-only Unity and Unreal asset structure validators."""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from ..models import Confidence, FileRecord, Finding, Severity
from ._common import make_finding, record_bytes
from .types import AssetValidationResult

GUID = re.compile(r"(?mi)^\s*guid:\s*([0-9a-f]{32})\s*$")
UNREAL_PACKAGE_MAGIC = 0x9E2A83C1


def validate_engine_assets(files: list[FileRecord]) -> list[Finding]:
    findings: list[Finding] = []
    unity_meta: dict[str, list[FileRecord]] = defaultdict(list)
    unity_serialized = {".unity", ".prefab", ".asset"}
    for record in files:
        path = record.path.replace("\\", "/")
        suffix = Path(path).suffix.lower()
        if suffix == ".meta" and record.text:
            match = GUID.search(record.text)
            if not match:
                findings.append(
                    make_finding(
                        "ASSET-UNITY-META-GUID",
                        "Unity metadata file has no recognizable GUID",
                        Severity.MEDIUM,
                        record.path,
                        "A .meta file was read but no 32-character GUID declaration was found.",
                        module="SceneSentry",
                        confidence=Confidence.HIGH,
                        remediation="Regenerate or repair the Unity .meta file and verify references in the editor.",
                        metadata={"engine": "Unity"},
                    )
                )
            else:
                unity_meta[match.group(1).lower()].append(record)
        if suffix in unity_serialized and record.text and record.text.strip() and not record.text.lstrip().startswith(("%YAML", "---")):
            findings.append(
                make_finding(
                    "ASSET-UNITY-SERIALIZED-FORMAT",
                    "Unity serialized asset has an unexpected text header",
                    Severity.MEDIUM,
                    record.path,
                    "The asset is text-readable but does not begin with a common Unity YAML header; format validity requires Unity to import it.",
                    evidence=record.text.splitlines()[0][:160],
                    module="SceneSentry",
                    confidence=Confidence.MEDIUM,
                    remediation="Open the asset in the target Unity version or restore a valid serialized export.",
                    metadata={"engine": "Unity", "claims": []},
                )
            )
    for guid, records in sorted(unity_meta.items()):
        if len(records) > 1:
            findings.append(
                make_finding(
                    "ASSET-UNITY-DUPLICATE-GUID",
                    "Unity metadata GUID is duplicated",
                    Severity.HIGH,
                    records[0].path,
                    f"The GUID {guid} appears in {len(records)} .meta files; Unity references may resolve ambiguously.",
                    evidence=", ".join(record.path for record in records),
                    module="SceneSentry",
                    confidence=Confidence.HIGH,
                    remediation="Resolve the duplicate GUIDs in Unity and re-check serialized references before release.",
                    metadata={"engine": "Unity", "guid": guid, "paths": [record.path for record in records]},
                )
            )

    for record in files:
        suffix = Path(record.path).suffix.lower()
        if suffix not in {".uasset", ".umap"}:
            continue
        if record.size == 0:
            continue  # SceneSentry already emits the stable empty-asset finding.
        data = record_bytes(record)
        if len(data) < 4:
            state = "insufficient bytes"
            valid = None
        else:
            magic = int.from_bytes(data[:4], "little")
            state = f"package magic 0x{magic:08x}"
            valid = magic == UNREAL_PACKAGE_MAGIC
        if valid is True:
            findings.append(
                make_finding(
                    "ASSET-UNREAL-HEADER",
                    "Unreal package header was recognized",
                    Severity.INFO,
                    record.path,
                    "The Unreal package magic was recognized. This is header evidence only; package contents and loadability were not validated.",
                    evidence=state,
                    module="SceneSentry",
                    confidence=Confidence.HIGH,
                    actionable=False,
                    metadata={"engine": "Unreal Engine", "header_status": "recognized", "claims": []},
                )
            )
        elif valid is False:
            findings.append(
                make_finding(
                    "ASSET-UNREAL-HEADER",
                    "Unreal package header was not recognized",
                    Severity.MEDIUM,
                    record.path,
                    "The bounded bytes do not begin with the standard Unreal package magic; a corrupt, encrypted, or differently packaged asset cannot be ruled in or out.",
                    evidence=state,
                    module="SceneSentry",
                    confidence=Confidence.MEDIUM,
                    remediation="Validate the asset in the target Unreal Engine version and restore or re-export it if the editor cannot load it.",
                    metadata={"engine": "Unreal Engine", "header_status": "unrecognized", "claims": []},
                )
            )
    if findings:
        return findings
    return []


def validate_assets(files: list[FileRecord]) -> AssetValidationResult:
    findings = validate_engine_assets(files)
    engine = "Unity" if any(Path(record.path).suffix.lower() == ".meta" for record in files) else "Unreal Engine" if any(Path(record.path).suffix.lower() in {".uasset", ".umap"} for record in files) else ""
    checked = sum(Path(record.path).suffix.lower() in {".meta", ".unity", ".prefab", ".asset", ".uasset", ".umap"} for record in files)
    return AssetValidationResult(adapter="assets", state="inspected" if checked else "not_applicable", findings=findings, engine=engine, assets_checked=checked, limitations=["Asset headers and text structure do not prove editor import, references, rendering, or runtime behavior."] if checked else [])


def analyze(files: list[FileRecord]) -> list[Finding]:
    return validate_engine_assets(files)


def validate_unity_assets(files: list[FileRecord]) -> AssetValidationResult:
    selected = [record for record in files if Path(record.path).suffix.lower() in {".meta", ".unity", ".prefab", ".asset"}]
    findings = validate_engine_assets(selected)
    return AssetValidationResult(adapter="assets.unity", state="inspected" if selected else "not_applicable", findings=findings, engine="Unity", assets_checked=len(selected), limitations=["Unity asset structure does not prove editor import or runtime behavior."] if selected else [])


def validate_unreal_assets(files: list[FileRecord]) -> AssetValidationResult:
    selected = [record for record in files if Path(record.path).suffix.lower() in {".uasset", ".umap"}]
    findings = validate_engine_assets(selected)
    return AssetValidationResult(adapter="assets.unreal", state="inspected" if selected else "not_applicable", findings=findings, engine="Unreal Engine", assets_checked=len(selected), limitations=["Unreal package headers do not prove editor loadability or runtime behavior."] if selected else [])
