"""Deterministic project structure, asset and Unity reference checks."""
import json, re, struct
from collections import defaultdict
from ..models import FileRecord, Finding, Severity, Confidence
from ._util import finding
from .code_audit import analyze as analyze_code
from .mobile_audit import analyze as analyze_mobile
from .model_audit import analyze as analyze_model
from ..adapters.assets import validate_engine_assets
from ..adapters.build import validate_build_evidence

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".tga"}

def _dimensions(data: bytes) -> tuple[int, int] | None:
    if data.startswith(b"\x89PNG") and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if data.startswith(b"\xff\xd8"):
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF: i += 1; continue
            marker = data[i+1]; i += 2
            if marker in (0xD8, 0xD9): continue
            length = int.from_bytes(data[i:i+2], "big")
            if marker in range(0xC0, 0xC4): return int.from_bytes(data[i+5:i+7], "big"), int.from_bytes(data[i+3:i+5], "big")
            i += max(length, 2)
    return None

def analyze(files: list[FileRecord], *, large_file_bytes: int = 25 * 1024 * 1024, **_: object) -> list[Finding]:
    out: list[Finding] = []
    out.extend(analyze_code(files))
    out.extend(analyze_mobile(files))
    out.extend(analyze_model(files))
    out.extend(validate_engine_assets(files))
    out.extend(validate_build_evidence(files).findings)
    paths = {f.path for f in files}
    types = []
    if "Packages/manifest.json" in paths or any(p.startswith("ProjectSettings/") for p in paths) or any(p.endswith(".unity") for p in paths): types.append("Unity")
    unreal_files = [f for f in files if f.path.lower().endswith((".uproject", ".uplugin"))]
    if unreal_files or any(p.startswith("Content/") for p in paths) and any(p.startswith("Config/") for p in paths): types.append("Unreal Engine")
    if any(f.path.lower().endswith(".blend") for f in files): types.append("Blender")
    if any(f.path.lower().endswith((".ma", ".mb")) for f in files): types.append("Maya")
    if not types: types.append("General repository")
    out.append(finding("SCENE-PROJECT-TYPE", "Project type detected", Severity.INFO, "", "Detected project type(s): " + ", ".join(types), module="SceneSentry", confidence=Confidence.HIGH, actionable=False, metadata={"project_types": types}))
    by_hash: dict[str, list[FileRecord]] = defaultdict(list)
    for f in files: by_hash[f.sha256].append(f)
    for digest, group in sorted(by_hash.items()):
        if len(group) > 1:
            paths = ", ".join(x.path for x in group)
            out.append(finding("SCENE-DUPLICATE", "Identical files share storage", Severity.LOW, group[0].path,
                f"{len(group)} files have the same SHA-256; possible duplicate storage: {sum(x.size for x in group[1:])} bytes.", evidence=paths, module="SceneSentry", confidence=Confidence.HIGH,
                why="Duplicate bytes can increase package size, but identical content is not proof an asset is safe to delete.", remediation="Review references and intentional reuse before consolidating assets.", metadata={"sha256": digest, "paths": [x.path for x in group], "potential_duplicate_bytes": sum(x.size for x in group[1:])}))
    unity = "Unity" in types
    if unity:
        paths = {f.path for f in files}
        for expected in ("Assets", "ProjectSettings", "Packages/manifest.json"):
            if not any(p == expected or p.startswith(expected + "/") for p in paths):
                out.append(finding("SCENE-STRUCTURE", f"Expected Unity path is missing: {expected}", Severity.INFO, "", "Informational structure check; absence may be intentional.", module="SceneSentry", confidence=Confidence.HIGH, actionable=False))
        manifest = next((f for f in files if f.path == "Packages/manifest.json"), None)
        if manifest and manifest.text:
            try: json.loads(manifest.text)
            except json.JSONDecodeError as exc:
                out.append(finding("SCENE-MANIFEST", "Unity package manifest is malformed", Severity.MEDIUM, manifest.path, "Packages/manifest.json could not be parsed as JSON.", evidence=str(exc), module="SceneSentry", confidence=Confidence.HIGH, remediation="Fix the JSON syntax and validate the manifest in Unity."))
    guids = {m.text.split("guid:", 1)[1].split()[0].strip() for m in files if m.path.endswith(".meta") and m.text and "guid:" in m.text}
    for f in files:
        if f.text:
            for no, line in enumerate(f.text.splitlines(), 1):
                if re.search(r"\b(?:eval|exec)\s*\(", line):
                    out.append(finding("SCENE001", "Dynamic code execution", Severity.HIGH, f.path, "Dynamic execution was detected; review whether untrusted input can reach it.", no, line.strip(), module="SceneSentry", confidence=Confidence.HIGH, remediation="Avoid dynamic execution or strictly constrain and validate all inputs."))
        if f.text and f.path.endswith((".unity", ".prefab", ".asset")):
            for match in sorted(set(re.findall(r"guid:\s*([0-9a-fA-F]{32})", f.text))):
                if match not in guids and match.lower() not in {"0000000000000000e000000000000000", "0000000000000000f000000000000000"}:
                    out.append(finding("SCENE-MISSING-REF", "Unity GUID reference cannot be resolved", Severity.MEDIUM, f.path, "A serialized Unity reference points to a GUID with no local .meta declaration; package or built-in references may be valid.", evidence=f"guid: {match[:8]}…", module="SceneSentry", confidence=Confidence.MEDIUM, remediation="Verify the reference in Unity and restore the asset or remove the stale serialized reference."))
    for f in unreal_files:
        if f.text:
            try:
                data = json.loads(f.text)
                if not isinstance(data, dict): raise ValueError("root is not an object")
            except (json.JSONDecodeError, ValueError) as exc:
                out.append(finding("SCENE-UNREAL-MANIFEST", "Unreal project descriptor is malformed", Severity.MEDIUM, f.path, "The Unreal .uproject/.uplugin descriptor is not valid JSON.", evidence=str(exc), module="SceneSentry", confidence=Confidence.HIGH, remediation="Fix the descriptor JSON and validate it in Unreal Editor."))
    for f in files:
        lower = f.path.lower()
        if lower.endswith(".ma") and f.text:
            if not f.text.lstrip().startswith("//Maya"):
                out.append(finding("SCENE-MAYA-FORMAT", "Maya ASCII scene header is missing", Severity.MEDIUM, f.path, "The file uses the .ma extension but does not begin with a recognizable Maya ASCII header.", module="SceneSentry", confidence=Confidence.MEDIUM, remediation="Open and validate the scene in a compatible Maya version or restore the correct export."))
        if lower.endswith((".blend", ".mb", ".uasset", ".umap")) and f.size == 0:
            out.append(finding("SCENE-EMPTY-ASSET", "Engine asset file is empty", Severity.MEDIUM, f.path, "The asset file has zero bytes; this may indicate a failed export or placeholder.", module="SceneSentry", confidence=Confidence.HIGH, remediation="Verify the source asset and re-export it before release."))
        if f.size > large_file_bytes:
            out.append(finding("SCENE-LARGE-FILE", "Large project file may affect release size", Severity.MEDIUM, f.path, f"File size is {f.size} bytes; this is a heuristic, not measured runtime performance.", module="SceneSentry", confidence=Confidence.HIGH, remediation="Review compression, import settings, and whether the file belongs in the release."))
        if f.path.lower().endswith(tuple(IMAGE_EXT)) and f.text is None:
            width, height = f.metadata.get("width"), f.metadata.get("height")
            if width and height and max(width, height) > 4096:
                out.append(finding("SCENE-TEXTURE", "Oversized texture dimension is a potential risk", Severity.MEDIUM, f.path,
                    f"Measured image dimensions are {width}×{height}; this is a file heuristic, not a GPU-memory or FPS measurement.", module="SceneSentry", confidence=Confidence.HIGH,
                    remediation="Review import compression, max-size settings, mipmaps, and platform overrides in Unity.", metadata={"width": width, "height": height, "heuristic": True}))
    return out

def scene_sentry(files: list[FileRecord]) -> list[Finding]: return analyze(files)
