"""Bounded filesystem scanner. It only reads files; it never executes them."""
from datetime import datetime, timezone
from time import monotonic
from pathlib import Path
from .models import FileRecord, ScanResult
from .security import read_bounded, safe_relative, sha256_bytes

def _image_dimensions(data: bytes, suffix: str) -> tuple[int, int] | None:
    """Read dimensions from common headers without decoding or executing image data."""
    import struct
    suffix = suffix.lower()
    if suffix == ".png" and data.startswith(b"\x89PNG") and len(data) >= 24:
        return struct.unpack(">II", data[16:24])
    if suffix in {".jpg", ".jpeg"} and data.startswith(b"\xff\xd8"):
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1; continue
            marker = data[i + 1]; i += 2
            if marker in (0xD8, 0xD9): continue
            length = int.from_bytes(data[i:i + 2], "big")
            if marker in range(0xC0, 0xC4) and i + 7 <= len(data):
                return int.from_bytes(data[i + 5:i + 7], "big"), int.from_bytes(data[i + 3:i + 5], "big")
            i += max(length, 2)
    return None

DEFAULT_IGNORES = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", "Library", "Temp", "obj", "Build", "build", "dist", ".idea"}
RETAIN_BINARY = {".onnx", ".tflite", ".pt", ".pth", ".uasset", ".umap", ".blend", ".fbx", ".glb", ".gltf", ".mlmodel", ".safetensors", ".pkl", ".joblib"}

def _detect_project_types(files: list[FileRecord]) -> list[str]:
    paths = {f.path for f in files}
    suffixes = {Path(f.path).suffix.lower() for f in files}
    types = []
    if "Packages/manifest.json" in paths or any(p.startswith("ProjectSettings/") for p in paths) or ".unity" in suffixes:
        types.append("Unity")
    if any(Path(p).suffix.lower() == ".uproject" for p in paths) or any(p.startswith("Config/") for p in paths) and ("Content" in paths or any(p.startswith("Content/") for p in paths)):
        types.append("Unreal Engine")
    if ".blend" in suffixes or any(Path(p).name == "blender_manifest.toml" for p in paths):
        types.append("Blender")
    if ".ma" in suffixes or ".mb" in suffixes or any(Path(p).name.lower().startswith("maya") for p in paths):
        types.append("Maya")
    if not types:
        types.append("General repository")
    return types

def scan_project(root: str | Path, *, max_bytes: int = 2_000_000, max_files: int = 25_000, ignores: set[str] | None = None) -> ScanResult:
    base = Path(root).expanduser().resolve()
    result = ScanResult(base)
    if not base.is_dir():
        result.errors.append(f"project root is not a directory: {base}")
        return result
    ignored = DEFAULT_IGNORES | (ignores or set())
    for path in sorted(base.rglob("*")):
        rel_path = path.relative_to(base)
        if path.is_symlink():
            result.skipped.append({"path": rel_path.as_posix(), "reason": "symlink"})
            continue
        if not path.is_file() or any(part in ignored for part in rel_path.parts):
            continue
        if len(result.files) >= max_files:
            result.skipped.append({"path": rel_path.as_posix(), "reason": "file limit"})
            continue
        try:
            if path.stat().st_size > max_bytes:
                result.skipped.append({"path": rel_path.as_posix(), "reason": "per-file size limit"})
                continue
            data = read_bounded(path, max_bytes)
            rel = safe_relative(path, base)
            text = None
            if b"\0" not in data:
                text = data.decode("utf-8", errors="replace")
            metadata = {}
            dimensions = _image_dimensions(data, path.suffix)
            if dimensions:
                metadata["width"], metadata["height"] = dimensions
            # Text is already retained for text analyzers. Binary payloads are
            # retained only for bounded formats with structural adapters so a
            # validator can inspect bytes without reopening or executing them.
            raw = data if (text is None or path.suffix.lower() in RETAIN_BINARY) else None
            result.files.append(FileRecord(rel, len(data), sha256_bytes(data), text, metadata, raw))
        except (OSError, ValueError, UnicodeError) as exc:
            result.errors.append(f"{safe_relative(path, base)}: {exc}")
    return result

def analyze_project(root: str | Path, *, max_bytes: int = 2_000_000, max_files: int = 25_000, ignores: set[str] | None = None, enabled: set[str] | None = None, requirements: str | Path | None = None, large_file_bytes: int = 25 * 1024 * 1024, vulnerability_database=None, dependency_database=None) -> ScanResult:
    """Scan a project and run all built-in, read-only analyzers."""
    started = monotonic()
    if vulnerability_database is None:
        vulnerability_database = dependency_database
    result = scan_project(root, max_bytes=max_bytes, max_files=max_files, ignores=ignores)
    result.started_at = datetime.now(timezone.utc).isoformat()
    result.metadata["project_types"] = _detect_project_types(result.files)
    code_extensions = {".py", ".cs", ".cpp", ".h", ".hpp", ".c", ".js", ".ts", ".java", ".go", ".rs", ".lua", ".rb", ".php", ".shader", ".usf", ".ush", ".mel", ".pyw"}
    asset_extensions = {".unity", ".prefab", ".asset", ".uasset", ".umap", ".blend", ".ma", ".mb", ".fbx", ".obj", ".gltf", ".glb", ".dae", ".abc"}
    result.metadata["code_files"] = sum(Path(f.path).suffix.lower() in code_extensions for f in result.files)
    result.metadata["asset_files"] = sum(Path(f.path).suffix.lower() in asset_extensions for f in result.files)
    from .modules import crash_lens, scene_sentry, scope_guard, trust_trail
    analyzers = {"SceneSentry": scene_sentry, "CrashLens": crash_lens, "TrustTrail": trust_trail, "ScopeGuard": scope_guard}
    for name, analyzer in analyzers.items():
        if enabled and name not in enabled:
            result.module_status[name] = "not run"
            continue
        try:
            kwargs = {"requirements": requirements} if name == "ScopeGuard" else {}
            if name == "TrustTrail":
                kwargs["vulnerability_database"] = vulnerability_database
            if name == "SceneSentry": kwargs["large_file_bytes"] = large_file_bytes
            result.findings.extend(analyzer(result.files, **kwargs))
            result.module_status[name] = "completed"
        except Exception as exc:  # one malformed artifact must not stop other modules
            result.errors.append(f"{name}: {type(exc).__name__}: {exc}")
            result.module_status[name] = "failed"
    unique = {f.finding_id: f for f in result.findings}
    result.findings = sorted(unique.values(), key=lambda f: (-int(f.severity), -int(f.confidence), f.path, f.rule_id, f.line or 0))
    result.duration_seconds = round(monotonic() - started, 4)
    return result

scan = analyze_project
