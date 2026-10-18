"""Security-oriented helpers: no execution, bounded reads, and redaction."""
import hashlib
import re
from pathlib import Path

SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|token|password|private[_-]?key)\s*[:=]\s*(['\"]?)[^\s'\"]+\2"),
    re.compile(r"\b(?:sk|ghp|github_pat|xox[baprs])-[-_A-Za-z0-9]{10,}\b"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.I | re.S),
    re.compile(r"(?i)(://[^:/\s]+:)[^@\s]+(@)"),
)

def redact(value: str) -> str:
    """Replace common credentials while retaining useful surrounding context."""
    result = value
    for pattern in SECRET_PATTERNS:
        result = pattern.sub(lambda m: m.group(0)[:m.group(0).find(":") + 1] + " [REDACTED]" if ":" in m.group(0) else "[REDACTED]", result)
    return result

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe_relative(path: Path, root: Path) -> str:
    """Return a stable relative path and reject paths escaping root."""
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(resolved_root).as_posix()
    except ValueError as exc:
        raise ValueError("path is outside project root") from exc

def read_bounded(path: Path, max_bytes: int = 1_048_576) -> bytes:
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"file exceeds {max_bytes} byte limit")
    return data
