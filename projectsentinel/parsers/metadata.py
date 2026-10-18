from typing import Any
try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None

def parse_metadata(text: str, suffix: str) -> dict[str, Any]:
    """Parse TOML using the stdlib; unsupported formats return an empty mapping."""
    if suffix.lower() in (".toml", ".tml") and tomllib:
        try:
            value = tomllib.loads(text)
            return value if isinstance(value, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}
