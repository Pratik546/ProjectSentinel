"""Small, safe parsers for project metadata."""
from .common import parse_env, parse_requirements
from .metadata import parse_metadata
__all__ = ["parse_env", "parse_requirements", "parse_metadata"]
