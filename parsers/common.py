from pathlib import Path

def parse_env(text: str) -> dict[str, str]:
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values

def parse_requirements(text: str) -> list[str]:
    return sorted({line.split("#", 1)[0].strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", "-"))})
