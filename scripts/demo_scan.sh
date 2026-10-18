#!/usr/bin/env bash
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: bash scripts/demo_scan.sh /path/to/project [requirements.json]" >&2
  exit 2
fi
python - "$ROOT" "$1" "${2-}" <<'PY'
from pathlib import Path
import sys
from projectsentinel.scanner import analyze_project
from projectsentinel.report import html_report, json_report

root = Path(sys.argv[2]).expanduser()
requirements = Path(sys.argv[3]).expanduser() if len(sys.argv) > 3 and sys.argv[3] else None
result = analyze_project(root, requirements=requirements)
output = Path.cwd() / "reports"
output.mkdir(parents=True, exist_ok=True)
(output / "projectsentinel-report.json").write_text(json_report(result), encoding="utf-8")
(output / "projectsentinel-report.html").write_text(html_report(result), encoding="utf-8")
print(f"{len(result.findings)} findings; {len(result.files)} files inspected; {len(result.errors)} errors")
print(f"Reports: {output}")
PY
