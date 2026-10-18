#!/usr/bin/env bash
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python -c "from projectsentinel.scanner import analyze_project; from projectsentinel.report import json_report, html_report; from pathlib import Path; r=analyze_project(Path('$ROOT/examples/sample_unity_project'), requirements=Path('$ROOT/examples/sample_requirements.json')); Path('$ROOT/demo-report.json').write_text(json_report(r)); Path('$ROOT/demo-report.html').write_text(html_report(r)); print(f'{len(r.findings)} findings; {len(r.files)} files inspected')"
