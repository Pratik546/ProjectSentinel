# ProjectSentinel

ProjectSentinel is an offline-first release-readiness auditor for Unity, Unreal Engine, Blender, Maya, and general software repositories. It answers **“what should I fix before release?”** with deterministic evidence rather than a chatbot or a cloud service.

## Features

- **SceneSentry**: bounded inventory, duplicate-byte detection, Unity manifest/GUID checks, Unreal descriptor checks, Maya ASCII validation, Blender/Maya/Unreal asset inventory, and large-file/texture heuristics.
- **CrashLens**: repeated error signatures, occurrence counts, and stack-location hints from text logs.
- **TrustTrail**: conservative redacted credential detection, `.env` checks, dependency pinning checks, and explicit advisory-database limitations.
- **ScopeGuard**: requirements JSON validation, unverified requirement findings, and release evidence checks.
- **Cross-platform code and mobile checks**: source inventory across common languages, Python syntax parsing, merge-conflict detection, Android/iOS/Flutter/React Native project discovery, manifest/plist/debug configuration checks, and ML artifact inventory for ONNX, TensorFlow Lite, Core ML, PyTorch, Safetensors, and related formats.
- Shared typed findings, severity/confidence, deterministic IDs, safe relative paths, deduplication, escaped HTML and JSON exports.

No code is executed, dependencies are never installed, the scanned project is never modified, symlinks are skipped, and no network service is required. Source files are inventoried across common Python, C#, C/C++, JavaScript/TypeScript, Java, Go, Rust, Lua, Ruby, PHP, shader, MEL, and related extensions; static checks remain conservative and do not claim to prove runtime correctness.

## Quick start

Requires Python 3.12.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-lock.txt
streamlit run app.py
```

Enter a project directory in the sidebar, choose modules, and click **Scan Project**. The default exclusions include Git metadata, virtual environments, dependency folders, build output, caches, and Unity generated folders. Limits are configurable.

## 60-second judge demo

1. Run `streamlit run app.py`.
2. Keep the preloaded `examples/sample_unity_project` target or click **Use sample project**.
3. Click **Scan Project**.
4. Open **Findings & evidence** and inspect the duplicate asset, malformed manifest, repeated log error, redacted placeholder credential, and unverified requirement.
5. Open **Export report** and download the reviewable HTML report.

The product story is simple: choose a project, scan locally, review evidence, and export a report. Nothing is executed, modified, or uploaded.

## Why this is useful

Small teams often have assets, source code, logs, credentials, mobile configuration, and release requirements spread across one project. ProjectSentinel turns that scattered pre-release work into one explainable release gate: it shows what was checked, what failed, the file-level evidence, and the next action. It is intentionally honest about uncertainty instead of claiming that a static scan proves a game or app is safe.

For a buildathon presentation, demonstrate the before/after loop: start with the sample project, show the release gate and top actions, open one finding to prove its evidence and remediation, then export the HTML report. A winning result cannot be guaranteed, but this flow makes user value and technical proof visible in under two minutes.

## Demo

```bash
bash scripts/demo_scan.sh
```

The synthetic fixture under `examples/sample_unity_project` contains duplicate text assets, a malformed package manifest, an unresolved-looking GUID, a repeated log error, a nonfunctional placeholder credential, and unverified requirements. It is safe and contains no real credentials.

## Docker

```bash
docker compose up --build
```

Open <http://localhost:8501>. To inspect another project, set `PROJECTSENTINEL_TARGET` or use the read-only `./target:/target:ro` mount in `compose.yaml`. Docker build/run was not verified when Docker is unavailable; local tests remain the source of truth.

## Tests

```bash
python -m pytest -q
python -m compileall -q projectsentinel app.py
```

Tests use temporary fixtures and no internet. The JSON report has schema version `1.0`, a summary, module status, portable findings, skipped-file reasons, errors, and limitations. HTML is escaped and intentionally states it is not a security certification.

## Architecture

`projectsentinel/scanner.py` performs safe discovery and invokes analyzers. `models.py` defines the shared `Finding` and `ScanResult` contracts. Modules are in `projectsentinel/modules/`; parsers and security helpers are deliberately standard-library based. Add a module by implementing `analyze(files, **kwargs) -> list[Finding]`, registering it in `analyze_project`, and adding fixture-backed tests.

## Scope and limitations

This is evidence gathering, not proof of correctness, runtime performance, exploitability, or release safety. Python syntax is parsed locally; for other languages ProjectSentinel inventories source and performs conservative evidence checks, but does not replace the language compiler, type checker, linter, or test suite. Texture GPU memory/FPS, actual Unity/Unreal/Blender/Maya/mobile execution, deep proprietary binary internals, ML model accuracy/latency/safety, dependency vulnerability intelligence, Git history, and manual requirements are not claimed. Secret matches are conservative and can be false positives; all values are redacted. Review every finding before deleting or changing an asset.

## Privacy and security

Scans are local. Reports use relative paths by default. Files are bounded and read-only; absolute roots and complete secrets are not included in reports. Do not point the tool at sensitive directories you did not intend to inspect.

## License

MIT. See `LICENSE`.

## Contributing

Keep checks deterministic, evidence-based, redacted, and offline-capable. Add tests for malformed input, path boundaries, empty projects, and partial failures. Run the test and compile commands above before opening a pull request.
