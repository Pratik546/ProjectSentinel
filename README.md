# ProjectSentinel

ProjectSentinel is an offline-first release-readiness auditor for Unity, Unreal Engine, Blender, Maya, and general software repositories. It answers **“what should I fix before release?”** with deterministic evidence rather than a chatbot or a cloud service.

> **Buildathon pitch:** Point ProjectSentinel at a game or app project. It scans locally, finds evidence-backed release risks across code, assets, logs, security, mobile configuration, model artifacts, and requirements, then produces an explainable release gate and a shareable report. It never executes project code, modifies the project, or uploads source files.

**Demo outcome:** In under two minutes, judges can scan a real project, see a `REVIEW`/`BLOCKED`/`VERIFY` release decision, open the exact evidence behind a finding, and download the HTML report. The tool is designed to make uncertainty visible rather than pretending that static analysis proves runtime safety.

## Features

- **SceneSentry**: bounded inventory, duplicate-byte detection, Unity manifest/GUID checks, Unreal descriptor checks, Maya ASCII validation, Blender/Maya/Unreal asset inventory, and large-file/texture heuristics.
- **CrashLens**: repeated error signatures, occurrence counts, and stack-location hints from text logs.
- **TrustTrail**: conservative redacted credential detection, `.env` checks, dependency pinning checks, and explicit advisory-database limitations.
- **ScopeGuard**: requirements JSON validation, unverified requirement findings, and release evidence checks.
- **Cross-platform code and mobile checks**: source inventory across common languages, Python syntax parsing, merge-conflict detection, Android/iOS/Flutter/React Native project discovery, manifest/plist/debug configuration checks, and ML artifact inventory for ONNX, TensorFlow Lite, Core ML, PyTorch, Safetensors, and related formats.
- **Opt-in command checks**: read-only adapter discovery proposes bounded argv checks for C#, C++, JavaScript, TypeScript, Java, Kotlin, Rust, Swift, and Dart. Execution is disabled by default, uses an executable allowlist, never invokes a shell, blocks install actions, and reports skipped/blocked/timeout/output-limit states.
- **Verification plans**: every finding can produce manual and automated follow-up steps with explicit pass criteria. Proposed checks are never reported as passed until an external receipt exists.
- **Optional adapters**: bounded crash-log imports; Android/iOS manifest and permission checks; Unity/Unreal build-log evidence; Unity/Unreal asset validation; local exact-version dependency advisory matching; and structural ONNX, TensorFlow Lite, PyTorch, and related model checks.
- Shared typed findings, severity/confidence, deterministic IDs, safe relative paths, deduplication, escaped HTML and JSON exports.

Normal scans never execute code, install dependencies, modify the scanned project, or require a network service; symlinks are skipped. The separate command-check subsystem remains disabled unless a caller explicitly enables its allowlisted argv request, and it still blocks install actions and shell execution. Source files are inventoried across common Python, C#, C/C++, JavaScript/TypeScript, Java, Go, Rust, Lua, Ruby, PHP, shader, MEL, and related extensions; static checks remain conservative and do not claim to prove runtime correctness.

## Quick start

Requires Python 3.12.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-lock.txt
streamlit run app.py
```

Enter a project directory in the sidebar, choose modules, and click **Scan Project**. The default exclusions include Git metadata, virtual environments, dependency folders, build output, caches, and Unity generated folders. Limits are configurable.

ProjectSentinel does not require an API key or secret. If you want to preconfigure a local target, copy `.env.example` to `.env` and set `PROJECTSENTINEL_TARGET`; never commit real credentials.

## Quick live-project demo

1. Run `streamlit run app.py`.
2. Enter the folder of a real game, app, repository, or asset project.
3. Click **Scan Project**.
4. Open **Findings & evidence** and inspect the file-level evidence and remediation.
5. Open **Export report** and download the reviewable HTML report.

For a terminal scan and report export:

```bash
bash scripts/demo_scan.sh /path/to/project
# Optional requirements evidence:
bash scripts/demo_scan.sh /path/to/project /path/to/requirements.json
```

Reports are written to `reports/`, which is ignored by Git. The repository intentionally does not include a bundled sample project; use your own project or temporary test fixtures.

## Crash-log workflow

1. Open the sidebar's **Import crash logs** control and choose the `.log`, `.trace`, `.crash`, `.ips`, or named crash-text files exported from the real device or engine.
2. Click **Import selected crash logs**. CrashLens reads the bounded files in memory and adds redacted, relative-path findings to the current scan.
3. Open **Crash logs** to review the detected format, signature, line, and occurrence count. Documentation and source files are not treated as crash logs.
4. Click **Download CrashLens evidence JSON** to save the redacted findings, file hashes, and imported-log receipt. Raw log bodies are intentionally not embedded; keep the original logs separately when a release reviewer needs them.

ProjectSentinel does not download logs from a phone, engine, or cloud service. Export the log using the platform's normal developer tooling first, then import that local file. The evidence download is a review receipt, not a replacement for the original diagnostic artifact.

## Optional verification adapters

Normal scans are read-only and never run project commands. If a developer explicitly enables verification execution in the UI or calls the runner API, ProjectSentinel accepts only adapter-provided argv commands, checks an executable allowlist, uses `shell=False`, applies timeout/output bounds, blocks install/mutation actions, and records a redacted receipt. This is not an OS sandbox; explicitly enabled tools may still write files or access the network according to their own behavior.

Optional local dependency intelligence can be supplied through the adapter API with an exact package/version database. Without that database, ProjectSentinel reports that vulnerability intelligence was not checked; it does not infer vulnerabilities from package names.

## Why this is useful

Small teams often have assets, source code, logs, credentials, mobile configuration, and release requirements spread across one project. ProjectSentinel turns that scattered pre-release work into one explainable release gate: it shows what was checked, what failed, the file-level evidence, and the next action. It is intentionally honest about uncertainty instead of claiming that a static scan proves a game or app is safe.

For a buildathon presentation, demonstrate the loop on a small project: show the release gate and top actions, open one finding to prove its evidence and remediation, then export the HTML report. A winning result cannot be guaranteed, but this flow makes user value and technical proof visible in under two minutes.

The dashboard keeps a real scan receipt: target folder, scan ID, recorded timestamp, enabled modules, files inspected, skipped files, duration, module status, and errors. If you change scan controls after a scan, the result is marked **STALE** and report downloads are disabled until you scan again.

## Docker

```bash
docker compose up --build
```

Open <http://localhost:8501>. The supplied Compose file mounts the current directory read-only at `/workspace`. To inspect another project, change the mount source and set `PROJECTSENTINEL_TARGET` to its container path. Verify the container with `docker compose up --build`; a successful image build alone does not verify that the running container is healthy. The repository currently has no GitHub Actions workflow, so local test results should not be confused with a new CI run.

## Tests

```bash
python -m pytest -q
python -m compileall -q projectsentinel app.py
# Or run both checks together:
bash scripts/run_tests.sh
```

Tests use temporary fixtures and no internet. The JSON report has schema version `1.1`, a summary, module status, portable findings, verification plans, adapter status, imported crash-log receipts, skipped-file reasons, errors, and limitations. HTML is escaped and intentionally states it is not a security certification.

## Architecture

`projectsentinel/scanner.py` performs safe discovery and invokes analyzers. `models.py` defines the shared `Finding` and `ScanResult` contracts. Modules are in `projectsentinel/modules/`; parsers and security helpers are deliberately standard-library based. `projectsentinel/command_runner.py` owns the disabled-by-default execution boundary, while `projectsentinel/language_adapters_impl.py` discovers language evidence and proposes commands without running them. Add a module by implementing `analyze(files, **kwargs) -> list[Finding]`, registering it in `analyze_project`, and adding fixture-backed tests.

## Scope and limitations

This is evidence gathering, not proof of correctness, runtime performance, exploitability, or release safety. Python syntax is parsed locally; for other languages ProjectSentinel inventories source and proposes opt-in toolchain checks, but does not replace the language compiler, type checker, linter, or test suite. Texture GPU memory/FPS, actual Unity/Unreal/Blender/Maya/mobile execution, deep proprietary binary internals, ML model accuracy/latency/safety, dependency vulnerability intelligence without a supplied local database, Git history, and manual requirements are not claimed. Secret matches are conservative and can be false positives; all values are redacted. Review every finding before deleting or changing an asset.

## Privacy and security

Scans are local. Reports use relative paths by default. Files are bounded and read-only; absolute roots and complete secrets are not included in reports. Do not point the tool at sensitive directories you did not intend to inspect.

## License

MIT. See `LICENSE`.

## Contributing

Keep checks deterministic, evidence-based, redacted, and offline-capable. Add tests for malformed input, path boundaries, empty projects, and partial failures. Run the test and compile commands above before opening a pull request.
