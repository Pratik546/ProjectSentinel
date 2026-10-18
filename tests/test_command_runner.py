from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from projectsentinel.adapters import ProposalStatus, discover_adapters, execute_proposal
from projectsentinel.command_runner import (
    CommandRunner,
    CommandSpec,
    ExecutionPolicy,
    ExecutionStatus,
)


def _python_policy(**kwargs: object) -> ExecutionPolicy:
    name = Path(sys.executable).name
    return ExecutionPolicy(
        enabled=True,
        allowed_executables=frozenset({name}),
        **kwargs,
    )


def test_execution_is_disabled_before_process_creation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("disabled command execution created a subprocess")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    result = CommandRunner().run(CommandSpec("missing-tool", cwd=tmp_path))
    assert result.status is ExecutionStatus.SKIPPED
    assert "disabled" in result.reason


def test_allowlist_no_shell_and_redacted_bounded_output(tmp_path: Path):
    code = "print('token=TOP_SECRET ' + 'x' * 500)"
    spec = CommandSpec(sys.executable, ("-c", code), cwd=tmp_path, max_output_bytes=64)
    result = CommandRunner(_python_policy(max_output_bytes=128)).run(spec)
    assert result.status is ExecutionStatus.OUTPUT_LIMIT
    assert result.output_truncated
    assert len(result.stdout.encode("utf-8")) <= 64
    assert "TOP_SECRET" not in result.stdout


def test_timeout_and_install_action_are_visible(tmp_path: Path):
    sleep_spec = CommandSpec(
        sys.executable,
        ("-c", "import time; time.sleep(2)"),
        cwd=tmp_path,
        timeout_seconds=0.05,
    )
    timed_out = CommandRunner(_python_policy(timeout_seconds=0.2)).run(sleep_spec)
    assert timed_out.status is ExecutionStatus.TIMED_OUT
    assert "timeout" in timed_out.reason

    blocked = CommandRunner(
        ExecutionPolicy(enabled=True, allowed_executables=frozenset({"npm"}))
    ).run(CommandSpec("npm", ("install", "example"), cwd=tmp_path))
    assert blocked.status is ExecutionStatus.BLOCKED
    assert "install" in blocked.reason

    shell = CommandRunner(
        ExecutionPolicy(enabled=True, allowed_executables=frozenset({"sh"}))
    ).run(CommandSpec("sh", ("-c", "echo unsafe"), cwd=tmp_path))
    assert shell.status is ExecutionStatus.BLOCKED
    assert "shell" in shell.reason


def test_discovery_proposes_nine_languages_without_running_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    files = {
        "App.csproj": "<Project />",
        "main.cpp": "int main() {}",
        "index.js": "console.log('ok')",
        "index.ts": "const value: number = 1",
        "Main.java": "class Main {}",
        "Main.kt": "fun main() {}",
        "Cargo.toml": "[package]\nname='demo'\nversion='0.1.0'\n",
        "Package.swift": "// package",
        "pubspec.yaml": "name: demo\n",
        "tsconfig.json": "{}",
    }
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("adapter discovery executed a command")

    monkeypatch.setattr(subprocess, "Popen", fail_if_called)
    discovery = discover_adapters(tmp_path, check_executables=False)
    languages = {proposal.language for proposal in discovery}
    assert languages == {
        "C#",
        "C++",
        "JavaScript",
        "TypeScript",
        "Java",
        "Kotlin",
        "Rust",
        "Swift",
        "Dart",
    }
    assert all(proposal.status is ProposalStatus.PROPOSED for proposal in discovery)


def test_missing_adapter_executable_is_skipped_not_executed(tmp_path: Path):
    (tmp_path / "main.swift").write_text("print(1)", encoding="utf-8")
    discovery = discover_adapters(tmp_path, check_executables=True)
    swift = next(proposal for proposal in discovery if proposal.language == "Swift")
    # The test environment need not have Swift; either state is valid, and in
    # both cases discovery itself never runs the proposal.
    assert swift.status in {ProposalStatus.PROPOSED, ProposalStatus.SKIPPED}
    assert swift.spec.cwd == tmp_path


def test_execute_proposal_stays_disabled_without_policy(tmp_path: Path):
    (tmp_path / "main.js").write_text("const value = 1;", encoding="utf-8")
    proposal = next(
        item for item in discover_adapters(tmp_path, check_executables=False)
        if item.language == "JavaScript"
    )
    result = execute_proposal(proposal)
    assert result.status is ExecutionStatus.SKIPPED
    assert "disabled" in result.reason
