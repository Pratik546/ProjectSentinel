"""Explicitly opt-in, bounded command execution for local project checks.

The normal ProjectSentinel scan never calls this module.  Callers that want to
run a proposed check must construct an :class:`ExecutionPolicy` with
``enabled=True`` and an executable allowlist.  Commands are always passed to
``subprocess.Popen`` as an argv list with ``shell=False``; package-installing
actions and shell interpreters are not accepted by the built-in policy.
"""

from __future__ import annotations

import math
import ntpath
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from time import monotonic, sleep
from typing import Iterable, Sequence

from .security import redact


MAX_TIMEOUT_SECONDS = 300.0
MAX_OUTPUT_BYTES = 10 * 1024 * 1024
MAX_ARGUMENTS = 256
MAX_ARGUMENT_BYTES = 8 * 1024


class ExecutionStatus(str, Enum):
    """The observable outcome of a command request."""

    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"
    # A compatibility spelling for callers that use the shorter name.
    TIMEOUT = "timed_out"
    OUTPUT_LIMIT = "output_limit"


# These are executable *names*, not paths.  Adapters only propose commands
# using this set.  A caller may provide a smaller or purpose-built allowlist.
DEFAULT_ALLOWED_EXECUTABLES = frozenset(
    {
        "cargo",
        "c++",
        "clang++",
        "cmake",
        "ctest",
        "csc",
        "dart",
        "dotnet",
        "gradle",
        "gradlew",
        "g++",
        "javac",
        "kotlinc",
        "mvn",
        "node",
        "npm",
        "rustc",
        "swift",
        "swiftc",
        "tsc",
    }
)

SHELL_EXECUTABLES = frozenset(
    {
        "bash",
        "cmd",
        "csh",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "shell",
        "wsl",
        "zsh",
    }
)

# This is intentionally independent from the executable allowlist.  An
# explicitly approved executable still cannot be used for package installs.
INSTALL_OR_MUTATION_ACTIONS = frozenset(
    {
        "add",
        "ci",
        "create",
        "download",
        "fetch",
        "generate",
        "init",
        "install",
        "login",
        "new",
        "publish",
        "package",
        "pub",
        "resolve",
        "remove",
        "restore",
        "uninstall",
        "update",
        "upgrade",
        "get",
    }
)


def _executable_name(value: str) -> str:
    """Return a stable basename for both POSIX and Windows-style paths."""

    # ntpath handles a Windows path even when tests run on a POSIX host.
    name = ntpath.basename(value.replace("/", "\\"))
    lowered = name.casefold()
    if lowered.endswith((".exe", ".cmd", ".bat", ".com")):
        name = name.rsplit(".", 1)[0]
    return name.casefold()


def _normalise_allowlist(values: Iterable[str]) -> frozenset[str]:
    names: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("allowed executable names must be non-empty strings")
        names.add(_executable_name(value))
    return frozenset(names)


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    """Limits applied to every command run by a :class:`CommandRunner`.

    ``enabled`` defaults to ``False`` so constructing a runner cannot execute
    a command by accident.  Time and output limits are upper bounds; a command
    may request smaller limits in its :class:`CommandSpec`.
    """

    enabled: bool = False
    allowed_executables: frozenset[str] = field(
        default_factory=lambda: DEFAULT_ALLOWED_EXECUTABLES
    )
    timeout_seconds: float = 30.0
    max_output_bytes: int = 128 * 1024

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a bool")
        object.__setattr__(self, "allowed_executables", _normalise_allowlist(self.allowed_executables))
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(f"timeout_seconds must be between 0 and {MAX_TIMEOUT_SECONDS:g}")
        if (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or self.max_output_bytes <= 0
            or self.max_output_bytes > MAX_OUTPUT_BYTES
        ):
            raise ValueError(f"max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}")

    @property
    def allowlist(self) -> frozenset[str]:
        return self.allowed_executables


# A descriptive alias is useful for integrations that call this a command
# execution policy rather than a general execution policy.
CommandExecutionPolicy = ExecutionPolicy


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """An argv command, never a shell command string."""

    executable: str
    argv: tuple[str, ...] = ()
    cwd: Path | str | None = None
    timeout_seconds: float | None = None
    max_output_bytes: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.executable, str) or not self.executable.strip():
            raise ValueError("executable must be a non-empty name")
        if any(ord(char) < 32 or ord(char) == 127 for char in self.executable):
            raise ValueError("executable cannot contain control characters")
        if isinstance(self.argv, (str, bytes)):
            raise TypeError("argv must be a sequence of argument strings")
        try:
            values = tuple(self.argv)
        except TypeError as exc:
            raise TypeError("argv must be a sequence of argument strings") from exc
        if any(not isinstance(value, str) for value in values):
            raise TypeError("argv must contain only strings")
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value) for value in values):
            raise ValueError("argv cannot contain control characters")
        if len(values) > MAX_ARGUMENTS:
            raise ValueError(f"argv cannot contain more than {MAX_ARGUMENTS} arguments")
        if any(len(value.encode("utf-8")) > MAX_ARGUMENT_BYTES for value in values):
            raise ValueError(f"each argv item must be at most {MAX_ARGUMENT_BYTES} bytes")
        object.__setattr__(self, "argv", values)

        if self.cwd is not None:
            cwd = Path(self.cwd).expanduser()
            if not cwd.is_dir():
                raise ValueError(f"cwd is not a directory: {cwd}")
            object.__setattr__(self, "cwd", cwd)
        if self.timeout_seconds is not None and (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(f"timeout_seconds must be between 0 and {MAX_TIMEOUT_SECONDS:g}")
        if self.max_output_bytes is not None and (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or self.max_output_bytes <= 0
            or self.max_output_bytes > MAX_OUTPUT_BYTES
        ):
            raise ValueError(f"max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}")

    @property
    def command(self) -> tuple[str, ...]:
        """The exact argv tuple that would be handed to the child process."""

        return (self.executable, *self.argv)

    @property
    def args(self) -> tuple[str, ...]:
        """Alias for callers that use ``args`` instead of ``argv``."""

        return self.argv


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Redacted receipt for a command request."""

    status: ExecutionStatus
    executable: str
    argv: tuple[str, ...] = ()
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    reason: str = ""
    duration_seconds: float = 0.0
    output_truncated: bool = False

    @property
    def command(self) -> tuple[str, ...]:
        return (self.executable, *self.argv)

    @property
    def succeeded(self) -> bool:
        return self.status is ExecutionStatus.COMPLETED

    @property
    def exit_code(self) -> int | None:
        """Compatibility spelling for integrations that use exit_code."""

        return self.returncode

    @property
    def timed_out(self) -> bool:
        return self.status is ExecutionStatus.TIMED_OUT

    @property
    def truncated(self) -> bool:
        return self.output_truncated

    @property
    def output(self) -> str:
        """Combined bounded output, useful for concise UI receipts."""

        if self.stdout and self.stderr:
            return f"{self.stdout}\n{self.stderr}"
        return self.stdout or self.stderr


# This alias keeps the public contract easy to discover for consumers that
# call receipts "execution results".
ExecutionResult = CommandResult
CommandExecutionResult = CommandResult


def _blocked_action(argv: Sequence[str]) -> str | None:
    """Return a package-mutating action present in argv, if any.

    We inspect all non-option tokens so commands such as ``npm run install``
    are blocked too.  Values following ordinary options are not executable
    actions, but checking them is conservative and avoids special-casing every
    package manager's option grammar.
    """

    for raw in argv:
        token = raw.strip().casefold()
        if not token or token == "--":
            continue
        if token.startswith("-"):
            continue
        if token in INSTALL_OR_MUTATION_ACTIONS:
            return token
    return None


def _redacted(value: str) -> str:
    return redact(value) if value else ""


class CommandRunner:
    """Run an allowlisted argv command only when explicitly enabled."""

    def __init__(self, policy: ExecutionPolicy | None = None) -> None:
        self.policy = policy or ExecutionPolicy()

    def _receipt(
        self,
        spec: CommandSpec,
        status: ExecutionStatus,
        started: float,
        *,
        reason: str = "",
        stdout: str = "",
        stderr: str = "",
        returncode: int | None = None,
        output_truncated: bool = False,
    ) -> CommandResult:
        return CommandResult(
            status=status,
            executable=_redacted(spec.executable),
            argv=tuple(_redacted(arg) for arg in spec.argv),
            stdout=_redacted(stdout),
            stderr=_redacted(stderr),
            returncode=returncode,
            reason=_redacted(reason),
            duration_seconds=round(monotonic() - started, 4),
            output_truncated=output_truncated,
        )

    def _resolve_executable(self, spec: CommandSpec) -> tuple[str | None, str | None]:
        name = _executable_name(spec.executable)
        if name in SHELL_EXECUTABLES:
            return None, f"shell executable is blocked: {name}"
        if name not in self.policy.allowed_executables:
            return None, f"executable is not allowlisted: {name}"

        resolved = shutil.which(spec.executable)
        if resolved is None:
            return None, f"allowlisted executable was not found: {name}"
        return resolved, None

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            process.terminate()
            process.wait(timeout=0.5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=0.5)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def run(self, spec: CommandSpec) -> CommandResult:
        """Execute ``spec`` according to the policy and return a receipt.

        The disabled branch is deliberately before executable resolution and
        process creation.  Discovery can therefore safely hand proposals to a
        caller that has not yet decided to enable execution.
        """

        if not isinstance(spec, CommandSpec):
            raise TypeError("run expects a CommandSpec")
        started = monotonic()
        if not self.policy.enabled:
            return self._receipt(
                spec,
                ExecutionStatus.SKIPPED,
                started,
                reason="command execution is disabled; enable it explicitly to run this command",
            )

        action = _blocked_action(spec.argv)
        if action:
            return self._receipt(
                spec,
                ExecutionStatus.BLOCKED,
                started,
                reason=f"package or project mutation command is blocked: {action}",
            )

        executable, reason = self._resolve_executable(spec)
        if executable is None:
            return self._receipt(
                spec,
                ExecutionStatus.BLOCKED,
                started,
                reason=reason or "command blocked",
            )

        timeout = spec.timeout_seconds or self.policy.timeout_seconds
        output_limit = spec.max_output_bytes or self.policy.max_output_bytes
        # Per-command limits may only tighten the policy, never widen it.
        timeout = min(timeout, self.policy.timeout_seconds)
        output_limit = min(output_limit, self.policy.max_output_bytes)

        try:
            process = subprocess.Popen(
                [executable, *spec.argv],
                cwd=str(spec.cwd) if spec.cwd is not None else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=os.name != "nt",
            )
        except (OSError, ValueError) as exc:
            return self._receipt(
                spec,
                ExecutionStatus.FAILED,
                started,
                reason=f"could not start command: {type(exc).__name__}: {exc}",
            )

        output: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        output_lock = threading.Lock()
        limit_reached = threading.Event()

        def collect(stream_name: str, stream: object) -> None:
            # Popen's PIPE is a BufferedReader; keeping the type broad avoids
            # exposing its implementation in this small helper.
            reader = stream  # type: ignore[assignment]
            try:
                while True:
                    chunk = reader.read(4096)
                    if not chunk:
                        return
                    with output_lock:
                        remaining = output_limit - sum(len(value) for value in output.values())
                        if remaining > 0:
                            output[stream_name].extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            limit_reached.set()
            except (OSError, ValueError):
                return

        threads = [
            threading.Thread(target=collect, args=(name, stream), daemon=True)
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
            if stream is not None
        ]
        for thread in threads:
            thread.start()

        outcome: ExecutionStatus | None = None
        deadline = monotonic() + timeout
        while process.poll() is None:
            if limit_reached.is_set():
                outcome = ExecutionStatus.OUTPUT_LIMIT
                self._terminate(process)
                break
            if monotonic() >= deadline:
                outcome = ExecutionStatus.TIMED_OUT
                self._terminate(process)
                break
            sleep(0.005)

        if outcome is None:
            # The process exited normally; wait briefly for reader threads to
            # drain the pipe buffers before making the receipt.
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                outcome = ExecutionStatus.TIMED_OUT
                self._terminate(process)
        for thread in threads:
            thread.join(timeout=0.5)

        stdout = bytes(output["stdout"]).decode("utf-8", errors="replace")
        stderr = bytes(output["stderr"]).decode("utf-8", errors="replace")
        returncode = process.returncode
        if outcome is None and limit_reached.is_set():
            outcome = ExecutionStatus.OUTPUT_LIMIT
        if outcome is None:
            outcome = ExecutionStatus.COMPLETED if returncode == 0 else ExecutionStatus.FAILED
        reason = ""
        if outcome is ExecutionStatus.TIMED_OUT:
            reason = f"command exceeded timeout of {timeout:g} seconds"
        elif outcome is ExecutionStatus.OUTPUT_LIMIT:
            reason = f"command output exceeded {output_limit} bytes"
        elif outcome is ExecutionStatus.FAILED:
            reason = f"command exited with status {returncode}"
        return self._receipt(
            spec,
            outcome,
            started,
            reason=reason,
            stdout=stdout,
            stderr=stderr,
            returncode=returncode,
            output_truncated=limit_reached.is_set(),
        )

    # ``execute`` reads naturally at call sites and is intentionally just an
    # alias; both names preserve the same explicit policy behavior.
    execute = run


def run_command(
    command: CommandSpec | str | Sequence[str],
    *,
    policy: ExecutionPolicy | None = None,
    enabled: bool | None = None,
    allowed_executables: Iterable[str] | None = None,
    cwd: Path | str | None = None,
    timeout_seconds: float | None = None,
    max_output_bytes: int | None = None,
) -> CommandResult:
    """Convenience wrapper around :class:`CommandRunner`.

    A string is treated as one executable name, never parsed as a shell
    command.  A sequence must contain the executable as its first item.
    ``enabled`` and limits are useful for small integrations that do not need
    to retain an explicit policy object.
    """

    if isinstance(command, CommandSpec):
        spec = command
    elif isinstance(command, str):
        spec = CommandSpec(command, cwd=cwd, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes)
    else:
        values = tuple(command)
        if not values:
            raise ValueError("command sequence cannot be empty")
        spec = CommandSpec(
            values[0],
            values[1:],
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    if policy is None:
        policy = ExecutionPolicy(
            enabled=False if enabled is None else enabled,
            allowed_executables=(
                DEFAULT_ALLOWED_EXECUTABLES
                if allowed_executables is None
                else frozenset(allowed_executables)
            ),
        )
    elif enabled is not None and enabled != policy.enabled:
        policy = ExecutionPolicy(
            enabled=enabled,
            allowed_executables=policy.allowed_executables,
            timeout_seconds=policy.timeout_seconds,
            max_output_bytes=policy.max_output_bytes,
        )
    return CommandRunner(policy).run(spec)


# A name that makes the opt-in boundary especially obvious in documentation.
execute_command = run_command


__all__ = [
    "CommandExecutionPolicy",
    "CommandExecutionResult",
    "CommandResult",
    "CommandRunner",
    "CommandSpec",
    "DEFAULT_ALLOWED_EXECUTABLES",
    "ExecutionPolicy",
    "ExecutionResult",
    "ExecutionStatus",
    "MAX_ARGUMENTS",
    "MAX_ARGUMENT_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "execute_command",
    "run_command",
]
