"""Read-only language adapter discovery and command proposals.

Discovery only inventories filenames and creates :class:`CommandProposal`
records.  It never invokes a compiler, package manager, test runner, or shell.
Use :func:`projectsentinel.command_runner.run_command` with an explicitly
enabled policy if a caller chooses to execute a proposal.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ClassVar, Iterable, Iterator, Sequence

from .command_runner import CommandResult, CommandRunner, CommandSpec, ExecutionPolicy, ExecutionStatus


class ProposalStatus(str, Enum):
    """Whether a discovered proposal can be offered to an enabled runner."""

    PROPOSED = "proposed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class CommandProposal:
    """A command suggested by an adapter, never an execution receipt."""

    language: str
    executable: str
    argv: tuple[str, ...]
    cwd: Path
    reason: str
    evidence: tuple[str, ...] = ()
    status: ProposalStatus = ProposalStatus.PROPOSED

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "cwd", Path(self.cwd))

    @property
    def command(self) -> tuple[str, ...]:
        return (self.executable, *self.argv)

    @property
    def args(self) -> tuple[str, ...]:
        return self.argv

    @property
    def spec(self) -> CommandSpec:
        """Convert the proposal into a runner request without executing it."""

        return CommandSpec(self.executable, self.argv, cwd=self.cwd)

    def to_command_spec(self) -> CommandSpec:
        return self.spec


@dataclass(frozen=True, slots=True)
class DiscoverySkip:
    """A language adapter state that needs to remain visible to callers."""

    language: str
    reason: str
    status: ProposalStatus = ProposalStatus.SKIPPED


@dataclass(frozen=True, slots=True)
class AdapterDiscovery:
    """Read-only discovery receipt.

    The object is iterable and indexable so simple integrations can use it as
    a sequence of proposals while richer integrations can inspect ``skipped``
    and ``detected_languages`` explicitly.
    """

    root: Path
    proposals: tuple[CommandProposal, ...] = ()
    skipped: tuple[DiscoverySkip, ...] = ()

    def __iter__(self) -> Iterator[CommandProposal]:
        return iter(self.proposals)

    def __len__(self) -> int:
        return len(self.proposals)

    def __getitem__(self, index: int) -> CommandProposal:
        return self.proposals[index]

    @property
    def detected_languages(self) -> tuple[str, ...]:
        values = {proposal.language for proposal in self.proposals}
        values.update(skip.language for skip in self.skipped)
        return tuple(sorted(values))


DEFAULT_DISCOVERY_IGNORES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "Library",
        "Temp",
        "obj",
        "Build",
        "build",
        "dist",
        ".idea",
    }
)


def _project_files(root: Path, *, max_files: int = 10_000) -> tuple[Path, ...]:
    """Bounded, symlink-free filename inventory for adapter discovery."""

    files: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in DEFAULT_DISCOVERY_IGNORES
            and not (current / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = current / filename
            if path.is_symlink() or not path.is_file():
                continue
            files.append(path)
            if len(files) >= max_files:
                return tuple(files)
    return tuple(files)


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _suffixes(paths: Iterable[Path]) -> set[str]:
    return {path.suffix.casefold() for path in paths}


def _names(paths: Iterable[Path]) -> set[str]:
    return {path.name.casefold() for path in paths}


def _files_with_suffix(paths: Sequence[Path], suffixes: frozenset[str]) -> list[Path]:
    return sorted(path for path in paths if path.suffix.casefold() in suffixes)


def _proposal(
    *,
    language: str,
    executable: str,
    argv: Sequence[str],
    cwd: Path,
    reason: str,
    evidence: Iterable[str] = (),
    check_executable: bool = True,
) -> CommandProposal:
    status = ProposalStatus.PROPOSED
    final_reason = reason
    if check_executable and shutil.which(executable) is None:
        status = ProposalStatus.SKIPPED
        final_reason = f"{reason}; executable '{executable}' is not available on PATH"
    return CommandProposal(
        language=language,
        executable=executable,
        argv=tuple(argv),
        cwd=cwd,
        reason=final_reason,
        evidence=tuple(evidence),
        status=status,
    )


class LanguageAdapter:
    """Base contract implemented by each language-specific adapter."""

    language: ClassVar[str] = ""
    extensions: ClassVar[frozenset[str]] = frozenset()
    marker_names: ClassVar[frozenset[str]] = frozenset()
    executable: ClassVar[str] = ""

    @property
    def name(self) -> str:
        return self.language

    def detects(self, files: Sequence[Path]) -> bool:
        names = _names(files)
        marker_found = any(
            name in self.marker_names
            or any(marker.startswith(".") and name.endswith(marker) for marker in self.marker_names)
            for name in names
        )
        return bool(_suffixes(files) & self.extensions or marker_found)

    def detect(self, root: str | Path) -> bool:
        """Inspect a project root without creating or running a command."""

        base = Path(root).expanduser().resolve()
        return base.is_dir() and self.detects(_project_files(base))

    def discover(
        self,
        root: str | Path,
        *,
        check_executables: bool = True,
    ) -> list[CommandProposal]:
        """Return this adapter's proposals without invoking a subprocess."""

        base = Path(root).expanduser().resolve()
        if not base.is_dir():
            return []
        files = _project_files(base)
        if not self.detects(files):
            return []
        return self.propose(base, files, check_executables=check_executables)

    def propose(
        self,
        root: Path,
        files: Sequence[Path],
        *,
        check_executables: bool = True,
    ) -> list[CommandProposal]:
        raise NotImplementedError


class CSharpAdapter(LanguageAdapter):
    language = "C#"
    extensions = frozenset({".cs"})
    marker_names = frozenset({".csproj", ".sln", ".slnx"})
    executable = "dotnet"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        projects = sorted(
            path for path in files if path.suffix.casefold() in {".csproj", ".sln", ".slnx"}
        )
        marker = _relative(root, projects[0]) if projects else "."
        return [
            _proposal(
                language=self.language,
                executable=self.executable,
                argv=("build", marker, "--no-restore"),
                cwd=root,
                reason="build C# without an implicit package restore",
                evidence=(_relative(root, projects[0]),) if projects else (),
                check_executable=check_executables,
            )
        ]


class CppAdapter(LanguageAdapter):
    language = "C++"
    extensions = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
    marker_names = frozenset({"cmakelists.txt", "makefile", "meson.build", ".vcxproj"})
    executable = "clang++"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        names = _names(files)
        if "cmakelists.txt" in names:
            return [
                _proposal(
                    language=self.language,
                    executable="cmake",
                    argv=("--build", "build", "--config", "Release", "--parallel", "1"),
                    cwd=root,
                    reason="build the existing CMake tree without invoking a shell",
                    evidence=(next(_relative(root, path) for path in files if path.name.casefold() == "cmakelists.txt"),),
                    check_executable=check_executables,
                )
            ]
        sources = _files_with_suffix(files, frozenset({".c", ".cc", ".cpp", ".cxx"}))
        if not sources:
            return []
        source = _relative(root, sources[0])
        return [
            _proposal(
                language=self.language,
                executable=self.executable,
                argv=("-fsyntax-only", source),
                cwd=root,
                reason="check one C++ translation unit without linking or running it",
                evidence=(source,),
                check_executable=check_executables,
            )
        ]


class JavaScriptAdapter(LanguageAdapter):
    language = "JavaScript"
    extensions = frozenset({".js", ".jsx", ".mjs", ".cjs"})
    marker_names = frozenset({"package.json"})
    executable = "node"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        sources = _files_with_suffix(files, self.extensions)
        if not sources:
            return [
                _proposal(
                    language=self.language,
                    executable="npm",
                    argv=("run", "test", "--if-present"),
                    cwd=root,
                    reason="run the existing JavaScript test script without installing packages",
                    evidence=("package.json",),
                    check_executable=check_executables,
                )
            ]
        source = _relative(root, sources[0])
        return [
            _proposal(
                language=self.language,
                executable=self.executable,
                argv=("--check", source),
                cwd=root,
                reason="check JavaScript syntax without executing the source file",
                evidence=(source,),
                check_executable=check_executables,
            )
        ]


class TypeScriptAdapter(LanguageAdapter):
    language = "TypeScript"
    extensions = frozenset({".ts", ".tsx", ".mts", ".cts"})
    marker_names = frozenset({"tsconfig.json"})
    executable = "tsc"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        names = _names(files)
        if "tsconfig.json" in names:
            args = ("--noEmit", "--pretty", "false", "--project", "tsconfig.json")
            evidence = ("tsconfig.json",)
        else:
            sources = _files_with_suffix(files, self.extensions)
            if not sources:
                return []
            source = _relative(root, sources[0])
            args = ("--noEmit", "--pretty", "false", source)
            evidence = (source,)
        return [
            _proposal(
                language=self.language,
                executable=self.executable,
                argv=args,
                cwd=root,
                reason="type-check TypeScript without emitting files or installing packages",
                evidence=evidence,
                check_executable=check_executables,
            )
        ]


class JavaAdapter(LanguageAdapter):
    language = "Java"
    extensions = frozenset({".java"})
    marker_names = frozenset({"pom.xml", "build.gradle", "build.gradle.kts", "gradlew"})
    executable = "javac"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        sources = _files_with_suffix(files, self.extensions)
        if len(sources) > 100:
            return []
        if sources:
            relative = tuple(_relative(root, path) for path in sources)
            return [
                _proposal(
                    language=self.language,
                    executable=self.executable,
                    argv=("-proc:none", "-Xlint:all", *relative),
                    cwd=root,
                    reason="compile Java sources with annotation processing disabled",
                    evidence=relative,
                    check_executable=check_executables,
                )
            ]
        return [
            _proposal(
                language=self.language,
                executable="mvn",
                argv=("--offline", "test"),
                cwd=root,
                reason="run the existing Java build offline without dependency installation",
                evidence=("pom.xml",),
                check_executable=check_executables,
            )
        ]


class KotlinAdapter(LanguageAdapter):
    language = "Kotlin"
    extensions = frozenset({".kt", ".kts"})
    marker_names = frozenset({"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"})
    executable = "kotlinc"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        sources = _files_with_suffix(files, self.extensions)
        if len(sources) > 100:
            return []
        if sources:
            relative = tuple(_relative(root, path) for path in sources)
            return [
                _proposal(
                    language=self.language,
                    executable=self.executable,
                    argv=("-Werror", *relative),
                    cwd=root,
                    reason="compile Kotlin sources with warnings treated as errors",
                    evidence=relative,
                    check_executable=check_executables,
                )
            ]
        return [
            _proposal(
                language=self.language,
                executable="gradle",
                argv=("--offline", "test"),
                cwd=root,
                reason="run the existing Kotlin build offline without dependency installation",
                evidence=("build.gradle",),
                check_executable=check_executables,
            )
        ]


class RustAdapter(LanguageAdapter):
    language = "Rust"
    extensions = frozenset({".rs"})
    marker_names = frozenset({"cargo.toml"})
    executable = "cargo"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        if "cargo.toml" in _names(files):
            return [
                _proposal(
                    language=self.language,
                    executable=self.executable,
                    argv=("check", "--offline"),
                    cwd=root,
                    reason="check the Rust package without fetching dependencies",
                    evidence=("Cargo.toml",),
                    check_executable=check_executables,
                )
            ]
        sources = _files_with_suffix(files, self.extensions)
        if not sources:
            return []
        source = _relative(root, sources[0])
        return [
            _proposal(
                language=self.language,
                executable="rustc",
                argv=("--emit=metadata", source),
                cwd=root,
                reason="type-check one Rust source file without running it",
                evidence=(source,),
                check_executable=check_executables,
            )
        ]


class SwiftAdapter(LanguageAdapter):
    language = "Swift"
    extensions = frozenset({".swift"})
    marker_names = frozenset({"package.swift"})
    executable = "swiftc"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        sources = _files_with_suffix(files, self.extensions)
        if not sources:
            if "package.swift" not in _names(files):
                return []
            return [
                _proposal(
                    language=self.language,
                    executable="swift",
                    argv=("test",),
                    cwd=root,
                    reason="run Swift package tests without invoking a shell",
                    evidence=("Package.swift",),
                    check_executable=check_executables,
                )
            ]
        source = _relative(root, sources[0])
        return [
            _proposal(
                language=self.language,
                executable=self.executable,
                argv=("-typecheck", source),
                cwd=root,
                reason="type-check Swift source without producing or running a binary",
                evidence=(source,),
                check_executable=check_executables,
            )
        ]


class DartAdapter(LanguageAdapter):
    language = "Dart"
    extensions = frozenset({".dart"})
    marker_names = frozenset({"pubspec.yaml"})
    executable = "dart"

    def propose(self, root: Path, files: Sequence[Path], *, check_executables: bool = True) -> list[CommandProposal]:
        if "pubspec.yaml" not in _names(files) and not _files_with_suffix(files, self.extensions):
            return []
        return [
            _proposal(
                language=self.language,
                executable=self.executable,
                argv=("analyze",),
                cwd=root,
                reason="analyze Dart sources without invoking pub install",
                evidence=("pubspec.yaml",) if "pubspec.yaml" in _names(files) else (),
                check_executable=check_executables,
            )
        ]


DEFAULT_ADAPTERS: tuple[LanguageAdapter, ...] = (
    CSharpAdapter(),
    CppAdapter(),
    JavaScriptAdapter(),
    TypeScriptAdapter(),
    JavaAdapter(),
    KotlinAdapter(),
    RustAdapter(),
    SwiftAdapter(),
    DartAdapter(),
)


def discover_adapters(
    root: str | Path,
    *,
    adapters: Sequence[LanguageAdapter] = DEFAULT_ADAPTERS,
    max_files: int = 10_000,
    check_executables: bool = True,
) -> AdapterDiscovery:
    """Discover language adapters and propose commands without running them."""

    if not isinstance(max_files, int) or isinstance(max_files, bool) or max_files <= 0:
        raise ValueError("max_files must be a positive integer")
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        return AdapterDiscovery(
            base,
            skipped=(DiscoverySkip("project", f"project root is not a directory: {base}"),),
        )
    files = _project_files(base, max_files=max_files)
    proposals: list[CommandProposal] = []
    skipped: list[DiscoverySkip] = []
    for adapter in adapters:
        if not adapter.detects(files):
            continue
        current = adapter.propose(base, files, check_executables=check_executables)
        if current:
            proposals.extend(current)
        else:
            skipped.append(
                DiscoverySkip(
                    adapter.language,
                    "language evidence was found, but the adapter could not produce a bounded command",
                )
            )
    return AdapterDiscovery(base, tuple(proposals), tuple(skipped))


def discover_commands(root: str | Path, **kwargs: object) -> AdapterDiscovery:
    """Alias emphasizing that returned commands are proposals only."""

    return discover_adapters(root, **kwargs)  # type: ignore[arg-type]


def execute_proposal(
    proposal: CommandProposal,
    *,
    policy: ExecutionPolicy | None = None,
) -> CommandResult:
    """Execute one proposal only through the explicit runner policy.

    A proposal marked ``skipped`` or ``blocked`` remains skipped here; callers
    must rediscover after changing tool availability rather than bypassing the
    adapter's safety state.
    """

    if proposal.status is not ProposalStatus.PROPOSED:
        return CommandResult(
            status=ExecutionStatus.SKIPPED,
            executable=proposal.executable,
            argv=proposal.argv,
            reason=proposal.reason,
        )
    return CommandRunner(policy or ExecutionPolicy()).run(proposal.spec)


__all__ = [
    "AdapterDiscovery",
    "CSharpAdapter",
    "CppAdapter",
    "DartAdapter",
    "DiscoverySkip",
    "JavaAdapter",
    "JavaScriptAdapter",
    "KotlinAdapter",
    "LanguageAdapter",
    "ProposalStatus",
    "CommandProposal",
    "RustAdapter",
    "SwiftAdapter",
    "TypeScriptAdapter",
    "DEFAULT_ADAPTERS",
    "discover_adapters",
    "discover_commands",
    "execute_proposal",
]
