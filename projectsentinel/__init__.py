"""Safe, deterministic project inspection primitives."""

from .models import Finding, ScanResult, Severity
from .scanner import analyze_project, scan_project
from .adapters import (
    AdapterDiscovery,
    CommandProposal,
    ProposalStatus,
    discover_adapters,
    discover_commands,
    execute_proposal,
)
from .command_runner import (
    CommandExecutionPolicy,
    CommandExecutionResult,
    CommandResult,
    CommandRunner,
    CommandSpec,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
    execute_command,
    run_command,
)

__all__ = [
    "AdapterDiscovery",
    "CommandExecutionPolicy",
    "CommandExecutionResult",
    "CommandProposal",
    "CommandResult",
    "CommandRunner",
    "CommandSpec",
    "ExecutionPolicy",
    "ExecutionResult",
    "ExecutionStatus",
    "Finding",
    "ProposalStatus",
    "ScanResult",
    "Severity",
    "analyze_project",
    "discover_adapters",
    "discover_commands",
    "execute_proposal",
    "execute_command",
    "run_command",
    "scan_project",
]
