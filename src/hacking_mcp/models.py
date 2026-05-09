"""Core data models for hacking-mcp."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SafetyTier(Enum):
    """Safety classification for tools.

    SAFE: Read-only recon, info gathering, analysis. Always available.
    CAUTION: Active scanning, exploitation. Requires explicit target, logged.
    DANGEROUS: DDOS, RAT, payloads, phishing. Excluded from MCP by default.
    """

    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"


class InstallMethod(Enum):
    PIP = "pip"
    GO = "go"
    GEM = "gem"
    GIT_CLONE = "git_clone"
    APT = "apt"
    CURL = "curl"
    DOCKER = "docker"
    NPM = "npm"
    CARGO = "cargo"


@dataclass
class HackingToolDef:
    """Definition of a single security tool, ported from hackingtool's HackingTool class.

    This is pure data — no Rich UI, no os.system() calls. The MCP server uses
    these definitions to know what tools exist, how to run them, and how to
    classify them for safety purposes.
    """

    name: str  # Unique identifier, e.g. "nmap", "nuclei"
    title: str  # Display name, e.g. "Network Map (nmap)"
    description: str
    category: str  # e.g. "Information Gathering"
    install_commands: list[str] = field(default_factory=list)
    run_command: str = ""  # Template, e.g. "nmap {target}"
    project_url: str = ""
    tags: list[str] = field(default_factory=list)
    safety_tier: SafetyTier = SafetyTier.SAFE
    supported_os: list[str] = field(default_factory=lambda: ["linux", "macos"])
    requires_root: bool = False
    requires_wifi: bool = False
    requires_docker: bool = False
    archived: bool = False
    archived_reason: str = ""

    @property
    def executable(self) -> str:
        """Return the base executable name from run_command.

        Handles patterns like:
          "nmap {target}"                   → "nmap"
          "cd dir && sudo python3 foo.py"   → "python3"
          "sudo nmap -O -Pn {target}"       → "nmap"
        """
        if not self.run_command:
            return self.name
        cmd = self.run_command.strip()
        # Strip "cd dir &&" prefix
        if " && " in cmd:
            # Take everything after the last &&
            segments = cmd.split(" && ")
            cmd = segments[-1]
        # Strip sudo
        if cmd.startswith("sudo "):
            cmd = cmd[5:].strip()
        return cmd.split()[0] if cmd else self.name

    def can_run_on(self, system: str, has_wsl2: bool = False) -> bool:
        """Check if this tool can run on the given system/configuration."""
        if system in self.supported_os:
            return True
        if has_wsl2 and "linux" in self.supported_os:
            return True
        return False


@dataclass
class CategoryDef:
    """Definition of a tool category."""

    name: str  # e.g. "Information Gathering"
    description: str
    icon: str = ""  # Optional emoji/icon
    tools: list[HackingToolDef] = field(default_factory=list)


@dataclass
class RunResult:
    """Result of running a security tool."""

    tool_name: str
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    was_blocked: bool = False
    block_reason: str = ""
    output_file: str = ""  # Path to persisted asset result, if saved


class TaskStatus(Enum):
    """Background task execution states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TaskRecord:
    """Background task state, persisted to ~/.hacking-mcp/tasks/{task_id}.json."""

    task_id: str
    tool_name: str
    target: str
    status: TaskStatus
    created_at: str = ""  # ISO 8601 UTC
    options: str = ""
    category: str = ""
    confirm_authorized: bool = False
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    result: Optional["RunResult"] = None
    error: str = ""
    asset_scan_id: str = ""


@dataclass
class InstallRecord:
    """Install state for a single tool, persisted to ~/.hacking-mcp/installs/state.json."""

    tool_name: str
    installed: bool
    method: str = ""  # "pip", "apt", "go", "git_clone", etc.
    installed_at: str = ""  # ISO 8601
    version: str = ""
    error: str = ""
    steps_completed: int = 0
    steps_total: int = 0


@dataclass
class AssetRecord:
    """Per-asset metadata, persisted to ~/.hacking-mcp/assets/<sanitized>/index.json."""

    target: str
    sanitized: str
    first_seen: str = ""
    last_scanned: str = ""
    scan_count: int = 0
    scans: list[dict] = field(default_factory=list)


@dataclass
class ToolAvailability:
    """Availability status of a tool on the current system."""

    tool_name: str
    available: bool
    path: Optional[str] = None
    version: Optional[str] = None
    platform_supported: bool = True
