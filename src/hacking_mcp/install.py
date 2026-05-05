"""InstallManager — one-click tool installation engine.

Parses install_commands from tool definitions, classifies them by method,
and executes them sequentially via ToolRunner.run_raw().

All tools install into ~/.hacking-mcp/tools/ (the get_tools_dir() path).
Install state is persisted to ~/.hacking-mcp/installs/state.json.
"""

import json
import logging
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from hacking_mcp.models import InstallRecord
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.runner import ToolRunner
from hacking_mcp.environment import get_tools_dir, get_installs_dir

logger = logging.getLogger("hacking-mcp.install")


@dataclass
class InstallStep:
    """A single parsed install step."""

    method: str  # "git_clone", "pip", "apt", "go", "gem", "curl", "npm", "cargo", "shell"
    command: list[str]  # subprocess-ready command list
    cwd: str = ""  # working directory for this step
    requires_sudo: bool = False
    is_piped: bool = False  # uses bash -c wrapper (curated/safe case)
    description: str = ""
    clone_url: str = ""  # for git_clone
    clone_dir: str = ""  # for git_clone, the resolved target directory


class InstallCommandParser:
    """Parse raw install_commands strings into structured InstallStep lists."""

    @staticmethod
    def parse(cmd_str: str, tools_dir: str) -> list[InstallStep]:
        """Parse a single install command string into one or more InstallStep objects.

        Handles &&-chained commands, carries forward cd context.
        """
        if not cmd_str or not cmd_str.strip():
            return []

        steps: list[InstallStep] = []
        current_cwd = tools_dir

        # Split on && for multi-step commands
        segments = [s.strip() for s in cmd_str.split(" && ")]

        for segment in segments:
            if not segment:
                continue

            # Handle cd prefix
            if segment.startswith("cd "):
                dir_name = segment[3:].strip()
                # Handle quoted directory names
                if (dir_name.startswith('"') and dir_name.endswith('"')) or \
                   (dir_name.startswith("'") and dir_name.endswith("'")):
                    dir_name = dir_name[1:-1]
                # Resolve: if relative, prepend current_cwd
                if not dir_name.startswith("/") and not dir_name.startswith("~"):
                    current_cwd = str(Path(current_cwd) / dir_name)
                else:
                    current_cwd = dir_name
                continue

            # Detect sudo
            requires_sudo = False
            work_segment = segment
            if segment.startswith("sudo "):
                requires_sudo = True
                work_segment = segment[5:].strip()

            # Classify the command
            step = InstallCommandParser._classify(work_segment, current_cwd, tools_dir)
            step.requires_sudo = requires_sudo
            steps.append(step)

            # After git clone, keep cwd at tools_dir. The 'cd X' segment
            # (if present) handles navigating into the cloned directory.

        return steps

    @staticmethod
    def _classify(cmd_str: str, cwd: str, tools_dir: str) -> InstallStep:
        """Classify a single command segment into an InstallStep."""
        # Try shlex tokenization
        try:
            tokens = shlex.split(cmd_str)
        except ValueError:
            tokens = cmd_str.split()

        if not tokens:
            return InstallStep(method="shell", command=[], cwd=cwd, description=cmd_str)

        first = tokens[0].lower()

        # git clone
        if first == "git" and len(tokens) >= 3 and tokens[1] == "clone":
            repo_url = tokens[2]
            # Extract repo name from URL
            repo_name = repo_url.rstrip("/").split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]
            # Check if there's a custom target directory (4th argument)
            if len(tokens) >= 4:
                target_dir = tokens[3]
                if not target_dir.startswith("/") and not target_dir.startswith("~"):
                    target_dir = str(Path(tools_dir) / target_dir)
            else:
                target_dir = str(Path(tools_dir) / repo_name)

            return InstallStep(
                method="git_clone",
                command=["git", "clone", repo_url, target_dir],
                cwd=tools_dir,
                description=f"Clone {repo_url}",
                clone_url=repo_url,
                clone_dir=target_dir,
            )

        # pip install
        if first in ("pip", "pip3", "python3", "python"):
            if len(tokens) >= 3 and tokens[1] in ("install", "-m"):
                return InstallStep(
                    method="pip",
                    command=tokens,
                    cwd=cwd,
                    description=f"pip: {' '.join(tokens[1:])}",
                )
            # python3 -m pip install ...
            if len(tokens) >= 5 and tokens[1] == "-m" and tokens[2] == "pip":
                return InstallStep(
                    method="pip",
                    command=tokens,
                    cwd=cwd,
                    description=f"pip: {' '.join(tokens[3:])}",
                )

        # apt / apt-get
        if first in ("apt-get", "apt"):
            return InstallStep(
                method="apt",
                command=tokens,
                cwd=cwd,
                description=f"apt: {' '.join(tokens[1:])}",
            )

        # go install
        if first == "go" and len(tokens) >= 2:
            return InstallStep(
                method="go",
                command=tokens,
                cwd=cwd,
                description=f"go: {' '.join(tokens[1:])}",
            )

        # gem install
        if first == "gem" and len(tokens) >= 2:
            return InstallStep(
                method="gem",
                command=tokens,
                cwd=cwd,
                description=f"gem: {' '.join(tokens[1:])}",
            )

        # npm install
        if first == "npm":
            return InstallStep(
                method="npm",
                command=tokens,
                cwd=cwd,
                description=f"npm: {' '.join(tokens[1:])}",
            )

        # cargo
        if first == "cargo":
            return InstallStep(
                method="cargo",
                command=tokens,
                cwd=cwd,
                description=f"cargo: {' '.join(tokens[1:])}",
            )

        # curl | sh (piped)
        if first == "curl" and "|" in cmd_str:
            return InstallStep(
                method="curl_pipe_sh",
                command=["bash", "-c", cmd_str],
                cwd=cwd,
                is_piped=True,
                description=f"curl|sh: {cmd_str[:80]}",
            )

        # curl download
        if first == "curl":
            return InstallStep(
                method="curl",
                command=tokens,
                cwd=cwd,
                description=f"curl: {' '.join(tokens[1:])}",
            )

        # chmod
        if first == "chmod":
            return InstallStep(
                method="shell",
                command=tokens,
                cwd=cwd,
                description=f"chmod: {' '.join(tokens[1:])}",
            )

        # Everything else: shell command
        return InstallStep(
            method="shell",
            command=tokens,
            cwd=cwd,
            description=cmd_str[:80],
        )


class InstallManager:
    """Manages tool installation and install state persistence.

    On install, parses the tool's install_commands into InstallSteps
    and executes each sequentially via ToolRunner.run_raw().

    State is persisted to ~/.hacking-mcp/installs/state.json.
    """

    def __init__(self, runner: ToolRunner, registry: ToolRegistry):
        self._runner = runner
        self._registry = registry
        self._state: dict[str, dict] = {}
        self._load_state()

    @property
    def tools_dir(self) -> str:
        return str(get_tools_dir())

    @property
    def installs_dir(self) -> str:
        return str(get_installs_dir())

    def _state_path(self) -> Path:
        return Path(self.installs_dir) / "state.json"

    def _load_state(self) -> None:
        """Load install records from disk."""
        sp = self._state_path()
        if sp.exists():
            try:
                with open(sp, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._state = {}

    def _save_state(self) -> None:
        """Persist install records to disk."""
        sp = self._state_path()
        sp.parent.mkdir(parents=True, exist_ok=True)
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, ensure_ascii=False)

    def get_install_status(self, tool_name: str) -> InstallRecord:
        """Get install record for a tool."""
        data = self._state.get(tool_name, {})
        return InstallRecord(
            tool_name=tool_name,
            installed=data.get("installed", False),
            method=data.get("method", ""),
            installed_at=data.get("installed_at", ""),
            version=data.get("version", ""),
            error=data.get("error", ""),
            steps_completed=data.get("steps_completed", 0),
            steps_total=data.get("steps_total", 0),
        )

    def list_installs(self) -> dict[str, InstallRecord]:
        """Return all install records."""
        return {name: self.get_install_status(name) for name in self._state}

    def is_installed(self, tool_name: str) -> bool:
        """Check if a tool is fully installed."""
        return self._state.get(tool_name, {}).get("installed", False)

    async def install_tool(self, tool_name: str) -> InstallRecord:
        """Install a tool by executing its install_commands.

        Steps:
        1. Look up tool in registry
        2. Get install_commands
        3. Parse into InstallSteps
        4. Execute each step via runner.run_raw()
        5. Update state after each step
        6. Return InstallRecord
        """
        tool = self._registry.get_tool(tool_name)
        if not tool:
            return InstallRecord(
                tool_name=tool_name,
                installed=False,
                error=f"Unknown tool: {tool_name}",
            )

        install_cmds = tool.install_commands
        if not install_cmds:
            return InstallRecord(
                tool_name=tool_name,
                installed=False,
                error=f"No install commands defined for '{tool_name}'.",
            )

        # Check if already installed
        if self.is_installed(tool_name):
            existing = self.get_install_status(tool_name)
            logger.info("Tool '%s' already installed (method=%s)", tool_name, existing.method)
            return existing

        # Parse all install commands into steps
        all_steps: list[InstallStep] = []
        for cmd_str in install_cmds:
            steps = InstallCommandParser.parse(cmd_str, self.tools_dir)
            all_steps.extend(steps)

        if not all_steps:
            return InstallRecord(
                tool_name=tool_name,
                installed=False,
                error=f"Could not parse install commands for '{tool_name}'.",
            )

        # Determine primary install method
        primary_method = all_steps[0].method if all_steps else ""

        # Check for existing git repos (git pull instead of clone)
        for step in all_steps:
            if step.method == "git_clone" and Path(step.clone_dir).exists():
                if (Path(step.clone_dir) / ".git").exists():
                    logger.info("Git repo exists at %s, pulling instead", step.clone_dir)
                    step.command = ["git", "-C", step.clone_dir, "pull"]
                    step.description = f"git pull in {step.clone_dir}"
                    step.method = "git_pull"

        # Initialize state
        now = datetime.now(timezone.utc).isoformat()
        self._state[tool_name] = {
            "tool_name": tool_name,
            "installed": False,
            "method": primary_method,
            "installed_at": "",
            "version": "",
            "error": "",
            "steps_completed": 0,
            "steps_total": len(all_steps),
        }
        self._save_state()

        # Execute steps sequentially
        completed = 0
        for i, step in enumerate(all_steps):
            logger.info(
                "Install step %d/%d for '%s': %s [%s]",
                i + 1, len(all_steps), tool_name, step.method, step.description,
            )

            result = await self._runner.run_raw(
                cmd=step.command,
                cwd=step.cwd,
                timeout=600,  # 10 min per step
                description=step.description,
            )

            if result.return_code != 0 and not (
                # apt-get returns 100 for "no updates" — still OK
                step.method == "apt" and result.return_code == 100
            ):
                error_msg = (
                    f"Step {i + 1}/{len(all_steps)} failed: {step.description}\n"
                    f"Exit code: {result.return_code}\n"
                    f"Stderr: {result.stderr[:500]}"
                )
                self._state[tool_name].update({
                    "error": error_msg,
                    "steps_completed": i,
                })
                self._save_state()
                return InstallRecord(
                    tool_name=tool_name,
                    installed=False,
                    method=primary_method,
                    error=error_msg,
                    steps_completed=i,
                    steps_total=len(all_steps),
                )

            completed = i + 1
            self._state[tool_name]["steps_completed"] = completed
            self._save_state()

        # Success
        self._state[tool_name].update({
            "installed": True,
            "installed_at": now,
            "steps_completed": completed,
            "error": "",
        })
        self._save_state()

        # Refresh registry availability
        self._registry.refresh()

        return InstallRecord(
            tool_name=tool_name,
            installed=True,
            method=primary_method,
            installed_at=now,
            steps_completed=completed,
            steps_total=len(all_steps),
        )

    async def uninstall_tool(self, tool_name: str) -> bool:
        """Remove install state for a tool. Does NOT delete files."""
        if tool_name in self._state:
            del self._state[tool_name]
            self._save_state()
            logger.info("Uninstalled: %s", tool_name)
            return True
        return False
