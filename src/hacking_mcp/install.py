"""InstallManager — one-click tool installation engine.

Parses install_commands from tool definitions, classifies them by method,
and executes them sequentially via ToolRunner.run_raw().

All tools install into ~/.hacking-mcp/tools/ (the get_tools_dir() path).
Install state is persisted to ~/.hacking-mcp/installs/state.json.
"""

import json
import logging
import shlex
import shutil
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

# Chinese mirror sources for faster downloads
MIRRORS = {
    "pip": "https://pypi.tuna.tsinghua.edu.cn/simple",
    "apt": "http://mirrors.tuna.tsinghua.edu.cn/ubuntu",
    "go": "https://goproxy.cn,direct",
    "gem": "https://gems.ruby-china.com",
}


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

        # git clone — pass all original args, just resolve target directory path
        if first == "git" and len(tokens) >= 3 and tokens[1] == "clone":
            # Find the URL (first arg containing :// or github.com/ etc.)
            repo_url = ""
            for t in tokens[2:]:
                if "/" in t and not t.startswith("-"):
                    repo_url = t
                    break
            if not repo_url:
                return InstallStep(method="shell", command=tokens, cwd=cwd,
                                   description=f"git clone (no URL): {cmd_str[:80]}")

            repo_name = repo_url.rstrip("/").split("/")[-1]
            if repo_name.endswith(".git"):
                repo_name = repo_name[:-4]

            # Last positional arg is the target dir; replace with resolved path.
            # If no target dir arg, append resolved path.
            pos_args = [i for i, t in enumerate(tokens) if i >= 2 and not t.startswith("-")]
            # Exclude URL itself from positional args
            url_idx = tokens.index(repo_url, 2)
            target_args = [i for i in pos_args if i > url_idx]

            # Determine target dir: use user-specified dir if provided, else repo name
            if target_args:
                user_dir = tokens[target_args[-1]]
                if not user_dir.startswith("/") and not user_dir.startswith("~"):
                    user_dir = str(Path(tools_dir) / user_dir)
                resolved_target = user_dir
            else:
                resolved_target = str(Path(tools_dir) / repo_name)

            clone_cmd = list(tokens)
            if target_args:
                clone_cmd[target_args[-1]] = resolved_target
            else:
                clone_cmd.append(resolved_target)

            return InstallStep(
                method="git_clone",
                command=clone_cmd,
                cwd=tools_dir,
                description=f"Clone {repo_url}",
                clone_url=repo_url,
                clone_dir=resolved_target,
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

    # Packages required in WSL for building/installing security tools
    WSL_BOOTSTRAP_PACKAGES = [
        "python3", "python3-pip", "python3-venv",
        "git", "curl", "wget",
        "golang-go",
        "ruby", "ruby-dev",
        "build-essential",
    ]

    def __init__(self, runner: ToolRunner, registry: ToolRegistry,
                 proxy_env: dict[str, str] | None = None,
                 mirrors: dict[str, str] | None = None):
        self._runner = runner
        self._registry = registry
        self._proxy_env = proxy_env or {}
        self._mirrors = mirrors or {}
        self._state: dict[str, dict] = {}
        self._bootstrap_done = False
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

    # Commands to verify after bootstrap, with fallback install packages
    WSL_REQUIRED_COMMANDS = {
        "python3": "python3",
        "pip3": "python3-pip",
        "git": "git",
        "curl": "curl",
        "go": "golang-go",
        "gem": "ruby",
        "gcc": "build-essential",
    }

    def _wsl_root_cmd(self, cmd: str) -> list[str]:
        """Build a WSL command that runs as root (avoids sudo password prompt)."""
        return ["wsl", "-u", "root", "bash", "-c", cmd]

    async def _verify_wsl_command(self, cmd_name: str) -> bool:
        """Check if a command actually exists in WSL."""
        result = await self._runner.run_raw(
            cmd=["bash", "-c", f"command -v {shlex.quote(cmd_name)}"],
            timeout=10,
            description=f"Check if {cmd_name} exists in WSL",
        )
        # Non-zero exit is OK for missing commands
        return result.return_code == 0 and bool(result.stdout.strip())

    async def _bootstrap_wsl(self) -> str:
        """Ensure WSL has basic dev tools (pip, git, go, curl, etc.).

        Runs once per process. Uses wsl -u root to avoid sudo password prompts.
        After installing packages, verifies each command actually works.
        Returns error message if bootstrap fails, empty string on success.
        """
        if self._bootstrap_done:
            return ""

        from hacking_mcp.environment import ExecBackend
        if self._runner.env.backend != ExecBackend.WSL2:
            self._bootstrap_done = True  # No WSL → no bootstrap needed, mark done
            return ""

        # Check if we can reach WSL (cold start can take 15-30s)
        test = await self._runner.run_raw(
            cmd=["echo", "ok"],
            timeout=60,
            description="Test WSL connectivity (may take time if WSL was stopped)",
        )
        if "ok" not in test.stdout:
            return (
                f"WSL connectivity test failed: {test.stderr.strip() or 'no output'}.\n"
                "Ensure WSL is running: run 'wsl echo ok' in a terminal first."
            )

        logger.info("Checking WSL dev environment...")

        # Check each required command
        missing = []
        for cmd_name, pkg_name in self.WSL_REQUIRED_COMMANDS.items():
            if await self._verify_wsl_command(cmd_name):
                logger.info("  ✓ %s found", cmd_name)
            else:
                logger.info("  ✗ %s missing (needs %s)", cmd_name, pkg_name)
                missing.append(pkg_name)

        if not missing:
            # Even if all found, verify pip actually works
            pip_test = await self._runner.run_raw(
                cmd=["sh", "-c", "python3 -m pip --version 2>/dev/null || pip3 --version 2>/dev/null || true"],
                timeout=10,
                description="Verify pip works",
            )
            if not pip_test.stdout.strip():
                missing.append("python3-pip")
                logger.info("  ✗ pip not functional (will reinstall python3-pip)")

        if not missing:
            logger.info("WSL dev environment ready")
            return ""

        # Install missing packages one by one (as root, no sudo)
        # One-by-one gives clear error per package
        logger.info("Installing %d missing packages via apt-get...", len(missing))
        update_result = await self._runner.run_raw(
            cmd=self._wsl_root_cmd("apt-get update -qq 2>/dev/null"),
            timeout=180,  # 3 min for apt update on slow connections
            env=self._proxy_env or None,
            description="apt-get update (root)",
        )

        failed_packages = []
        for pkg in missing:
            result = await self._runner.run_raw(
                cmd=self._wsl_root_cmd(
                    f"DEBIAN_FRONTEND=noninteractive apt-get install -y {shlex.quote(pkg)} 2>&1"
                ),
                timeout=120,
                env=self._proxy_env or None,
                description=f"apt-get install {pkg}",
            )
            if result.return_code != 0:
                failed_packages.append(pkg)
                logger.warning("  ✗ %s install failed (exit %d): %s",
                             pkg, result.return_code, result.stderr[:200])
            else:
                logger.info("  ✓ %s installed", pkg)

        if failed_packages:
            # Try with sudo as fallback
            logger.info("Retrying %d packages with sudo...", len(failed_packages))
            for pkg in failed_packages[:]:
                result = await self._runner.run_raw(
                    cmd=["sh", "-c",
                         f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {shlex.quote(pkg)} 2>&1"],
                    timeout=120,
                    env=self._proxy_env or None,
                    description=f"sudo apt-get install {pkg}",
                )
                if result.return_code == 0:
                    failed_packages.remove(pkg)
                    logger.info("  ✓ %s installed via sudo", pkg)
                elif "sudo: no tty present" in result.stderr or "a password is required" in result.stderr:
                    logger.warning("  ✗ sudo requires password for %s — skipping", pkg)

        # Verify each missing command now works (login shell for PATH)
        still_missing = []
        for cmd_name in self.WSL_REQUIRED_COMMANDS:
            if await self._verify_wsl_command(cmd_name):
                logger.info("  ✓ %s now available", cmd_name)
            else:
                still_missing.append(cmd_name)

        if still_missing:
            # One more try: python3 -m pip
            if "pip3" in still_missing:
                pip_check = await self._runner.run_raw(
                    cmd=["sh", "-c", "python3 -m pip --version 2>/dev/null || true"],
                    timeout=10,
                    description="Check python3 -m pip",
                )
                if pip_check.stdout.strip():
                    still_missing.remove("pip3")

            if still_missing:
                return (
                    f"{len(still_missing)} packages installed but commands still not found: {', '.join(still_missing)}.\n"
                    f"This may be a PATH issue in non-login shells.\n"
                    f"Run manually in WSL: sudo apt-get install -y {' '.join(still_missing)}"
                )

        logger.info("WSL dev environment ready")
        self._bootstrap_done = True
        return ""

    async def install_tool(self, tool_name: str) -> InstallRecord:
        """Install a tool by executing its install_commands.

        Steps:
        0. Auto-bootstrap WSL with basic dev tools if needed
        1. Look up tool in registry
        2. Get install_commands
        3. Parse into InstallSteps
        4. Execute each step via runner.run_raw()
        5. Update state after each step
        6. Return InstallRecord
        """
        # Ensure WSL has basic tools
        bootstrap_error = await self._bootstrap_wsl()
        if bootstrap_error:
            return InstallRecord(
                tool_name=tool_name,
                installed=False,
                error=f"WSL environment not ready:\n{bootstrap_error}",
            )

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

        # Check for existing git repos — clean up stale/broken clones
        for step in all_steps:
            if step.method == "git_clone" and Path(step.clone_dir).exists():
                if (Path(step.clone_dir) / ".git").exists():
                    # Fresh clone is safer than git pull for partial/broken repos
                    logger.info("Git repo exists at %s, removing for fresh clone", step.clone_dir)
                    # (shutil already imported at top)
                    try:
                        shutil.rmtree(step.clone_dir)
                    except OSError:
                        pass
                else:
                    # Stale directory without .git — remove it
                    logger.info("Stale directory at %s, removing", step.clone_dir)
                    try:
                        Path(step.clone_dir).rmdir()
                    except OSError:
                        pass

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

            cmd = list(step.command)
            extra_env = dict(self._proxy_env or {})

            # ── Apply mirrors and command fixes ──
            if step.method == "pip":
                # pip → pip3, add mirror
                if cmd and cmd[0] == "pip":
                    cmd[0] = "pip3"
                # Ubuntu 24.04+ PEP 668: allow system installs when running as root
                if self._runner.env.backend.value == "wsl2":
                    for j, token in enumerate(cmd):
                        if token == "install" and j + 1 < len(cmd):
                            cmd.insert(j + 1, "--break-system-packages")
                            break

                # Insert mirror after "install" subcommand
                mirror = self._mirrors.get("pip", "")
                if mirror:
                    for j, token in enumerate(cmd):
                        if token == "install" and j + 1 < len(cmd):
                            cmd.insert(j + 1, "-i")
                            cmd.insert(j + 2, mirror)
                            break

            elif step.method == "go":
                if self._mirrors.get("go"):
                    extra_env["GOPROXY"] = self._mirrors["go"]

            elif step.method == "gem":
                # Use mirror for gem install
                mirror = self._mirrors.get("gem", "")
                if mirror:
                    for j, token in enumerate(cmd):
                        if token == "install" and j + 1 < len(cmd):
                            cmd.insert(j + 1, "--source")
                            cmd.insert(j + 2, mirror)
                            break

            # ── Strip sudo prefix, use run_as_root instead ──
            use_root = False
            if step.requires_sudo:
                use_root = True
            if step.method == "apt":
                use_root = True
            if use_root and cmd and cmd[0] == "sudo":
                cmd = cmd[1:]  # Strip sudo — run_as_root handles privilege

            # ── git clone: ensure target directory is clean ──
            if step.method == "git_clone" and step.clone_dir and Path(step.clone_dir).exists():
                logger.info("Clone target %s exists, removing", step.clone_dir)
                # (shutil already imported at top)
                try:
                    shutil.rmtree(step.clone_dir)
                except OSError:
                    pass

            result = await self._runner.run_raw(
                cmd=cmd,
                cwd=step.cwd,
                timeout=600,
                env=extra_env or None,
                description=step.description,
                run_as_root=use_root,
            )

            # ── pip fallback chain: pip3 → python3 -m pip → ensurepip ──
            if (result.return_code != 0 and step.method == "pip" and
                ("not found" in result.stderr.lower() or
                 "No module named pip" in result.stderr or
                 result.return_code == 127)):
                # Try python3 -m pip
                pip_cmd = ["python3", "-m", "pip"] + cmd[1:]
                logger.info("Retrying with python3 -m pip")
                result = await self._runner.run_raw(
                    cmd=pip_cmd, cwd=step.cwd, timeout=600,
                    env=extra_env or None, description=step.description,
                )
                if result.return_code != 0:
                    # Ubuntu 24.04+ PEP 668: --break-system-packages
                    if "externally-managed" in result.stderr:
                        logger.info("PEP 668 detected, retrying with --break-system-packages")
                        pep_cmd = list(pip_cmd)
                        pep_cmd.insert(2, "--break-system-packages")
                        result = await self._runner.run_raw(
                            cmd=pep_cmd, cwd=step.cwd, timeout=600,
                            env=extra_env or None, description=step.description,
                        )
                    if result.return_code != 0:
                        # Try ensurepip + retry
                        logger.info("Bootstrapping pip via ensurepip")
                        await self._runner.run_raw(
                            cmd=["sh", "-c", "python3 -m ensurepip --upgrade 2>/dev/null || true"],
                            timeout=60, description="ensurepip bootstrap",
                        )
                        result = await self._runner.run_raw(
                            cmd=pip_cmd, cwd=step.cwd, timeout=600,
                            env=extra_env or None, description=step.description,
                        )

            # ── Command not found → re-bootstrap and retry once ──
            if (result.return_code != 0 and not result.timed_out and
                ("command not found" in result.stderr.lower() or
                 "not found" in result.stderr.lower())):
                missing_cmd = cmd[0] if cmd else ""
                logger.info("Command '%s' not found, re-bootstrapping...", missing_cmd)
                self._bootstrap_done = False
                await self._bootstrap_wsl()
                result = await self._runner.run_raw(
                    cmd=cmd, cwd=step.cwd, timeout=600,
                    env=extra_env or None,
                    run_as_root=use_root,
                    description=f"{step.description} (retry after bootstrap)",
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
