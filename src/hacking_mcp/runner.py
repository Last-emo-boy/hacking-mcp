"""ToolRunner — safe async subprocess execution with safety gates and WSL2 support.

On Windows, Linux-only tools are executed through WSL2.
On Linux/macOS, tools run natively.
"""

import asyncio
import logging
import time
from typing import Optional

from hacking_mcp.models import HackingToolDef, RunResult
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.environment import (
    ExecBackend,
    Environment,
    detect_environment,
    get_tools_dir,
    to_wsl_path,
)
from hacking_mcp.command import (
    ParsedCommand,
    parse_command,
    build_command,
)

logger = logging.getLogger("hacking-mcp.runner")

# Lazy-initialized environment
_env: Optional[Environment] = None


def get_environment() -> Environment:
    """Get the current execution environment (lazy, cached)."""
    global _env
    if _env is None:
        _env = detect_environment()
    return _env


class ToolRunner:
    """The sole execution pathway for all security tools.

    Enforces safety policy before execution. Uses asyncio subprocess
    for non-blocking execution. Applies timeouts, output size caps,
    and audit logging. Never uses shell=True.

    On Windows, Linux-only tools are automatically routed through WSL2.
    """

    def __init__(self, registry: ToolRegistry, safety: SafetyPolicy):
        self.registry = registry
        self.safety = safety
        self.env = get_environment()
        self._current_proc: Optional["asyncio.subprocess.Process"] = None

    async def run(
        self,
        tool_name: str,
        args: Optional[list[str]] = None,
        timeout: int = 300,
        env: Optional[dict] = None,
    ) -> RunResult:
        """Run a tool safely, adapting to the current OS environment.

        Args:
            tool_name: Name of the tool to run (e.g., 'nmap')
            args: Arguments to pass to the tool. First arg is typically the target.
            timeout: Maximum execution time in seconds
            env: Optional extra environment variables

        Returns:
            RunResult with stdout, stderr, return code, timing info
        """
        args = args or []

        # Look up tool definition
        tool = self.registry.get_tool(tool_name)
        if tool is None:
            return RunResult(
                tool_name=tool_name,
                command=[],
                return_code=-1,
                stdout="",
                stderr=f"Unknown tool: {tool_name}",
                duration_ms=0,
                was_blocked=True,
                block_reason=f"Tool '{tool_name}' not found in registry.",
            )

        # Safety check
        allowed, reason = self.safety.check_tool(tool)
        if not allowed:
            self.safety.log_invocation(tool_name, "", args, allowed=False)
            return RunResult(
                tool_name=tool_name,
                command=[],
                return_code=-1,
                stdout="",
                stderr=reason,
                duration_ms=0,
                was_blocked=True,
                block_reason=reason,
            )

        # Check if tool can run on this OS
        if not self._can_run(tool):
            avail = self.registry.get_availability(tool_name)
            return RunResult(
                tool_name=tool_name,
                command=[],
                return_code=-1,
                stdout="",
                stderr=(
                    f"Tool '{tool_name}' cannot run on {self.env.system}.\n"
                    f"Supported OS: {', '.join(tool.supported_os)}.\n"
                    + (
                        f"WSL2 is available — ensure the tool is installed in your WSL distro."
                        if self.env.backend == ExecBackend.WSL2
                        else "Install WSL2 to run Linux tools on Windows."
                    )
                ),
                duration_ms=0,
                was_blocked=True,
                block_reason=f"Platform not supported: {self.env.system}",
            )

        # Check availability
        if not self.registry.is_available(tool_name):
            install_cmds = self.registry.get_install_commands(tool_name)
            msg = f"Tool '{tool_name}' is not installed."
            if install_cmds:
                msg += "\n\n**Install commands (run in WSL2 terminal):**\n"
                for cmd in install_cmds:
                    msg += f"```bash\n{cmd}\n```\n"
            return RunResult(
                tool_name=tool_name,
                command=[],
                return_code=-1,
                stdout="",
                stderr=msg,
                duration_ms=0,
                was_blocked=True,
                block_reason="Not installed",
            )

        # Build the command adapted to the execution environment
        target = args[0] if args else ""
        extra_args = args[1:] if len(args) > 1 else []

        parsed = parse_command(tool.run_command, target)
        # Append extra user args to the parsed args
        if extra_args:
            parsed.args.extend(extra_args)

        # Add chdir prefix if tool needs it
        if parsed.chdir:
            tools_dir = str(get_tools_dir())
            if not parsed.chdir.startswith("/") and not parsed.chdir.startswith("~"):
                parsed.chdir = f"{tools_dir}/{parsed.chdir}"

        # Build final command list for the execution backend
        cmd = build_command(parsed, self.env.backend, distro=self.env.wsl_distro)

        if not cmd:
            return RunResult(
                tool_name=tool_name,
                command=[],
                return_code=-1,
                stdout="",
                stderr=f"No run command defined for '{tool_name}'. This tool may be web-based or archived.",
                duration_ms=0,
            )

        timeout = min(timeout, self.safety.max_timeout_seconds)

        self.safety.log_invocation(tool_name, target, args, allowed=True)
        logger.info("Running [%s]: %s (timeout=%ds)", self.env.backend.value, " ".join(cmd), timeout)

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            self._current_proc = proc
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                timed_out = False
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                stdout_bytes, stderr_bytes = b"", b"[Command timed out]"
                timed_out = True

            duration_ms = int((time.monotonic() - start) * 1000)

            max_bytes = self.safety.max_output_bytes
            stdout = stdout_bytes.decode("utf-8", errors="replace")[:max_bytes]
            stderr = stderr_bytes.decode("utf-8", errors="replace")[:max_bytes]

            return RunResult(
                tool_name=tool_name,
                command=cmd,
                return_code=proc.returncode or -1,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=timed_out,
            )

        except FileNotFoundError:
            duration_ms = int((time.monotonic() - start) * 1000)
            exe = parsed.executable or tool.run_command.split()[0]
            return RunResult(
                tool_name=tool_name,
                command=cmd,
                return_code=-1,
                stdout="",
                stderr=(
                    f"Command not found: {exe}. Is {tool_name} installed?\n"
                    + (
                        f"Make sure it's installed in your WSL2 distro."
                        if self.env.backend == ExecBackend.WSL2
                        else "Install it via your package manager or from source."
                    )
                ),
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.exception("Error running %s", tool_name)
            return RunResult(
                tool_name=tool_name,
                command=cmd,
                return_code=-1,
                stdout="",
                stderr=f"Error executing {tool_name}: {e}",
                duration_ms=duration_ms,
            )
        finally:
            self._current_proc = None

    def _can_run(self, tool: HackingToolDef) -> bool:
        """Check if a tool can run in the current environment."""
        # If native OS is in supported list, always OK
        if self.env.system in tool.supported_os:
            return True
        # On Windows with WSL2, Linux tools can run
        if self.env.backend == ExecBackend.WSL2 and "linux" in tool.supported_os:
            return True
        # On macOS — no WSL2 fallback, only native + explicitly supported
        return False

    def kill_current(self) -> None:
        """Kill the currently running subprocess, if any."""
        proc = self._current_proc
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass

    async def run_raw(
        self,
        cmd: list[str],
        cwd: str = "",
        timeout: int = 900,
        env: Optional[dict] = None,
        description: str = "",
    ) -> RunResult:
        """Run an arbitrary command with WSL2 routing, timeout, and output truncation.

        Unlike run(), this does NOT look up the tool in the registry, apply safety
        checks, or parse a run_command template. It directly executes the given
        command list. Used for install commands and other non-tool execution.

        On WSL2, the command is wrapped in: wsl [-d distro] bash -c "<cmd>"

        Args:
            cmd: Command list to execute (e.g. ["git", "clone", url])
            cwd: Optional working directory (on WSL2, translated to /mnt/ path)
            timeout: Maximum execution time in seconds (default 900s for installs)
            env: Optional extra environment variables
            description: Human-readable description for logging

        Returns:
            RunResult with stdout, stderr, return code, timing info
        """
        if not cmd:
            return RunResult(
                tool_name="raw",
                command=[],
                return_code=-1,
                stdout="",
                stderr="Empty command",
                duration_ms=0,
            )

        # Build command for the execution backend
        if self.env.backend == ExecBackend.WSL2:
            # Wrap for WSL2 execution
            import shlex
            # Build bash command string
            if cwd:
                wsl_cwd = to_wsl_path(cwd) if ":" in cwd else cwd
                bash_cmd = f"cd {shlex.quote(wsl_cwd)} && {' '.join(shlex.quote(a) for a in cmd)}"
            else:
                bash_cmd = " ".join(shlex.quote(a) for a in cmd)
            exec_cmd = ["wsl"]
            if self.env.wsl_distro:
                exec_cmd.extend(["-d", self.env.wsl_distro])
            exec_cmd.extend(["bash", "-c", bash_cmd])
        else:
            # Native execution
            exec_cmd = list(cmd)

        timeout = min(timeout, self.safety.max_timeout_seconds)

        desc = description or " ".join(cmd)
        logger.info("run_raw [%s]: %s (timeout=%ds)", self.env.backend.value, desc, timeout)

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *exec_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd if self.env.backend != ExecBackend.WSL2 else None,
                env=env,
            )
            self._current_proc = proc
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                timed_out = False
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                stdout_bytes, stderr_bytes = b"", b"[Command timed out]"
                timed_out = True

            duration_ms = int((time.monotonic() - start) * 1000)

            max_bytes = self.safety.max_output_bytes
            stdout = stdout_bytes.decode("utf-8", errors="replace")[:max_bytes]
            stderr = stderr_bytes.decode("utf-8", errors="replace")[:max_bytes]

            return RunResult(
                tool_name="raw",
                command=exec_cmd,
                return_code=proc.returncode or -1,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=timed_out,
            )

        except FileNotFoundError:
            duration_ms = int((time.monotonic() - start) * 1000)
            return RunResult(
                tool_name="raw",
                command=exec_cmd,
                return_code=-1,
                stdout="",
                stderr=f"Command not found: {cmd[0] if cmd else 'unknown'}",
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.exception("Error running raw command: %s", desc)
            return RunResult(
                tool_name="raw",
                command=exec_cmd,
                return_code=-1,
                stdout="",
                stderr=f"Error executing command: {e}",
                duration_ms=duration_ms,
            )
        finally:
            self._current_proc = None

    def dry_run(self, tool_name: str, args: Optional[list[str]] = None) -> str:
        """Return the command that would be executed (for debugging)."""
        tool = self.registry.get_tool(tool_name)
        if tool is None:
            return f"# Unknown tool: {tool_name}"
        args = args or []
        target = args[0] if args else ""
        extra_args = args[1:] if len(args) > 1 else []

        parsed = parse_command(tool.run_command, target)
        if extra_args:
            parsed.args.extend(extra_args)

        if parsed.chdir:
            tools_dir = str(get_tools_dir())
            if not parsed.chdir.startswith("/") and not parsed.chdir.startswith("~"):
                parsed.chdir = f"{tools_dir}/{parsed.chdir}"

        cmd = build_command(parsed, self.env.backend, distro=self.env.wsl_distro)
        return " ".join(cmd) if cmd else f"# No run command for {tool_name}"

    def get_install_instructions(self, tool_name: str) -> list[str]:
        """Return install commands for a tool (informational only).

        On WSL2, commands should be run inside a WSL terminal.
        """
        return self.registry.get_install_commands(tool_name)

    def get_environment_info(self) -> dict:
        """Return information about the current execution environment."""
        return {
            "system": self.env.system,
            "backend": self.env.backend.value,
            "wsl_available": self.env.wsl_available,
            "wsl_distro": self.env.wsl_distro,
            "tools_dir": str(get_tools_dir()),
        }
