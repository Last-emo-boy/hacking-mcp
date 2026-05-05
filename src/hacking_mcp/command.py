"""Command parser and builder — adapts tool run_command for native/WSL2 execution.

Parses run_command templates into structured commands, then builds
executable command lists for the target environment (native or WSL2).
"""

import shlex
from dataclasses import dataclass, field

from hacking_mcp.environment import ExecBackend, to_wsl_path


@dataclass
class ParsedCommand:
    """A run_command broken into structured parts."""

    chdir: str | None = None  # "cd <dir> && ..." directory
    sudo: bool = False
    executable: str = ""  # the actual binary/script to run
    args: list[str] = field(default_factory=list)  # args after executable
    raw: str = ""  # original run_command


def parse_command(run_command: str, target: str = "") -> ParsedCommand:
    """Parse a run_command template into a structured command.

    Handles patterns:
        - "nmap {target}"                      → direct binary
        - "sudo nmap -O -Pn {target}"          → sudo + binary
        - "cd dir && python3 script.py {t}"    → chdir + binary
        - "cd dir && sudo bash script.sh"      → chdir + sudo + binary
        - "amass enum -d {target}"             → binary with subcommand
        - "./script.sh"                        → local binary
        - "" (no command)                      → empty
    """
    result = ParsedCommand(raw=run_command)

    if not run_command:
        return result

    cmd = run_command.strip()

    # Replace {target} placeholder
    if "{target}" in cmd and target:
        cmd = cmd.replace("{target}", target)
    elif "{target}" in cmd and not target:
        # Leave {target} in place if no target supplied
        pass

    # Split on "&&" for multi-step commands (cd X && cmd)
    if " && " in cmd:
        parts = [p.strip() for p in cmd.split(" && ")]
        # First part is usually "cd <dir>"
        first = parts[0]
        if first.startswith("cd "):
            result.chdir = first[3:].strip()
        elif first.startswith("sudo cd "):
            result.chdir = first[8:].strip()

        # The rest is the actual command
        cmd = " && ".join(parts[1:])
    elif cmd.startswith("cd "):
        # "cd dir" without && — unusual, treat dir as chdir
        result.chdir = cmd[3:].strip()
        return result

    # Handle sudo prefix
    if cmd.startswith("sudo "):
        result.sudo = True
        cmd = cmd[5:].strip()

    # Parse remaining command into executable + args
    if cmd:
        try:
            tokens = shlex.split(cmd)
        except ValueError:
            # Fall back to simple split on shlex failure
            tokens = cmd.split()

        if tokens:
            result.executable = tokens[0]
            result.args = tokens[1:] if len(tokens) > 1 else []

    return result


def build_native_command(parsed: ParsedCommand) -> list[str]:
    """Build command list for native execution (Linux/macOS or Windows native).

    Returns a list ready for asyncio.create_subprocess_exec.
    """
    if not parsed.executable:
        return []

    cmd = []
    if parsed.sudo:
        cmd.append("sudo")
    cmd.append(parsed.executable)
    cmd.extend(parsed.args)
    return cmd


def build_wsl_command(
    parsed: ParsedCommand,
    tools_dir_win: str = "",
    distro: str = "",
) -> list[str]:
    """Build command list for WSL2 execution on Windows.

    Wraps the Linux command in: wsl [-d <distro>] bash -c "<linux_cmd>"

    The chdir path is translated from Windows → WSL (/mnt/c/...).
    """
    if not parsed.executable:
        return []

    # Build the command after cd (space-joined)
    cmd_parts = []

    # sudo (note: requires passwordless sudo in WSL or --user root)
    if parsed.sudo:
        cmd_parts.append("sudo")

    # executable + args
    cmd_parts.append(shlex.quote(parsed.executable))
    for arg in parsed.args:
        cmd_parts.append(shlex.quote(arg))

    cmd_str = " ".join(cmd_parts)

    # Prepend cd if needed
    if parsed.chdir:
        wsl_dir = to_wsl_path(parsed.chdir) if ":" in parsed.chdir else parsed.chdir
        linux_cmd = f"cd {shlex.quote(wsl_dir)} && {cmd_str}"
    else:
        linux_cmd = cmd_str

    # Wrap in wsl bash -c
    wsl_cmd = ["wsl"]
    if distro:
        wsl_cmd.extend(["-d", distro])
    wsl_cmd.extend(["bash", "-c", linux_cmd])
    return wsl_cmd


def build_command(
    parsed: ParsedCommand,
    backend: ExecBackend,
    tools_dir_win: str = "",
    distro: str = "",
) -> list[str]:
    """Build the correct command list for the given execution backend."""
    if backend == ExecBackend.WSL2:
        return build_wsl_command(parsed, tools_dir_win, distro)
    return build_native_command(parsed)


def needs_sudo(parsed: ParsedCommand) -> bool:
    """Check if this command requires sudo/root."""
    return parsed.sudo
