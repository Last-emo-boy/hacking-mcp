"""Shared helpers for MCP tool modules.

These functions were originally in recon.py and imported by the other
six MCP tool modules. They're kept here for backward compatibility.

New code should use ToolOrchestrator instead — it consolidates all
validation and formatting into a single execute() pipeline.
"""

from hacking_mcp.registry import ToolRegistry


def _unknown_tool(tool_name: str, registry: ToolRegistry) -> str:
    """Build 'unknown tool' error message with similar-tool suggestions."""
    similar = [t.name for t in registry.search_tools(tool_name)[:5]]
    msg = f"Unknown tool: '{tool_name}'."
    if similar:
        msg += f"\nDid you mean: {', '.join(similar)}?"
    return msg


def _not_installed(tool_name: str, registry: ToolRegistry) -> str:
    """Build 'not installed' error message with install instructions."""
    install_cmds = registry.get_install_commands(tool_name)
    msg = f"Tool '{tool_name}' is not installed.\n\n"
    if install_cmds:
        msg += "**Install commands (run manually):**\n"
        for cmd in install_cmds:
            msg += f"```bash\n{cmd}\n```\n"
    return msg


def _format_result(tool_name: str, result) -> str:
    """Format a RunResult as Markdown."""
    if result.was_blocked:
        return f"⛔ **{tool_name}** was blocked: {result.block_reason}"

    lines = [
        f"## {tool_name} Results",
        f"**Exit code:** {result.return_code} | **Duration:** {result.duration_ms}ms",
    ]

    if result.timed_out:
        lines.append("⚠️ **Command timed out.**")

    if result.stdout:
        stdout = result.stdout
        if len(stdout) > 15000:
            stdout = stdout[:15000] + "\n... (output truncated)"
        lines.append(f"\n### Output\n```\n{stdout}\n```")

    if result.stderr:
        stderr = result.stderr
        if len(stderr) > 3000:
            stderr = stderr[:3000] + "\n... (truncated)"
        lines.append(f"\n### Stderr\n```\n{stderr}\n```")

    if result.return_code != 0:
        lines.append(f"\n⚠️ Command exited with non-zero code: {result.return_code}")

    return "\n".join(lines)
