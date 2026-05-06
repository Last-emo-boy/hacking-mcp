"""Install MCP tools — one-click tool installation and management."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.install import InstallManager
from hacking_mcp.registry import ToolRegistry


def register(mcp: FastMCP, install_mgr: InstallManager, registry: ToolRegistry):
    @mcp.tool(
        name="security_bootstrap_wsl",
        description="Install base development tools into WSL2 (python3, pip, git, curl, go, ruby, build-essential). "
        "Runs 'sudo apt-get install' inside WSL to set up the environment needed for installing security tools. "
        "Use this once after setting up WSL2, before installing any security tools. "
        "Safe to run multiple times — only installs missing packages.",
    )
    async def security_bootstrap_wsl(ctx: Context = None) -> str:
        """Bootstrap WSL2 with basic dev toolchain."""
        error = await install_mgr._bootstrap_wsl()
        if error:
            return f"❌ Bootstrap failed:\n\n{error}"
        return (
            "✅ WSL2 dev environment is ready.\n\n"
            "Installed packages:\n"
            + "\n".join(f"- `{p}`" for p in InstallManager.WSL_BOOTSTRAP_PACKAGES)
            + "\n\nYou can now use `security_install_tool` to install security tools."
        )

    @mcp.tool(
        name="security_install_tool",
        description="Install a security tool automatically. "
        "Executes the tool's install commands (git clone, pip install, apt install, etc.) "
        "sequentially and reports progress. "
        "Use when a tool returns 'not installed' from any run endpoint.",
    )
    async def security_install_tool(
        tool_name: str,
        ctx: Context = None,
    ) -> str:
        """Install a security tool with one click.

        Args:
            tool_name: Tool to install (e.g., 'nmap', 'theHarvester', 'sqlmap')
        """
        tool = registry.get_tool(tool_name)
        if not tool:
            similar = [t.name for t in registry.search_tools(tool_name)[:5]]
            msg = f"Unknown tool: '{tool_name}'."
            if similar:
                msg += f"\nDid you mean: {', '.join(similar)}?"
            return msg

        # Already installed?
        current = install_mgr.get_install_status(tool_name)
        if current.installed:
            return (
                f"## {tool_name} — Already Installed\n\n"
                f"**Method:** {current.method}\n"
                f"**Installed at:** {current.installed_at}\n"
                f"**Steps:** {current.steps_completed}/{current.steps_total}\n\n"
                f"Use `security_get_install_status('{tool_name}')` for details."
            )

        # Show what will be done
        steps_preview = "\n".join(f"{i+1}. `{cmd}`" for i, cmd in enumerate(tool.install_commands))
        lines = [
            f"## Installing {tool.title}",
            "",
            f"**Steps ({len(tool.install_commands)}):**",
            steps_preview,
            "",
        ]

        if ctx:
            await ctx.info(f"Installing {tool_name} ({len(tool.install_commands)} steps)...")

        try:
            record = await install_mgr.install_tool(tool_name)
        except Exception as e:
            return "\n".join(lines) + f"\n❌ **Install failed:** {e}"

        if record.installed:
            lines.append(f"✅ **{tool_name} installed successfully!**")
            lines.append(f"**Method:** {record.method}")
            lines.append(f"**Steps completed:** {record.steps_completed}/{record.steps_total}")
            if ctx:
                await ctx.info(f"{tool_name} installed successfully")
        else:
            lines.append(f"❌ **Install failed** ({record.steps_completed}/{record.steps_total} steps complete)")
            if record.error:
                lines.append(f"```\n{record.error}\n```")

        return "\n".join(lines)

    @mcp.tool(
        name="security_get_install_status",
        description="Check install status of security tools. "
        "Without arguments, lists all tools that have been installed or attempted. "
        "With a tool_name, shows detailed install status for one tool.",
    )
    async def security_get_install_status(
        tool_name: str = "",
        ctx: Context = None,
    ) -> str:
        """Check install status.

        Args:
            tool_name: Optional tool name for detailed status. Leave empty to list all.
        """
        if tool_name:
            tool = registry.get_tool(tool_name)
            if not tool:
                return f"Unknown tool: '{tool_name}'."

            record = install_mgr.get_install_status(tool_name)
            status_emoji = "✅" if record.installed else "❌"
            lines = [
                f"## {tool.title} — Install Status",
                f"**Status:** {status_emoji} {'Installed' if record.installed else 'Not installed'}",
            ]
            if record.method:
                lines.append(f"**Method:** {record.method}")
            if record.installed_at:
                lines.append(f"**Installed at:** {record.installed_at}")
            if record.steps_total:
                lines.append(f"**Steps:** {record.steps_completed}/{record.steps_total}")
            if record.error:
                lines.append(f"\n**Error:**\n```\n{record.error}\n```")
            if tool.install_commands:
                lines.append("\n**Install commands:**")
                for cmd in tool.install_commands:
                    lines.append(f"```bash\n{cmd}\n```")
            return "\n".join(lines)

        # List all
        all_installs = install_mgr.list_installs()
        if not all_installs:
            return (
                "## Install Status\n\n"
                "No tools have been installed yet. "
                "Use `security_install_tool('tool_name')` to install a tool."
            )

        installed = [r for r in all_installs.values() if r.installed]
        failed = [r for r in all_installs.values() if not r.installed and r.error]

        lines = [
            "# Install Status",
            f"**{len(installed)} installed, {len(failed)} failed**",
            "",
        ]
        if installed:
            lines.append("## Installed")
            for r in sorted(installed, key=lambda x: x.installed_at, reverse=True):
                lines.append(f"- ✅ **{r.tool_name}** — {r.method} ({r.installed_at})")
        if failed:
            lines.append("\n## Failed")
            for r in failed:
                err = r.error[:100] if r.error else "Unknown error"
                lines.append(f"- ❌ **{r.tool_name}** — {err}")

        return "\n".join(lines)

    @mcp.tool(
        name="security_uninstall_tool",
        description="Uninstall a security tool (removes install tracking, not files). "
        "After uninstalling, you can reinstall with security_install_tool.",
    )
    async def security_uninstall_tool(
        tool_name: str,
        ctx: Context = None,
    ) -> str:
        """Uninstall a tool.

        Args:
            tool_name: Tool to uninstall
        """
        record = install_mgr.get_install_status(tool_name)
        if not record.installed and not record.error:
            return f"'{tool_name}' is not installed."

        success = await install_mgr.uninstall_tool(tool_name)
        if success:
            if ctx:
                await ctx.info(f"{tool_name} uninstalled")
            return f"✅ '{tool_name}' has been uninstalled."
        return f"❌ Failed to uninstall '{tool_name}'."
