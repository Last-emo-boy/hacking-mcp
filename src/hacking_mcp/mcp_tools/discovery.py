"""Discovery MCP tools — list, search, and inspect available security tools."""

from mcp.server.fastmcp import FastMCP, Context
from mcp.types import ToolAnnotations

from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.runner import get_environment
from hacking_mcp.environment import get_tools_dir


def register(mcp: FastMCP, registry: ToolRegistry, safety: SafetyPolicy):
    @mcp.tool(
        name="security_list_tools",
        description="List all available security tools organized by category. "
        "Shows tool name, description, safety tier, and whether it's installed. "
        "Use to discover what tools are available before running them.",
    )
    async def security_list_tools(
        category: str = "",
        tag: str = "",
        search: str = "",
        show_unavailable: bool = True,
        ctx: Context = None,
    ) -> str:
        """List security tools with optional filtering.

        Args:
            category: Filter by category name (e.g., 'Information Gathering', 'Web Attack')
            tag: Filter by tag (e.g., 'osint', 'recon', 'web', 'scanner')
            search: Search tools by name, description, or tags
            show_unavailable: Include tools not installed on this system
        """
        # Apply filters
        if search:
            tools = registry.search_tools(search)
            heading = f"Search results for: '{search}'"
        elif tag:
            tools = registry.search_by_tag(tag)
            heading = f"Tools tagged: '{tag}'"
        elif category:
            tools = registry.get_category_tools(category)
            heading = f"Category: {category}"
        else:
            # List all by category
            lines = ["# Security Tools Catalog\n"]
            lines.append(f"**Policy:** {len(safety.disabled_categories)} categories disabled, "
                         f"{len(safety.require_confirmation_categories)} require confirmation\n")
            for cat_info in registry.list_categories():
                lines.append(f"\n## {cat_info['name']} "
                             f"({cat_info['available_count']}/{cat_info['tool_count']} available)")
                lines.append(f"_{cat_info['description']}_\n")
                cat_tools = registry.get_category_tools(cat_info['name'])
                for t in cat_tools:
                    avail = registry.get_availability(t.name)
                    status = "✓" if avail.available else "✗"
                    tier_emoji = {"safe": "🟢", "caution": "🟡", "dangerous": "🔴"}
                    tier = tier_emoji.get(t.safety_tier.value, "⚪")
                    lines.append(
                        f"- {status} {tier} **{t.name}** — {t.title}"
                    )
                    if not avail.platform_supported:
                        lines[-1] += " *(unsupported platform)*"
                    elif not avail.available and show_unavailable:
                        lines[-1] += " *(not installed)*"
            return "\n".join(lines)

        # Filtered output
        lines = [f"# {heading} ({len(tools)} tools)\n"]
        for t in tools:
            avail = registry.get_availability(t.name)
            status = "✓ installed" if avail.available else "✗ not installed"
            if not avail.platform_supported:
                status = "⊘ unsupported platform"
            tier_emoji = {"safe": "🟢 SAFE", "caution": "🟡 CAUTION", "dangerous": "🔴 DANGEROUS"}
            tier = tier_emoji.get(t.safety_tier.value, "⚪ UNKNOWN")
            lines.append(f"## {t.name}")
            lines.append(f"**Title:** {t.title}")
            lines.append(f"**Category:** {t.category}")
            lines.append(f"**Tier:** {tier}")
            lines.append(f"**Status:** {status}")
            lines.append(f"**Description:** {t.description}")
            if t.project_url:
                lines.append(f"**URL:** {t.project_url}")
            if t.tags:
                lines.append(f"**Tags:** {', '.join(t.tags)}")
            lines.append("")
        return "\n".join(lines)

    @mcp.tool(
        name="security_get_tool_info",
        description="Get detailed information about a specific security tool, "
        "including description, install commands, project URL, and safety tier. "
        "Use before running a tool to understand what it does.",
    )
    async def security_get_tool_info(
        tool_name: str,
        ctx: Context = None,
    ) -> str:
        """Get detailed information about a specific tool.

        Args:
            tool_name: Name of the tool (e.g., 'nmap', 'nuclei', 'theHarvester')
        """
        tool = registry.get_tool(tool_name)
        if not tool:
            similar = [t.name for t in registry.search_tools(tool_name)[:5]]
            msg = f"Tool '{tool_name}' not found."
            if similar:
                msg += f"\nDid you mean: {', '.join(similar)}?"
            return msg

        avail = registry.get_availability(tool_name)
        tier_emoji = {"safe": "SAFE (always available)", "caution": "CAUTION (explicit target required, logged)",
                       "dangerous": "DANGEROUS (excluded from MCP)"}

        lines = [
            f"# {tool.title}",
            f"",
            f"**Name:** `{tool.name}`",
            f"**Category:** {tool.category}",
            f"**Safety Tier:** {tier_emoji.get(tool.safety_tier.value, 'UNKNOWN')}",
            f"",
            f"## Description",
            f"{tool.description}",
            f"",
            f"## Availability",
        ]
        if avail.available:
            lines.append(f"✓ Installed at: `{avail.path}`")
        elif not avail.platform_supported:
            lines.append(f"⊘ Not supported on this platform. Supported: {', '.join(tool.supported_os)}")
        else:
            lines.append("✗ Not installed")
            if tool.install_commands:
                lines.append("\n**Install commands:**")
                for cmd in tool.install_commands:
                    lines.append(f"```bash\n{cmd}\n```")

        if tool.project_url:
            lines.append(f"\n## Project URL\n{tool.project_url}")
        if tool.tags:
            lines.append(f"\n## Tags\n{', '.join(tool.tags)}")
        if tool.requires_root:
            lines.append("\n⚠️ Requires root privileges")
        if tool.requires_docker:
            lines.append("\n🐳 Requires Docker")

        # Check safety policy
        allowed, reason = safety.check_tool(tool)
        if not allowed:
            lines.append(f"\n## Policy\n🚫 {reason}")
        elif safety.requires_confirmation(tool):
            lines.append("\n## Policy\n⚠️ This tool requires explicit confirmation before each use.")

        return "\n".join(lines)

    @mcp.tool(
        name="security_get_environment",
        description="Show the current execution environment: operating system, "
        "execution backend (native or WSL2), WSL2 distro, and tools directory. "
        "Helps understand where tools will run.",
    )
    async def security_get_environment(ctx: Context = None) -> str:
        """Display the current execution environment."""
        env = get_environment()
        tools_dir = str(get_tools_dir())

        lines = [
            "# Execution Environment",
            "",
            f"**Operating System:** {env.system}",
            f"**Execution Backend:** {env.backend.value}",
        ]

        if env.is_windows:
            if env.wsl_available:
                lines.append(f"**WSL2:** Available — distro: `{env.wsl_distro}`")
                lines.append("")
                lines.append("Linux tools will be executed through WSL2:")
                lines.append("```")
                lines.append(f"wsl -d {env.wsl_distro} bash -c \"<linux command>\"")
                lines.append("```")
                lines.append("")
                lines.append(f"**WSL tools directory:** `{tools_dir}`")
                lines.append("(mapped from Windows `~/.hacking-mcp/tools`)")
            else:
                lines.append("**WSL2:** NOT available")
                lines.append("")
                lines.append(
                    "179/182 tools are Linux-only and **cannot run** without WSL2.\\n"
                    "Install WSL2 to enable execution of security tools.\\n"
                    "```powershell\\n"
                    "wsl --install -d Ubuntu-22.04\\n"
                    "```"
                )

        elif env.is_linux:
            lines.append("")
            lines.append("All tools run natively on Linux.")
            lines.append(f"**Tools directory:** `{tools_dir}`")
        elif env.is_macos:
            lines.append("")
            lines.append("Tools marked for macOS run natively. Linux-only tools are unavailable.")
            lines.append(f"**Tools directory:** `{tools_dir}`")

        return "\n".join(lines)

    @mcp.tool(
        name="security_get_policy",
        description="Show the current safety policy: which categories are disabled, "
        "which require confirmation, scope configuration, and execution limits.",
    )
    async def security_get_policy(ctx: Context = None) -> str:
        """Display the current safety policy."""
        summary = safety.get_policy_summary()
        lines = [
            "# Safety Policy Summary",
            "",
            "## Execution Limits",
            f"- Max timeout: {summary['max_timeout_seconds']}s",
            f"- Max output: {summary['max_output_mb']}MB",
            "",
            "## Disabled Categories",
        ]
        if summary['disabled_categories']:
            for c in summary['disabled_categories']:
                lines.append(f"- 🚫 {c}")
        else:
            lines.append("- (none)")
        lines.extend([
            "",
            "## Confirmation-Required Categories",
        ])
        if summary['confirmation_categories']:
            for c in summary['confirmation_categories']:
                lines.append(f"- ⚠️ {c}")
        else:
            lines.append("- (none)")
        lines.extend([
            "",
            "## Disabled Tools",
        ])
        if summary['disabled_tools']:
            for t in summary['disabled_tools']:
                lines.append(f"- 🚫 {t}")
        else:
            lines.append("- (none)")
        lines.extend([
            "",
            "## Target Scope",
            f"- Scope active: {summary['scope_active']}",
            f"- IP ranges: {summary['scope_cidr_count']}",
            f"- Domains: {summary['scope_domain_count']}",
        ])
        return "\n".join(lines)
