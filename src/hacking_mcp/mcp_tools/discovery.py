"""Discovery MCP tools — progressive disclosure of available security tools.

Three levels of detail:
  Level 1: Category overview (no args) — names, counts, descriptions
  Level 2: Tool listing (by category/tag/search) — compact one-line per tool
  Level 3: Full detail — security_get_tool_info("name")
"""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.runner import get_environment
from hacking_mcp.environment import get_tools_dir
from hacking_mcp.ai_help import format_ai_help
from hacking_mcp.mcp_tools.tool_adapters import (
    adapter_parameter_names,
    build_adapter_specs,
)


def register(mcp: FastMCP, registry: ToolRegistry, safety: SafetyPolicy):
    @mcp.tool(
        name="security_list_tools",
        description="Progressive discovery of security tools. "
        "Without arguments: lists all 20 categories with tool counts and descriptions. "
        "With a category: lists tools in that category (compact, one line each). "
        "With search/tag: finds matching tools (compact results). "
        "Use security_get_tool_info('name') for full details on any tool.",
    )
    async def security_list_tools(
        category: str = "",
        tag: str = "",
        search: str = "",
        ctx: Context = None,
    ) -> str:
        """List security tools with progressive disclosure.

        Level 1 (no args): Category overview — name, counts, description.
        Level 2 (category/tag/search): Compact tool list — name + one-liner.
        Level 3: Use security_get_tool_info('name') for full detail.

        Args:
            category: Filter by category name (e.g., 'Information Gathering', 'Web Attack')
            tag: Filter by tag (e.g., 'osint', 'recon', 'web', 'scanner')
            search: Search tools by name, description, or tags
        """
        tier_emoji = {"safe": "🟢", "caution": "🟡", "dangerous": "🔴"}

        # ── Level 2: Search results (compact) ──
        if search:
            tools = registry.search_tools(search)
            if not tools:
                return (
                    f"No tools found matching '{search}'. "
                    "Try a different term or use `security_list_tools` to browse categories."
                )
            lines = [f"# Search: '{search}' ({len(tools)} tools)\n"]
            for t in tools:
                avail = registry.get_availability(t.name)
                status = "✓" if avail.available else "✗"
                tier = tier_emoji.get(t.safety_tier.value, "")
                note = ""
                if not avail.platform_supported:
                    note = " *(unsupported)*"
                elif not avail.available:
                    note = " *(not installed)*"
                lines.append(f"- {status} {tier} **{t.name}** — {t.title}{note}")
            lines.append(f"\nUse `security_get_tool_info('name')` for full details on any tool above.")
            return "\n".join(lines)

        # ── Level 2: Tag results (compact) ──
        if tag:
            tools = registry.search_by_tag(tag)
            if not tools:
                all_tags = registry.get_all_tags()
                return f"No tools tagged '{tag}'. Available tags: {', '.join(all_tags[:20])}..."
            lines = [f"# Tag: '{tag}' ({len(tools)} tools)\n"]
            for t in tools:
                avail = registry.get_availability(t.name)
                status = "✓" if avail.available else "✗"
                tier = tier_emoji.get(t.safety_tier.value, "")
                lines.append(f"- {status} {tier} **{t.name}** — {t.title}")
            lines.append(f"\nUse `security_get_tool_info('name')` for full details on any tool above.")
            return "\n".join(lines)

        # ── Level 2: Category drill-down (compact) ──
        if category:
            tools = registry.get_category_tools(category)
            if not tools:
                cat_names = [c["name"] for c in registry.list_categories()]
                return f"Unknown category: '{category}'. Available categories: {', '.join(cat_names)}"
            available = sum(1 for t in tools if registry.is_available(t.name))
            lines = [f"# {category} ({available}/{len(tools)} available)\n"]
            for t in tools:
                avail = registry.get_availability(t.name)
                status = "✓" if avail.available else "✗"
                tier = tier_emoji.get(t.safety_tier.value, "")
                note = ""
                if not avail.platform_supported:
                    note = " *(unsupported)*"
                elif not avail.available:
                    note = " *(not installed)*"
                lines.append(f"- {status} {tier} **{t.name}** — {t.title}{note}")
            lines.append(f"\nUse `security_get_tool_info('name')` for full details on any tool above.")
            lines.append(f"Use `security_install_tool('name')` to install a missing tool.")
            return "\n".join(lines)

        # ── Level 1: Category overview (no args) ──
        all_cats = registry.list_categories()
        total_tools = registry.get_tool_names()
        total_avail = sum(1 for n in total_tools if registry.is_available(n))

        lines = [
            f"# Security Tools — {len(all_cats)} categories, {len(total_tools)} tools ({total_avail} installed)",
            "",
        ]

        disabled_set = safety.disabled_categories
        confirm_set = safety.require_confirmation_categories

        for cat_info in all_cats:
            name = cat_info["name"]
            n_avail = cat_info["available_count"]
            n_total = cat_info["tool_count"]
            desc = cat_info["description"]

            if name in disabled_set:
                tag_line = "🚫 disabled"
            elif name in confirm_set:
                tag_line = "⚠️ requires confirmation"
            else:
                tag_line = "🟢 available"

            lines.append(f"## {name} ({n_avail}/{n_total} tools) — {tag_line}")
            if desc:
                lines.append(f"_{desc}_")
            lines.append("")

        lines.append("---")
        lines.append("**Next steps:**")
        lines.append('- Use `security_list_tools(category="Category Name")` to see tools in a category.')
        lines.append('- Use `security_list_tools(search="keyword")` to find tools by name or function.')
        lines.append('- Use `security_get_tool_info("tool_name")` for full detail on a specific tool.')
        lines.append('- Use `security_install_tool("tool_name")` to install a tool.')

        return "\n".join(lines)

    @mcp.tool(
        name="security_list_tool_adapters",
        description="List dedicated per-tool MCP adapter coverage. "
        "Use execution='executable' or execution='blocked' to filter adapters. "
        "Optional category/search filters narrow the inventory.",
    )
    async def security_list_tool_adapters(
        category: str = "",
        execution: str = "",
        search: str = "",
        limit: int = 200,
        ctx: Context = None,
    ) -> str:
        """List generated per-tool MCP adapter coverage."""
        specs = build_adapter_specs(registry, safety)
        specs.sort(key=lambda item: (item.category, item.tool_name))

        category_filter = category.strip().lower()
        execution_filter = execution.strip().lower()
        search_filter = search.strip().lower()

        if category_filter:
            specs = [s for s in specs if s.category.lower() == category_filter]
        if search_filter:
            specs = [
                s for s in specs
                if search_filter in s.tool_name.lower()
                or search_filter in s.title.lower()
                or search_filter in s.category.lower()
            ]
        if execution_filter in {"executable", "enabled"}:
            specs = [s for s in specs if s.exposed]
        elif execution_filter in {"blocked", "policy-only", "policy_only"}:
            specs = [s for s in specs if not s.exposed]
        elif execution_filter and execution_filter != "all":
            return (
                "Unknown execution filter. Use one of: all, executable, blocked."
            )

        total_specs = build_adapter_specs(registry, safety)
        total = len(total_specs)
        executable = sum(1 for s in total_specs if s.exposed)
        blocked = total - executable
        limit = max(1, min(limit, 500))

        lines = [
            "# Dedicated MCP Adapter Inventory",
            "",
            f"Total adapters: {total}",
            f"Executable adapters: {executable}",
            f"Policy/info-only adapters: {blocked}",
            f"Showing: {min(len(specs), limit)}/{len(specs)}",
            "",
        ]

        for spec in specs[:limit]:
            state = "executable" if spec.exposed else "policy/info-only"
            confirm = ", confirmation required" if spec.requires_confirmation else ""
            reason = ""
            if not spec.exposed:
                reason = f" - {spec.blocked_reason or 'not executable by policy'}"
            tool = registry.get_tool(spec.tool_name)
            params = adapter_parameter_names(tool, spec) if tool else []
            param_list = ", ".join(params)
            lines.append(
                f"- `{spec.mcp_name}` -> `{spec.tool_name}` "
                f"({spec.category}, {spec.safety_tier}, {state}{confirm}; "
                f"params: {param_list}){reason}"
            )

        if len(specs) > limit:
            lines.append("")
            remaining = len(specs) - limit
            lines.append(f"Use a higher limit or narrower filters to see {remaining} more.")

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
        tier_labels = {
            "safe": "SAFE (always available)",
            "caution": "CAUTION (explicit target required, logged)",
            "dangerous": "DANGEROUS (excluded from MCP)",
        }

        lines = [
            f"# {tool.title}",
            "",
            f"**Name:** `{tool.name}`",
            f"**Category:** {tool.category}",
            f"**Safety Tier:** {tier_labels.get(tool.safety_tier.value, 'UNKNOWN')}",
            "",
            "## Description",
            f"{tool.description}",
            "",
            format_ai_help(tool),
            "",
            _format_adapter_info(tool_name, registry, safety),
            "",
            "## Availability",
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
                    "181/184 tools are Linux-only and **cannot run** without WSL2.\\n"
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

    @mcp.tool(
        name="security_get_proxy_config",
        description="Show the current proxy configuration for tool downloads. "
        "Proxy is ONLY used during tool installation (git clone, pip, curl, etc.) — "
        "never during security tool execution. "
        "Configure proxy in ~/.hacking-mcp/safety_policy.yaml.",
    )
    async def security_get_proxy_config(ctx: Context = None) -> str:
        """Display current proxy configuration."""
        proxy = safety.get_proxy_config()
        lines = [
            "# Proxy Configuration",
            "",
            "Proxy is **only** used for tool downloads during installation.",
            "Security tool execution never uses proxy.",
            "",
        ]
        if proxy.get("http") or proxy.get("https"):
            if proxy.get("http"):
                lines.append(f"- **HTTP_PROXY:** `{proxy['http']}`")
            if proxy.get("https"):
                lines.append(f"- **HTTPS_PROXY:** `{proxy['https']}`")
            if proxy.get("no_proxy"):
                lines.append(f"- **NO_PROXY:** `{proxy['no_proxy']}`")
            lines.append("")
            lines.append("✅ Proxy is **active** for install operations.")
        else:
            lines.append("❌ **No proxy configured.**")
            lines.append("")
            lines.append("To set a proxy, edit `~/.hacking-mcp/safety_policy.yaml`:")
            lines.append("```yaml")
            lines.append("proxy:")
            lines.append('  http: "http://127.0.0.1:8080"')
            lines.append('  https: "http://127.0.0.1:8080"')
            lines.append('  no_proxy: "localhost,127.0.0.1,.local"')
            lines.append("```")
        return "\n".join(lines)


def _format_adapter_info(
    tool_name: str,
    registry: ToolRegistry,
    safety: SafetyPolicy,
) -> str:
    specs = build_adapter_specs(registry, safety)
    spec = next((item for item in specs if item.tool_name == tool_name), None)
    if spec is None:
        return "## Dedicated MCP Adapter\nNot available."
    if spec.exposed:
        confirm_note = (
            "\n**Confirmation:** pass `confirm_authorized=true` when invoking this adapter."
            if spec.requires_confirmation
            else ""
        )
        target_note = "required" if spec.target_required else "optional"
        return (
            "## Dedicated MCP Adapter\n"
            f"**Endpoint:** `{spec.mcp_name}`\n"
            f"**Target:** {target_note}\n"
            f"**Scope validation:** {spec.validate_scope}"
            f"{confirm_note}"
        )
    return (
        "## Dedicated MCP Adapter\n"
        f"**Endpoint:** `{spec.mcp_name}`\n"
        f"**Execution:** blocked: {spec.blocked_reason or 'not exposed by policy'}"
    )
