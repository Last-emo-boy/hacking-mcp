"""Recon MCP tool — information gathering and reconnaissance."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest
# Backward-compatible re-exports (used by older modules that import from here)
from hacking_mcp.mcp_tools.helpers import _unknown_tool, _not_installed, _format_result

RECON_CATEGORY = "Information Gathering"
# Tools from other categories that also do recon
EXTRA_RECON_TOOLS = {
    "trufflehog", "gitleaks",
    "sherlock", "socialscan", "finduser", "socialmapper", "knockmail",
    "dnstwist", "hatcloud",
    "howmanypeople",
}


def register(mcp: FastMCP, orchestrator: ToolOrchestrator):
    # Build the full recon allowlist
    recon_tools = {t.name for t in orchestrator.registry.get_category_tools(RECON_CATEGORY)}
    recon_tools.update(EXTRA_RECON_TOOLS)

    @mcp.tool(
        name="security_run_recon",
        description="Run information gathering and reconnaissance tools. "
        "Supports: nmap, theHarvester, amass, httpx, subfinder, masscan, rustscan, "
        "holehe, maigret, spiderfoot, trufflehog, gitleaks, and more.\n"
        "All recon tools are SAFE tier — read-only information gathering.\n"
        "Use security_list_tools to see all available recon tools.",
    )
    async def security_run_recon(
        tool_name: str,
        target: str,
        options: str = "",
        ctx: Context = None,
    ) -> str:
        """Run a reconnaissance tool against a target.

        Args:
            tool_name: Recon tool to use (e.g., 'nmap', 'theHarvester', 'amass', 'subfinder', 'httpx', 'holehe', 'maigret')
            target: Target IP, domain, email, username, or path
            options: Additional CLI options (e.g., '-sV -p 80,443' for nmap, '-b all' for theHarvester)
        """
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=tool_name,
                target=target,
                options=options,
                allowed_tools=recon_tools,
                category_label="reconnaissance",
            ),
            ctx=ctx,
        )
        return response.format()
