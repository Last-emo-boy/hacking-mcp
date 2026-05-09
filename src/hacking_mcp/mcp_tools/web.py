"""Web Audit MCP tool — web application testing and discovery."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest

WEB_TOOLS = {
    "ffuf", "dirsearch", "gobuster", "feroxbuster", "katana",
    "dirb", "arjun", "skipfish", "sublist3r", "checkurl",
    "takeover", "breacher", "secretfinder",
    "gospider", "crivo",
}


def register(mcp: FastMCP, orchestrator: ToolOrchestrator):
    @mcp.tool(
        name="security_run_web_audit",
        description="Run web application testing and discovery tools. "
        "Supports: ffuf (fuzzing), dirsearch (path discovery), gobuster (dir/DNS/vhost), "
        "feroxbuster (recursive discovery), katana (crawler), arjun (parameter discovery), "
        "sublist3r (subdomain enum), dirb, skipfish, and more.\n"
        "SAFE tier tools — content discovery and enumeration, no exploitation.\n"
        "Use security_list_tools to see all available web tools.",
    )
    async def security_run_web_audit(
        tool_name: str,
        target: str,
        options: str = "",
        confirm_authorized: bool = False,
        ctx: Context = None,
    ) -> str:
        """Run a web application testing tool against a target.

        Args:
            tool_name: Web tool to use (e.g., 'ffuf', 'dirsearch', 'gobuster', 'feroxbuster', 'katana', 'arjun', 'sublist3r')
            target: Target URL (e.g., https://example.com)
            options: Additional CLI options (e.g., '-w wordlist.txt' for ffuf)
            confirm_authorized: Set true when the selected tool requires explicit authorization confirmation.
        """
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=tool_name,
                target=target,
                options=options,
                confirm_authorized=confirm_authorized,
                allowed_tools=WEB_TOOLS,
                category_label="web audit",
            ),
            ctx=ctx,
        )
        return response.format()
