"""Scanner MCP tool — vulnerability and security scanning."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest

SCANNER_TOOLS = {
    # Web Attack category
    "nuclei", "nikto", "wafw00f", "testssl", "owasp-zap",
    # XSS Attack category
    "dalfox", "xspear", "xsscon", "xanxss", "xsstrike", "rvuln",
    # SQL Injection category (scanners only, not exploiters)
    "dsss", "sqlscan",
    # Other
    "gitleaks",
}


def register(mcp: FastMCP, orchestrator: ToolOrchestrator):
    @mcp.tool(
        name="security_run_scanner",
        description="Run vulnerability and security scanners. "
        "Supports: nuclei (template-based), nikto (web server), wafw00f (WAF detection), "
        "testssl (TLS/SSL), dalfox (XSS), xsstrike (advanced XSS), dsss (SQLi), and more.\n"
        "SAFE tier tools — read-only vulnerability detection, no exploitation.\n"
        "Use security_list_tools to see all available scanners.",
    )
    async def security_run_scanner(
        tool_name: str,
        target: str,
        options: str = "",
        confirm_authorized: bool = False,
        ctx: Context = None,
    ) -> str:
        """Run a vulnerability scanner against a target.

        Args:
            tool_name: Scanner to use (e.g., 'nuclei', 'nikto', 'wafw00f', 'testssl', 'dalfox', 'xsstrike', 'dsss')
            target: Target URL, IP, or domain
            options: Additional CLI options (e.g., '-severity critical' for nuclei)
            confirm_authorized: Set true only when you have authorization to scan this target.
        """
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=tool_name,
                target=target,
                options=options,
                confirm_authorized=confirm_authorized,
                allowed_tools=SCANNER_TOOLS,
                category_label="scanner",
                require_confirmation=True,
                confirmation_message="Ensure you have authorization to scan this target.",
            ),
            ctx=ctx,
        )
        return response.format()
