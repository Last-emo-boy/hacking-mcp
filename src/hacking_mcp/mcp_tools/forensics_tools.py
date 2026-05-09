"""Forensics MCP tool — file, memory, and binary analysis."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest

FORENSICS_TOOLS_LIST = {
    "binwalk", "volatility3", "pspy", "trufflehog", "gitleaks",
    "steghide", "stegcracker",
    "haiti", "hashbuster", "hcxtools",
}


def register(mcp: FastMCP, orchestrator: ToolOrchestrator):
    @mcp.tool(
        name="security_run_forensics",
        description="Run digital forensics and analysis tools. "
        "Supports: binwalk (firmware analysis), volatility3 (memory forensics), "
        "pspy (process monitoring), trufflehog (secret scanning), gitleaks (git secrets), "
        "haiti (hash identification), steghide/stegcracker (steganography).\n"
        "SAFE tier — read-only analysis, no modification.\n"
        "Use security_list_tools to see all available forensics tools.",
    )
    async def security_run_forensics(
        tool_name: str,
        target: str,
        options: str = "",
        confirm_authorized: bool = False,
        ctx: Context = None,
    ) -> str:
        """Run a forensics/analysis tool against a target.

        Args:
            tool_name: Forensics tool (e.g., 'binwalk', 'volatility3', 'pspy', 'trufflehog', 'gitleaks', 'haiti', 'steghide')
            target: Target file, directory, hash, or memory dump path
            options: Additional CLI options
            confirm_authorized: Set true when the selected tool requires explicit authorization confirmation.
        """
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=tool_name,
                target=target,
                options=options,
                confirm_authorized=confirm_authorized,
                allowed_tools=FORENSICS_TOOLS_LIST,
                category_label="forensics",
                validate_scope=False,  # Targets are local file paths
            ),
            ctx=ctx,
        )
        return response.format()
