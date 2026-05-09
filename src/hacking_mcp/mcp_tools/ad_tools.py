"""Active Directory MCP tool — AD enumeration and attack tools."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest

AD_TOOL_NAMES = {"bloodhound", "netexec", "impacket", "responder", "certipy", "kerbrute"}


def register(mcp: FastMCP, orchestrator: ToolOrchestrator):
    @mcp.tool(
        name="security_run_ad_tools",
        description="Run Active Directory security tools. "
        "Supports: bloodhound (attack path analysis), netexec (nxc — network pentesting), "
        "impacket (SMB/Kerberos/LDAP), responder (credential capture), "
        "certipy (AD CS abuse), kerbrute (Kerberos bruteforce).\n"
        "Most AD tools are CAUTION tier — ensure you have explicit authorization.\n"
        "Use security_list_tools to see all available AD tools.",
    )
    async def security_run_ad_tools(
        tool_name: str,
        target: str,
        options: str = "",
        confirm_authorized: bool = False,
        ctx: Context = None,
    ) -> str:
        """Run an Active Directory security tool against a target.

        Args:
            tool_name: AD tool (e.g., 'bloodhound', 'netexec', 'impacket', 'responder', 'certipy', 'kerbrute')
            target: Target domain, DC IP, or username
            options: Additional CLI options (e.g., '-u username -p password' for netexec)
            confirm_authorized: Set true only when you have written authorization for this domain.
        """
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=tool_name,
                target=target,
                options=options,
                confirm_authorized=confirm_authorized,
                allowed_tools=AD_TOOL_NAMES,
                category_label="Active Directory",
                require_confirmation=True,
                confirmation_message="Ensure you have explicit written authorization for the target domain.",
            ),
            ctx=ctx,
        )
        return response.format()
