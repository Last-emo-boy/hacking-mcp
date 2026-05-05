"""Cloud Security MCP tool — cloud infrastructure assessment."""

from mcp.server.fastmcp import FastMCP, Context

from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest

CLOUD_TOOL_NAMES = {"prowler", "scoutsuite", "trivy", "pacu"}


def register(mcp: FastMCP, orchestrator: ToolOrchestrator):
    @mcp.tool(
        name="security_run_cloud_audit",
        description="Run cloud security assessment tools. "
        "Supports: prowler (AWS/Azure/GCP/K8s), scoutsuite (multi-cloud auditing), "
        "trivy (containers/K8s/IaC scanning), pacu (AWS exploitation framework).\n"
        "Pacu is CAUTION tier — ensure you have authorization for the target cloud environment.\n"
        "Use security_list_tools to see all available cloud tools.",
    )
    async def security_run_cloud_audit(
        tool_name: str,
        target: str = "",
        options: str = "",
        ctx: Context = None,
    ) -> str:
        """Run a cloud security tool.

        Args:
            tool_name: Cloud tool (e.g., 'prowler', 'scoutsuite', 'trivy', 'pacu')
            target: Optional target (AWS account ID, container image, K8s cluster, etc.)
            options: Additional CLI options
        """
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=tool_name,
                target=target,
                options=options,
                allowed_tools=CLOUD_TOOL_NAMES,
                category_label="cloud security",
                target_required=False,
                validate_scope=False,
                require_confirmation=True,
                confirmation_message="Ensure you have authorization for the target cloud environment.",
            ),
            ctx=ctx,
        )
        return response.format()
