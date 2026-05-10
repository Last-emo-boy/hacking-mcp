"""Integration tests for the MCP server."""

import pytest


class TestServerCreation:
    def test_server_imports(self):
        """Server module should import without errors."""
        from hacking_mcp.server import create_server
        server = create_server()
        assert server is not None

    def test_server_name(self):
        """Server should have correct name."""
        from hacking_mcp.server import create_server
        server = create_server()
        assert server.name == "hacking-mcp"

    def test_registry_global(self):
        """Global registry should have tools."""
        from hacking_mcp.server import registry
        assert len(registry.get_tool_names()) > 100

    def test_safety_global(self):
        """Global safety should have policy loaded."""
        from hacking_mcp.server import safety
        summary = safety.get_policy_summary()
        assert len(summary["disabled_categories"]) > 0

    def test_runner_global(self):
        """Global runner should be initialized."""
        from hacking_mcp.server import runner
        assert runner is not None
        # Should be able to dry-run
        cmd = runner.dry_run("nmap", ["-sV", "localhost"])
        assert "nmap" in cmd

    @pytest.mark.asyncio
    async def test_per_tool_adapters_registered(self):
        """Server should expose a dedicated adapter for every registry tool."""
        from hacking_mcp.server import create_server, registry

        server = create_server()
        names = {tool.name for tool in await server.list_tools()}
        adapter_names = {name for name in names if name.startswith("security_tool_")}

        assert "security_tool_nmap" in names
        assert "security_tool_sqlmap" in names
        assert "security_tool_vegil" in names
        assert "security_run_recon" in names
        assert "security_list_tool_adapters" in names
        assert "security_get_tool_adapter_info" in names
        assert "security_preview_tool_adapter" in names
        assert "security_audit_tool_adapters" in names
        assert "security_get_adapter_research_status" in names
        assert len(adapter_names) == len(registry.get_tool_names())

    @pytest.mark.asyncio
    async def test_tool_adapter_inventory_reports_coverage(self):
        """Adapter inventory should summarize executable and policy-only coverage."""
        from hacking_mcp.server import create_server

        server = create_server()
        content, metadata = await server.call_tool(
            "security_list_tool_adapters",
            {"execution": "blocked", "limit": 3},
        )

        result = metadata["result"]
        assert "Total adapters: 184" in result
        assert "Executable adapters: 123" in result
        assert "Policy/info-only adapters: 61" in result
        assert "policy/info-only" in result
        assert "params:" in result
        assert content

    @pytest.mark.asyncio
    async def test_tool_adapter_info_reports_parameters_and_policy_state(self):
        """Single-tool adapter info should expose generated parameter details."""
        from hacking_mcp.server import create_server

        server = create_server()
        _, nmap_metadata = await server.call_tool(
            "security_get_tool_adapter_info",
            {"tool_name": "nmap"},
        )
        _, vegil_metadata = await server.call_tool(
            "security_get_tool_adapter_info",
            {"tool_name": "vegil"},
        )

        assert "**Endpoint:** `security_tool_nmap`" in nmap_metadata["result"]
        assert "`ports`" in nmap_metadata["result"]
        assert "**Execution:** executable" in nmap_metadata["result"]
        assert "## Example Arguments" in nmap_metadata["result"]
        assert '"ports": "80,443"' in nmap_metadata["result"]

        assert "**Endpoint:** `security_tool_vegil`" in vegil_metadata["result"]
        assert "`lhost`" in vegil_metadata["result"]
        assert "**Execution:** policy/info-only" in vegil_metadata["result"]
        assert "## Research Status" in vegil_metadata["result"]
        assert "Source reviewed: False" in vegil_metadata["result"]
        assert '"lhost": "127.0.0.1"' in vegil_metadata["result"]
        assert "does not execute" in vegil_metadata["result"]

    @pytest.mark.asyncio
    async def test_tool_adapter_preview_generates_options_without_execution(self):
        """Adapter preview should show generated options for executable and blocked tools."""
        from hacking_mcp.server import create_server

        server = create_server()
        _, nmap_metadata = await server.call_tool(
            "security_preview_tool_adapter",
            {
                "tool_name": "nmap",
                "arguments_json": (
                    '{"target":"127.0.0.1","ports":"80,443",'
                    '"service_version":true,"timing":4}'
                ),
            },
        )
        _, vegil_metadata = await server.call_tool(
            "security_preview_tool_adapter",
            {
                "tool_name": "vegil",
                "arguments_json": (
                    '{"target":"example.com","lhost":"127.0.0.1","lport":4444}'
                ),
            },
        )

        assert "**Endpoint:** `security_tool_nmap`" in nmap_metadata["result"]
        assert "**Generated options:** `-p 80,443 -sV -T4`" in nmap_metadata["result"]
        assert "No command was executed." in nmap_metadata["result"]

        assert "**Endpoint:** `security_tool_vegil`" in vegil_metadata["result"]
        assert "**Executable:** False" in vegil_metadata["result"]
        assert "**Generated options:** `--lhost 127.0.0.1 --lport 4444`" in vegil_metadata["result"]
        assert "No command was executed." in vegil_metadata["result"]

    @pytest.mark.asyncio
    async def test_tool_adapter_audit_reports_full_coverage(self):
        """Adapter audit should verify all registry tools have usable adapters."""
        from hacking_mcp.server import create_server

        server = create_server()
        _, metadata = await server.call_tool(
            "security_audit_tool_adapters",
            {"include_details": True},
        )

        result = metadata["result"]
        assert "**Status:** PASS" in result
        assert "Registry tools: 184" in result
        assert "Adapter specs: 184" in result
        assert "Missing adapter specs: 0" in result
        assert "Missing tool-specific parameters: 0" in result
        assert "Preview generation errors: 0" in result

    @pytest.mark.asyncio
    async def test_adapter_research_status_reports_source_review_gaps(self):
        """Research status should expose current evidence and source-review gaps."""
        from hacking_mcp.server import create_server
        from hacking_mcp.server import registry, safety
        from hacking_mcp.mcp_tools.adapter_research import (
            build_adapter_research_records,
            summarize_adapter_research,
        )

        research_summary = summarize_adapter_research(
            build_adapter_research_records(registry, safety)
        )

        server = create_server()
        _, summary_metadata = await server.call_tool(
            "security_get_adapter_research_status",
            {"status": "source-review-gap", "limit": 3},
        )
        _, nmap_metadata = await server.call_tool(
            "security_get_adapter_research_status",
            {"tool_name": "nmap"},
        )

        result = summary_metadata["result"]
        assert "Total adapters: 184" in result
        assert f"Source-reviewed: {research_summary['source_reviewed']}" in result
        assert (
            f"Fully source-verified: {research_summary['fully_source_verified']}"
            in result
        )
        assert (
            f"Open source-review gaps: {research_summary['source_review_gaps']}"
            in result
        )
        assert f"Showing: 3/{research_summary['source_review_gaps']}" in result

        nmap = nmap_metadata["result"]
        assert "**Tool:** `nmap`" in nmap
        assert "**Source status:** `source-reviewed`" in nmap
        assert "dedicated split adapter module is registered" in nmap
        assert "**Unverified params:** 0" in nmap
        assert "## Unverified Parameters" not in nmap
        assert "source reference: https://nmap.org/book/man.html" in nmap


class TestToolCoherence:
    """Verify that all tools referenced in MCP tool modules exist in the registry."""

    def test_recon_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.recon import RECON_CATEGORY, EXTRA_RECON_TOOLS
        recon_tools = [t.name for t in registry.get_category_tools(RECON_CATEGORY)]
        recon_tools.extend(EXTRA_RECON_TOOLS)
        for name in recon_tools:
            assert registry.get_tool(name) is not None, f"Recon tool '{name}' not in registry"

    def test_scanner_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.scanner import SCANNER_TOOLS
        for name in SCANNER_TOOLS:
            assert registry.get_tool(name) is not None, f"Scanner tool '{name}' not in registry"

    def test_web_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.web import WEB_TOOLS
        for name in WEB_TOOLS:
            assert registry.get_tool(name) is not None, f"Web tool '{name}' not in registry"

    def test_forensics_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.forensics_tools import FORENSICS_TOOLS_LIST
        for name in FORENSICS_TOOLS_LIST:
            assert registry.get_tool(name) is not None, f"Forensics tool '{name}' not in registry"

    def test_cloud_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.cloud_tools import CLOUD_TOOL_NAMES
        for name in CLOUD_TOOL_NAMES:
            assert registry.get_tool(name) is not None, f"Cloud tool '{name}' not in registry"

    def test_ad_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.ad_tools import AD_TOOL_NAMES
        for name in AD_TOOL_NAMES:
            assert registry.get_tool(name) is not None, f"AD tool '{name}' not in registry"

    def test_exploit_tools_exist(self):
        from hacking_mcp.server import registry
        from hacking_mcp.mcp_tools.exploit import EXPLOIT_TOOL_NAMES
        for name in EXPLOIT_TOOL_NAMES:
            assert registry.get_tool(name) is not None, f"Exploit tool '{name}' not in registry"


class TestSafetyTiers:
    """Verify safety tier assignments are reasonable."""

    def test_no_dangerous_tools_in_mcp(self):
        """DANGEROUS tier tools should not be in any MCP tool set."""
        from hacking_mcp.server import registry
        dangerous = [
            t.name for t in registry.list_all_tools()
            if t.safety_tier.value == "dangerous"
        ]
        # Only mythic is DANGEROUS; ensure it's not accidentally in MCP tools
        from hacking_mcp.mcp_tools.recon import EXTRA_RECON_TOOLS
        from hacking_mcp.mcp_tools.scanner import SCANNER_TOOLS
        from hacking_mcp.mcp_tools.web import WEB_TOOLS
        from hacking_mcp.mcp_tools.forensics_tools import FORENSICS_TOOLS_LIST
        from hacking_mcp.mcp_tools.cloud_tools import CLOUD_TOOL_NAMES
        from hacking_mcp.mcp_tools.ad_tools import AD_TOOL_NAMES
        from hacking_mcp.mcp_tools.exploit import EXPLOIT_TOOL_NAMES

        all_mcp_tools = (
            set(EXTRA_RECON_TOOLS)
            | SCANNER_TOOLS
            | WEB_TOOLS
            | FORENSICS_TOOLS_LIST
            | CLOUD_TOOL_NAMES
            | AD_TOOL_NAMES
            | EXPLOIT_TOOL_NAMES
        )
        for name in dangerous:
            assert name not in all_mcp_tools, f"DANGEROUS tool '{name}' is exposed via MCP!"
