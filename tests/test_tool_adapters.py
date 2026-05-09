"""Tests for per-tool MCP adapter generation."""

import pytest

from hacking_mcp.mcp_tools.tool_adapters import (
    MCP_TOOL_PREFIX,
    build_adapter_specs,
    register,
)
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy
from hacking_mcp.models import SafetyTier


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def safety(tmp_path):
    return SafetyPolicy(
        disabled_categories=[
            "DDOS Attack",
            "Remote Administration (RAT)",
            "Payload Creation",
            "Phishing Attack",
            "Wireless Attack",
            "Anonymously Hiding",
        ],
        disabled_tools=["Chrome Keylogger", "Vegile", "Spycam", "SayCheese"],
        require_confirmation_categories=[
            "SQL Injection",
            "Exploit Framework",
            "Post Exploitation",
            "XSS Attack",
        ],
        _audit_path=tmp_path / "audit" / "audit.jsonl",
    )


def test_adapter_specs_cover_every_registry_tool(registry, safety):
    specs = build_adapter_specs(registry, safety)
    assert len(specs) == len(registry.get_tool_names())
    assert {s.tool_name for s in specs} == set(registry.get_tool_names())


def test_adapter_names_are_unique_and_prefixed(registry, safety):
    specs = build_adapter_specs(registry, safety)
    names = [s.mcp_name for s in specs]
    assert len(names) == len(set(names))
    assert all(name.startswith(MCP_TOOL_PREFIX) for name in names)


def test_dangerous_tools_are_not_exposed(registry, safety):
    specs = build_adapter_specs(registry, safety)
    exposed = {s.tool_name for s in specs if s.exposed}
    dangerous = {
        tool.name
        for tool in registry.list_all_tools()
        if tool.safety_tier == SafetyTier.DANGEROUS
    }
    assert dangerous
    assert exposed.isdisjoint(dangerous)


def test_common_safe_and_caution_tools_are_exposed(registry, safety):
    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}

    assert specs["nmap"].exposed is True
    assert specs["nmap"].mcp_name == "security_tool_nmap"
    assert specs["nmap"].target_required is True

    assert specs["sqlmap"].exposed is True
    assert specs["sqlmap"].requires_confirmation is True
    assert specs["sqlmap"].mcp_name == "security_tool_sqlmap"


def test_disabled_safe_categories_are_not_exposed(registry, safety):
    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    if "howmanypeople" in specs:
        assert specs["howmanypeople"].exposed is False


@pytest.mark.asyncio
async def test_register_adds_exposed_tool_names(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock()

    specs = register(mcp, orchestrator, registry, safety)
    tool_names = {tool.name for tool in await mcp.list_tools()}
    exposed_names = {spec.mcp_name for spec in specs if spec.exposed}

    assert "security_tool_nmap" in tool_names
    assert "security_tool_sqlmap" in tool_names
    assert exposed_names.issubset(tool_names)
