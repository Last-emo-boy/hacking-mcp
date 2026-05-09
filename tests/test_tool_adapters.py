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


def test_dangerous_tools_are_not_executable(registry, safety):
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


def test_every_adapter_has_tool_specific_parameters(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    base_params = {"target", "options", "confirm_authorized"}
    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    missing = []
    for tool in registry.list_all_tools():
        params = set(adapter_parameter_names(tool, specs[tool.name]))
        if not (params - base_params):
            missing.append(tool.name)

    assert missing == []


@pytest.mark.asyncio
async def test_register_adds_every_tool_name(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock()

    specs = register(mcp, orchestrator, registry, safety)
    tool_names = {tool.name for tool in await mcp.list_tools()}
    adapter_names = {spec.mcp_name for spec in specs}

    assert "security_tool_nmap" in tool_names
    assert "security_tool_sqlmap" in tool_names
    assert "security_tool_vegil" in tool_names
    assert adapter_names == tool_names


@pytest.mark.asyncio
async def test_adapter_schema_includes_tool_specific_parameters(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock()

    register(mcp, orchestrator, registry, safety)
    tools = {tool.name: tool for tool in await mcp.list_tools()}

    nmap_schema = tools["security_tool_nmap"].inputSchema["properties"]
    assert {
        "target", "ports", "scan_type", "service_version", "timing", "scripts",
        "script_args", "exclude_hosts",
    }.issubset(nmap_schema)

    sqlmap_schema = tools["security_tool_sqlmap"].inputSchema["properties"]
    assert {
        "target", "data", "dbms", "risk", "level", "enumerate_databases",
        "cookie", "tamper", "technique", "random_agent",
    }.issubset(sqlmap_schema)

    httpx_schema = tools["security_tool_httpx"].inputSchema["properties"]
    assert {"status_code", "title", "tech_detect", "content_length"}.issubset(
        httpx_schema
    )

    bloodhound_schema = tools["security_tool_bloodhound"].inputSchema["properties"]
    assert {"domain", "username", "dc_ip", "collection_method"}.issubset(
        bloodhound_schema
    )

    binwalk_schema = tools["security_tool_binwalk"].inputSchema["properties"]
    assert {"output_dir", "extract", "plugin"}.issubset(binwalk_schema)

    jadx_schema = tools["security_tool_jadx"].inputSchema["properties"]
    assert {"binary_path", "output_dir", "decompile"}.issubset(jadx_schema)

    setoolkit_schema = tools["security_tool_setoolkit"].inputSchema["properties"]
    assert {"template", "listener_host", "listener_port", "tunnel"}.issubset(
        setoolkit_schema
    )

    msfvenom_schema = tools["security_tool_msfvenom"].inputSchema["properties"]
    assert {"payload_type", "platform", "lhost", "lport", "format"}.issubset(
        msfvenom_schema
    )

    wifite_schema = tools["security_tool_wifite"].inputSchema["properties"]
    assert {"interface", "bssid", "essid", "channel", "wordlist"}.issubset(
        wifite_schema
    )

    vegil_schema = tools["security_tool_vegil"].inputSchema["properties"]
    assert {"lhost", "lport", "listener", "protocol"}.issubset(vegil_schema)


@pytest.mark.asyncio
async def test_structured_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_nmap",
        {
            "target": "127.0.0.1",
            "ports": "80,443",
            "service_version": True,
            "timing": 4,
            "options": "--reason",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "nmap"
    assert request.target == "127.0.0.1"
    assert request.options == "-p 80,443 -sV -T4 --reason"


@pytest.mark.asyncio
async def test_tool_specific_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_sqlmap",
        {
            "target": "https://example.test/item?id=1",
            "data": "id=1",
            "risk": 2,
            "level": 3,
            "tamper": "space2comment",
            "technique": "BEUSTQ",
            "random_agent": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "sqlmap"
    assert request.options == (
        "--data id=1 --risk 2 --level 3 --tamper space2comment "
        "--technique BEUSTQ --random-agent"
    )


@pytest.mark.asyncio
async def test_ad_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_bloodhound",
        {
            "target": "corp.local",
            "domain": "corp.local",
            "username": "alice",
            "dc_ip": "10.0.0.10",
            "collection_method": "Default",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "bloodhound"
    assert request.target == "corp.local"
    assert request.options == "-d corp.local -u alice -dc-ip 10.0.0.10 -c Default"


@pytest.mark.asyncio
async def test_blocked_adapter_does_not_execute_orchestrator(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock()

    register(mcp, orchestrator, registry, safety)
    content, metadata = await mcp.call_tool(
        "security_tool_vegil",
        {"target": "example.com", "lhost": "127.0.0.1", "lport": 4444},
    )

    assert "classified DANGEROUS" in metadata["result"]
    assert "does not run the tool" in metadata["result"]
    assert content
    orchestrator.execute.assert_not_awaited()
