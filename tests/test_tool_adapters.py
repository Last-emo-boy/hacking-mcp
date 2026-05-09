"""Tests for per-tool MCP adapter generation."""

import pytest

from hacking_mcp.mcp_tools.tool_adapters import (
    MCP_TOOL_PREFIX,
    build_adapter_specs,
    register,
)
from hacking_mcp.mcp_tools.adapter_research import (
    SOURCE_REVIEWED_TOOLS,
    build_adapter_research_records,
    summarize_adapter_research,
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


def test_adapter_research_records_cover_every_registry_tool(registry, safety):
    records = build_adapter_research_records(registry, safety)
    summary = summarize_adapter_research(records)

    assert len(records) == len(registry.get_tool_names())
    assert {record.tool_name for record in records} == set(registry.get_tool_names())
    assert summary["total"] == len(registry.get_tool_names())
    assert (
        summary["registry_derived"]
        + summary["named_override"]
        + summary["source_reviewed"]
        == summary["total"]
    )
    assert summary["source_reviewed"] == len(SOURCE_REVIEWED_TOOLS)
    assert summary["fully_source_verified"] == len(SOURCE_REVIEWED_TOOLS)
    assert summary["source_review_gaps"] == summary["total"] - len(SOURCE_REVIEWED_TOOLS)


def test_adapter_research_distinguishes_named_overrides(registry, safety):
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["nmap"].source_status == "source-reviewed"
    assert records["nmap"].named_override is True
    assert records["nmap"].source_reviewed is True
    assert records["nmap"].unverified_parameters == ()
    assert records["nmap"].gap == ""
    assert any("nmap.org" in item for item in records["nmap"].evidence)

    assert records["ffuf"].source_status == "source-reviewed"
    assert records["ffuf"].unverified_parameters == ()
    assert records["ffuf"].gap == ""

    assert records["httpx"].source_status == "source-reviewed"
    assert records["httpx"].unverified_parameters == ()
    assert any("projectdiscovery.io" in item for item in records["httpx"].evidence)

    assert records["subfinder"].source_status == "source-reviewed"
    assert records["subfinder"].unverified_parameters == ()
    assert any("subfinder/usage" in item for item in records["subfinder"].evidence)

    assert records["amass"].source_status == "source-reviewed"
    assert records["amass"].unverified_parameters == ()
    assert any("owasp-amass/amass" in item for item in records["amass"].evidence)

    assert records["masscan"].source_status == "source-reviewed"
    assert records["masscan"].unverified_parameters == ()
    assert any("robertdavidgraham/masscan" in item for item in records["masscan"].evidence)

    assert records["rustscan"].source_status == "source-reviewed"
    assert records["rustscan"].unverified_parameters == ()
    assert any("RustScan/RustScan" in item for item in records["rustscan"].evidence)

    assert records["katana"].source_status == "source-reviewed"
    assert records["katana"].unverified_parameters == ()
    assert any("katana/usage" in item for item in records["katana"].evidence)

    assert records["arjun"].source_status == "source-reviewed"
    assert records["arjun"].unverified_parameters == ()
    assert any("Arjun/wiki/Usage" in item for item in records["arjun"].evidence)

    assert records["gobuster"].source_status == "source-reviewed"
    assert records["gobuster"].unverified_parameters == ()
    assert any("OJ/gobuster" in item for item in records["gobuster"].evidence)

    assert records["gitleaks"].source_status == "source-reviewed"
    assert records["gitleaks"].unverified_parameters == ()
    assert any("gitleaks/gitleaks" in item for item in records["gitleaks"].evidence)

    assert records["trufflehog"].source_status == "source-reviewed"
    assert records["trufflehog"].unverified_parameters == ()
    assert any("trufflesecurity/trufflehog" in item for item in records["trufflehog"].evidence)

    assert records["dracnmap"].source_status == "registry-derived"
    assert records["dracnmap"].named_override is False
    assert records["dracnmap"].gap


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

    subfinder_schema = tools["security_tool_subfinder"].inputSchema["properties"]
    assert {
        "input_file", "sources", "exclude_sources", "all_sources", "recursive",
        "resolver_file", "rate_limit", "output_file", "json_output", "silent",
    }.issubset(subfinder_schema)

    amass_schema = tools["security_tool_amass"].inputSchema["properties"]
    assert {
        "config_file", "output_dir", "active", "passive", "brute",
        "domain_file", "exclude_sources", "include_sources", "resolver_file",
        "dns_qps", "trusted_resolver_file", "wordlist", "wordlist_masks",
    }.issubset(amass_schema)

    nuclei_schema = tools["security_tool_nuclei"].inputSchema["properties"]
    assert {"workflows", "exclude_templates", "headless", "interactsh"}.issubset(
        nuclei_schema
    )

    harvester_schema = tools["security_tool_theharvester"].inputSchema["properties"]
    assert {"limit", "start", "takeover", "dns_lookup"}.issubset(harvester_schema)

    trufflehog_schema = tools["security_tool_trufflehog"].inputSchema["properties"]
    assert {
        "json_output", "github_actions", "concurrency", "no_verification",
        "results", "filter_entropy", "config_path", "fail", "log_level",
    }.issubset(trufflehog_schema)

    gitleaks_schema = tools["security_tool_gitleaks"].inputSchema["properties"]
    assert {
        "redact", "log_opts", "config_path", "baseline_path", "ignore_path",
        "report_format", "report_path", "log_level", "no_banner", "no_color",
    }.issubset(gitleaks_schema)

    prowler_schema = tools["security_tool_prowler"].inputSchema["properties"]
    assert {"provider", "checks", "excluded_checks", "output_format"}.issubset(
        prowler_schema
    )

    netexec_schema = tools["security_tool_netexec"].inputSchema["properties"]
    assert {"users_file", "passwords_file", "kerberos", "local_auth"}.issubset(
        netexec_schema
    )

    volatility_schema = tools["security_tool_volatility3"].inputSchema["properties"]
    assert {"symbol_dir", "renderer", "dump_files"}.issubset(volatility_schema)

    binwalk_schema = tools["security_tool_binwalk"].inputSchema["properties"]
    assert {"signature_scan", "entropy", "matryoshka", "carve"}.issubset(
        binwalk_schema
    )

    hashcat_schema = tools["security_tool_hashcat"].inputSchema["properties"]
    assert {"rules", "mask", "session", "show", "potfile_path"}.issubset(
        hashcat_schema
    )

    mobsf_schema = tools["security_tool_mobsf"].inputSchema["properties"]
    assert {"server_url", "api_key", "frida_script", "runtime_command"}.issubset(
        mobsf_schema
    )

    masscan_schema = tools["security_tool_masscan"].inputSchema["properties"]
    assert {
        "ports", "rate", "config_file", "echo", "banners", "source_ip",
        "source_port", "exclude_file", "include_file", "output_xml",
        "output_json", "output_format", "readscan",
    }.issubset(masscan_schema)

    rustscan_schema = tools["security_tool_rustscan"].inputSchema["properties"]
    assert {
        "ports", "port_range", "no_config", "no_banner", "config_path",
        "greppable", "resolver", "batch_size", "timeout", "ulimit",
        "scan_order", "scripts", "exclude_ports", "exclude_addresses", "udp",
    }.issubset(rustscan_schema)

    ffuf_schema = tools["security_tool_ffuf"].inputSchema["properties"]
    assert {"filter_codes", "filter_size", "filter_words", "add_slash"}.issubset(
        ffuf_schema
    )

    gobuster_schema = tools["security_tool_gobuster"].inputSchema["properties"]
    assert {
        "wordlist", "extensions", "headers", "cookies", "show_length",
        "status_codes", "threads", "delay", "user_agent", "timeout",
        "output_file", "quiet", "no_progress", "expanded", "add_slash",
    }.issubset(gobuster_schema)

    katana_schema = tools["security_tool_katana"].inputSchema["properties"]
    assert {
        "input_file", "depth", "strategy", "js_crawl", "known_files",
        "automatic_form_fill", "headless", "proxy", "rate_limit", "json_output",
    }.issubset(katana_schema)

    arjun_schema = tools["security_tool_arjun"].inputSchema["properties"]
    assert {
        "input_file", "output_json", "output_burp", "output_text", "method",
        "include_data", "threads", "delay", "timeout", "stable", "rate_limit",
        "wordlist", "chunk_size", "disable_redirects", "passive", "headers",
    }.issubset(arjun_schema)

    evil_winrm_schema = tools["security_tool_evil_winrm"].inputSchema["properties"]
    assert {"ssl", "key_file", "cert_file", "upload", "download"}.issubset(
        evil_winrm_schema
    )

    commix_schema = tools["security_tool_commix"].inputSchema["properties"]
    assert {"parameter", "method", "delay", "os_shell", "batch"}.issubset(
        commix_schema
    )

    pacu_schema = tools["security_tool_pacu"].inputSchema["properties"]
    assert {"session", "module", "regions", "report_dir"}.issubset(pacu_schema)

    evilginx_schema = tools["security_tool_evilginx3"].inputSchema["properties"]
    assert {"site", "redirect_url", "custom_domain", "phishlet"}.issubset(
        evilginx_schema
    )

    msfvenom_schema = tools["security_tool_msfvenom"].inputSchema["properties"]
    assert {"stager", "listener_name", "apk_name", "bundle_id", "sign_apk"}.issubset(
        msfvenom_schema
    )

    airgeddon_schema = tools["security_tool_airgeddon"].inputSchema["properties"]
    assert {"pmkid", "deauth_count", "capture_file", "target_essid"}.issubset(
        airgeddon_schema
    )

    anonsurf_schema = tools["security_tool_anonsurf"].inputSchema["properties"]
    assert {"action", "new_identity", "dns_only"}.issubset(anonsurf_schema)

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
async def test_second_wave_named_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_nuclei",
        {
            "target": "https://example.test",
            "severity": "critical,high",
            "tags": "exposure",
            "headless": True,
            "workflows": "workflows/",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "nuclei"
    assert request.options == (
        "-severity critical,high -tags exposure -w workflows/ -headless"
    )


@pytest.mark.asyncio
async def test_httpx_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_httpx",
        {
            "target": "https://example.test",
            "status_code": True,
            "title": True,
            "tech_detect": True,
            "content_length": True,
            "match_codes": "200,302",
            "filter_codes": "404",
            "threads": 25,
            "rate_limit": 100,
            "path": "/login",
            "follow_redirects": True,
            "proxy": "http://127.0.0.1:8080",
            "headers": "X-Test: 1",
            "method": "GET",
            "timeout": 5,
            "output_file": "httpx.jsonl",
            "json_output": True,
            "silent": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "httpx"
    assert request.options == (
        "-sc -title -td -cl -mc 200,302 -fc 404 -t 25 -rl 100 "
        "-path /login -fr -proxy http://127.0.0.1:8080 -H 'X-Test: 1' "
        "-x GET -timeout 5 -o httpx.jsonl -json -silent"
    )


@pytest.mark.asyncio
async def test_subfinder_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_subfinder",
        {
            "target": "example.test",
            "input_file": "domains.txt",
            "sources": "crtsh,github",
            "exclude_sources": "shodan",
            "all_sources": True,
            "recursive": True,
            "active": True,
            "resolvers": "1.1.1.1,8.8.8.8",
            "resolver_file": "resolvers.txt",
            "rate_limit": 50,
            "threads": 20,
            "timeout": 30,
            "max_time": 10,
            "output_file": "subdomains.txt",
            "json_output": True,
            "output_dir": "subfinder-out",
            "collect_sources": True,
            "include_ip": True,
            "config_file": "config.yaml",
            "provider_config": "providers.yaml",
            "proxy": "http://127.0.0.1:8080",
            "silent": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "subfinder"
    assert request.options == (
        "-dL domains.txt -s crtsh,github -es shodan -all -recursive "
        "-active -r 1.1.1.1,8.8.8.8 -rL resolvers.txt -rl 50 -t 20 "
        "-timeout 30 -max-time 10 -o subdomains.txt -oJ -oD subfinder-out "
        "-cs -oI -config config.yaml -pc providers.yaml "
        "-proxy http://127.0.0.1:8080 -silent"
    )


@pytest.mark.asyncio
async def test_amass_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_amass",
        {
            "target": "example.test",
            "config_file": "amass.yaml",
            "output_dir": "amass-out",
            "active": True,
            "brute": True,
            "domain_file": "domains.txt",
            "exclude_sources": "shodan",
            "include_sources": "crtsh",
            "interface": "eth0",
            "include_ip": True,
            "log_file": "amass.log",
            "max_depth": 3,
            "output_file": "names.txt",
            "ports": "80,443",
            "resolvers": "1.1.1.1",
            "resolver_file": "resolvers.txt",
            "dns_qps": 200,
            "resolver_qps": 20,
            "scripts_dir": "scripts",
            "timeout": 30,
            "trusted_resolvers": "8.8.8.8",
            "trusted_resolver_file": "trusted.txt",
            "trusted_qps": 50,
            "verbose": True,
            "wordlist": "words.txt",
            "wordlist_masks": "?l?l?l",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "amass"
    assert request.options == (
        "-config amass.yaml -dir amass-out -active -brute -df domains.txt "
        "-exclude shodan -include crtsh -iface eth0 -ip -log amass.log "
        "-max-depth 3 -o names.txt -p 80,443 -r 1.1.1.1 -rf resolvers.txt "
        "-dns-qps 200 -rqps 20 -scripts scripts -timeout 30 -tr 8.8.8.8 "
        "-trf trusted.txt -trqps 50 -v -w words.txt -wm '?l?l?l'"
    )


@pytest.mark.asyncio
async def test_masscan_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_masscan",
        {
            "target": "192.0.2.0/24",
            "ports": "80,443",
            "rate": 1000,
            "config_file": "masscan.conf",
            "banners": True,
            "source_ip": "192.0.2.10",
            "source_port": 61000,
            "exclude_file": "exclude.txt",
            "include_file": "include.txt",
            "output_xml": "scan.xml",
            "output_json": "scan.json",
            "output_format": "list",
            "output_filename": "scan.lst",
            "readscan": "scan.bin",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "masscan"
    assert request.options == (
        "-p 80,443 --rate 1000 -c masscan.conf --banners "
        "--source-ip 192.0.2.10 --source-port 61000 --excludefile exclude.txt "
        "--includefile include.txt -oX scan.xml -oJ scan.json "
        "--output-format list --output-filename scan.lst --readscan scan.bin"
    )


@pytest.mark.asyncio
async def test_rustscan_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_rustscan",
        {
            "target": "192.0.2.10",
            "ports": "80,443",
            "port_range": "1-1000",
            "no_banner": True,
            "config_path": "rustscan.toml",
            "greppable": True,
            "resolver": "1.1.1.1",
            "batch_size": 500,
            "timeout": 1500,
            "tries": 2,
            "ulimit": 5000,
            "scan_order": "serial",
            "scripts": "none",
            "exclude_ports": "25,110",
            "exclude_addresses": "192.0.2.1",
            "udp": True,
            "nmap_args": "-sV -sC",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "rustscan"
    assert request.options == (
        "-p 80,443 -r 1-1000 --no-banner --config-path rustscan.toml "
        "-g --resolver 1.1.1.1 -b 500 -t 1500 --tries 2 -u 5000 "
        "--scan-order serial --scripts none --exclude-ports 25,110 "
        "--exclude-addresses 192.0.2.1 --udp -- -sV -sC"
    )


@pytest.mark.asyncio
async def test_katana_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_katana",
        {
            "target": "https://example.test",
            "input_file": "urls.txt",
            "depth": 3,
            "strategy": "depth-first",
            "js_crawl": True,
            "known_files": "robots.txt,sitemap.xml",
            "automatic_form_fill": True,
            "form_extraction": True,
            "headless": True,
            "no_sandbox": True,
            "system_chrome": True,
            "proxy": "http://127.0.0.1:8080",
            "headers": "X-Test: 1",
            "timeout": 10,
            "retry": 2,
            "rate_limit": 50,
            "concurrency": 10,
            "parallelism": 2,
            "delay": "1s",
            "crawl_duration": "5m",
            "output_file": "katana.jsonl",
            "json_output": True,
            "field": "url",
            "silent": True,
            "no_color": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "katana"
    assert request.options == (
        "-list urls.txt -d 3 -strategy depth-first -jc -kf robots.txt,sitemap.xml "
        "-aff -fx -headless -nos -system-chrome -proxy http://127.0.0.1:8080 "
        "-H 'X-Test: 1' -timeout 10 -retry 2 -rl 50 -c 10 -p 2 "
        "-delay 1s -ct 5m -o katana.jsonl -jsonl -field url -silent -no-color"
    )


@pytest.mark.asyncio
async def test_arjun_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_arjun",
        {
            "target": "https://example.test",
            "input_file": "targets.txt",
            "output_json": "arjun.json",
            "output_burp": "burp.xml",
            "output_text": "arjun.txt",
            "method": "POST",
            "include_data": "api_key=test",
            "threads": 20,
            "delay": 1,
            "timeout": 10,
            "stable": True,
            "rate_limit": 5,
            "wordlist": "large",
            "chunk_size": 250,
            "disable_redirects": True,
            "passive": "-",
            "casing": "foo_bar",
            "headers": "X-Test: 1",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "arjun"
    assert request.options == (
        "-i targets.txt -oJ arjun.json -oB burp.xml -oT arjun.txt "
        "-m POST --include api_key=test -t 20 -d 1 -T 10 --stable "
        "--ratelimit 5 -w large -c 250 --disable-redirects --passive - "
        "--casing foo_bar --headers 'X-Test: 1'"
    )


@pytest.mark.asyncio
async def test_gobuster_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_gobuster",
        {
            "target": "https://example.test",
            "wordlist": "words.txt",
            "extensions": "php,txt",
            "headers": "X-Test: 1",
            "cookies": "session=value",
            "show_length": True,
            "status_codes": "200,301,302",
            "threads": 20,
            "delay": "1s",
            "user_agent": "hacking-mcp",
            "timeout": "10s",
            "output_file": "gobuster.txt",
            "quiet": True,
            "no_progress": True,
            "expanded": True,
            "add_slash": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "gobuster"
    assert request.options == (
        "-w words.txt -x php,txt -H 'X-Test: 1' -c session=value -l "
        "-s 200,301,302 -t 20 --delay 1s -a hacking-mcp --timeout 10s "
        "-o gobuster.txt -q --no-progress -e -f"
    )


@pytest.mark.asyncio
async def test_gitleaks_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_gitleaks",
        {
            "target": "repo",
            "redact": True,
            "log_opts": "since=2026-01-01",
            "config_path": "gitleaks.toml",
            "baseline_path": "baseline.json",
            "ignore_path": ".gitleaksignore",
            "enable_rule": "generic-api-key",
            "exit_code": 2,
            "follow_symlinks": True,
            "ignore_allow": True,
            "max_decode_depth": 2,
            "max_archive_depth": 1,
            "max_target_mb": 5,
            "report_format": "json",
            "report_path": "gitleaks.json",
            "report_template": "template.tmpl",
            "log_level": "debug",
            "no_banner": True,
            "no_color": True,
            "verbose": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "gitleaks"
    assert request.options == (
        "--redact --log-opts since=2026-01-01 --config gitleaks.toml "
        "--baseline-path baseline.json --gitleaks-ignore-path .gitleaksignore "
        "--enable-rule generic-api-key --exit-code 2 --follow-symlinks "
        "--ignore-gitleaks-allow --max-decode-depth 2 --max-archive-depth 1 "
        "--max-target-megabytes 5 --report-format json --report-path gitleaks.json "
        "--report-template template.tmpl --log-level debug --no-banner --no-color "
        "--verbose"
    )


@pytest.mark.asyncio
async def test_trufflehog_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_trufflehog",
        {
            "target": "repo",
            "json_output": True,
            "github_actions": True,
            "concurrency": 12,
            "no_verification": True,
            "results": "verified,unknown",
            "no_color": True,
            "allow_verification_overlap": True,
            "filter_unverified": True,
            "filter_entropy": 3.0,
            "config_path": "trufflehog.yaml",
            "print_avg_detector_time": True,
            "fail": True,
            "log_level": "info",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "trufflehog"
    assert request.options == (
        "--json --github-actions --concurrency 12 --no-verification "
        "--results verified,unknown --no-color --allow-verification-overlap "
        "--filter-unverified --filter-entropy 3.0 --config trufflehog.yaml "
        "--print-avg-detector-time --fail --log-level info"
    )


@pytest.mark.asyncio
async def test_local_analysis_named_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_binwalk",
        {
            "target": "firmware.bin",
            "extract": True,
            "entropy": True,
            "matryoshka": True,
            "output_dir": "out",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "binwalk"
    assert request.options == "-o out -e -E -M"


@pytest.mark.asyncio
async def test_web_discovery_named_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_ffuf",
        {
            "target": "https://example.test/FUZZ",
            "wordlist": "words.txt",
            "filter_codes": "404,403",
            "filter_size": "1234",
            "threads": 20,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "ffuf"
    assert request.options == "-w words.txt -t 20 -fc 404,403 -fs 1234"


@pytest.mark.asyncio
async def test_offensive_named_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_commix",
        {
            "target": "https://example.test/vuln?x=1",
            "parameter": "x",
            "method": "POST",
            "delay": 5,
            "os_shell": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "commix"
    assert request.options == "-p x --method POST --time-sec 5 --os-shell --batch"


@pytest.mark.asyncio
async def test_policy_only_named_parameters_preview_without_execution(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock()

    register(mcp, orchestrator, registry, safety)
    content, metadata = await mcp.call_tool(
        "security_tool_msfvenom",
        {
            "target": "lab",
            "payload_type": "generic/shell_reverse_tcp",
            "lhost": "127.0.0.1",
            "lport": 4444,
            "format": "raw",
            "sign_apk": True,
        },
    )

    assert "does not run the tool" in metadata["result"]
    assert content
    orchestrator.execute.assert_not_awaited()


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
