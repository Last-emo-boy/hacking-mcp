"""Tests for per-tool MCP adapter generation."""

import pytest

from hacking_mcp.mcp_tools.tool_adapters import (
    MCP_TOOL_PREFIX,
    adapter_request_preview,
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


def test_split_adapter_registry_includes_migrated_tools():
    from hacking_mcp.registry import ALL_CATEGORIES
    from hacking_mcp.mcp_tools.adapters import (
        PARAMETER_PROVIDERS,
        has_split_adapter,
    )

    registry_tools = {
        tool.name
        for tools in ALL_CATEGORIES.values()
        for tool in tools
    }
    assert registry_tools.issubset(PARAMETER_PROVIDERS)
    assert all(has_split_adapter(tool_name) for tool_name in registry_tools)


def test_adapter_research_distinguishes_named_overrides(registry, safety):
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["nmap"].source_status == "source-reviewed"
    assert records["nmap"].named_override is False
    assert records["nmap"].source_reviewed is True
    assert records["nmap"].unverified_parameters == ()
    assert records["nmap"].gap == ""
    assert "dedicated split adapter module is registered" in records["nmap"].evidence
    assert any("nmap.org" in item for item in records["nmap"].evidence)

    assert records["portscan"].source_status == "source-reviewed"
    assert records["portscan"].unverified_parameters == ()
    assert any("nmap.org" in item for item in records["portscan"].evidence)

    assert records["host2ip"].source_status == "source-reviewed"
    assert records["host2ip"].unverified_parameters == ()
    assert any("socket.gethostbyname" in item for item in records["host2ip"].evidence)

    assert records["isitdown"].source_status == "source-reviewed"
    assert records["isitdown"].unverified_parameters == ()
    assert any("urllib.request.urlopen" in item for item in records["isitdown"].evidence)

    assert records["ffuf"].source_status == "source-reviewed"
    assert records["ffuf"].unverified_parameters == ()
    assert records["ffuf"].gap == ""

    assert records["httpx"].source_status == "source-reviewed"
    assert records["httpx"].unverified_parameters == ()
    assert any("projectdiscovery.io" in item for item in records["httpx"].evidence)

    assert records["binwalk"].source_status == "source-reviewed"
    assert records["binwalk"].unverified_parameters == ()
    assert any("ReFirmLabs/binwalk" in item for item in records["binwalk"].evidence)

    assert records["volatility3"].source_status == "source-reviewed"
    assert records["volatility3"].unverified_parameters == ()
    assert any("volatilityfoundation/volatility3" in item for item in records["volatility3"].evidence)

    assert records["pspy"].source_status == "source-reviewed"
    assert records["pspy"].unverified_parameters == ()
    assert any("DominicBreuker/pspy" in item for item in records["pspy"].evidence)

    assert records["haiti"].source_status == "source-reviewed"
    assert records["haiti"].unverified_parameters == ()
    assert any("noraj/haiti" in item for item in records["haiti"].evidence)

    assert records["steghide"].source_status == "source-reviewed"
    assert records["steghide"].unverified_parameters == ()
    assert any("steghide" in item for item in records["steghide"].evidence)

    assert records["stegcracker"].source_status == "source-reviewed"
    assert records["stegcracker"].unverified_parameters == ()
    assert any("Paradoxis/StegCracker" in item for item in records["stegcracker"].evidence)

    assert records["stegocracker"].source_status == "source-reviewed"
    assert records["stegocracker"].unverified_parameters == ()
    assert any("W1LDN16H7/StegoCracker" in item for item in records["stegocracker"].evidence)

    assert records["subfinder"].source_status == "source-reviewed"
    assert records["subfinder"].unverified_parameters == ()
    assert any("subfinder/usage" in item for item in records["subfinder"].evidence)

    assert records["theHarvester"].source_status == "source-reviewed"
    assert records["theHarvester"].unverified_parameters == ()
    assert any("laramies/theHarvester" in item for item in records["theHarvester"].evidence)

    assert records["sherlock"].source_status == "source-reviewed"
    assert records["sherlock"].unverified_parameters == ()
    assert any("sherlock-project/sherlock" in item for item in records["sherlock"].evidence)

    assert records["amass"].source_status == "source-reviewed"
    assert records["amass"].unverified_parameters == ()
    assert any("owasp-amass/amass" in item for item in records["amass"].evidence)

    assert records["masscan"].source_status == "source-reviewed"
    assert records["masscan"].unverified_parameters == ()
    assert any("robertdavidgraham/masscan" in item for item in records["masscan"].evidence)

    assert records["rustscan"].source_status == "source-reviewed"
    assert records["rustscan"].unverified_parameters == ()
    assert any("RustScan/RustScan" in item for item in records["rustscan"].evidence)

    assert records["rang3r"].source_status == "source-reviewed"
    assert records["rang3r"].unverified_parameters == ()
    assert any("floriankunushevci/rang3r" in item for item in records["rang3r"].evidence)

    assert records["striker"].source_status == "source-reviewed"
    assert records["striker"].unverified_parameters == ()
    assert any("s0md3v/Striker" in item for item in records["striker"].evidence)

    assert records["recondog"].source_status == "source-reviewed"
    assert records["recondog"].unverified_parameters == ()
    assert any("s0md3v/ReconDog" in item for item in records["recondog"].evidence)

    assert records["katana"].source_status == "source-reviewed"
    assert records["katana"].unverified_parameters == ()
    assert any("katana/usage" in item for item in records["katana"].evidence)

    assert records["arjun"].source_status == "source-reviewed"
    assert records["arjun"].unverified_parameters == ()
    assert any("Arjun/wiki/Usage" in item for item in records["arjun"].evidence)

    assert records["gobuster"].source_status == "source-reviewed"
    assert records["gobuster"].unverified_parameters == ()
    assert any("OJ/gobuster" in item for item in records["gobuster"].evidence)

    assert records["feroxbuster"].source_status == "source-reviewed"
    assert records["feroxbuster"].unverified_parameters == ()
    assert any("feroxbuster" in item for item in records["feroxbuster"].evidence)

    assert records["dirsearch"].source_status == "source-reviewed"
    assert records["dirsearch"].unverified_parameters == ()
    assert any("maurosoria/dirsearch" in item for item in records["dirsearch"].evidence)

    assert records["dirb"].source_status == "source-reviewed"
    assert records["dirb"].unverified_parameters == ()
    assert any("manpages.debian.org" in item for item in records["dirb"].evidence)

    assert records["takeover"].source_status == "source-reviewed"
    assert records["takeover"].unverified_parameters == ()
    assert any("edoardottt/takeover" in item for item in records["takeover"].evidence)

    assert records["skipfish"].source_status == "source-reviewed"
    assert records["skipfish"].unverified_parameters == ()
    assert any("skipfish" in item for item in records["skipfish"].evidence)

    assert records["caido"].source_status == "source-reviewed"
    assert records["caido"].unverified_parameters == ()
    assert any("caido" in item.lower() for item in records["caido"].evidence)

    assert records["mitmproxy"].source_status == "source-reviewed"
    assert records["mitmproxy"].unverified_parameters == ()
    assert any("mitmproxy" in item.lower() for item in records["mitmproxy"].evidence)

    assert records["nikto"].source_status == "source-reviewed"
    assert records["nikto"].unverified_parameters == ()
    assert any("sullo/nikto" in item for item in records["nikto"].evidence)

    assert records["owasp-zap"].source_status == "source-reviewed"
    assert records["owasp-zap"].unverified_parameters == ()
    assert any("zaproxy.org/docs/desktop/cmdline" in item for item in records["owasp-zap"].evidence)

    assert records["testssl"].source_status == "source-reviewed"
    assert records["testssl"].unverified_parameters == ()
    assert any("drwetter/testssl.sh" in item for item in records["testssl"].evidence)

    assert records["dalfox"].source_status == "source-reviewed"
    assert records["dalfox"].unverified_parameters == ()
    assert any("dalfox.hahwul.com" in item for item in records["dalfox"].evidence)

    assert records["xsstrike"].source_status == "source-reviewed"
    assert records["xsstrike"].unverified_parameters == ()
    assert any("UltimateHackers/XSStrike" in item for item in records["xsstrike"].evidence)

    assert records["xspear"].source_status == "source-reviewed"
    assert records["xspear"].unverified_parameters == ()
    assert any("hahwul/XSpear" in item for item in records["xspear"].evidence)

    assert records["xsscon"].source_status == "source-reviewed"
    assert records["xsscon"].unverified_parameters == ()
    assert any("menkrep1337/XSSCon" in item for item in records["xsscon"].evidence)

    assert records["xanxss"].source_status == "source-reviewed"
    assert records["xanxss"].unverified_parameters == ()
    assert any("Ekultek/XanXSS" in item for item in records["xanxss"].evidence)

    assert records["dsss"].source_status == "source-reviewed"
    assert records["dsss"].unverified_parameters == ()
    assert any("stamparm/DSSS" in item for item in records["dsss"].evidence)

    assert records["sqlscan"].source_status == "source-reviewed"
    assert records["sqlscan"].unverified_parameters == ()
    assert any("Cvar1984/sqlscan" in item for item in records["sqlscan"].evidence)

    assert records["wafw00f"].source_status == "source-reviewed"
    assert records["wafw00f"].unverified_parameters == ()
    assert any("EnableSecurity/wafw00f" in item for item in records["wafw00f"].evidence)

    assert records["gitleaks"].source_status == "source-reviewed"
    assert records["gitleaks"].unverified_parameters == ()
    assert any("gitleaks/gitleaks" in item for item in records["gitleaks"].evidence)

    assert records["trufflehog"].source_status == "source-reviewed"
    assert records["trufflehog"].unverified_parameters == ()
    assert any("trufflesecurity/trufflehog" in item for item in records["trufflehog"].evidence)

    assert records["whatweb"].source_status == "source-reviewed"
    assert records["whatweb"].unverified_parameters == ()
    assert any("urbanadventurer/WhatWeb" in item for item in records["whatweb"].evidence)

    assert records["hatcloud"].source_status == "source-reviewed"
    assert records["hatcloud"].unverified_parameters == ()
    assert any("HatBashBR/HatCloud" in item for item in records["hatcloud"].evidence)

    assert records["gospider"].source_status == "source-reviewed"
    assert records["gospider"].unverified_parameters == ()
    assert any("jaeles-project/gospider" in item for item in records["gospider"].evidence)

    assert records["frida"].source_status == "source-reviewed"
    assert records["frida"].unverified_parameters == ()
    assert any("frida/frida-tools" in item for item in records["frida"].evidence)

    assert records["objection"].source_status == "source-reviewed"
    assert records["objection"].unverified_parameters == ()
    assert any("sensepost/objection" in item for item in records["objection"].evidence)

    assert records["radare2"].source_status == "source-reviewed"
    assert records["radare2"].unverified_parameters == ()
    assert any("radareorg/radare2" in item for item in records["radare2"].evidence)

    assert records["ghidra"].source_status == "source-reviewed"
    assert records["ghidra"].unverified_parameters == ()
    assert any("NationalSecurityAgency/ghidra" in item for item in records["ghidra"].evidence)

    assert records["apk2gold"].source_status == "source-reviewed"
    assert records["apk2gold"].unverified_parameters == ()
    assert any("lxdvs/apk2gold" in item for item in records["apk2gold"].evidence)

    assert records["androguard"].source_status == "source-reviewed"
    assert records["androguard"].unverified_parameters == ()
    assert any("androguard/androguard" in item for item in records["androguard"].evidence)

    assert records["anonsurf"].source_status == "source-reviewed"
    assert records["anonsurf"].unverified_parameters == ()
    assert any("kali-anonsurf" in item for item in records["anonsurf"].evidence)

    assert records["multitor"].source_status == "source-reviewed"
    assert records["multitor"].unverified_parameters == ()
    assert any("trimstray/multitor" in item for item in records["multitor"].evidence)

    assert records["cupp"].source_status == "source-reviewed"
    assert records["cupp"].unverified_parameters == ()
    assert any("Mebus/cupp" in item for item in records["cupp"].evidence)

    assert records["wlcreator"].source_status == "source-reviewed"
    assert records["wlcreator"].unverified_parameters == ()
    assert any("Z4nzu/wlcreator" in item for item in records["wlcreator"].evidence)

    assert records["dracnmap"].source_status == "source-reviewed"
    assert records["dracnmap"].unverified_parameters == ()
    assert any("Screetsec/Dracnmap" in item for item in records["dracnmap"].evidence)


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
    assert {
        "sources", "limit", "start", "proxies", "shodan", "screenshot",
        "dns_server", "takeover", "dns_resolve", "dns_lookup", "dns_brute",
        "filename", "wordlist", "api_scan", "quiet",
    }.issubset(harvester_schema)

    sherlock_schema = tools["security_tool_sherlock"].inputSchema["properties"]
    assert {
        "verbose", "folder_output", "output_file", "csv_output", "xlsx_output",
        "sites", "site_list", "proxy", "dump_response", "json_file", "timeout",
        "print_all", "print_found", "no_color", "browse", "local", "nsfw",
        "txt_output", "ignore_exclusions",
    }.issubset(sherlock_schema)

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

    whatweb_schema = tools["security_tool_whatweb"].inputSchema["properties"]
    assert {
        "input_file", "url_prefix", "url_suffix", "url_pattern", "aggression",
        "user_agent", "header", "follow_redirect", "max_redirects",
        "basic_auth", "cookie", "cookiejar", "no_cookies", "proxy",
        "proxy_user", "list_plugins", "info_plugins", "info_plugin_search",
        "search_plugins", "plugins", "grep", "custom_plugin", "dorks",
        "verbose", "color", "quiet", "no_errors", "log_brief", "log_json",
        "max_threads", "open_timeout", "read_timeout", "wait", "output_sync",
        "output_buffer_size", "short_help", "debug", "version",
    }.issubset(whatweb_schema)

    prowler_schema = tools["security_tool_prowler"].inputSchema["properties"]
    assert {
        "profile", "region", "services", "severity", "checks",
        "excluded_checks", "excluded_services", "output_formats",
        "output_directory", "output_filename", "list_checks", "list_services",
        "no_banner", "no_color", "verbose", "log_level",
    }.issubset(prowler_schema)

    scoutsuite_schema = tools["security_tool_scoutsuite"].inputSchema["properties"]
    assert {
        "profile", "regions", "excluded_regions", "services",
        "skipped_services", "list_services", "result_format", "report_dir",
        "report_name", "timestamp", "fetch_local", "update", "ruleset",
        "exceptions", "force_write", "debug", "quiet", "no_browser",
        "max_workers", "max_rate",
    }.issubset(scoutsuite_schema)

    pacu_schema = tools["security_tool_pacu"].inputSchema["properties"]
    assert {
        "session", "activate_session", "new_session", "set_keys",
        "import_keys", "module_name", "data", "module_args", "list_modules",
        "pacu_help", "module_info", "execute_module", "set_regions", "whoami",
        "version", "quiet",
    }.issubset(pacu_schema)

    trivy_schema = tools["security_tool_trivy"].inputSchema["properties"]
    assert {
        "command", "severity", "output_format", "output_file", "template",
        "ignorefile", "exit_code", "ignore_unfixed", "scanners", "skip_dirs",
        "skip_files", "offline_scan", "parallel", "timeout", "config",
        "cache_dir", "quiet", "debug", "insecure",
    }.issubset(trivy_schema)

    netexec_schema = tools["security_tool_netexec"].inputSchema["properties"]
    assert {
        "username", "password", "hashes", "domain", "local_auth", "kerberos",
        "use_kcache", "aes_key", "kdc_host", "cred_id", "ignore_pw_decoding",
        "no_bruteforce", "continue_on_success", "gfail_limit", "ufail_limit",
        "fail_limit", "threads", "timeout", "jitter", "no_progress",
        "log_file", "verbose", "debug", "force_ipv6", "dns_server",
        "dns_tcp", "dns_timeout", "module", "module_options", "list_modules",
        "show_module_options", "port", "share", "smb_server_port",
        "no_smbv1", "no_admin_check", "gen_relay_list", "smb_timeout",
        "shares", "users", "groups", "pass_pol", "rid_brute", "exec_method",
        "execute_cmd", "execute_ps",
    }.issubset(netexec_schema)

    certipy_schema = tools["security_tool_certipy"].inputSchema["properties"]
    assert {
        "password", "hashes", "kerberos", "aes_key", "no_pass", "dc_ip",
        "dc_host", "target_ip", "target_host", "nameserver", "dns_tcp",
        "timeout", "ldap_scheme", "ldap_port", "no_ldap_channel_binding",
        "no_ldap_signing", "ldap_simple_auth", "ldap_user_dn", "text",
        "stdout", "json_output", "csv", "output_prefix", "enabled",
        "dc_only", "vulnerable", "oids", "hide_admins", "sid", "dn",
    }.issubset(certipy_schema)

    volatility_schema = tools["security_tool_volatility3"].inputSchema["properties"]
    assert {
        "config_file", "parallelism", "extend", "plugin_dirs", "symbol_dirs",
        "symbol_dir", "verbosity", "log_file", "output_dir", "quiet",
        "renderer", "write_config", "save_config", "clear_cache", "cache_path",
        "offline", "remote_isf_url", "filters", "hide_columns",
        "single_location", "stackers", "single_swap_locations", "plugin",
    }.issubset(volatility_schema)

    binwalk_schema = tools["security_tool_binwalk"].inputSchema["properties"]
    assert {
        "list_signatures", "stdin", "quiet", "verbose", "extract", "carve",
        "matryoshka", "search_all", "entropy", "png_output", "log_file",
        "threads", "exclude", "include", "output_dir",
    }.issubset(binwalk_schema)

    pspy_schema = tools["security_tool_pspy"].inputSchema["properties"]
    assert {
        "procevents", "fsevents", "recursive_dirs", "dirs", "interval",
        "color", "debug", "ppid", "truncate",
    }.issubset(pspy_schema)

    haiti_schema = tools["security_tool_haiti"].inputSchema["properties"]
    assert {
        "no_color", "extended", "short", "hashcat_only", "john_only",
        "ascii_art", "debug",
    }.issubset(haiti_schema)

    steghide_schema = tools["security_tool_steghide"].inputSchema["properties"]
    assert {
        "command", "extract", "embed_file", "cover_file", "stego_file",
        "extract_file", "output_file", "encryption", "compression_level",
        "no_compress", "no_checksum", "no_embed_name", "passphrase", "verbose",
        "quiet", "force",
    }.issubset(steghide_schema)

    stegcracker_schema = tools["security_tool_stegcracker"].inputSchema["properties"]
    assert {
        "wordlist", "output_file", "threads", "chunk_size", "quiet",
        "version", "verbose",
    }.issubset(stegcracker_schema)

    whitespace_schema = tools["security_tool_whitespace"].inputSchema["properties"]
    assert {
        "compress", "quiet", "space_report", "password", "line_length",
        "message_file", "message", "input_file", "output_file", "version",
        "help",
    }.issubset(whitespace_schema)

    hashcat_schema = tools["security_tool_hashcat"].inputSchema["properties"]
    assert {
        "hash_type", "attack_mode", "wordlist", "wordlist2", "mask",
        "rules", "rule_left", "rule_right", "generate_rules", "session",
        "restore", "restore_disable", "restore_file_path", "output_file",
        "outfile_format", "outfile_json", "outfile_autohex_disable",
        "separator", "show", "left", "username", "remove", "remove_timer",
        "potfile_disable", "potfile_path", "increment", "increment_inverse",
        "increment_min", "increment_max", "custom_charset1",
        "custom_charset2", "custom_charset3", "custom_charset4",
        "hex_charset", "hex_salt", "hex_wordlist", "workload_profile",
        "optimized_kernel", "backend_devices", "opencl_device_types",
        "backend_info", "status", "status_json", "status_timer", "runtime",
        "skip", "limit", "benchmark", "benchmark_all", "benchmark_min",
        "benchmark_max", "hash_info", "example_hashes", "identify",
        "stdout_candidates", "quiet", "force", "version", "help",
    }.issubset(hashcat_schema)

    john_schema = tools["security_tool_john"].inputSchema["properties"]
    assert {
        "single", "single_rules", "single_seed", "single_wordlist",
        "wordlist", "wordlist_default", "stdin", "pipe", "rules",
        "rules_default", "rules_stack", "rules_skip_nop", "incremental",
        "incremental_default", "mask", "custom_charset1",
        "custom_charset2", "custom_charset3", "custom_charset4", "markov",
        "external", "stdout_candidates", "stdout_length", "restore",
        "restore_session", "session", "status", "status_session", "show",
        "show_mode", "make_charset", "test", "test_time", "stress_test",
        "no_mask", "skip_self_tests", "users", "groups", "shells", "salts",
        "costs", "format", "subformat", "pot", "list_option", "config",
        "field_separator_char", "min_length", "max_length", "length",
        "max_run_time", "max_candidates", "progress_every", "fork", "node",
        "devices", "lws", "gws", "verbosity", "no_log", "log_stderr",
        "crack_status", "keep_guessing", "reject_printable", "force_tty",
        "help",
    }.issubset(john_schema)

    mobsf_schema = tools["security_tool_mobsf"].inputSchema["properties"]
    assert {"bind_host", "bind_port"}.issubset(mobsf_schema)

    frida_schema = tools["security_tool_frida"].inputSchema["properties"]
    assert {
        "device_id", "usb", "remote", "host", "certificate", "origin",
        "token", "keepalive_interval", "device_option", "p2p",
        "stun_server", "relay", "spawn_file", "attach_frontmost",
        "attach_name", "attach_identifier", "attach_pid", "await_spawn",
        "stdio", "aux", "realm", "runtime", "debug", "squelch_crash",
        "options_file", "load_script", "parameters_json", "cmodule",
        "toolchain", "codeshare", "eval_code", "quiet", "timeout", "pause",
        "output_file", "eternalize", "exit_on_error", "kill_on_exit",
        "auto_perform", "auto_reload", "no_auto_reload", "version",
    }.issubset(frida_schema)

    objection_schema = tools["security_tool_objection"].inputSchema["properties"]
    assert {
        "command", "network", "local", "host", "port", "api_host",
        "api_port", "name", "serial", "debug", "spawn", "no_pause",
        "foremost", "debugger", "uid", "plugin_folder", "quiet",
        "startup_command", "file_commands", "startup_script", "enable_api",
        "hook_debug", "runtime_command", "source", "architecture",
        "gadget_version", "codesign_signature", "provision_file",
        "binary_name", "skip_cleanup", "pause", "unzip_unicode",
        "enable_debug", "network_security_config", "skip_resources",
        "skip_signing", "target_class", "use_aapt2", "gadget_config",
        "script_source", "ignore_nativelibs", "manifest", "only_main_classes",
        "fix_concurrency_to", "bundle_id", "sources",
    }.issubset(objection_schema)

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

    feroxbuster_schema = tools["security_tool_feroxbuster"].inputSchema["properties"]
    assert {
        "wordlist", "extensions", "methods", "headers", "cookies", "filter_codes",
        "status_codes", "follow_redirects", "insecure", "no_recursion", "depth",
        "rate_limit", "collect_extensions", "verbosity", "json_output",
    }.issubset(feroxbuster_schema)

    dirsearch_schema = tools["security_tool_dirsearch"].inputSchema["properties"]
    assert {
        "wordlist", "extensions", "include_status", "exclude_status",
        "exclude_sizes", "recursive", "recursion_depth", "method", "headers",
        "follow_redirects", "proxy", "max_rate", "json_report", "no_color",
    }.issubset(dirsearch_schema)

    nikto_schema = tools["security_tool_nikto"].inputSchema["properties"]
    assert {
        "config_file", "display", "dbcheck", "evasion", "output_format", "auth",
        "list_plugins", "mutate", "no_ssl", "output_file", "plugins", "port",
        "ssl", "tuning", "user_agent", "use_proxy", "vhost",
    }.issubset(nikto_schema)

    owasp_zap_schema = tools["security_tool_owasp_zap"].inputSchema["properties"]
    assert {
        "quick_out", "quick_progress", "zapit_url", "config", "config_file",
        "home_dir", "install_dir", "new_session", "session", "low_mem",
        "experimental_db", "no_stdout", "log_level", "silent", "addon_install",
        "addon_install_all", "addon_uninstall", "addon_update", "addon_list",
        "script", "support_info", "sbom_zip",
    }.issubset(owasp_zap_schema)

    testssl_schema = tools["security_tool_testssl"].inputSchema["properties"]
    assert {
        "input_file", "mode", "warnings", "connect_timeout", "openssl_timeout",
        "basic_auth", "req_header", "mtls_file", "starttls", "xmpp_host", "mx",
        "ip", "proxy", "ipv6", "ssl_native", "openssl_path", "bugs",
        "assume_http", "no_dns", "sneaky", "user_agent", "ids_friendly",
        "phone_out", "add_ca", "each_cipher", "cipher_per_proto", "categories",
        "protocols", "server_defaults", "single_cipher", "check_headers",
        "client_simulation", "vulnerabilities", "quiet", "wide", "mapping",
        "show_each", "color", "debug", "log", "json_output", "jsonfile",
        "csv_output", "csvfile", "html_output", "htmlfile", "severity",
    }.issubset(testssl_schema)

    dalfox_schema = tools["security_tool_dalfox"].inputSchema["properties"]
    assert {
        "blind_callback", "config_file", "cookies", "custom_payload", "data",
        "deep_domxss", "follow_redirects", "headers", "ignore_param",
        "ignore_return", "method", "parameter", "proxy", "timeout",
        "user_agent", "waf_evasion", "max_cpu", "workers", "mining_dict",
        "mining_dom", "skip_mining_all", "only_custom_payload",
        "only_discovery", "skip_bav", "skip_discovery", "skip_headless",
        "skip_xss_scanning", "format", "found_action", "grep_file",
        "har_file_path", "no_color", "only_poc", "output_file",
        "output_request", "output_response", "poc_type", "report",
        "report_format", "silence",
    }.issubset(dalfox_schema)

    xsstrike_schema = tools["security_tool_xsstrike"].inputSchema["properties"]
    assert {
        "data", "encode", "fuzzer", "update", "timeout", "use_proxy", "crawl",
        "json_data", "path_injection", "seeds_file", "payload_file", "level",
        "headers", "threads", "delay", "skip", "skip_dom", "blind",
        "console_log_level", "file_log_level", "log_file",
    }.issubset(xsstrike_schema)

    xspear_schema = tools["security_tool_xspear"].inputSchema["properties"]
    assert {
        "data", "test_all_params", "no_xss", "headers", "cookie",
        "custom_payload", "raw_file", "parameter", "blind_callback", "threads",
        "output_format", "config_file", "verbose",
    }.issubset(xspear_schema)

    xsscon_schema = tools["security_tool_xsscon"].inputSchema["properties"]
    assert {
        "depth", "payload_level", "payload", "method", "user_agent",
        "single_url", "proxy", "about", "cookie",
    }.issubset(xsscon_schema)

    xanxss_schema = tools["security_tool_xanxss"].inputSchema["properties"]
    assert {
        "verification_amount", "amount_to_find", "test_time", "payloads",
        "payload_file", "verbose", "proxy", "headers", "throttle", "polyglot",
        "prefix", "suffix",
    }.issubset(xanxss_schema)

    dsss_schema = tools["security_tool_dsss"].inputSchema["properties"]
    assert {"data", "cookie", "user_agent", "referer", "proxy"}.issubset(
        dsss_schema
    )

    sqlscan_schema = tools["security_tool_sqlscan"].inputSchema["properties"]
    assert {"scan"}.issubset(sqlscan_schema)

    wafw00f_schema = tools["security_tool_wafw00f"].inputSchema["properties"]
    assert {
        "verbosity", "find_all", "no_redirect", "test_waf", "output_file",
        "output_format", "input_file", "list_wafs", "proxy", "version",
        "headers_file", "timeout", "no_color",
    }.issubset(wafw00f_schema)

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
    assert {
        "username", "password", "nt_hash", "port", "ssl", "public_key",
        "private_key", "realm", "ccache", "scripts_path", "spn",
        "executables_path", "url", "user_agent", "version", "no_colors",
        "no_rpath_completion", "log_session",
    }.issubset(evil_winrm_schema)

    commix_schema = tools["security_tool_commix"].inputSchema["properties"]
    assert {"parameter", "method", "delay", "time_sec", "os_cmd", "batch"}.issubset(
        commix_schema
    )

    pacu_schema = tools["security_tool_pacu"].inputSchema["properties"]
    assert {"session", "module_name", "set_regions", "whoami"}.issubset(pacu_schema)

    evilginx_schema = tools["security_tool_evilginx3"].inputSchema["properties"]
    assert {"phishlets_dir", "redirectors_dir", "config_dir", "debug"}.issubset(
        evilginx_schema
    )

    msfvenom_schema = tools["security_tool_msfvenom"].inputSchema["properties"]
    assert {"shell", "direction", "stager", "method", "batch", "loop"}.issubset(
        msfvenom_schema
    )

    airgeddon_schema = tools["security_tool_airgeddon"].inputSchema["properties"]
    assert {"pmkid", "deauth_count", "capture_file", "target_essid"}.issubset(
        airgeddon_schema
    )

    anonsurf_schema = tools["security_tool_anonsurf"].inputSchema["properties"]
    assert {"action"}.issubset(anonsurf_schema)

    multitor_schema = tools["security_tool_multitor"].inputSchema["properties"]
    assert {
        "init_instances", "user", "socks_port", "control_port", "proxy",
        "haproxy", "kill", "show_id", "new_id", "debug", "verbose", "help",
    }.issubset(multitor_schema)

    cupp_schema = tools["security_tool_cupp"].inputSchema["properties"]
    assert {
        "interactive", "improve_file", "download_wordlist", "alecto",
        "version", "quiet",
    }.issubset(cupp_schema)

    wlcreator_schema = tools["security_tool_wlcreator"].inputSchema["properties"]
    assert {"length"}.issubset(wlcreator_schema)

    bloodhound_schema = tools["security_tool_bloodhound"].inputSchema["properties"]
    assert {
        "username", "password", "kerberos", "hashes", "no_pass", "aes_key",
        "auth_method", "collection_method", "verbose", "nameserver",
        "dns_tcp", "dns_timeout", "domain_controller", "global_catalog",
        "workers", "exclude_dcs", "disable_pooling", "disable_autogc",
        "zip_output", "computerfile", "cachefile", "ldap_channel_binding",
        "use_ldaps", "output_prefix",
    }.issubset(bloodhound_schema)

    jadx_schema = tools["security_tool_jadx"].inputSchema["properties"]
    assert {
        "output_dir", "output_dir_src", "output_dir_res", "no_resources",
        "no_sources", "threads_count", "single_class", "single_class_output",
        "output_format", "export_gradle", "export_gradle_type",
        "decompilation_mode", "show_bad_code", "no_xml_pretty_print",
        "no_imports", "no_debug_info", "add_debug_lines",
        "no_inline_anonymous", "no_inline_methods", "no_move_inner_classes",
        "no_inline_kotlin_lambda", "no_finally",
        "no_restore_switch_over_string", "no_replace_consts",
        "escape_unicode", "respect_bytecode_access_modifiers",
        "mappings_path", "mappings_mode", "deobf", "deobf_min",
        "deobf_max", "deobf_whitelist", "deobf_cfg_file",
        "deobf_cfg_file_mode", "deobf_res_name_source",
        "use_source_name_as_class_name_alias", "source_name_repeat_limit",
        "use_kotlin_methods_for_var_names",
        "use_headers_for_detect_resource_extensions", "rename_flags",
        "integer_format", "type_update_limit", "fs_case_sensitive", "cfg",
        "raw_cfg", "fallback", "use_dx", "comments_level", "log_level",
        "verbose", "quiet", "disable_plugins", "config", "save_config",
        "print_files", "plugin_options", "version", "help",
    }.issubset(jadx_schema)

    apk2gold_schema = tools["security_tool_apk2gold"].inputSchema["properties"]
    assert {"apk_file"}.issubset(apk2gold_schema)

    androguard_schema = tools["security_tool_androguard"].inputSchema["properties"]
    assert {
        "command", "input_file", "apk_files", "output_file", "output_dir",
        "resource", "package", "locale", "resource_type", "resource_id",
        "list_packages", "list_locales", "list_types", "graph_format",
        "jar", "limit", "decompiler", "hash_algo", "all_hashes", "show",
        "session", "offset", "size", "modules", "enable_ui", "package_name",
        "output_type", "classname", "methodname", "descriptor", "accessflag",
        "no_isolated", "verbose",
    }.issubset(androguard_schema)

    radare2_schema = tools["security_tool_radare2"].inputSchema["properties"]
    assert {
        "arch", "bits", "base_addr", "map_addr", "seek_addr", "command",
        "eval_config", "script", "pre_script", "project", "patch_file",
        "rarun_profile", "rarun_directive", "debug", "debug_backend",
        "analyze", "write", "quiet", "quit_after_commands", "quick_quiet",
        "json", "version", "lib_version", "help", "long_help", "sandbox",
        "no_user_config", "no_scripts_plugins", "no_bin_info",
        "bin_structures_only", "full_file", "force_bin_plugin", "asm_os",
        "raw_names", "no_demangle", "list_io_plugins", "list_core_plugins",
        "no_exec", "no_extr", "no_strings", "load_strings", "connect_mode",
        "zero_sep", "stderr_to_stdout", "no_stderr",
    }.issubset(radare2_schema)

    ghidra_schema = tools["security_tool_ghidra"].inputSchema["properties"]
    assert {
        "project_name", "folder_path", "import_path", "process_path",
        "pre_script", "pre_script_args", "post_script", "post_script_args",
        "script_path", "properties_path", "script_log", "log_file",
        "overwrite", "mirror", "recursive", "recursive_depth", "read_only",
        "delete_project", "no_analysis", "processor", "cspec",
        "analysis_timeout_per_file", "keystore", "connect", "connect_user",
        "password", "commit", "commit_comment", "ok_to_delete", "max_cpu",
        "library_search_paths", "loader", "loader_args",
    }.issubset(ghidra_schema)

    setoolkit_schema = tools["security_tool_setoolkit"].inputSchema["properties"]
    assert {"interactive"}.issubset(setoolkit_schema)

    msfvenom_schema = tools["security_tool_msfvenom"].inputSchema["properties"]
    assert {"platform", "lhost", "lport", "shell", "direction", "method"}.issubset(
        msfvenom_schema
    )

    wifite_schema = tools["security_tool_wifite"].inputSchema["properties"]
    assert {"interface", "bssid", "essid", "channel", "wordlist"}.issubset(
        wifite_schema
    )

    vegil_schema = tools["security_tool_vegil"].inputSchema["properties"]
    assert {"action", "backdoor_path", "help"}.issubset(vegil_schema)


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


def test_sqlmap_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["sqlmap"].source_status == "source-reviewed"
    assert records["sqlmap"].unverified_parameters == ()
    assert records["sqlmap"].gap == ""
    assert any("sqlmapproject/sqlmap" in item for item in records["sqlmap"].evidence)

    params = adapter_parameter_names(registry.get_tool("sqlmap"), specs["sqlmap"])
    assert "module" not in params
    assert "rhost" not in params
    assert "rport" not in params
    assert "username" not in params
    assert "password" not in params
    assert "payload" not in params
    assert "parameter" in params
    assert "dbms_cred" in params
    assert "os_shell" in params

    preview = adapter_request_preview(
        registry.get_tool("sqlmap"),
        specs["sqlmap"],
        {
            "target": "https://example.test/item?id=1",
            "data": "id=1",
            "method": "POST",
            "cookie": "SID=abc",
            "headers": "X-Test: 1",
            "user_agent": "hacking-mcp",
            "referer": "https://ref.test",
            "auth_type": "Basic",
            "auth_cred": "alice:secret",
            "proxy": "http://127.0.0.1:8080",
            "delay": "0.5",
            "timeout": "15",
            "retries": 2,
            "csrf_token": "csrf",
            "parameter": "id",
            "skip": "token",
            "dbms": "MySQL",
            "dbms_cred": "dbu:dbp",
            "risk": 2,
            "level": 3,
            "tamper": "space2comment",
            "technique": "BEUSTQ",
            "random_agent": True,
            "enumerate_databases": True,
            "tables": True,
            "columns": True,
            "dump": True,
            "os_cmd": "whoami",
            "os_shell": True,
            "threads": 4,
            "forms": True,
            "crawl": 2,
            "flush_session": True,
            "output_dir": "out",
        },
    )
    assert preview["target"] == "https://example.test/item?id=1"
    assert preview["options"] == (
        "--data id=1 --method POST --cookie SID=abc --headers 'X-Test: 1' "
        "--user-agent hacking-mcp --referer https://ref.test "
        "--auth-type Basic --auth-cred alice:secret "
        "--proxy http://127.0.0.1:8080 --delay 0.5 --timeout 15 "
        "--retries 2 --csrf-token csrf -p id --skip token --dbms MySQL "
        "--dbms-cred dbu:dbp --risk 2 --level 3 --tamper space2comment "
        "--technique BEUSTQ --random-agent --dbs --tables --columns --dump "
        "--os-cmd whoami --os-shell --threads 4 --forms --crawl 2 "
        "--flush-session --output-dir out"
    )


def test_nosqlmap_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["nosqlmap"].source_status == "source-reviewed"
    assert records["nosqlmap"].unverified_parameters == ()
    assert records["nosqlmap"].gap == ""
    assert any("codingo/NoSQLMap" in item for item in records["nosqlmap"].evidence)

    params = adapter_parameter_names(registry.get_tool("nosqlmap"), specs["nosqlmap"])
    for removed in (
        "data",
        "dbms",
        "risk",
        "level",
        "enumerate_databases",
        "module",
        "rhost",
        "rport",
        "username",
        "password",
        "payload",
        "parameter",
        "method",
        "delay",
        "os_shell",
        "batch",
    ):
        assert removed not in params

    for verified in (
        "attack",
        "platform",
        "victim",
        "db_port",
        "my_ip",
        "my_port",
        "web_port",
        "uri",
        "http_method",
        "https",
        "verbose",
        "post_data",
        "request_headers",
        "injected_parameter",
        "inject_size",
        "inject_format",
        "params",
        "do_time_attack",
        "save_path",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("nosqlmap"),
        specs["nosqlmap"],
        {
            "target": "mongo.test",
            "attack": 2,
            "platform": "MongoDB",
            "db_port": 27017,
            "my_ip": "127.0.0.1",
            "my_port": 4444,
            "web_port": 8080,
            "uri": "/acct",
            "http_method": "GET",
            "https": True,
            "verbose": True,
            "post_data": "acctid,test",
            "request_headers": "X-Test,1",
            "injected_parameter": "acctid",
            "inject_size": 4,
            "inject_format": 2,
            "params": "1",
            "do_time_attack": "n",
            "save_path": "nosqlmap.out",
        },
    )
    assert preview["target"] == "mongo.test"
    assert preview["options"] == (
        "--attack 2 --platform MongoDB --victim mongo.test --dbPort 27017 "
        "--myIP 127.0.0.1 --myPort 4444 --webPort 8080 --uri /acct "
        "--httpMethod GET --https ON --verb ON --postData acctid,test "
        "--requestHeaders X-Test,1 --injectedParameter acctid "
        "--injectSize 4 --injectFormat 2 --params 1 --doTimeAttack n "
        "--savePath nosqlmap.out"
    )


def test_blisqy_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("blisqy")

    assert tool.run_command == ""
    assert tool.archived is True
    assert specs["blisqy"].exposed is False
    assert "archived" in specs["blisqy"].blocked_reason
    assert records["blisqy"].source_status == "source-reviewed"
    assert records["blisqy"].unverified_parameters == ()
    assert records["blisqy"].gap == ""
    assert any("JohnTroony/Blisqy" in item for item in records["blisqy"].evidence)

    params = adapter_parameter_names(tool, specs["blisqy"])
    for removed in (
        "batch",
        "data",
        "dbms",
        "delay",
        "enumerate_databases",
        "level",
        "method",
        "module",
        "os_shell",
        "parameter",
        "password",
        "payload",
        "rhost",
        "risk",
        "rport",
        "username",
    ):
        assert removed not in params
    assert "library_usage" in params

    preview = adapter_request_preview(
        tool,
        specs["blisqy"],
        {
            "target": "https://example.test",
            "library_usage": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == "https://example.test"
    assert preview["options"] == ""
    assert preview["executable"] is False
    assert preview["confirm_authorized"] is True


def test_leviathan_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("leviathan")

    assert tool.run_command == "cd leviathan && python leviathan.py"
    assert specs["leviathan"].requires_confirmation is True
    assert records["leviathan"].source_status == "source-reviewed"
    assert records["leviathan"].unverified_parameters == ()
    assert records["leviathan"].gap == ""
    assert any("utkusen/leviathan" in item for item in records["leviathan"].evidence)

    params = adapter_parameter_names(tool, specs["leviathan"])
    for removed in (
        "batch",
        "data",
        "dbms",
        "delay",
        "enumerate_databases",
        "extensions",
        "follow_redirects",
        "level",
        "match_codes",
        "method",
        "os_shell",
        "parameter",
        "proxy",
        "recursive",
        "risk",
        "threads",
        "wordlist",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["leviathan"],
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is True
    assert preview["confirm_authorized"] is True


def test_routersploit_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("routersploit")

    assert tool.run_command == "cd routersploit && sudo python3 rsf.py"
    assert specs["routersploit"].requires_confirmation is True
    assert records["routersploit"].source_status == "source-reviewed"
    assert records["routersploit"].unverified_parameters == ()
    assert records["routersploit"].gap == ""
    assert any("threat9/routersploit" in item for item in records["routersploit"].evidence)

    params = adapter_parameter_names(tool, specs["routersploit"])
    for removed in (
        "check_only",
        "password",
        "payload",
        "resource_file",
        "rhost",
        "rport",
        "username",
    ):
        assert removed not in params
    for expected in ("module", "set_options", "interactive"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["routersploit"],
        {
            "target": "192.0.2.10",
            "module": "exploits/routers/example",
            "set_options": "port 80;ssl true",
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-m exploits/routers/example -s 'target 192.0.2.10' "
        "-s 'port 80' -s 'ssl true'"
    )
    assert preview["confirm_authorized"] is True


def test_websploit_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("websploit")

    assert tool.run_command == "sudo websploit"
    assert specs["websploit"].requires_confirmation is True
    assert records["websploit"].source_status == "source-reviewed"
    assert records["websploit"].unverified_parameters == ()
    assert records["websploit"].gap == ""
    assert any("The404Hacking/websploit" in item for item in records["websploit"].evidence)

    params = adapter_parameter_names(tool, specs["websploit"])
    for removed in (
        "check_only",
        "extensions",
        "follow_redirects",
        "match_codes",
        "module",
        "password",
        "payload",
        "proxy",
        "recursive",
        "resource_file",
        "rhost",
        "rport",
        "set_options",
        "threads",
        "username",
        "wordlist",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["websploit"],
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is True
    assert preview["confirm_authorized"] is True


def test_pwncat_cs_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("pwncat-cs")

    assert tool.run_command == "pwncat-cs"
    assert specs["pwncat-cs"].requires_confirmation is True
    assert records["pwncat-cs"].source_status == "source-reviewed"
    assert records["pwncat-cs"].unverified_parameters == ()
    assert records["pwncat-cs"].gap == ""
    assert any("calebstewart/pwncat" in item for item in records["pwncat-cs"].evidence)

    params = adapter_parameter_names(tool, specs["pwncat-cs"])
    for removed in (
        "apk_path",
        "cert_file",
        "download",
        "key_file",
        "lhost",
        "listener",
        "lport",
        "output_file",
        "package_name",
        "protocol",
        "session_id",
        "upload",
    ):
        assert removed not in params
    for expected in (
        "listen",
        "port",
        "platform",
        "ssl",
        "ssl_cert",
        "ssl_key",
        "identity_file",
        "list_implants",
        "version",
        "download_plugins",
        "config_file",
        "verbose",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["pwncat-cs"],
        {
            "target": "10.10.10.10",
            "port": 4444,
            "platform": "windows",
            "ssl": True,
            "ssl_cert": "cert.pem",
            "ssl_key": "key.pem",
            "identity_file": "id_rsa",
            "verbose": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == "10.10.10.10"
    assert preview["options"] == (
        "-p 4444 -m windows -S --ssl-cert cert.pem "
        "--ssl-key key.pem -i id_rsa -V"
    )
    assert preview["confirm_authorized"] is True


def test_sliver_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("sliver")

    assert tool.run_command == "sliver"
    assert records["sliver"].source_status == "source-reviewed"
    assert records["sliver"].unverified_parameters == ()
    assert records["sliver"].gap == ""
    assert any("BishopFox/sliver" in item for item in records["sliver"].evidence)

    params = adapter_parameter_names(tool, specs["sliver"])
    for removed in (
        "auth_token",
        "connect_addr",
        "listen_addr",
        "listener",
        "lhost",
        "lport",
        "mode",
        "protocol",
        "session_id",
        "tun_name",
    ):
        assert removed not in params
    for expected in (
        "command",
        "rc_script",
        "enable_wg",
        "config_files",
        "mcp_config",
        "version",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["sliver"],
        {
            "target": "ignored-local-host",
            "command": "mcp",
            "enable_wg": True,
            "mcp_config": "root_127.0.0.1.cfg",
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "--enable-wg mcp --config root_127.0.0.1.cfg"
    assert preview["confirm_authorized"] is True


def test_havoc_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("havoc")

    assert tool.run_command == "cd Havoc && ./havoc"
    assert specs["havoc"].requires_confirmation is True
    assert records["havoc"].source_status == "source-reviewed"
    assert records["havoc"].unverified_parameters == ()
    assert records["havoc"].gap == ""
    assert any("HavocFramework/Havoc" in item for item in records["havoc"].evidence)

    params = adapter_parameter_names(tool, specs["havoc"])
    for removed in (
        "auth_token",
        "connect_addr",
        "listen_addr",
        "listener",
        "lhost",
        "lport",
        "mode",
        "protocol",
        "session_id",
        "tun_name",
    ):
        assert removed not in params
    for expected in (
        "command",
        "profile",
        "default_profile",
        "debug",
        "debug_dev",
        "send_logs",
        "verbose",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["havoc"],
        {
            "target": "ignored-local-host",
            "command": "server",
            "profile": "profiles/demo.yaotl",
            "debug": True,
            "debug_dev": True,
            "send_logs": True,
            "verbose": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "server --profile profiles/demo.yaotl --debug --debug-dev "
        "--send-logs --verbose"
    )
    assert preview["confirm_authorized"] is True


def test_mythic_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("mythic")

    assert tool.run_command == "cd Mythic && sudo ./mythic-cli"
    assert specs["mythic"].exposed is False
    assert "classified DANGEROUS" in specs["mythic"].blocked_reason
    assert records["mythic"].source_status == "source-reviewed"
    assert records["mythic"].unverified_parameters == ()
    assert records["mythic"].gap == ""
    assert any("its-a-feature/Mythic" in item for item in records["mythic"].evidence)

    params = adapter_parameter_names(tool, specs["mythic"])
    for removed in (
        "listener",
        "lhost",
        "lport",
        "protocol",
        "session_id",
    ):
        assert removed not in params
    for expected in (
        "command",
        "service_names",
        "keep_volume",
        "verbose",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["mythic"],
        {
            "target": "ignored-local-host",
            "command": "start",
            "service_names": "mythic_server,mythic_react",
            "keep_volume": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "start --keep-volume mythic_server mythic_react"
    assert preview["executable"] is False

    status_preview = adapter_request_preview(
        tool,
        specs["mythic"],
        {"command": "status", "verbose": True},
    )
    assert status_preview["options"] == "status --verbose"


def test_vegil_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("vegil")

    assert tool.run_command == "cd Vegile && sudo bash Vegile"
    assert specs["vegil"].exposed is False
    assert "classified DANGEROUS" in specs["vegil"].blocked_reason
    assert records["vegil"].source_status == "source-reviewed"
    assert records["vegil"].unverified_parameters == ()
    assert records["vegil"].gap == ""
    assert any("Screetsec/Vegile" in item for item in records["vegil"].evidence)

    params = adapter_parameter_names(tool, specs["vegil"])
    for removed in (
        "listener",
        "lhost",
        "lport",
        "protocol",
        "session_id",
    ):
        assert removed not in params
    for expected in ("action", "backdoor_path", "help"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["vegil"],
        {
            "target": "ignored-local-host",
            "action": "inject",
            "backdoor_path": "rootkit.bin",
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "--inject rootkit.bin"
    assert preview["executable"] is False

    help_preview = adapter_request_preview(tool, specs["vegil"], {"help": True})
    assert help_preview["options"] == "--help"


def test_chrome_keylogger_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("chrome-keylogger")

    assert tool.run_command == "cd HeraKeylogger && sudo python3 hera.py"
    assert specs["chrome-keylogger"].exposed is False
    assert "classified DANGEROUS" in specs["chrome-keylogger"].blocked_reason
    assert records["chrome-keylogger"].source_status == "source-reviewed"
    assert records["chrome-keylogger"].unverified_parameters == ()
    assert records["chrome-keylogger"].gap == ""
    assert any("UndeadSec/HeraKeylogger" in item for item in records["chrome-keylogger"].evidence)

    params = adapter_parameter_names(tool, specs["chrome-keylogger"])
    for removed in (
        "apk_path",
        "listener",
        "lhost",
        "lport",
        "output_file",
        "package_name",
        "protocol",
        "session_id",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["chrome-keylogger"],
        {"target": "ignored-local-host", "interactive": True},
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_evil_winrm_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("evil-winrm")

    assert tool.run_command == "evil-winrm -i {target}"
    assert specs["evil-winrm"].requires_confirmation is True
    assert records["evil-winrm"].source_status == "source-reviewed"
    assert records["evil-winrm"].unverified_parameters == ()
    assert records["evil-winrm"].gap == ""
    assert any("Hackplayers/evil-winrm" in item for item in records["evil-winrm"].evidence)

    params = adapter_parameter_names(tool, specs["evil-winrm"])
    for removed in (
        "cert_file",
        "download",
        "key_file",
        "lhost",
        "listener",
        "lport",
        "protocol",
        "session_id",
        "upload",
    ):
        assert removed not in params
    for expected in (
        "username",
        "password",
        "nt_hash",
        "port",
        "ssl",
        "public_key",
        "private_key",
        "realm",
        "ccache",
        "scripts_path",
        "spn",
        "executables_path",
        "url",
        "user_agent",
        "version",
        "no_colors",
        "no_rpath_completion",
        "log_session",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["evil-winrm"],
        {
            "target": "192.0.2.10",
            "username": "Administrator",
            "password": "Passw0rd!",
            "port": 5986,
            "ssl": True,
            "scripts_path": "/opt/ps1",
            "executables_path": "/opt/exe",
            "user_agent": "Microsoft WinRM Client",
            "no_colors": True,
            "no_rpath_completion": True,
            "log_session": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == "192.0.2.10"
    assert preview["options"] == (
        "-u Administrator -p 'Passw0rd!' -P 5986 -S -s /opt/ps1 "
        "-e /opt/exe -a 'Microsoft WinRM Client' -n -N -l"
    )
    assert preview["confirm_authorized"] is True


def test_chisel_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("chisel")

    assert tool.run_command == "chisel"
    assert specs["chisel"].requires_confirmation is True
    assert records["chisel"].source_status == "source-reviewed"
    assert records["chisel"].unverified_parameters == ()
    assert records["chisel"].gap == ""
    assert any("jpillora/chisel" in item for item in records["chisel"].evidence)

    params = adapter_parameter_names(tool, specs["chisel"])
    for removed in (
        "auth_token",
        "connect_addr",
        "listen_addr",
        "listener",
        "lhost",
        "lport",
        "mode",
        "protocol",
        "session_id",
        "tun_name",
    ):
        assert removed not in params
    for expected in (
        "command",
        "server",
        "remotes",
        "host",
        "port",
        "key_seed",
        "keygen",
        "keyfile",
        "authfile",
        "auth",
        "keepalive",
        "backend",
        "socks5",
        "reverse",
        "tls_key",
        "tls_cert",
        "tls_domain",
        "tls_ca",
        "fingerprint",
        "max_retry_count",
        "max_retry_interval",
        "proxy",
        "header",
        "hostname",
        "sni",
        "tls_skip_verify",
        "pid",
        "verbose",
        "version",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["chisel"],
        {
            "target": "https://chisel.example:443",
            "command": "client",
            "remotes": "R:2222:127.0.0.1:22;socks",
            "fingerprint": "fp123",
            "auth": "user:pass",
            "proxy": "http://proxy.example:8080",
            "header": "X-Test: 1",
            "hostname": "front.example",
            "sni": "tls.example",
            "tls_skip_verify": True,
            "verbose": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "client --fingerprint fp123 --auth user:pass "
        "--proxy http://proxy.example:8080 --header 'X-Test: 1' "
        "--hostname front.example --sni tls.example --tls-skip-verify "
        "https://chisel.example:443 R:2222:127.0.0.1:22 socks -v"
    )
    assert preview["confirm_authorized"] is True


def test_peass_ng_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("peass-ng")

    assert tool.run_command == "./linpeas.sh"
    assert records["peass-ng"].source_status == "source-reviewed"
    assert records["peass-ng"].unverified_parameters == ()
    assert records["peass-ng"].gap == ""
    assert any("peass-ng/PEASS-ng" in item for item in records["peass-ng"].evidence)

    params = adapter_parameter_names(tool, specs["peass-ng"])
    for removed in (
        "api_key",
        "checks",
        "json_output",
        "listener",
        "lhost",
        "lport",
        "output_file",
        "passive",
        "peas_variant",
        "protocol",
        "resolvers",
        "session_id",
        "sources",
    ):
        assert removed not in params
    for expected in (
        "all_checks",
        "extra_enum",
        "regex_checks",
        "stealth",
        "password",
        "debug",
        "auto_network_scan",
        "discover_net",
        "ports",
        "scan_ip",
        "port_forward",
        "firmware_path",
        "selected_checks",
        "wait",
        "force_linpeas",
        "force_macpeas",
        "quiet",
        "no_color",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["peass-ng"],
        {
            "target": "ignored-local-host",
            "all_checks": True,
            "regex_checks": True,
            "password": "Passw0rd!",
            "discover_net": "192.168.1.0/24",
            "ports": "22,80,443",
            "selected_checks": "system_information,interesting_files",
            "quiet": True,
            "no_color": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-a -r -P 'Passw0rd!' -d 192.168.1.0/24 -p 22,80,443 "
        "-o system_information,interesting_files -q -N"
    )


def test_ligolo_ng_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("ligolo-ng")

    assert tool.run_command == "cd ligolo-ng && ./proxy"
    assert records["ligolo-ng"].source_status == "source-reviewed"
    assert records["ligolo-ng"].unverified_parameters == ()
    assert records["ligolo-ng"].gap == ""
    assert any("nicocha30/ligolo-ng" in item for item in records["ligolo-ng"].evidence)

    params = adapter_parameter_names(tool, specs["ligolo-ng"])
    for removed in (
        "auth_token",
        "connect_addr",
        "listener",
        "lhost",
        "lport",
        "mode",
        "protocol",
        "session_id",
        "tun_name",
    ):
        assert removed not in params
    for expected in (
        "listen_addr",
        "autocert",
        "selfcert",
        "cert_file",
        "key_file",
        "allow_domains",
        "selfcert_domain",
        "config_file",
        "daemon",
        "api_listen_addr",
        "cpu_profile",
        "mem_profile",
        "verbose",
        "no_banner",
        "version",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["ligolo-ng"],
        {
            "target": "ignored-local-host",
            "listen_addr": "127.0.0.1:11601",
            "selfcert": True,
            "cert_file": "cert.pem",
            "key_file": "key.pem",
            "allow_domains": "lab.example,alt.example",
            "selfcert_domain": "lab.example",
            "config_file": "ligolo.yaml",
            "daemon": True,
            "api_listen_addr": "127.0.0.1:8080",
            "verbose": True,
            "no_banner": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-v -laddr 127.0.0.1:11601 -selfcert -certfile cert.pem "
        "-keyfile key.pem -allow-domains lab.example,alt.example "
        "-selfcert-domain lab.example -config ligolo.yaml -daemon "
        "-api-laddr 127.0.0.1:8080 -nobanner"
    )
    assert preview["confirm_authorized"] is True


def test_explo_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert registry.get_tool("explo").run_command == "cd explo && explo {target}"
    assert records["explo"].source_status == "source-reviewed"
    assert records["explo"].unverified_parameters == ()
    assert records["explo"].gap == ""
    assert any("telekom-security/explo" in item for item in records["explo"].evidence)

    params = adapter_parameter_names(registry.get_tool("explo"), specs["explo"])
    for removed in (
        "wordlist",
        "threads",
        "extensions",
        "match_codes",
        "recursive",
        "follow_redirects",
        "proxy",
        "data",
        "dbms",
        "risk",
        "level",
        "enumerate_databases",
        "parameter",
        "method",
        "delay",
        "os_shell",
        "batch",
    ):
        assert removed not in params
    assert "extra_files" in params
    assert "verbose" in params

    preview = adapter_request_preview(
        registry.get_tool("explo"),
        specs["explo"],
        {
            "target": "cases/one.yaml",
            "extra_files": "cases/two.yaml,cases/three.yaml",
            "verbose": True,
        },
    )
    assert preview["target"] == "cases/one.yaml"
    assert preview["options"] == "cases/two.yaml cases/three.yaml --verbose"


def test_holehe_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["holehe"].source_status == "source-reviewed"
    assert records["holehe"].unverified_parameters == ()
    assert records["holehe"].gap == ""
    assert any("megadose/holehe" in item for item in records["holehe"].evidence)

    params = adapter_parameter_names(registry.get_tool("holehe"), specs["holehe"])
    for removed in (
        "api_key",
        "json_output",
        "output_file",
        "passive",
        "resolvers",
        "sources",
    ):
        assert removed not in params

    for verified in (
        "only_used",
        "no_color",
        "no_clear",
        "no_password_recovery",
        "csv",
        "timeout",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("holehe"),
        specs["holehe"],
        {
            "target": "user@example.com",
            "only_used": True,
            "no_color": True,
            "no_clear": True,
            "no_password_recovery": True,
            "csv": True,
            "timeout": 20,
        },
    )
    assert preview["target"] == "user@example.com"
    assert preview["options"] == (
        "--only-used --no-color --no-clear --no-password-recovery --csv --timeout 20"
    )


def test_maigret_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["maigret"].source_status == "source-reviewed"
    assert records["maigret"].unverified_parameters == ()
    assert records["maigret"].gap == ""
    assert any("soxoj/maigret" in item for item in records["maigret"].evidence)

    params = adapter_parameter_names(registry.get_tool("maigret"), specs["maigret"])
    for removed in ("api_key", "json_output", "output_file", "passive", "resolvers", "sources"):
        assert removed not in params

    for verified in (
        "extra_usernames",
        "timeout",
        "retries",
        "max_connections",
        "no_recursion",
        "no_extracting",
        "id_type",
        "permute",
        "db_file",
        "no_autoupdate",
        "force_update",
        "cookies_jar_file",
        "ignore_ids",
        "folder_output",
        "proxy",
        "tor_proxy",
        "i2p_proxy",
        "with_domains",
        "all_sites",
        "top_sites",
        "tags",
        "exclude_tags",
        "sites",
        "use_disabled_sites",
        "parse_url",
        "self_check",
        "stats",
        "print_not_found",
        "print_errors",
        "verbose",
        "info",
        "debug",
        "no_color",
        "no_progressbar",
        "txt",
        "csv",
        "html",
        "pdf",
        "md",
        "graph",
        "json_report",
        "reports_sorting",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("maigret"),
        specs["maigret"],
        {
            "target": "alice",
            "extra_usernames": "bob,charlie",
            "timeout": 8,
            "retries": 2,
            "max_connections": 20,
            "no_recursion": True,
            "no_extracting": True,
            "id_type": "username",
            "permute": True,
            "db_file": "sites.json",
            "ignore_ids": "ignored1,ignored2",
            "folder_output": "reports",
            "proxy": "socks5://127.0.0.1:1080",
            "all_sites": True,
            "top_sites": 100,
            "tags": "photo",
            "sites": "github,twitter",
            "print_errors": True,
            "verbose": True,
            "no_color": True,
            "csv": True,
            "json_report": "simple",
            "reports_sorting": "data",
        },
    )
    assert preview["target"] == "alice"
    assert preview["options"] == (
        "bob charlie --timeout 8 --retries 2 --max-connections 20 "
        "--no-recursion --no-extracting --id-type username --permute "
        "--db sites.json --ignore-ids ignored1 --ignore-ids ignored2 "
        "--folderoutput reports --proxy socks5://127.0.0.1:1080 "
        "--all-sites --top-sites 100 --tags photo --site github "
        "--site twitter --print-errors --verbose --no-color --csv "
        "--json simple --reports-sorting data"
    )


def test_sublist3r_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["sublist3r"].source_status == "source-reviewed"
    assert records["sublist3r"].unverified_parameters == ()
    assert records["sublist3r"].gap == ""
    assert any("aboul3la/Sublist3r" in item for item in records["sublist3r"].evidence)

    params = adapter_parameter_names(registry.get_tool("sublist3r"), specs["sublist3r"])
    for removed in ("api_key", "json_output", "passive", "resolvers", "sources"):
        assert removed not in params
    for verified in (
        "bruteforce",
        "ports",
        "verbose",
        "threads",
        "engines",
        "output_file",
        "no_color",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("sublist3r"),
        specs["sublist3r"],
        {
            "target": "example.com",
            "bruteforce": True,
            "ports": "80,443",
            "verbose": True,
            "threads": 20,
            "engines": "google,bing",
            "output_file": "subs.txt",
            "no_color": True,
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == (
        "--bruteforce --ports 80,443 --verbose --threads 20 "
        "--engines google,bing --output subs.txt --no-color"
    )


def test_breacher_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["breacher"].source_status == "source-reviewed"
    assert records["breacher"].unverified_parameters == ()
    assert records["breacher"].gap == ""
    assert any("s0md3v/Breacher" in item for item in records["breacher"].evidence)

    params = adapter_parameter_names(registry.get_tool("breacher"), specs["breacher"])
    for removed in (
        "extensions",
        "follow_redirects",
        "match_codes",
        "proxy",
        "recursive",
        "threads",
        "wordlist",
    ):
        assert removed not in params
    assert "path" in params
    assert "panel_type" in params
    assert "fast" in params

    preview = adapter_request_preview(
        registry.get_tool("breacher"),
        specs["breacher"],
        {
            "target": "https://example.com",
            "path": "/admin",
            "panel_type": "php",
            "fast": True,
        },
    )
    assert preview["target"] == "https://example.com"
    assert preview["options"] == "--path /admin --type php --fast"


def test_secretfinder_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert registry.get_tool("secretfinder").run_command == (
        "cd secretfinder && python3 SecretFinder.py -i {target}"
    )
    assert records["secretfinder"].source_status == "source-reviewed"
    assert records["secretfinder"].unverified_parameters == ()
    assert records["secretfinder"].gap == ""
    assert any("m4ll0k/SecretFinder" in item for item in records["secretfinder"].evidence)

    params = adapter_parameter_names(registry.get_tool("secretfinder"), specs["secretfinder"])
    for removed in (
        "api_key",
        "extensions",
        "follow_redirects",
        "json_output",
        "match_codes",
        "passive",
        "recursive",
        "redact",
        "resolvers",
        "since_commit",
        "sources",
        "threads",
        "wordlist",
    ):
        assert removed not in params
    for verified in (
        "extract",
        "output_file",
        "regex",
        "burp",
        "cookie",
        "ignore",
        "only",
        "headers",
        "proxy",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("secretfinder"),
        specs["secretfinder"],
        {
            "target": "https://example.com/app.js",
            "extract": True,
            "output_file": "cli",
            "regex": "api",
            "burp": True,
            "cookie": "SID=abc",
            "ignore": "vendor",
            "only": "api",
            "headers": "X-Test:1",
            "proxy": "127.0.0.1:8080",
        },
    )
    assert preview["target"] == "https://example.com/app.js"
    assert preview["options"] == (
        "--extract --output cli --regex api --burp --cookie SID=abc "
        "--ignore vendor --only api --headers X-Test:1 --proxy 127.0.0.1:8080"
    )


def test_infoga_source_reviewed_archived_reference(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("infoga")

    assert tool.run_command == ""
    assert tool.archived is True
    assert "upstream repository returns 404" in tool.archived_reason
    assert specs["infoga"].exposed is False
    assert "archived" in specs["infoga"].blocked_reason
    assert records["infoga"].source_status == "source-reviewed"
    assert records["infoga"].unverified_parameters == ()
    assert records["infoga"].gap == ""
    assert any("m4ll0k/Infoga" in item for item in records["infoga"].evidence)

    params = adapter_parameter_names(tool, specs["infoga"])
    for removed in (
        "api_key",
        "json_output",
        "output_file",
        "passive",
        "resolvers",
        "scan_depth",
        "sources",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "archived_reference" in params

    preview = adapter_request_preview(
        tool,
        specs["infoga"],
        {"target": "ignored@example.com", "archived_reference": True},
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_shodanfy_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("shodanfy")

    assert tool.project_url == "https://github.com/owlonex/Shodanfy.py"
    assert tool.install_commands == ["git clone https://github.com/owlonex/Shodanfy.py.git"]
    assert tool.run_command == "cd Shodanfy.py && python3 shodanfy.py {target}"
    assert records["shodanfy"].source_status == "source-reviewed"
    assert records["shodanfy"].unverified_parameters == ()
    assert records["shodanfy"].gap == ""
    assert any("owlonex/Shodanfy.py" in item for item in records["shodanfy"].evidence)

    params = adapter_parameter_names(tool, specs["shodanfy"])
    for removed in (
        "api_key",
        "json_output",
        "output_file",
        "passive",
        "resolvers",
        "scan_depth",
        "sources",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    for expected in (
        "get_ports",
        "get_vuln",
        "get_info",
        "get_more_info",
        "get_banner",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["shodanfy"],
        {
            "target": "203.0.113.10",
            "get_ports": True,
            "get_vuln": True,
            "get_info": True,
            "get_more_info": True,
            "get_banner": True,
        },
    )
    assert preview["target"] == "203.0.113.10"
    assert preview["options"] == (
        "--getports --getvuln --getinfo --getmoreinfo --getbanner"
    )


def test_spiderfoot_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["spiderfoot"].source_status == "source-reviewed"
    assert records["spiderfoot"].unverified_parameters == ()
    assert records["spiderfoot"].gap == ""
    assert any("smicallef/spiderfoot" in item for item in records["spiderfoot"].evidence)

    params = adapter_parameter_names(registry.get_tool("spiderfoot"), specs["spiderfoot"])
    for removed in ("api_key", "json_output", "output_file", "passive", "resolvers", "sources", "timeout", "user_agent"):
        assert removed not in params
    for verified in (
        "debug",
        "listen",
        "modules",
        "list_modules",
        "correlate",
        "event_types",
        "use_case",
        "list_types",
        "output_format",
        "no_headers",
        "strip_newlines",
        "include_source",
        "max_data_length",
        "delimiter",
        "filter",
        "show_event_types",
        "strict_mode",
        "quiet",
        "version",
        "max_threads",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("spiderfoot"),
        specs["spiderfoot"],
        {
            "target": "example.com",
            "debug": True,
            "modules": "sfp_dnsresolve,sfp_whois",
            "event_types": "DOMAIN_NAME,IP_ADDRESS",
            "use_case": "passive",
            "output_format": "json",
            "no_headers": True,
            "strip_newlines": True,
            "include_source": True,
            "max_data_length": 120,
            "delimiter": ";",
            "filter": True,
            "show_event_types": "DOMAIN_NAME",
            "strict_mode": True,
            "quiet": True,
            "max_threads": 4,
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == (
        "--debug -m sfp_dnsresolve,sfp_whois -t DOMAIN_NAME,IP_ADDRESS "
        "-u passive -o json -H -n -r -S 120 -D ';' -f -F DOMAIN_NAME "
        "-x -q -max-threads 4"
    )


def test_commix_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["commix"].source_status == "source-reviewed"
    assert records["commix"].unverified_parameters == ()
    assert records["commix"].gap == ""
    assert any("commixproject/commix" in item for item in records["commix"].evidence)

    params = adapter_parameter_names(registry.get_tool("commix"), specs["commix"])
    for removed in (
        "wordlist",
        "extensions",
        "match_codes",
        "recursive",
        "follow_redirects",
        "module",
        "rhost",
        "rport",
        "username",
        "password",
        "payload",
        "os_shell",
    ):
        assert removed not in params
    for verified in (
        "batch",
        "data",
        "method",
        "cookie",
        "headers",
        "proxy",
        "timeout",
        "retries",
        "parameter",
        "skip",
        "technique",
        "delay",
        "time_sec",
        "os_cmd",
        "level",
        "skip_waf",
        "disable_coloring",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("commix"),
        specs["commix"],
        {
            "target": "https://example.test/vuln?x=1",
            "data": "x=1",
            "method": "POST",
            "cookie": "SID=abc",
            "headers": "X-Test: 1",
            "proxy": "http://127.0.0.1:8080",
            "timeout": 10,
            "retries": 2,
            "parameter": "x",
            "skip": "csrf",
            "technique": "f",
            "delay": 1,
            "time_sec": "5.0",
            "os_cmd": "whoami",
            "level": 2,
            "skip_waf": True,
            "disable_coloring": True,
        },
    )
    assert preview["target"] == "https://example.test/vuln?x=1"
    assert preview["options"] == (
        "--batch --method POST --data x=1 --cookie SID=abc "
        "--headers 'X-Test: 1' --proxy http://127.0.0.1:8080 "
        "--timeout 10 --retries 2 -p x --skip csrf --technique f "
        "--delay 1 --time-sec 5.0 --os-cmd whoami --level 2 "
        "--skip-waf --disable-coloring"
    )


def test_stegocracker_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["stegocracker"].source_status == "source-reviewed"
    assert records["stegocracker"].unverified_parameters == ()
    assert records["stegocracker"].gap == ""
    assert any("W1LDN16H7/StegoCracker" in item for item in records["stegocracker"].evidence)

    params = adapter_parameter_names(registry.get_tool("stegocracker"), specs["stegocracker"])
    for removed in ("extract", "output_file", "passphrase", "wordlist"):
        assert removed not in params
    for verified in (
        "input_image",
        "output_image",
        "message",
        "read_from",
        "encode",
        "decode",
        "music_file",
        "output_music",
        "convert",
        "version",
        "update",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("stegocracker"),
        specs["stegocracker"],
        {
            "target": "cover.png",
            "encode": True,
            "message": "secret",
            "output_image": "out.png",
        },
    )
    assert preview["target"] == "cover.png"
    assert preview["options"] == "--input cover.png --output out.png --message secret --encode"


def test_whitespace_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("whitespace")

    assert tool.run_command == "snow"
    assert tool.project_url == "https://github.com/mattkwan-zz/snow"
    assert records["whitespace"].source_status == "source-reviewed"
    assert records["whitespace"].unverified_parameters == ()
    assert records["whitespace"].gap == ""
    assert any("mattkwan-zz/snow" in item for item in records["whitespace"].evidence)

    params = adapter_parameter_names(tool, specs["whitespace"])
    for removed in ("extract", "passphrase", "wordlist"):
        assert removed not in params
    for expected in (
        "compress",
        "quiet",
        "space_report",
        "password",
        "line_length",
        "message_file",
        "message",
        "input_file",
        "output_file",
        "version",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["whitespace"],
        {
            "compress": True,
            "message": "I am lying",
            "password": "hello world",
            "line_length": 72,
            "input_file": "infile.txt",
            "output_file": "outfile.txt",
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-C -p 'hello world' -l 72 -m 'I am lying' infile.txt outfile.txt"
    )


def test_host2ip_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["host2ip"].source_status == "source-reviewed"
    assert records["host2ip"].unverified_parameters == ()
    assert records["host2ip"].gap == ""
    assert any("socket.gethostbyname" in item for item in records["host2ip"].evidence)

    params = adapter_parameter_names(registry.get_tool("host2ip"), specs["host2ip"])
    for removed in (
        "api_key",
        "default_scripts",
        "json_output",
        "os_detection",
        "ports",
        "rate",
        "resolvers",
        "scan_depth",
        "scan_type",
        "service_version",
        "sources",
        "timeout",
        "timing",
        "top_ports",
        "user_agent",
    ):
        assert removed not in params
    assert "hostname" in params

    preview = adapter_request_preview(
        registry.get_tool("host2ip"),
        specs["host2ip"],
        {
            "hostname": "example.com",
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == ""


def test_portscan_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["portscan"].source_status == "source-reviewed"
    assert records["portscan"].unverified_parameters == ()
    assert records["portscan"].gap == ""
    assert any("nmap.org" in item for item in records["portscan"].evidence)

    params = adapter_parameter_names(registry.get_tool("portscan"), specs["portscan"])
    for removed in (
        "default_scripts",
        "json_output",
        "os_detection",
        "output_file",
        "ports",
        "rate",
        "scan_depth",
        "scan_type",
        "service_version",
        "timeout",
        "timing",
        "top_ports",
        "user_agent",
    ):
        assert removed not in params
    assert "host" in params

    preview = adapter_request_preview(
        registry.get_tool("portscan"),
        specs["portscan"],
        {
            "host": "192.0.2.10",
        },
    )
    assert preview["target"] == "192.0.2.10"
    assert preview["options"] == ""


def test_rang3r_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["rang3r"].source_status == "source-reviewed"
    assert records["rang3r"].unverified_parameters == ()
    assert records["rang3r"].gap == ""
    assert any("floriankunushevci/rang3r" in item for item in records["rang3r"].evidence)

    params = adapter_parameter_names(registry.get_tool("rang3r"), specs["rang3r"])
    for removed in (
        "default_scripts",
        "json_output",
        "os_detection",
        "output_file",
        "ports",
        "rate",
        "scan_depth",
        "scan_type",
        "service_version",
        "timeout",
        "timing",
        "top_ports",
        "user_agent",
    ):
        assert removed not in params
    assert "ip" in params

    preview = adapter_request_preview(
        registry.get_tool("rang3r"),
        specs["rang3r"],
        {
            "ip": "192.0.2.0/24",
        },
    )
    assert preview["target"] == "192.0.2.0/24"
    assert preview["options"] == ""


def test_striker_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["striker"].source_status == "source-reviewed"
    assert records["striker"].unverified_parameters == ()
    assert records["striker"].gap == ""
    assert any("s0md3v/Striker" in item for item in records["striker"].evidence)

    params = adapter_parameter_names(registry.get_tool("striker"), specs["striker"])
    for removed in (
        "json_output",
        "output_file",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "domain" in params

    preview = adapter_request_preview(
        registry.get_tool("striker"),
        specs["striker"],
        {
            "domain": "example.com",
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == ""


def test_recondog_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["recondog"].source_status == "source-reviewed"
    assert records["recondog"].unverified_parameters == ()
    assert records["recondog"].gap == ""
    assert any("s0md3v/ReconDog" in item for item in records["recondog"].evidence)

    params = adapter_parameter_names(registry.get_tool("recondog"), specs["recondog"])
    for removed in (
        "api_key",
        "json_output",
        "output_file",
        "passive",
        "resolvers",
        "scan_depth",
        "sources",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "choice" in params

    preview = adapter_request_preview(
        registry.get_tool("recondog"),
        specs["recondog"],
        {
            "target": "example.com",
            "choice": "0",
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == "-c 0"


def test_isitdown_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["isitdown"].source_status == "source-reviewed"
    assert records["isitdown"].unverified_parameters == ()
    assert records["isitdown"].gap == ""
    assert any("urllib.request.urlopen" in item for item in records["isitdown"].evidence)

    params = adapter_parameter_names(registry.get_tool("isitdown"), specs["isitdown"])
    for removed in (
        "extensions",
        "follow_redirects",
        "json_output",
        "match_codes",
        "output_file",
        "proxy",
        "recursive",
        "scan_depth",
        "threads",
        "timeout",
        "user_agent",
        "wordlist",
    ):
        assert removed not in params
    assert "url" in params

    preview = adapter_request_preview(
        registry.get_tool("isitdown"),
        specs["isitdown"],
        {
            "url": "example.com",
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == ""


def test_hatcloud_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["hatcloud"].source_status == "source-reviewed"
    assert records["hatcloud"].unverified_parameters == ()
    assert records["hatcloud"].gap == ""
    assert any("HatBashBR/HatCloud" in item for item in records["hatcloud"].evidence)

    params = adapter_parameter_names(registry.get_tool("hatcloud"), specs["hatcloud"])
    for removed in (
        "extensions",
        "follow_redirects",
        "json_output",
        "match_codes",
        "output_file",
        "proxy",
        "recursive",
        "scan_depth",
        "threads",
        "timeout",
        "user_agent",
        "wordlist",
    ):
        assert removed not in params
    assert "domain" in params

    preview = adapter_request_preview(
        registry.get_tool("hatcloud"),
        specs["hatcloud"],
        {
            "domain": "example.com",
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == ""


def test_gospider_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["gospider"].source_status == "source-reviewed"
    assert records["gospider"].unverified_parameters == ()
    assert records["gospider"].gap == ""
    assert any("jaeles-project/gospider" in item for item in records["gospider"].evidence)

    params = adapter_parameter_names(registry.get_tool("gospider"), specs["gospider"])
    for removed in ("extensions", "follow_redirects", "match_codes", "recursive", "wordlist"):
        assert removed not in params
    for verified in (
        "site",
        "output_dir",
        "proxy",
        "user_agent",
        "cookie",
        "header",
        "burp_request",
        "blacklist",
        "whitelist",
        "whitelist_domain",
        "threads",
        "concurrent",
        "depth",
        "delay",
        "random_delay",
        "timeout",
        "base",
        "js",
        "subs",
        "sitemap",
        "robots",
        "other_source",
        "include_subs",
        "include_other_source",
        "debug",
        "json_output",
        "verbose",
        "length",
        "filter_length",
        "raw",
        "quiet",
        "no_redirect",
        "version",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("gospider"),
        specs["gospider"],
        {
            "site": "https://example.test",
            "output_dir": "out",
            "concurrent": 10,
            "depth": 2,
            "other_source": True,
            "include_subs": True,
            "cookie": "a=b",
            "header": "Accept: */*",
            "blacklist": ".(jpg|png)",
            "json_output": True,
            "quiet": True,
        },
    )
    assert preview["target"] == "https://example.test"
    assert preview["options"] == (
        "-o out --cookie a=b -H 'Accept: */*' --blacklist '.(jpg|png)' "
        "-c 10 -d 2 -a -w --json -q"
    )


def test_dirb_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["dirb"].source_status == "source-reviewed"
    assert records["dirb"].unverified_parameters == ()
    assert records["dirb"].gap == ""
    assert any("manpages.debian.org" in item for item in records["dirb"].evidence)

    params = adapter_parameter_names(registry.get_tool("dirb"), specs["dirb"])
    for removed in ("follow_redirects", "match_codes", "recursive", "threads"):
        assert removed not in params
    for verified in (
        "wordlist",
        "user_agent",
        "preserve_url_path",
        "cookie",
        "client_cert",
        "fine_tune_404",
        "header",
        "case_insensitive",
        "show_location",
        "ignore_code",
        "output_file",
        "proxy",
        "proxy_auth",
        "no_recursive",
        "interactive_recursion",
        "silent",
        "no_force_slash",
        "auth",
        "show_not_found",
        "ignore_warnings",
        "extensions_file",
        "extensions",
        "delay_ms",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("dirb"),
        specs["dirb"],
        {
            "target": "https://example.test",
            "wordlist": "words.txt",
            "user_agent": "Agent/1.0",
            "cookie": "a=b",
            "header": "X-Test: 1",
            "ignore_code": 404,
            "output_file": "dirb.txt",
            "proxy": "127.0.0.1:8080",
            "no_recursive": True,
            "silent": True,
            "extensions": "php,txt",
            "delay_ms": 100,
        },
    )
    assert preview["target"] == "https://example.test"
    assert preview["options"] == (
        "words.txt -a Agent/1.0 -c a=b -H 'X-Test: 1' -N 404 "
        "-o dirb.txt -p 127.0.0.1:8080 -r -S -X php,txt -z 100"
    )


def test_takeover_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["takeover"].source_status == "source-reviewed"
    assert records["takeover"].unverified_parameters == ()
    assert records["takeover"].gap == ""
    assert any("edoardottt/takeover" in item for item in records["takeover"].evidence)

    params = adapter_parameter_names(registry.get_tool("takeover"), specs["takeover"])
    for removed in (
        "api_key",
        "json_output",
        "passive",
        "resolvers",
        "scan_depth",
        "sources",
    ):
        assert removed not in params
    for verified in (
        "list_file",
        "proxy",
        "output_file",
        "threads",
        "timeout",
        "user_agent",
        "process_200",
        "verbose",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("takeover"),
        specs["takeover"],
        {
            "target": "example.com",
            "proxy": "http://127.0.0.1:8080",
            "output_file": "takeover.json",
            "threads": 8,
            "timeout": 20,
            "user_agent": "takeover-bot",
            "process_200": True,
            "verbose": True,
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == (
        "-p http://127.0.0.1:8080 -o takeover.json -t 8 -T 20 "
        "-u takeover-bot -k -v"
    )


def test_skipfish_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["skipfish"].source_status == "source-reviewed"
    assert records["skipfish"].unverified_parameters == ()
    assert records["skipfish"].gap == ""
    assert any("skipfish" in item for item in records["skipfish"].evidence)

    params = adapter_parameter_names(registry.get_tool("skipfish"), specs["skipfish"])
    for removed in ("extensions", "follow_redirects", "json_output", "match_codes", "recursive", "threads", "wordlist"):
        assert removed not in params
    for verified in (
        "output_dir",
        "write_wordlist",
        "read_wordlist",
        "auth",
        "host_ip",
        "cookie",
        "header",
        "browser",
        "no_new_cookies",
        "max_depth",
        "max_children",
        "max_descendants",
        "request_limit",
        "crawl_probability",
        "seed",
        "include_url",
        "exclude_url",
        "skip_param",
        "crawl_domain",
        "trust_domain",
        "skip_5xx",
        "no_forms",
        "no_html_parse",
        "log_mixed_content",
        "log_cache_mismatches",
        "log_external_urls",
        "suppress_duplicates",
        "quiet",
        "verbose",
        "no_autolearn",
        "no_extension_fuzzing",
        "purge_age",
        "form_autofill",
        "max_guesses",
        "signatures",
        "max_connections",
        "host_connections",
        "max_failures",
        "request_timeout",
        "io_timeout",
        "idle_timeout",
        "response_size_limit",
        "drop_binary_responses",
        "max_requests_per_second",
        "stop_after",
        "config_file",
    ):
        assert verified in params

    preview = adapter_request_preview(
        registry.get_tool("skipfish"),
        specs["skipfish"],
        {
            "target": "https://example.test",
            "output_dir": "out",
            "write_wordlist": "words.wl",
            "auth": "user:pass",
            "cookie": "a=b",
            "header": "X-Test: 1",
            "max_depth": 3,
            "max_children": 20,
            "include_url": "/admin",
            "exclude_url": "logout",
            "skip_param": "token",
            "crawl_domain": "example.org",
            "skip_5xx": True,
            "no_forms": True,
            "log_mixed_content": True,
            "suppress_duplicates": True,
            "quiet": True,
            "verbose": True,
            "max_connections": 20,
            "host_connections": 5,
            "request_timeout": 10,
            "max_requests_per_second": 30,
            "config_file": "skipfish.conf",
        },
    )
    assert preview["target"] == "https://example.test"
    assert preview["options"] == (
        "-o out -W words.wl -A user:pass -C a=b -H 'X-Test: 1' "
        "-d 3 -c 20 -I /admin -X logout -K token -D example.org "
        "-Z -O -M -Q -u -v -g 20 -m 5 -t 10 -l 30 --config skipfish.conf"
    )


def test_caido_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["caido"].source_status == "source-reviewed"
    assert records["caido"].unverified_parameters == ()
    assert records["caido"].gap == ""
    assert any("caido" in item.lower() for item in records["caido"].evidence)

    params = adapter_parameter_names(registry.get_tool("caido"), specs["caido"])
    for removed in ("extensions", "follow_redirects", "match_codes", "proxy", "recursive", "threads", "wordlist"):
        assert removed not in params
    assert "help" in params

    preview = adapter_request_preview(
        registry.get_tool("caido"),
        specs["caido"],
        {
            "help": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_mitmproxy_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["mitmproxy"].source_status == "source-reviewed"
    assert records["mitmproxy"].unverified_parameters == ()
    assert records["mitmproxy"].gap == ""
    assert any("mitmproxy" in item.lower() for item in records["mitmproxy"].evidence)

    params = adapter_parameter_names(registry.get_tool("mitmproxy"), specs["mitmproxy"])
    for removed in ("extensions", "follow_redirects", "match_codes", "proxy", "recursive", "threads", "wordlist"):
        assert removed not in params
    assert "version" in params

    preview = adapter_request_preview(
        registry.get_tool("mitmproxy"),
        specs["mitmproxy"],
        {
            "version": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_terminal_multiplexer_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["terminal-multiplexer"].source_status == "source-reviewed"
    assert records["terminal-multiplexer"].unverified_parameters == ()
    assert records["terminal-multiplexer"].gap == ""
    assert any("tilix" in item.lower() for item in records["terminal-multiplexer"].evidence)

    params = adapter_parameter_names(registry.get_tool("terminal-multiplexer"), specs["terminal-multiplexer"])
    for removed in ("command", "layout", "session_name"):
        assert removed not in params
    assert "version" in params

    preview = adapter_request_preview(
        registry.get_tool("terminal-multiplexer"),
        specs["terminal-multiplexer"],
        {
            "version": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_instabrute_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert specs["instabrute"].exposed is False
    assert records["instabrute"].source_status == "source-reviewed"
    assert records["instabrute"].unverified_parameters == ()
    assert records["instabrute"].gap == ""
    assert any("instabrute" in item.lower() for item in records["instabrute"].evidence)

    params = adapter_parameter_names(registry.get_tool("instabrute"), specs["instabrute"])
    assert "timeout" not in params
    for expected in ("user_file", "dictionary", "username", "delay", "proxy"):
        assert expected in params

    preview = adapter_request_preview(
        registry.get_tool("instabrute"),
        specs["instabrute"],
        {
            "username": "alice",
            "dictionary": "passwords.txt",
            "delay": 2,
            "proxy": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "-d passwords.txt -u alice -t 2 -p"
    assert preview["executable"] is False


def test_allinone_socialmedia_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert specs["allinone-socialmedia"].exposed is True
    assert specs["allinone-socialmedia"].requires_confirmation is True
    assert records["allinone-socialmedia"].source_status == "source-reviewed"
    assert records["allinone-socialmedia"].unverified_parameters == ()
    assert records["allinone-socialmedia"].gap == ""
    assert any("Brute_Force" in item for item in records["allinone-socialmedia"].evidence)

    params = adapter_parameter_names(
        registry.get_tool("allinone-socialmedia"),
        specs["allinone-socialmedia"],
    )
    assert "timeout" not in params
    assert "help" in params

    preview = adapter_request_preview(
        registry.get_tool("allinone-socialmedia"),
        specs["allinone-socialmedia"],
        {
            "help": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_faceshell_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("faceshell")

    assert specs["faceshell"].exposed is True
    assert specs["faceshell"].requires_confirmation is True
    assert tool.run_command == "cd Brute_Force && python3 Brute_Force.py -f {target}"
    assert records["faceshell"].source_status == "source-reviewed"
    assert records["faceshell"].unverified_parameters == ()
    assert records["faceshell"].gap == ""
    assert any("Brute_Force" in item for item in records["faceshell"].evidence)

    params = adapter_parameter_names(tool, specs["faceshell"])
    assert "timeout" not in params
    for expected in ("wordlist", "password", "proxy_file"):
        assert expected in params

    default_preview = adapter_request_preview(
        tool,
        specs["faceshell"],
        {
            "target": "alice",
            "confirm_authorized": True,
        },
    )
    assert default_preview["target"] == "alice"
    assert default_preview["options"] == "-l wordlist.txt"

    password_preview = adapter_request_preview(
        tool,
        specs["faceshell"],
        {
            "target": "alice",
            "password": "secret",
            "proxy_file": "proxies.txt",
            "confirm_authorized": True,
        },
    )
    assert password_preview["target"] == "alice"
    assert password_preview["options"] == "-p secret -X proxies.txt"
    assert password_preview["confirm_authorized"] is True


def test_hashbuster_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("hashbuster")

    assert tool.run_command == "buster {target}"
    assert records["hashbuster"].source_status == "source-reviewed"
    assert records["hashbuster"].unverified_parameters == ()
    assert records["hashbuster"].gap == ""
    assert any("Hash-Buster" in item for item in records["hashbuster"].evidence)

    params = adapter_parameter_names(tool, specs["hashbuster"])
    for removed in ("attack_mode", "hash_file", "hash_type", "max_length", "min_length", "output_file", "wordlist"):
        assert removed not in params
    for expected in ("input_type", "threads"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["hashbuster"],
        {
            "target": "hashes.txt",
            "input_type": "file",
            "threads": 8,
        },
    )
    assert preview["target"] == "hashes.txt"
    assert preview["options"] == "-t 8 -f"


def test_evilurl_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("evilurl")

    assert tool.run_command == "cd EvilURL && python3 evilurl.py -d {target}"
    assert specs["evilurl"].requires_confirmation is True
    assert records["evilurl"].source_status == "source-reviewed"
    assert records["evilurl"].unverified_parameters == ()
    assert records["evilurl"].gap == ""
    assert any("EvilURL" in item for item in records["evilurl"].evidence)

    params = adapter_parameter_names(tool, specs["evilurl"])
    for removed in ("domain", "extensions", "match_codes", "output_dir", "proxy", "recursive", "template", "threads", "tunnel", "wordlist"):
        assert removed not in params
    for expected in ("generate", "check_connection", "output_file", "check_availability"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["evilurl"],
        {
            "target": "example.com",
            "generate": True,
            "check_connection": True,
            "output_file": "evil.txt",
            "check_availability": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == "-g -c -o evil.txt -a"
    assert preview["confirm_authorized"] is True


def test_knockmail_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("knockmail")

    assert tool.run_command == "cd KnockMail && python3 knockmail.py"
    assert records["knockmail"].source_status == "source-reviewed"
    assert records["knockmail"].unverified_parameters == ()
    assert records["knockmail"].gap == ""
    assert any("KnockMail" in item for item in records["knockmail"].evidence)

    params = adapter_parameter_names(tool, specs["knockmail"])
    for removed in ("api_key", "json_output", "output_file", "passive", "resolvers", "scan_depth", "sources", "timeout", "user_agent"):
        assert removed not in params
    for expected in ("email", "input_file"):
        assert expected in params

    single_preview = adapter_request_preview(
        tool,
        specs["knockmail"],
        {
            "target": "user@example.com",
        },
    )
    assert single_preview["target"] == ""
    assert single_preview["options"] == "--email user@example.com"

    file_preview = adapter_request_preview(
        tool,
        specs["knockmail"],
        {
            "input_file": "emails.txt",
        },
    )
    assert file_preview["target"] == ""
    assert file_preview["options"] == "-f emails.txt"


def test_socialscan_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("socialscan")

    assert records["socialscan"].source_status == "source-reviewed"
    assert records["socialscan"].unverified_parameters == ()
    assert records["socialscan"].gap == ""
    assert any("socialscan" in item for item in records["socialscan"].evidence)

    params = adapter_parameter_names(tool, specs["socialscan"])
    for removed in ("api_key", "json_output", "output_file", "passive", "resolvers", "scan_depth", "sources", "timeout", "user_agent"):
        assert removed not in params
    for expected in ("platforms", "view_by", "available_only", "cache_tokens", "proxy_list", "verbose", "show_urls", "json_file", "debug"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["socialscan"],
        {
            "target": "alice",
            "platforms": "github,instagram",
            "view_by": "platform",
            "available_only": True,
            "cache_tokens": True,
            "proxy_list": "proxies.txt",
            "verbose": True,
            "show_urls": True,
            "json_file": "social.json",
            "debug": True,
        },
    )
    assert preview["target"] == "alice"
    assert preview["options"] == (
        "-p github instagram --view-by platform -a -c --proxy-list proxies.txt "
        "-v --show-urls --json social.json --debug"
    )


def test_appcheck_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("appcheck")

    assert records["appcheck"].source_status == "source-reviewed"
    assert records["appcheck"].unverified_parameters == ()
    assert records["appcheck"].gap == ""
    assert any("underhanded" in item.lower() for item in records["appcheck"].evidence)

    params = adapter_parameter_names(tool, specs["appcheck"])
    for removed in ("json_output", "output_file", "scan_depth", "timeout", "user_agent"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["appcheck"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""


def test_showme_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("showme")

    assert specs["showme"].requires_confirmation is True
    assert records["showme"].source_status == "source-reviewed"
    assert records["showme"].unverified_parameters == ()
    assert records["showme"].gap == ""
    assert any("SMWYG" in item for item in records["showme"].evidence)

    params = adapter_parameter_names(tool, specs["showme"])
    for removed in ("api_key", "attack_mode", "hash_file", "hash_type", "json_output", "max_length", "min_length", "output_file", "passive", "redact", "resolvers", "since_commit", "sources", "wordlist"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["showme"],
        {
            "target": "ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_goblin_wordgenerator_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("goblin-wordgenerator")

    assert records["goblin-wordgenerator"].source_status == "source-reviewed"
    assert records["goblin-wordgenerator"].unverified_parameters == ()
    assert records["goblin-wordgenerator"].gap == ""
    assert any("GoblinWordGenerator" in item for item in records["goblin-wordgenerator"].evidence)

    params = adapter_parameter_names(tool, specs["goblin-wordgenerator"])
    for removed in ("attack_mode", "hash_file", "hash_type", "max_length", "min_length", "output_file", "wordlist"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["goblin-wordgenerator"],
        {
            "target": "ignored",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""


def test_redhawk_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("redhawk")

    assert records["redhawk"].source_status == "source-reviewed"
    assert records["redhawk"].unverified_parameters == ()
    assert records["redhawk"].gap == ""
    assert any("RED_HAWK" in item for item in records["redhawk"].evidence)

    params = adapter_parameter_names(tool, specs["redhawk"])
    for removed in ("json_output", "output_file", "scan_depth", "timeout", "user_agent"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["redhawk"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""


def test_xerosploit_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("xerosploit")

    assert specs["xerosploit"].requires_confirmation is True
    assert records["xerosploit"].source_status == "source-reviewed"
    assert records["xerosploit"].unverified_parameters == ()
    assert records["xerosploit"].gap == ""
    assert any("xerosploit" in item.lower() for item in records["xerosploit"].evidence)

    params = adapter_parameter_names(tool, specs["xerosploit"])
    for removed in ("default_scripts", "os_detection", "ports", "rate", "scan_type", "service_version", "timing", "top_ports"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["xerosploit"],
        {
            "target": "ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_dracnmap_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("dracnmap")

    assert records["dracnmap"].source_status == "source-reviewed"
    assert records["dracnmap"].unverified_parameters == ()
    assert records["dracnmap"].gap == ""
    assert any("Screetsec/Dracnmap" in item for item in records["dracnmap"].evidence)

    params = adapter_parameter_names(tool, specs["dracnmap"])
    for removed in ("default_scripts", "json_output", "os_detection", "output_file", "ports", "rate", "scan_depth", "scan_type", "service_version", "timeout", "timing", "top_ports", "user_agent"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["dracnmap"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""


def test_reconspider_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("reconspider")

    assert records["reconspider"].source_status == "source-reviewed"
    assert records["reconspider"].unverified_parameters == ()
    assert records["reconspider"].gap == ""
    assert any("bhavsec/reconspider" in item for item in records["reconspider"].evidence)

    params = adapter_parameter_names(tool, specs["reconspider"])
    for removed in ("api_key", "json_output", "output_file", "passive", "resolvers", "scan_depth", "sources", "timeout", "user_agent"):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["reconspider"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""


def test_checkurl_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("checkurl")

    assert tool.run_command == "cd checkURL && python3 checkURL.py --url {target}"
    assert records["checkurl"].source_status == "source-reviewed"
    assert records["checkurl"].unverified_parameters == ()
    assert records["checkurl"].gap == ""
    assert any("checkURL" in item for item in records["checkurl"].evidence)

    params = adapter_parameter_names(tool, specs["checkurl"])
    for removed in (
        "domain",
        "extensions",
        "follow_redirects",
        "landing_url",
        "listener_host",
        "listener_port",
        "match_codes",
        "output_dir",
        "proxy",
        "recursive",
        "template",
        "threads",
        "tunnel",
        "wordlist",
    ):
        assert removed not in params
    assert "check_url" in params

    preview = adapter_request_preview(
        tool,
        specs["checkurl"],
        {
            "target": "example.com",
            "check_url": True,
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == "--check-url"


def test_blazy_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("blazy")

    assert specs["blazy"].exposed is False
    assert tool.run_command == "cd Blazy && python3 main.py -i {target}"
    assert records["blazy"].source_status == "source-reviewed"
    assert records["blazy"].unverified_parameters == ()
    assert records["blazy"].gap == ""
    assert any("s0md3v/Blazy" in item for item in records["blazy"].evidence)

    params = adapter_parameter_names(tool, specs["blazy"])
    for removed in (
        "extensions",
        "follow_redirects",
        "match_codes",
        "proxy",
        "recursive",
        "threads",
        "wordlist",
    ):
        assert removed not in params
    for expected in ("json_output", "timeout"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["blazy"],
        {
            "target": "https://example.test/login",
            "json_output": "blazy.json",
            "timeout": 15,
        },
    )
    assert preview["target"] == "https://example.test/login"
    assert preview["options"] == "-oJ blazy.json -t 15"
    assert preview["executable"] is False


def test_web2attack_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("web2attack")

    assert specs["web2attack"].requires_confirmation is True
    assert records["web2attack"].source_status == "source-reviewed"
    assert records["web2attack"].unverified_parameters == ()
    assert records["web2attack"].gap == ""
    assert any("santatic/web2attack" in item for item in records["web2attack"].evidence)

    params = adapter_parameter_names(tool, specs["web2attack"])
    for removed in (
        "extensions",
        "follow_redirects",
        "match_codes",
        "module",
        "password",
        "payload",
        "proxy",
        "recursive",
        "rhost",
        "rport",
        "threads",
        "username",
        "wordlist",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["web2attack"],
        {
            "target": "ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["confirm_authorized"] is True


def test_xssfinder_source_reviewed_config_driven(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("xssfinder")

    assert tool.run_command == "cd extended-xss-search && python3 extended-xss-search.py"
    assert records["xssfinder"].source_status == "source-reviewed"
    assert records["xssfinder"].unverified_parameters == ()
    assert records["xssfinder"].gap == ""
    assert any("extended-xss-search" in item for item in records["xssfinder"].evidence)

    params = adapter_parameter_names(tool, specs["xssfinder"])
    for removed in (
        "blind_callback",
        "cookies",
        "json_output",
        "output_file",
        "parameter",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "config_driven" in params

    preview = adapter_request_preview(
        tool,
        specs["xssfinder"],
        {
            "target": "https://ignored.example",
            "config_driven": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is True


def test_xss_payload_generator_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("xss-payload-generator")

    assert tool.run_command == "cd XSS-LOADER && sudo python3 payloader.py"
    assert specs["xss-payload-generator"].requires_confirmation is True
    assert records["xss-payload-generator"].source_status == "source-reviewed"
    assert records["xss-payload-generator"].unverified_parameters == ()
    assert records["xss-payload-generator"].gap == ""
    assert any("capture0x/XSS-LOADER" in item for item in records["xss-payload-generator"].evidence)

    params = adapter_parameter_names(tool, specs["xss-payload-generator"])
    for removed in (
        "architecture",
        "blind_callback",
        "cookies",
        "encoder",
        "format",
        "json_output",
        "lhost",
        "lport",
        "output_file",
        "parameter",
        "payload_type",
        "platform",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["xss-payload-generator"],
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is True
    assert preview["confirm_authorized"] is True


def test_xss_freak_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("xss-freak")

    assert tool.run_command == "cd XSS-Freak && sudo python3 XSS-Freak.py"
    assert specs["xss-freak"].requires_confirmation is True
    assert records["xss-freak"].source_status == "source-reviewed"
    assert records["xss-freak"].unverified_parameters == ()
    assert records["xss-freak"].gap == ""
    assert any("XSS-Freak" in item for item in records["xss-freak"].evidence)

    params = adapter_parameter_names(tool, specs["xss-freak"])
    for removed in (
        "blind_callback",
        "cookies",
        "json_output",
        "output_file",
        "parameter",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["xss-freak"],
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is True
    assert preview["confirm_authorized"] is True


def test_slowloris_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("slowloris")

    assert tool.run_command == "slowloris {target}"
    assert specs["slowloris"].exposed is False
    assert "DDOS Attack" in specs["slowloris"].blocked_reason
    assert records["slowloris"].source_status == "source-reviewed"
    assert records["slowloris"].unverified_parameters == ()
    assert records["slowloris"].gap == ""
    assert any("gkbrk/slowloris" in item for item in records["slowloris"].evidence)

    params = adapter_parameter_names(tool, specs["slowloris"])
    for removed in (
        "connections",
        "duration",
        "extensions",
        "follow_redirects",
        "match_codes",
        "method",
        "proxy",
        "recursive",
        "threads",
        "user_agent",
        "wordlist",
    ):
        assert removed not in params
    for expected in (
        "port",
        "sockets",
        "verbose",
        "randuseragents",
        "useproxy",
        "proxy_host",
        "proxy_port",
        "https",
        "sleeptime",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["slowloris"],
        {
            "target": "example.com",
            "port": 443,
            "sockets": 25,
            "verbose": True,
            "randuseragents": True,
            "useproxy": True,
            "proxy_host": "127.0.0.1",
            "proxy_port": 9050,
            "https": True,
            "sleeptime": 10,
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == (
        "--port 443 --sockets 25 --verbose --randuseragents --useproxy "
        "--proxy-host 127.0.0.1 --proxy-port 9050 --https --sleeptime 10"
    )
    assert preview["executable"] is False


def test_ddos_script_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("ddos-script")

    assert tool.run_command == "cd ddos && sudo python3 ddos {target}"
    assert specs["ddos-script"].exposed is False
    assert "DDOS Attack" in specs["ddos-script"].blocked_reason
    assert records["ddos-script"].source_status == "source-reviewed"
    assert records["ddos-script"].unverified_parameters == ()
    assert records["ddos-script"].gap == ""
    assert any("the-deepnet/ddos" in item for item in records["ddos-script"].evidence)

    params = adapter_parameter_names(tool, specs["ddos-script"])
    for removed in (
        "connections",
        "duration",
        "port",
        "ports",
        "rate",
        "scan_type",
        "user_agent",
    ):
        assert removed not in params
    for expected in (
        "method",
        "socks_type",
        "threads",
        "proxylist",
        "multiple",
        "timer",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["ddos-script"],
        {
            "target": "https://example.com",
            "method": "bypass",
            "socks_type": "5",
            "threads": 10,
            "proxylist": "socks5.txt",
            "multiple": 2,
            "timer": 30,
        },
    )
    assert preview["target"] == "bypass https://example.com"
    assert preview["options"] == "5 10 socks5.txt 2 30"
    assert preview["executable"] is False


def test_goldeneye_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("goldeneye")

    assert tool.run_command == "cd GoldenEye && sudo ./goldeneye.py {target}"
    assert specs["goldeneye"].exposed is False
    assert "DDOS Attack" in specs["goldeneye"].blocked_reason
    assert records["goldeneye"].source_status == "source-reviewed"
    assert records["goldeneye"].unverified_parameters == ()
    assert records["goldeneye"].gap == ""
    assert any("jseidl/GoldenEye" in item for item in records["goldeneye"].evidence)

    params = adapter_parameter_names(tool, specs["goldeneye"])
    for removed in (
        "connections",
        "duration",
        "extensions",
        "follow_redirects",
        "match_codes",
        "port",
        "proxy",
        "recursive",
        "threads",
        "user_agent",
        "wordlist",
    ):
        assert removed not in params
    for expected in (
        "useragents_file",
        "workers",
        "sockets",
        "method",
        "debug",
        "no_ssl_check",
        "help",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["goldeneye"],
        {
            "target": "https://example.com",
            "useragents_file": "uas.txt",
            "workers": 4,
            "sockets": 10,
            "method": "random",
            "debug": True,
            "no_ssl_check": True,
        },
    )
    assert preview["target"] == "https://example.com"
    assert preview["options"] == (
        "--useragents uas.txt --workers 4 --sockets 10 --method random "
        "--debug --nosslcheck"
    )
    assert preview["executable"] is False


def test_ufonet_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("ufonet")

    assert tool.run_command == "cd ufonet && python3 ufonet --gui"
    assert specs["ufonet"].exposed is False
    assert "DDOS Attack" in specs["ufonet"].blocked_reason
    assert records["ufonet"].source_status == "source-reviewed"
    assert records["ufonet"].unverified_parameters == ()
    assert records["ufonet"].gap == ""
    assert any("epsylon/ufonet" in item for item in records["ufonet"].evidence)

    params = adapter_parameter_names(tool, specs["ufonet"])
    for removed in (
        "connections",
        "duration",
        "method",
        "port",
        "target",
        "wordlist",
    ):
        if removed != "target":
            assert removed not in params
    for expected in (
        "gui",
        "verbose",
        "examples",
        "timeline",
        "update",
        "check_tor",
        "force_ssl",
        "proxy",
        "user_agent",
        "referer",
        "host_header",
        "x_forwarded_for",
        "x_client_ip",
        "timeout",
        "retries",
        "threads",
        "delay",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["ufonet"],
        {
            "target": "ignored.example",
            "gui": True,
            "verbose": True,
            "force_ssl": True,
            "proxy": "http://127.0.0.1:8118",
            "user_agent": "UA",
            "referer": "https://ref.example",
            "host_header": "host.example",
            "x_forwarded_for": True,
            "x_client_ip": True,
            "timeout": 10,
            "retries": 2,
            "threads": 5,
            "delay": 1,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "--gui --verbose --force-ssl --proxy http://127.0.0.1:8118 "
        "--user-agent UA --referer https://ref.example --host host.example "
        "--xforw --xclient --timeout 10 --retries 2 --threads 5 --delay 1"
    )
    assert preview["executable"] is False


def test_saphyra_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("saphyra")

    assert tool.run_command == "cd Saphyra-DDoS && python saphyra.py {target}"
    assert specs["saphyra"].exposed is False
    assert "DDOS Attack" in specs["saphyra"].blocked_reason
    assert records["saphyra"].source_status == "source-reviewed"
    assert records["saphyra"].unverified_parameters == ()
    assert records["saphyra"].gap == ""
    assert any("anonymous24x7/Saphyra-DDoS" in item for item in records["saphyra"].evidence)

    params = adapter_parameter_names(tool, specs["saphyra"])
    for removed in (
        "connections",
        "duration",
        "method",
        "port",
        "threads",
        "user_agent",
    ):
        assert removed not in params
    assert "safe" in params

    preview = adapter_request_preview(
        tool,
        specs["saphyra"],
        {
            "target": "https://example.com",
            "safe": True,
        },
    )
    assert preview["target"] == "https://example.com"
    assert preview["options"] == "safe"
    assert preview["executable"] is False


def test_asyncrone_source_reviewed_archived_reference(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("asyncrone")

    assert tool.run_command == ""
    assert tool.archived is True
    assert "repositories return 404" in tool.archived_reason
    assert specs["asyncrone"].exposed is False
    assert "DDOS Attack" in specs["asyncrone"].blocked_reason
    assert records["asyncrone"].source_status == "source-reviewed"
    assert records["asyncrone"].unverified_parameters == ()
    assert records["asyncrone"].gap == ""
    assert any("fatihsnsy/aSYNcrone" in item for item in records["asyncrone"].evidence)

    params = adapter_parameter_names(tool, specs["asyncrone"])
    for removed in (
        "connections",
        "duration",
        "method",
        "port",
        "ports",
        "rate",
        "scan_type",
        "threads",
        "user_agent",
    ):
        assert removed not in params
    assert "archived_reference" in params

    preview = adapter_request_preview(
        tool,
        specs["asyncrone"],
        {"target": "ignored.example", "archived_reference": True},
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_crivo_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("crivo")

    assert tool.run_command == "crivo"
    assert specs["crivo"].exposed is True
    assert records["crivo"].source_status == "source-reviewed"
    assert records["crivo"].unverified_parameters == ()
    assert records["crivo"].gap == ""
    assert any("GMDSantana/crivo" in item for item in records["crivo"].evidence)

    params = adapter_parameter_names(tool, specs["crivo"])
    for removed in (
        "extensions",
        "follow_redirects",
        "match_codes",
        "proxy",
        "recursive",
        "threads",
        "wordlist",
    ):
        assert removed not in params
    for expected in (
        "input_mode",
        "input_file",
        "webpage",
        "webpage_list",
        "output_file",
        "scope",
        "ip",
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "verbose",
        "version",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["crivo"],
        {
            "target": "https://example.com",
            "input_mode": "webpage",
            "output_file": "out.txt",
            "scope": "urls,domains",
            "ipv4": True,
            "domain": True,
            "verbose": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-w https://example.com -o out.txt -s urls,domains --ipv4 --domain -v"
    )
    assert preview["executable"] is True


def test_dnstwist_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("dnstwist")

    assert tool.run_command == "dnstwist {target}"
    assert specs["dnstwist"].exposed is False
    assert "Phishing Attack" in specs["dnstwist"].blocked_reason
    assert records["dnstwist"].source_status == "source-reviewed"
    assert records["dnstwist"].unverified_parameters == ()
    assert records["dnstwist"].gap == ""
    assert any("elceef/dnstwist" in item for item in records["dnstwist"].evidence)

    params = adapter_parameter_names(tool, specs["dnstwist"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "sources",
        "passive",
        "resolvers",
        "api_key",
        "json_output",
        "scan_depth",
        "timeout",
    ):
        assert removed not in params
    for expected in (
        "all_records",
        "banners",
        "dictionary",
        "output_format",
        "fuzzers",
        "geoip",
        "lsh",
        "lsh_url",
        "mxcheck",
        "output_file",
        "registered",
        "unregistered",
        "phash",
        "phash_url",
        "screenshots",
        "threads",
        "whois",
        "tld",
        "nameservers",
        "user_agent",
        "version",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["dnstwist"],
        {
            "target": "example.com",
            "registered": True,
            "output_format": "json",
            "output_file": "dnstwist.json",
            "fuzzers": "homoglyph,hyphenation",
            "threads": 8,
            "nameservers": "1.1.1.1,8.8.8.8",
            "user_agent": "UA",
        },
    )
    assert preview["target"] == "example.com"
    assert preview["options"] == (
        "--format json --fuzzers homoglyph,hyphenation --output dnstwist.json "
        "--registered --threads 8 --nameservers 1.1.1.1,8.8.8.8 "
        "--useragent UA"
    )
    assert preview["executable"] is False


def test_autophisher_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("autophisher")

    assert tool.run_command == "cd autophisher && sudo bash autophisher.sh"
    assert specs["autophisher"].exposed is False
    assert "Phishing Attack" in specs["autophisher"].blocked_reason
    assert records["autophisher"].source_status == "source-reviewed"
    assert records["autophisher"].unverified_parameters == ()
    assert records["autophisher"].gap == ""
    assert any("CodingRanjith/autophisher" in item for item in records["autophisher"].evidence)

    params = adapter_parameter_names(tool, specs["autophisher"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "sources",
        "passive",
        "resolvers",
        "api_key",
        "output_file",
        "json_output",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["autophisher"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == "ignored.example"
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_pyphisher_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("pyphisher")

    assert tool.run_command == "cd PyPhisher && sudo python3 pyphisher.py"
    assert specs["pyphisher"].exposed is False
    assert "Phishing Attack" in specs["pyphisher"].blocked_reason
    assert records["pyphisher"].source_status == "source-reviewed"
    assert records["pyphisher"].unverified_parameters == ()
    assert records["pyphisher"].gap == ""
    assert any("KasRoudra/PyPhisher" in item for item in records["pyphisher"].evidence)

    params = adapter_parameter_names(tool, specs["pyphisher"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "output_dir",
        "site",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    for expected in (
        "port",
        "template_option",
        "tunneler",
        "region",
        "folder",
        "domain",
        "subdomain",
        "redirect_url",
        "mode",
        "troubleshoot",
        "nokey",
        "kshrt",
        "noupdate",
        "nokill",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["pyphisher"],
        {
            "target": "ignored.example",
            "port": 8081,
            "template_option": "12",
            "tunneler": "cloudflared",
            "region": "eu",
            "folder": "custom-site",
            "domain": "example.com",
            "subdomain": "training",
            "redirect_url": "https://example.com/after",
            "mode": "test",
            "troubleshoot": "cloudflared",
            "nokey": True,
            "kshrt": True,
            "noupdate": True,
            "nokill": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "--port 8081 --option 12 --tunneler cloudflared --region eu "
        "--folder custom-site --domain example.com --subdomain training "
        "--url https://example.com/after --mode test --troubleshoot "
        "cloudflared --nokey --kshrt --noupdate --nokill"
    )
    assert preview["executable"] is False


def test_advphishing_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("advphishing")

    assert tool.run_command == "cd AdvPhishing && sudo bash AdvPhishing.sh"
    assert specs["advphishing"].exposed is False
    assert "Phishing Attack" in specs["advphishing"].blocked_reason
    assert records["advphishing"].source_status == "source-reviewed"
    assert records["advphishing"].unverified_parameters == ()
    assert records["advphishing"].gap == ""
    assert any("Ignitetch/AdvPhishing" in item for item in records["advphishing"].evidence)

    params = adapter_parameter_names(tool, specs["advphishing"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "sources",
        "passive",
        "resolvers",
        "api_key",
        "output_file",
        "json_output",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["advphishing"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_setoolkit_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("setoolkit")

    assert tool.run_command == "sudo setoolkit"
    assert specs["setoolkit"].exposed is False
    assert "Phishing Attack" in specs["setoolkit"].blocked_reason
    assert records["setoolkit"].source_status == "source-reviewed"
    assert records["setoolkit"].unverified_parameters == ()
    assert records["setoolkit"].gap == ""
    assert any("trustedsec/social-engineer-toolkit" in item for item in records["setoolkit"].evidence)

    params = adapter_parameter_names(tool, specs["setoolkit"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["setoolkit"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_socialfish_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("socialfish")

    assert tool.run_command == "cd SocialFish && sudo python3 SocialFish.py"
    assert specs["socialfish"].exposed is False
    assert "Phishing Attack" in specs["socialfish"].blocked_reason
    assert records["socialfish"].source_status == "source-reviewed"
    assert records["socialfish"].unverified_parameters == ()
    assert records["socialfish"].gap == ""
    assert any("UndeadSec/SocialFish" in item for item in records["socialfish"].evidence)

    params = adapter_parameter_names(tool, specs["socialfish"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "sources",
        "passive",
        "resolvers",
        "api_key",
        "output_file",
        "json_output",
        "scan_depth",
        "timeout",
        "user_agent",
    ):
        assert removed not in params
    assert "username" in params
    assert "password" in params

    preview = adapter_request_preview(
        tool,
        specs["socialfish"],
        {
            "target": "ignored.example",
            "username": "admin",
            "password": "pass",
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "admin pass"
    assert preview["executable"] is False


def test_hiddeneye_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("hiddeneye")

    assert tool.run_command == "cd HiddenEye && sudo python3 HiddenEye.py"
    assert specs["hiddeneye"].exposed is False
    assert "Phishing Attack" in specs["hiddeneye"].blocked_reason
    assert records["hiddeneye"].source_status == "source-reviewed"
    assert records["hiddeneye"].unverified_parameters == ()
    assert records["hiddeneye"].gap == ""
    assert any("Morsmalleo/HiddenEye" in item for item in records["hiddeneye"].evidence)
    assert any("HITVICKY/HIDDEN-eye-" in item for item in records["hiddeneye"].evidence)

    params = adapter_parameter_names(tool, specs["hiddeneye"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["hiddeneye"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_evilginx3_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("evilginx3")

    assert tool.run_command == "evilginx"
    assert specs["evilginx3"].exposed is False
    assert "Phishing Attack" in specs["evilginx3"].blocked_reason
    assert records["evilginx3"].source_status == "source-reviewed"
    assert records["evilginx3"].unverified_parameters == ()
    assert records["evilginx3"].gap == ""
    assert any("kgretzky/evilginx2" in item for item in records["evilginx3"].evidence)

    params = adapter_parameter_names(tool, specs["evilginx3"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    for expected in (
        "phishlets_dir",
        "redirectors_dir",
        "config_dir",
        "debug",
        "developer",
        "version",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["evilginx3"],
        {
            "target": "ignored.example",
            "phishlets_dir": "phishlets",
            "redirectors_dir": "redirectors",
            "config_dir": "cfg",
            "debug": True,
            "developer": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "-p phishlets -t redirectors -c cfg -debug -developer"
    assert preview["executable"] is False


def test_iseeyou_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("iseeyou")

    assert tool.run_command == "cd I-See-You && sudo bash ISeeYou.sh"
    assert specs["iseeyou"].exposed is False
    assert "Phishing Attack" in specs["iseeyou"].blocked_reason
    assert records["iseeyou"].source_status == "source-reviewed"
    assert records["iseeyou"].unverified_parameters == ()
    assert records["iseeyou"].gap == ""
    assert any("Viralmaniar/I-See-You" in item for item in records["iseeyou"].evidence)

    params = adapter_parameter_names(tool, specs["iseeyou"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["iseeyou"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_saycheese_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("saycheese")

    assert tool.run_command == "cd saycheese && sudo bash saycheese.sh"
    assert specs["saycheese"].exposed is False
    assert "Phishing Attack" in specs["saycheese"].blocked_reason
    assert records["saycheese"].source_status == "source-reviewed"
    assert records["saycheese"].unverified_parameters == ()
    assert records["saycheese"].gap == ""
    assert any("hangetzzu/saycheese" in item for item in records["saycheese"].evidence)

    params = adapter_parameter_names(tool, specs["saycheese"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["saycheese"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_qrjacking_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("qrjacking")

    assert tool.run_command == "cd ohmyqr && sudo bash ohmyqr.sh"
    assert specs["qrjacking"].exposed is False
    assert "Phishing Attack" in specs["qrjacking"].blocked_reason
    assert records["qrjacking"].source_status == "source-reviewed"
    assert records["qrjacking"].unverified_parameters == ()
    assert records["qrjacking"].gap == ""
    assert any("cryptedwolf/ohmyqr" in item for item in records["qrjacking"].evidence)

    params = adapter_parameter_names(tool, specs["qrjacking"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["qrjacking"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_blackeye_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("blackeye")

    assert tool.run_command == "cd blackeye && sudo bash blackeye.sh"
    assert specs["blackeye"].exposed is False
    assert "Phishing Attack" in specs["blackeye"].blocked_reason
    assert records["blackeye"].source_status == "source-reviewed"
    assert records["blackeye"].unverified_parameters == ()
    assert records["blackeye"].gap == ""
    assert any("An0nUD4Y/blackeye" in item for item in records["blackeye"].evidence)
    assert any("thewickedkarma/blackeye-im" in item for item in records["blackeye"].evidence)

    params = adapter_parameter_names(tool, specs["blackeye"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["blackeye"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_shellphish_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("shellphish")

    assert tool.run_command == "cd shellphish && sudo bash shellphish.sh"
    assert specs["shellphish"].exposed is False
    assert "Phishing Attack" in specs["shellphish"].blocked_reason
    assert records["shellphish"].source_status == "source-reviewed"
    assert records["shellphish"].unverified_parameters == ()
    assert records["shellphish"].gap == ""
    assert any("An0nUD4Y/shellphish" in item for item in records["shellphish"].evidence)
    assert any(
        "Kecatoca/thelinuxchoice-shellphish" in item
        for item in records["shellphish"].evidence
    )

    params = adapter_parameter_names(tool, specs["shellphish"])
    for removed in (
        "timeout",
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["shellphish"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_thanos_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("thanos")

    assert tool.run_command == "cd Thanos && sudo bash Thanos.sh"
    assert specs["thanos"].exposed is False
    assert "Phishing Attack" in specs["thanos"].blocked_reason
    assert records["thanos"].source_status == "source-reviewed"
    assert records["thanos"].unverified_parameters == ()
    assert records["thanos"].gap == ""
    assert any("TridevReddy/Thanos" in item for item in records["thanos"].evidence)

    params = adapter_parameter_names(tool, specs["thanos"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["thanos"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_qrljacking_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("qrljacking")

    assert tool.run_command == "cd QRLJacking/QRLJacker && python3 QrlJacker.py"
    assert specs["qrljacking"].exposed is False
    assert "Phishing Attack" in specs["qrljacking"].blocked_reason
    assert records["qrljacking"].source_status == "source-reviewed"
    assert records["qrljacking"].unverified_parameters == ()
    assert records["qrljacking"].gap == ""
    assert any("OWASP/QRLJacking" in item for item in records["qrljacking"].evidence)

    params = adapter_parameter_names(tool, specs["qrljacking"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    for expected in (
        "resource_file",
        "execute_command",
        "debug",
        "dev",
        "verbose",
        "quiet",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["qrljacking"],
        {
            "target": "ignored.example",
            "resource_file": "history.rc",
            "execute_command": "help;exit",
            "debug": True,
            "dev": True,
            "verbose": True,
            "quiet": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "-r history.rc -x 'help;exit' --debug --dev --verbose -q"
    assert preview["executable"] is False


def test_maskphish_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("maskphish")

    assert tool.run_command == "cd maskphish && sudo bash maskphish.sh"
    assert specs["maskphish"].exposed is False
    assert "Phishing Attack" in specs["maskphish"].blocked_reason
    assert records["maskphish"].source_status == "source-reviewed"
    assert records["maskphish"].unverified_parameters == ()
    assert records["maskphish"].gap == ""
    assert any("jaykali/maskphish" in item for item in records["maskphish"].evidence)

    params = adapter_parameter_names(tool, specs["maskphish"])
    for removed in (
        "wordlist",
        "threads",
        "extensions",
        "match_codes",
        "recursive",
        "follow_redirects",
        "proxy",
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["maskphish"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_blackphish_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("blackphish")

    assert tool.run_command == "cd BlackPhish && sudo python3 blackphish.py"
    assert specs["blackphish"].exposed is False
    assert "Phishing Attack" in specs["blackphish"].blocked_reason
    assert records["blackphish"].source_status == "source-reviewed"
    assert records["blackphish"].unverified_parameters == ()
    assert records["blackphish"].gap == ""
    assert any("iinc0gnit0/BlackPhish" in item for item in records["blackphish"].evidence)
    assert any("yangr0/BlackPhish" in item for item in records["blackphish"].evidence)

    params = adapter_parameter_names(tool, specs["blackphish"])
    for removed in (
        "template",
        "landing_url",
        "listener_host",
        "listener_port",
        "tunnel",
        "domain",
        "output_dir",
        "site",
        "redirect_url",
        "custom_domain",
        "phishlet",
        "capture_path",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["blackphish"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_thefatrat_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("thefatrat")

    assert tool.run_command == "cd TheFatRat && sudo bash setup.sh"
    assert specs["thefatrat"].exposed is False
    assert "Payload Creation" in specs["thefatrat"].blocked_reason
    assert records["thefatrat"].source_status == "source-reviewed"
    assert records["thefatrat"].unverified_parameters == ()
    assert records["thefatrat"].gap == ""
    assert any("Screetsec/TheFatRat" in item for item in records["thefatrat"].evidence)

    params = adapter_parameter_names(tool, specs["thefatrat"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["thefatrat"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_brutal_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("brutal")

    assert tool.run_command == "cd Brutal && sudo bash Brutal.sh"
    assert specs["brutal"].exposed is False
    assert "Payload Creation" in specs["brutal"].blocked_reason
    assert records["brutal"].source_status == "source-reviewed"
    assert records["brutal"].unverified_parameters == ()
    assert records["brutal"].gap == ""
    assert any("Screetsec/Brutal" in item for item in records["brutal"].evidence)

    params = adapter_parameter_names(tool, specs["brutal"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["brutal"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_stitch_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("stitch")

    assert tool.run_command == "cd Stitch && sudo python3 main.py"
    assert specs["stitch"].exposed is False
    assert "Payload Creation" in specs["stitch"].blocked_reason
    assert records["stitch"].source_status == "source-reviewed"
    assert records["stitch"].unverified_parameters == ()
    assert records["stitch"].gap == ""
    assert any("nathanlopez/Stitch" in item for item in records["stitch"].evidence)

    params = adapter_parameter_names(tool, specs["stitch"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["stitch"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_msfvenom_source_reviewed_msfpc_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("msfvenom")

    assert tool.run_command == "cd msfpc && sudo bash msfpc.sh -h -v"
    assert specs["msfvenom"].exposed is False
    assert "Payload Creation" in specs["msfvenom"].blocked_reason
    assert records["msfvenom"].source_status == "source-reviewed"
    assert records["msfvenom"].unverified_parameters == ()
    assert records["msfvenom"].gap == ""
    assert any("g0tmi1k/msfpc" in item for item in records["msfvenom"].evidence)

    params = adapter_parameter_names(tool, specs["msfvenom"])
    for expected in (
        "platform",
        "lhost",
        "lport",
        "shell",
        "direction",
        "stager",
        "method",
        "batch",
        "loop",
        "verbose",
        "help",
    ):
        assert expected in params
    for removed in (
        "payload_type",
        "architecture",
        "format",
        "encoder",
        "output_file",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["msfvenom"],
        {
            "platform": "windows",
            "lhost": "127.0.0.1",
            "lport": 4444,
            "shell": "msf",
            "direction": "reverse",
            "stager": "stageless",
            "method": "https",
            "batch": True,
            "verbose": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "--platform windows --ip 127.0.0.1 --port 4444 --shell msf "
        "--direction reverse --stage stageless --method https --batch --verbose"
    )
    assert preview["executable"] is False


def test_venom_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("venom")

    assert tool.run_command == "cd venom && sudo ./venom.sh"
    assert specs["venom"].exposed is False
    assert "Payload Creation" in specs["venom"].blocked_reason
    assert records["venom"].source_status == "source-reviewed"
    assert records["venom"].unverified_parameters == ()
    assert records["venom"].gap == ""
    assert any("r00t-3xp10it/venom" in item for item in records["venom"].evidence)

    params = adapter_parameter_names(tool, specs["venom"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
        "shell",
        "direction",
        "method",
        "batch",
        "loop",
        "verbose",
        "help",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["venom"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_spycam_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("spycam")

    assert tool.run_command == "cd spycam && ./spycam"
    assert specs["spycam"].exposed is False
    assert (
        "Payload Creation" in specs["spycam"].blocked_reason
        or "Spycam" in specs["spycam"].blocked_reason
    )
    assert records["spycam"].source_status == "source-reviewed"
    assert records["spycam"].unverified_parameters == ()
    assert records["spycam"].gap == ""
    assert any("indexnotfound404/spycam" in item for item in records["spycam"].evidence)

    params = adapter_parameter_names(tool, specs["spycam"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["spycam"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_mobdroid_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("mobdroid")

    assert tool.run_command == "cd mob-droid && sudo python3 mob-droid.py"
    assert specs["mobdroid"].exposed is False
    assert "Payload Creation" in specs["mobdroid"].blocked_reason
    assert records["mobdroid"].source_status == "source-reviewed"
    assert records["mobdroid"].unverified_parameters == ()
    assert records["mobdroid"].gap == ""
    assert any("kinghacker0/Mob-Droid" in item for item in records["mobdroid"].evidence)

    params = adapter_parameter_names(tool, specs["mobdroid"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "apk_path",
        "package_name",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["mobdroid"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_enigma_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("enigma")

    assert tool.run_command == "cd Enigma && sudo python3 enigma.py"
    assert specs["enigma"].exposed is False
    assert "Payload Creation" in specs["enigma"].blocked_reason
    assert records["enigma"].source_status == "source-reviewed"
    assert records["enigma"].unverified_parameters == ()
    assert records["enigma"].gap == ""
    assert any("UndeadSec/Enigma" in item for item in records["enigma"].evidence)

    params = adapter_parameter_names(tool, specs["enigma"])
    for removed in (
        "payload_type",
        "platform",
        "architecture",
        "lhost",
        "lport",
        "format",
        "encoder",
        "output_file",
        "stager",
        "listener_name",
        "apk_name",
        "bundle_id",
        "sign_apk",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["enigma"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_wifipumpkin_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("wifipumpkin")

    assert tool.run_command == "sudo wifipumpkin3"
    assert specs["wifipumpkin"].exposed is False
    assert "Wireless Attack" in specs["wifipumpkin"].blocked_reason
    assert records["wifipumpkin"].source_status == "source-reviewed"
    assert records["wifipumpkin"].unverified_parameters == ()
    assert records["wifipumpkin"].gap == ""
    assert any("P0cL4bs/wifipumpkin3" in item for item in records["wifipumpkin"].evidence)

    params = adapter_parameter_names(tool, specs["wifipumpkin"])
    for expected in (
        "interface",
        "interface_net",
        "session",
        "pulp_file",
        "xpulp_commands",
        "wireless_mode",
        "no_colors",
        "rest",
        "restport",
        "username",
        "password",
        "ignore_networkmanager",
        "remove_networkmanager",
        "version",
    ):
        assert expected in params
    for removed in (
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "monitor_mode",
    ):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["wifipumpkin"],
        {
            "target": "ignored.example",
            "interface": "wlan0",
            "interface_net": "eth0",
            "session": "lab",
            "pulp_file": "setup.pulp",
            "xpulp_commands": "show;exit",
            "wireless_mode": "ap",
            "no_colors": True,
            "rest": True,
            "restport": 8080,
            "username": "api",
            "password": "secret",
            "ignore_networkmanager": "wlan0",
            "remove_networkmanager": "wlan1",
            "version": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-i wlan0 -iNet eth0 -s lab -p setup.pulp -x 'show;exit' -m ap "
        "--no-colors --rest --restport 8080 --username api --password secret "
        "-iNM wlan0 -rNM wlan1 --version"
    )
    assert preview["executable"] is False


def test_pixiewps_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("pixiewps")

    assert tool.run_command == "pixiewps --help"
    assert specs["pixiewps"].exposed is False
    assert "Wireless Attack" in specs["pixiewps"].blocked_reason
    assert records["pixiewps"].source_status == "source-reviewed"
    assert records["pixiewps"].unverified_parameters == ()
    assert records["pixiewps"].gap == ""
    assert any("wiire/pixiewps" in item for item in records["pixiewps"].evidence)

    params = adapter_parameter_names(tool, specs["pixiewps"])
    for expected in (
        "pke",
        "pkr",
        "e_hash1",
        "e_hash2",
        "authkey",
        "e_nonce",
        "r_nonce",
        "e_bssid",
        "verbosity",
        "output_file",
        "jobs",
        "mode",
        "start",
        "end",
        "force",
        "m7_enc",
        "m5_enc",
        "help",
        "version",
    ):
        assert expected in params
    for removed in (
        "interface",
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "monitor_mode",
    ):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["pixiewps"],
        {
            "target": "ignored.example",
            "pke": "aa",
            "pkr": "bb",
            "e_hash1": "cc",
            "e_hash2": "dd",
            "authkey": "ee",
            "e_nonce": "ff",
            "r_nonce": "11",
            "e_bssid": "00:11:22:33:44:55",
            "verbosity": 3,
            "output_file": "pixie.log",
            "jobs": 4,
            "mode": "1,3",
            "start": "01/2015",
            "end": "12/2016",
            "force": True,
            "m7_enc": "abcd",
            "m5_enc": "ef01",
            "version": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "--pke aa --pkr bb --e-hash1 cc --e-hash2 dd --authkey ee "
        "--e-nonce ff --r-nonce 11 --e-bssid 00:11:22:33:44:55 "
        "--verbosity 3 --output pixie.log --jobs 4 --mode 1,3 "
        "--start 01/2015 --end 12/2016 --force --m7-enc abcd "
        "--m5-enc ef01 --version"
    )
    assert preview["executable"] is False


def test_bluepot_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("bluepot")

    assert tool.run_command == "cd bluepot && sudo java -jar bluepot.jar"
    assert specs["bluepot"].exposed is False
    assert "Wireless Attack" in specs["bluepot"].blocked_reason
    assert records["bluepot"].source_status == "source-reviewed"
    assert records["bluepot"].unverified_parameters == ()
    assert records["bluepot"].gap == ""
    assert any("andrewmichaelsmith/bluepot" in item for item in records["bluepot"].evidence)

    params = adapter_parameter_names(tool, specs["bluepot"])
    for removed in (
        "interface",
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "monitor_mode",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["bluepot"],
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is False


def test_fluxion_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("fluxion")

    assert tool.run_command == "cd fluxion && sudo bash fluxion.sh -i"
    assert specs["fluxion"].exposed is False
    assert "Wireless Attack" in specs["fluxion"].blocked_reason
    assert records["fluxion"].source_status == "source-reviewed"
    assert records["fluxion"].unverified_parameters == ()
    assert records["fluxion"].gap == ""
    assert any("FluxionNetwork/fluxion" in item for item in records["fluxion"].evidence)

    params = adapter_parameter_names(tool, specs["fluxion"])
    for expected in (
        "bssid",
        "essid",
        "channel",
        "language",
        "attack",
        "interface",
        "jammer_interface",
        "ap_interface",
        "tracker_interface",
        "ap_service",
        "debug",
        "debug_log",
        "killer",
        "reloader",
        "airmon_ng",
        "multiplexer",
        "install",
        "ratio",
        "auto",
        "scan_time",
        "scan_only",
        "list_interfaces",
        "skip_dependencies",
        "timeout",
        "reg_domain",
        "band",
        "version",
        "help",
    ):
        assert expected in params
    for removed in ("wordlist", "handshake_file", "monitor_mode", "pmkid", "deauth_count"):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["fluxion"],
        {
            "target": "ignored.example",
            "bssid": "00:11:22:33:44:55",
            "essid": "LabNet",
            "channel": 6,
            "language": "en",
            "attack": "Handshake Snooper",
            "interface": "wlan0",
            "jammer_interface": "wlan1",
            "ap_interface": "wlan2",
            "tracker_interface": "wlan3",
            "ap_service": "hostapd",
            "debug": True,
            "debug_log": "fluxion.log",
            "killer": True,
            "reloader": True,
            "airmon_ng": True,
            "multiplexer": True,
            "install": True,
            "ratio": "16:9",
            "auto": True,
            "scan_time": 30,
            "scan_only": True,
            "list_interfaces": True,
            "skip_dependencies": True,
            "timeout": 120,
            "reg_domain": "US",
            "band": "2.4",
            "version": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "--version --debug --debug-log fluxion.log --killer --reloader "
        "--airmon-ng --multiplexer --bssid 00:11:22:33:44:55 --essid LabNet "
        "--channel 6 --language en --attack 'Handshake Snooper' --install "
        "--ratio 16:9 --auto --scan-time 30 --scan-only --list-interfaces "
        "--interface wlan0 --skip-dependencies --jammer-interface wlan1 "
        "--ap-interface wlan2 --tracker-interface wlan3 --ap-service hostapd "
        "--timeout 120 --reg-domain US --band 2.4"
    )
    assert preview["executable"] is False


def test_wifiphisher_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("wifiphisher")

    assert tool.run_command == "cd wifiphisher && sudo wifiphisher"
    assert specs["wifiphisher"].exposed is False
    assert "Wireless Attack" in specs["wifiphisher"].blocked_reason
    assert records["wifiphisher"].source_status == "source-reviewed"
    assert records["wifiphisher"].unverified_parameters == ()
    assert records["wifiphisher"].gap == ""
    assert any("wifiphisher/wifiphisher" in item for item in records["wifiphisher"].evidence)

    params = adapter_parameter_names(tool, specs["wifiphisher"])
    for expected in (
        "interface",
        "internet_interface",
        "protect_interfaces",
        "mitm_interface",
        "essid",
        "deauth_essid",
        "deauth_channels",
        "ap_interface",
        "extensions_interface",
        "no_mac_randomization",
        "keep_networkmanager",
        "no_extensions",
        "no_deauth",
        "phishing_scenario",
        "preshared_key",
        "credential_log",
        "payload_path",
        "handshake_capture",
        "quitonsuccess",
        "lure10_capture",
        "lure10_exploit",
        "logging",
        "disable_karma",
        "log_path",
        "channel_monitor",
        "wps_pbc",
        "wpspbc_assoc_interface",
        "known_beacons",
        "force_hostapd",
        "phishing_pages_directory",
        "dnsmasq_conf",
        "phishing_essid",
        "mac_ap_interface",
        "mac_extensions_interface",
        "help",
    ):
        assert expected in params
    for removed in (
        "bssid",
        "channel",
        "wordlist",
        "pmkid",
        "deauth_count",
        "capture_file",
        "target_essid",
        "ble",
    ):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["wifiphisher"],
        {
            "target": "ignored.example",
            "interface": "wlan0",
            "internet_interface": "eth0",
            "protect_interfaces": "wlan1 wlan2",
            "mitm_interface": "wlan3",
            "essid": "Free WiFi",
            "deauth_essid": "TargetNet",
            "deauth_channels": "1 6 11",
            "ap_interface": "wlan4",
            "extensions_interface": "wlan5",
            "no_mac_randomization": True,
            "keep_networkmanager": True,
            "no_extensions": True,
            "no_deauth": True,
            "phishing_scenario": "firmware_upgrade",
            "preshared_key": "secretpass",
            "credential_log": "creds.log",
            "payload_path": "payload.bin",
            "handshake_capture": "capture.pcap",
            "quitonsuccess": True,
            "lure10_capture": True,
            "lure10_exploit": "lure.db",
            "logging": True,
            "disable_karma": True,
            "log_path": "wf.log",
            "channel_monitor": True,
            "wps_pbc": True,
            "wpspbc_assoc_interface": "wlan6",
            "known_beacons": True,
            "force_hostapd": True,
            "phishing_pages_directory": "pages",
            "dnsmasq_conf": "dnsmasq.conf",
            "phishing_essid": "Portal",
            "mac_ap_interface": "02:00:00:00:00:01",
            "mac_extensions_interface": "02:00:00:00:00:02",
            "help": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-i wlan0 -iI eth0 -pI 'wlan1 wlan2' -mI wlan3 -e 'Free WiFi' "
        "-dE TargetNet -dC '1 6 11' -aI wlan4 -eI wlan5 -iNM -kN -nE "
        "-nD -p firmware_upgrade -pK secretpass -cP creds.log "
        "--payload-path payload.bin -hC capture.pcap -qS -lC -lE lure.db "
        "--logging -dK -lP wf.log -cM -wP -wAI wlan6 -kB -fH -pPD pages "
        "--dnsmasq-conf dnsmasq.conf -pE Portal -iAM 02:00:00:00:00:01 "
        "-iEM 02:00:00:00:00:02 --help"
    )
    assert preview["executable"] is False


def test_wifite_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("wifite")

    assert tool.run_command == "sudo wifite"
    assert specs["wifite"].exposed is False
    assert "Wireless Attack" in specs["wifite"].blocked_reason
    assert records["wifite"].source_status == "source-reviewed"
    assert records["wifite"].unverified_parameters == ()
    assert records["wifite"].gap == ""
    assert any("derv82/wifite2" in item for item in records["wifite"].evidence)

    params = adapter_parameter_names(tool, specs["wifite"])
    for expected in (
        "interface",
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "pmkid",
        "deauth_count",
    ):
        assert expected in params
    for removed in ("monitor_mode", "capture_file", "target_essid", "ble"):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["wifite"],
        {
            "target": "ignored.example",
            "interface": "wlan0",
            "bssid": "00:11:22:33:44:55",
            "essid": "LabNet",
            "channel": 6,
            "wordlist": "wordlist.txt",
            "handshake_file": "capture.cap",
            "pmkid": True,
            "deauth_count": 5,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "-i wlan0 -b 00:11:22:33:44:55 -e LabNet -c 6 --dict wordlist.txt "
        "--check capture.cap --pmkid --num-deauths 5"
    )
    assert preview["executable"] is False


def test_eviltwin_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("eviltwin")

    assert tool.run_command == "cd fakeap && sudo bash fakeap.sh"
    assert specs["eviltwin"].exposed is False
    assert "Wireless Attack" in specs["eviltwin"].blocked_reason
    assert records["eviltwin"].source_status == "source-reviewed"
    assert records["eviltwin"].unverified_parameters == ()
    assert records["eviltwin"].gap == ""
    assert any("Z4nzu/fakeap" in item for item in records["eviltwin"].evidence)

    params = adapter_parameter_names(tool, specs["eviltwin"])
    for removed in (
        "redact",
        "since_commit",
        "interface",
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "monitor_mode",
    ):
        assert removed not in params
    assert "action" in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["eviltwin"],
        {
            "target": "ignored.example",
            "action": "stop",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "--stop"
    assert preview["executable"] is False


def test_fastssh_source_reviewed_interactive_policy_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("fastssh")

    assert tool.run_command == "cd fastssh && sudo bash fastssh.sh --scan"
    assert specs["fastssh"].exposed is False
    assert "Wireless Attack" in specs["fastssh"].blocked_reason
    assert records["fastssh"].source_status == "source-reviewed"
    assert records["fastssh"].unverified_parameters == ()
    assert records["fastssh"].gap == ""
    assert any("Z4nzu/fastssh" in item for item in records["fastssh"].evidence)

    params = adapter_parameter_names(tool, specs["fastssh"])
    for removed in (
        "ports",
        "scan_type",
        "service_version",
        "os_detection",
        "default_scripts",
        "timing",
        "top_ports",
        "rate",
        "interface",
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "monitor_mode",
    ):
        assert removed not in params
    assert "mode" in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["fastssh"],
        {
            "target": "ignored.example",
            "mode": "bruteforcer",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "--bruteforcer"
    assert preview["executable"] is False


def test_howmanypeople_source_reviewed_policy_only_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("howmanypeople")

    assert tool.run_command == "howmanypeoplearearound"
    assert specs["howmanypeople"].exposed is False
    assert "Wireless Attack" in specs["howmanypeople"].blocked_reason
    assert records["howmanypeople"].source_status == "source-reviewed"
    assert records["howmanypeople"].unverified_parameters == ()
    assert records["howmanypeople"].gap == ""
    assert any("howmanypeoplearearound" in item for item in records["howmanypeople"].evidence)

    params = adapter_parameter_names(tool, specs["howmanypeople"])
    for expected in (
        "adapter",
        "analyze",
        "scantime",
        "output_file",
        "verbose",
        "number",
        "json_output",
        "nearby",
        "nocorrection",
        "loop",
        "sort",
    ):
        assert expected in params
    for removed in (
        "interface",
        "bssid",
        "essid",
        "channel",
        "wordlist",
        "handshake_file",
        "monitor_mode",
        "timeout",
        "user_agent",
    ):
        assert removed not in params

    preview = adapter_request_preview(
        tool,
        specs["howmanypeople"],
        {
            "target": "ignored.example",
            "adapter": "wlan0",
            "analyze": "scan.json",
            "scantime": 20,
            "output_file": "people.json",
            "verbose": True,
            "number": True,
            "json_output": True,
            "nearby": True,
            "nocorrection": True,
            "loop": True,
            "sort": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == (
        "--adapter wlan0 --analyze scan.json --scantime 20 --out people.json "
        "--verbose --number --jsonprint --nearby --nocorrection --loop --sort"
    )
    assert preview["executable"] is False


def test_rvuln_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("rvuln")

    assert tool.run_command == "cd RVuln && ./target/release/RVuln"
    assert specs["rvuln"].requires_confirmation is True
    assert records["rvuln"].source_status == "source-reviewed"
    assert records["rvuln"].unverified_parameters == ()
    assert records["rvuln"].gap == ""
    assert any("yangr0/RVuln" in item for item in records["rvuln"].evidence)

    params = adapter_parameter_names(tool, specs["rvuln"])
    for removed in (
        "extensions",
        "follow_redirects",
        "json_output",
        "match_codes",
        "output_file",
        "proxy",
        "recursive",
        "scan_depth",
        "threads",
        "timeout",
        "user_agent",
        "wordlist",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["rvuln"],
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""
    assert preview["executable"] is True
    assert preview["confirm_authorized"] is True

def test_wireshark_source_reviewed_interactive_only(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("wireshark")

    assert tool.run_command == "sudo wireshark"
    assert records["wireshark"].source_status == "source-reviewed"
    assert records["wireshark"].unverified_parameters == ()
    assert records["wireshark"].gap == ""
    assert any("wireshark.org" in item for item in records["wireshark"].evidence)

    params = adapter_parameter_names(tool, specs["wireshark"])
    for removed in (
        "default_scripts",
        "extract",
        "os_detection",
        "output_dir",
        "plugin",
        "ports",
        "profile",
        "rate",
        "scan_type",
        "service_version",
        "timing",
        "top_ports",
    ):
        assert removed not in params
    assert "interactive" in params

    preview = adapter_request_preview(
        tool,
        specs["wireshark"],
        {
            "target": "ignored.pcapng",
            "interactive": True,
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == ""


def test_bulk_extractor_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("bulk-extractor")

    assert tool.run_command == "bulk_extractor {target}"
    assert records["bulk-extractor"].source_status == "source-reviewed"
    assert records["bulk-extractor"].unverified_parameters == ()
    assert records["bulk-extractor"].gap == ""
    assert any("bulk_extractor.cpp" in item for item in records["bulk-extractor"].evidence)

    params = adapter_parameter_names(tool, specs["bulk-extractor"])
    for removed in ("extract", "plugin", "profile"):
        assert removed not in params
    for expected in (
        "output_dir",
        "banner_file",
        "alert_list",
        "stop_list",
        "sampling",
        "find_patterns",
        "find_files",
        "context_window",
        "page_size",
        "margin_size",
        "threads",
        "max_depth",
        "scanner_dirs",
        "recursive",
        "settings",
        "scan_range",
        "page_start",
        "exclusive_scanner",
        "enabled_scanners",
        "disabled_scanners",
        "quiet",
        "no_notify",
        "legacy_notification",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["bulk-extractor"],
        {
            "target": "evidence.E01",
            "output_dir": "case-out",
            "banner_file": "banner.txt",
            "alert_list": "alerts.txt",
            "stop_list": "stops.txt",
            "sampling": "0.1:2",
            "find_patterns": "secret api-key",
            "find_files": "regex.txt",
            "context_window": 64,
            "page_size": "16M",
            "margin_size": "4096",
            "threads": 4,
            "max_depth": 3,
            "scanner_dirs": "plugins extra",
            "recursive": True,
            "settings": "hash_alg=sha1",
            "scan_range": "1024-4096",
            "page_start": 2,
            "exclusive_scanner": "email",
            "enabled_scanners": "email url",
            "disabled_scanners": "gps",
            "quiet": True,
            "no_notify": True,
            "legacy_notification": True,
        },
    )
    assert preview["target"] == "evidence.E01"
    assert preview["options"] == (
        "-o case-out -b banner.txt -r alerts.txt -w stops.txt -s 0.1:2 "
        "-f secret -f api-key -F regex.txt -C 64 -G 16M -g 4096 -j 4 "
        "-M 3 -P plugins -P extra -R -S hash_alg=sha1 -Y 1024-4096 "
        "-z 2 -E email -e email -e url -x gps -q -0 -1"
    )


def test_autopsy_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("autopsy")

    assert tool.run_command == "sudo autopsy"
    assert records["autopsy"].source_status == "source-reviewed"
    assert records["autopsy"].unverified_parameters == ()
    assert records["autopsy"].gap == ""
    assert any("autopsy" in item.lower() for item in records["autopsy"].evidence)

    params = adapter_parameter_names(tool, specs["autopsy"])
    for removed in ("extract", "output_dir", "plugin", "profile"):
        assert removed not in params
    for expected in (
        "use_cookies",
        "no_cookies",
        "evidence_locker",
        "live_device",
        "live_filesystem",
        "live_mount",
        "port",
        "remote_addr",
    ):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["autopsy"],
        {
            "use_cookies": True,
            "evidence_locker": "/cases",
            "live_device": "/dev/sda1",
            "live_filesystem": "ext4",
            "live_mount": "/mnt/root",
            "port": 8888,
            "remote_addr": "10.1.34.19",
        },
    )
    assert preview["target"] == "10.1.34.19"
    assert preview["options"] == "-c -d /cases -i /dev/sda1 ext4 /mnt/root -p 8888"


def test_guymager_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("guymager")

    assert tool.run_command == "sudo guymager"
    assert records["guymager"].source_status == "source-reviewed"
    assert records["guymager"].unverified_parameters == ()
    assert records["guymager"].gap == ""
    assert any("guymager" in item.lower() for item in records["guymager"].evidence)

    params = adapter_parameter_names(tool, specs["guymager"])
    for removed in ("extract", "output_dir", "plugin", "profile"):
        assert removed not in params
    for expected in ("log_file", "config_file"):
        assert expected in params

    preview = adapter_request_preview(
        tool,
        specs["guymager"],
        {
            "target": "ignored.raw",
            "log_file": "guymager.log",
            "config_file": "guymager.cfg",
        },
    )
    assert preview["target"] == ""
    assert preview["options"] == "log=guymager.log cfg=guymager.cfg"


def test_toolsley_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }
    tool = registry.get_tool("toolsley")

    assert "hashlib.sha256(sys.argv[1].encode())" in tool.run_command
    assert records["toolsley"].source_status == "source-reviewed"
    assert records["toolsley"].unverified_parameters == ()
    assert records["toolsley"].gap == ""
    assert any("hashlib.sha256" in item for item in records["toolsley"].evidence)

    params = adapter_parameter_names(tool, specs["toolsley"])
    for removed in (
        "attack_mode",
        "extensions",
        "extract",
        "follow_redirects",
        "hash_file",
        "hash_type",
        "match_codes",
        "max_length",
        "min_length",
        "output_dir",
        "output_file",
        "plugin",
        "profile",
        "proxy",
        "recursive",
        "threads",
        "wordlist",
    ):
        assert removed not in params
    assert "text" in params

    preview = adapter_request_preview(
        tool,
        specs["toolsley"],
        {
            "text": "hello",
        },
    )
    assert preview["target"] == "hello"
    assert preview["options"] == ""


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
async def test_theharvester_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_theharvester",
        {
            "target": "example.test",
            "sources": "bing,crtsh",
            "limit": 100,
            "start": 10,
            "proxies": True,
            "shodan": True,
            "screenshot": "shots",
            "dns_server": "1.1.1.1",
            "takeover": True,
            "dns_resolve": "resolvers.txt",
            "dns_lookup": True,
            "dns_brute": True,
            "filename": "harvester",
            "wordlist": "apis.txt",
            "api_scan": True,
            "quiet": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "theHarvester"
    assert request.options == (
        "-b bing,crtsh -l 100 -S 10 -p -s --screenshot shots -e 1.1.1.1 "
        "-t -r resolvers.txt -n -c -f harvester -w apis.txt -a -q"
    )


@pytest.mark.asyncio
async def test_sherlock_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_sherlock",
        {
            "target": "user123",
            "verbose": True,
            "folder_output": "sherlock-out",
            "output_file": "user123.txt",
            "csv_output": True,
            "xlsx_output": True,
            "sites": "GitHub,Reddit",
            "site_list": "Twitter",
            "proxy": "socks5://127.0.0.1:9050",
            "dump_response": True,
            "json_file": "user123.json",
            "timeout": 15,
            "print_all": True,
            "print_found": True,
            "no_color": True,
            "browse": True,
            "local": True,
            "nsfw": True,
            "txt_output": True,
            "ignore_exclusions": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "sherlock"
    assert request.target == "user123"
    assert request.options == (
        "--verbose --folderoutput sherlock-out --output user123.txt --csv "
        "--xlsx --site GitHub --site Reddit --site Twitter "
        "--proxy socks5://127.0.0.1:9050 --dump-response --json user123.json "
        "--timeout 15 --print-all --print-found --no-color --browse --local "
        "--nsfw --txt --ignore-exclusions"
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
async def test_feroxbuster_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_feroxbuster",
        {
            "target": "https://example.test",
            "wordlist": "words.txt",
            "extensions": "php,txt",
            "methods": "GET,POST",
            "headers": "X-Test: 1",
            "cookies": "session=value",
            "query": "token=value",
            "add_slash": True,
            "filter_size": "1234",
            "filter_regex": "^ignore",
            "filter_words": "20",
            "filter_lines": "5",
            "filter_codes": "404,403",
            "status_codes": "200,301,302",
            "unique": True,
            "timeout": 10,
            "follow_redirects": True,
            "insecure": True,
            "threads": 20,
            "no_recursion": True,
            "depth": 3,
            "scan_limit": 4,
            "parallelism": 2,
            "rate_limit": 50,
            "time_limit": "10m",
            "collect_extensions": True,
            "collect_backups": "bak,old",
            "collect_words": True,
            "verbosity": 2,
            "json_output": True,
            "output_file": "ferox.json",
            "no_state": True,
            "limit_bars": 5,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "feroxbuster"
    assert request.options == (
        "-w words.txt -x php,txt -m GET,POST -H 'X-Test: 1' "
        "-b session=value -Q token=value -f -S 1234 -X '^ignore' "
        "-W 20 -N 5 -C 404,403 -s 200,301,302 --unique -T 10 -r -k "
        "-t 20 -n -d 3 -L 4 --parallel 2 --rate-limit 50 --time-limit 10m "
        "-E -B bak,old -g -vv --json -o ferox.json --no-state --limit-bars 5"
    )


@pytest.mark.asyncio
async def test_dirsearch_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_dirsearch",
        {
            "target": "https://example.test",
            "wordlist": "words.txt",
            "extensions": "php,txt",
            "include_status": "200,301,302",
            "exclude_status": "404,403",
            "exclude_sizes": "0B",
            "exclude_text": "not found",
            "prefixes": "admin",
            "suffixes": "backup",
            "threads": 20,
            "recursive": True,
            "recursion_depth": 3,
            "subdirs": "api,admin",
            "method": "POST",
            "data": "a=b",
            "headers": "X-Test: 1",
            "follow_redirects": True,
            "random_agent": True,
            "user_agent": "hacking-mcp",
            "cookies": "session=value",
            "proxy": "http://127.0.0.1:8080",
            "timeout": 10,
            "delay": "1s",
            "max_rate": 50,
            "retries": 2,
            "format": "json",
            "output_file": "dirsearch.out",
            "json_report": "dirsearch.json",
            "quiet": True,
            "full_url": True,
            "no_color": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "dirsearch"
    assert request.options == (
        "-w words.txt -e php,txt -i 200,301,302 -x 404,403 -X 0B "
        "--exclude-text 'not found' --prefixes admin --suffixes backup "
        "-t 20 -r -R 3 --subdirs api,admin -m POST -d a=b -H 'X-Test: 1' "
        "-F --random-agent --user-agent hacking-mcp --cookie session=value "
        "--proxy http://127.0.0.1:8080 --timeout 10 --delay 1s --max-rate 50 "
        "--retries 2 --format json -o dirsearch.out --json-report dirsearch.json "
        "--quiet --full-url --no-color"
    )


@pytest.mark.asyncio
async def test_nikto_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_nikto",
        {
            "target": "https://example.test",
            "cgi_dirs": "all",
            "config_file": "nikto.conf",
            "display": "V",
            "dbcheck": True,
            "evasion": "1",
            "output_format": "json",
            "auth": "user:pass",
            "max_time": "1h",
            "mutate": "2",
            "mutate_options": "admin",
            "no_interactive": True,
            "no_lookup": True,
            "output_file": "nikto.json",
            "pause": 1,
            "plugins": "tests",
            "port": "443",
            "root": "/app",
            "ssl": True,
            "tuning": "x",
            "timeout": 10,
            "user_agent": "hacking-mcp",
            "use_proxy": True,
            "vhost": "example.test",
            "notfound_code": "404",
            "notfound_string": "not found",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "nikto"
    assert request.options == (
        "-Cgidirs all -config nikto.conf -Display V -dbcheck -evasion 1 "
        "-Format json -id user:pass -maxtime 1h -mutate 2 "
        "-mutate-options admin -nointeractive -nolookup -output nikto.json "
        "-Pause 1 -Plugins tests -port 443 -root /app -ssl -Tuning x "
        "-timeout 10 -useragent hacking-mcp -useproxy -vhost example.test "
        "-404code 404 -404string 'not found'"
    )


@pytest.mark.asyncio
async def test_sqlscan_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_sqlscan",
        {
            "target": "https://example.test/?id=1",
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "sqlscan"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True
    assert request.options == "--scan"


@pytest.mark.asyncio
async def test_xspear_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xspear",
        {
            "target": "https://example.test/?q=1",
            "confirm_authorized": True,
            "data": "q=1",
            "test_all_params": True,
            "no_xss": True,
            "headers": "X-Test: 1",
            "cookie": "a=b",
            "custom_payload": "payloads.json",
            "raw_file": "request.txt",
            "parameter": "q",
            "blind_callback": "https://callback.test",
            "threads": 8,
            "output_format": "json",
            "config_file": "xspear.json",
            "verbose": 2,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xspear"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True
    assert request.options == (
        "-d q=1 -a --no-xss --headers 'X-Test: 1' --cookie a=b "
        "--custom-payload payloads.json --raw request.txt -p q "
        "-b https://callback.test -t 8 -o json -c xspear.json -vv"
    )


@pytest.mark.asyncio
async def test_xanxss_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xanxss",
        {
            "target": "https://example.test/?q=1",
            "confirm_authorized": True,
            "verification_amount": 3,
            "amount_to_find": 2,
            "test_time": 5,
            "payloads": "<script>alert(1)</script>",
            "payload_file": "payloads.txt",
            "verbose": True,
            "proxy": "http://127.0.0.1:8080",
            "headers": "X-Test=1",
            "throttle": 1,
            "polyglot": True,
            "prefix": "pre",
            "suffix": "suf",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xanxss"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True
    assert request.options == (
        "-a 3 -f 2 -t 5 -p '<script>alert(1)</script>' -F payloads.txt "
        "-v --proxy http://127.0.0.1:8080 --headers X-Test=1 --throttle 1 "
        "--polyglot --prefix pre --suffix suf"
    )


@pytest.mark.asyncio
async def test_xsscon_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xsscon",
        {
            "target": "https://example.test",
            "confirm_authorized": True,
            "depth": 2,
            "payload_level": 5,
            "payload": "<script>alert(1)</script>",
            "method": 2,
            "user_agent": "hacking-mcp",
            "single_url": "https://example.test/?q=1",
            "proxy": '{"http":"http://127.0.0.1:8080"}',
            "about": True,
            "cookie": '{"sid":"abc"}',
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xsscon"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True
    assert request.options == (
        "--depth 2 --payload-level 5 --payload '<script>alert(1)</script>' "
        "--method 2 --user-agent hacking-mcp "
        "--single 'https://example.test/?q=1' "
        "--proxy '{\"http\":\"http://127.0.0.1:8080\"}' --about "
        "--cookie '{\"sid\":\"abc\"}'"
    )


@pytest.mark.asyncio
async def test_dsss_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_dsss",
        {
            "target": "https://example.test/?id=1",
            "confirm_authorized": True,
            "data": "q=1",
            "cookie": "a=b",
            "user_agent": "hacking-mcp",
            "referer": "https://ref.example",
            "proxy": "http://127.0.0.1:8080",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "dsss"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True
    assert request.options == (
        "--data q=1 --cookie a=b --user-agent hacking-mcp "
        "--referer https://ref.example --proxy http://127.0.0.1:8080"
    )


@pytest.mark.asyncio
async def test_owasp_zap_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_owasp_zap",
        {
            "target": "https://example.test",
            "quick_out": "zap.html",
            "quick_progress": True,
            "zapit_url": "https://zapit.example",
            "config": "api.disablekey=true",
            "config_file": "zap.properties",
            "home_dir": "zap-home",
            "install_dir": "/opt/zap",
            "new_session": "zap.session",
            "low_mem": True,
            "experimental_db": True,
            "no_stdout": True,
            "log_level": "DEBUG",
            "silent": True,
            "addon_install": "pscanrulesAlpha",
            "addon_install_all": True,
            "addon_uninstall": "hud",
            "addon_update": True,
            "addon_list": True,
            "script": "script.js",
            "support_info": True,
            "sbom_zip": "sbom.zip",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "owasp-zap"
    assert request.require_confirmation is False
    assert request.options == (
        "-quickout zap.html -quickprogress -zapit https://zapit.example "
        "-config api.disablekey=true -configfile zap.properties -dir zap-home "
        "-installdir /opt/zap -newsession zap.session -lowmem "
        "-experimentaldb -nostdout -loglevel DEBUG -silent "
        "-addoninstall pscanrulesAlpha -addoninstallall -addonuninstall hud "
        "-addonupdate -addonlist -script script.js -suppinfo -sbomzip sbom.zip"
    )


@pytest.mark.asyncio
async def test_xsstrike_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xsstrike",
        {
            "target": "https://example.test/?q=1",
            "confirm_authorized": True,
            "data": "q=1",
            "encode": "base64",
            "fuzzer": True,
            "update": True,
            "timeout": 10,
            "use_proxy": True,
            "crawl": True,
            "json_data": True,
            "path_injection": True,
            "seeds_file": "seeds.txt",
            "payload_file": "payloads.txt",
            "level": 3,
            "headers": "X-Test: 1",
            "threads": 8,
            "delay": 2,
            "skip": True,
            "skip_dom": True,
            "blind": True,
            "console_log_level": "DEBUG",
            "file_log_level": "INFO",
            "log_file": "xsstrike.log",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xsstrike"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True
    assert request.options == (
        "--data q=1 -e base64 --fuzzer --update --timeout 10 --proxy "
        "--crawl --json --path --seeds seeds.txt -f payloads.txt -l 3 "
        "--headers 'X-Test: 1' -t 8 -d 2 --skip --skip-dom --blind "
        "--console-log-level DEBUG --file-log-level INFO --log-file xsstrike.log"
    )


@pytest.mark.asyncio
async def test_dalfox_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_dalfox",
        {
            "target": "https://example.test/?q=1",
            "confirm_authorized": True,
            "blind_callback": "https://callback.test",
            "config_file": "dalfox.toml",
            "cookies": "a=b",
            "custom_alert_type": "str",
            "custom_alert_value": "alert",
            "custom_payload": "payloads.txt",
            "data": "q=1",
            "deep_domxss": True,
            "delay": 100,
            "follow_redirects": True,
            "force_headless_verification": True,
            "headers": "X-Test: 1",
            "ignore_param": "token",
            "ignore_return": "302",
            "method": "POST",
            "parameter": "q",
            "proxy": "http://127.0.0.1:8080",
            "remote_payloads": "portswigger",
            "timeout": 10,
            "user_agent": "hacking-mcp",
            "waf_evasion": True,
            "max_cpu": 80,
            "workers": 20,
            "mining_dict": True,
            "mining_dict_word": "extra",
            "mining_dom": True,
            "remote_wordlists": "burp",
            "skip_mining_all": True,
            "skip_mining_dict": True,
            "skip_mining_dom": True,
            "only_custom_payload": True,
            "only_discovery": True,
            "skip_bav": True,
            "skip_discovery": True,
            "skip_grepping": True,
            "skip_headless": True,
            "skip_xss_scanning": True,
            "use_bav": True,
            "debug": True,
            "format": "json",
            "found_action": "notify.sh",
            "found_action_shell": "bash",
            "grep_file": "gf.json",
            "har_file_path": "dalfox.har",
            "no_color": True,
            "no_spinner": True,
            "only_poc": "g",
            "output_file": "dalfox.json",
            "output_all": True,
            "output_request": True,
            "output_response": True,
            "poc_type": "curl",
            "report": True,
            "report_format": "json",
            "silence": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "dalfox"
    assert request.confirm_authorized is True
    assert request.options == (
        "-b https://callback.test --config dalfox.toml -C a=b "
        "--custom-alert-type str --custom-alert-value alert "
        "--custom-payload payloads.txt -d q=1 --deep-domxss --delay 100 "
        "--follow-redirects --force-headless-verification -H 'X-Test: 1' "
        "--ignore-param token --ignore-return 302 -X POST -p q "
        "--proxy http://127.0.0.1:8080 --remote-payloads portswigger "
        "--timeout 10 --user-agent hacking-mcp --waf-evasion --max-cpu 80 "
        "-w 20 --mining-dict --mining-dict-word extra --mining-dom "
        "--remote-wordlists burp --skip-mining-all --skip-mining-dict "
        "--skip-mining-dom --only-custom-payload --only-discovery --skip-bav "
        "--skip-discovery --skip-grepping --skip-headless --skip-xss-scanning "
        "--use-bav --debug --format json --found-action notify.sh "
        "--found-action-shell bash --grep gf.json --har-file-path dalfox.har "
        "--no-color --no-spinner --only-poc g -o dalfox.json --output-all "
        "--output-request --output-response --poc-type curl --report "
        "--report-format json --silence"
    )


@pytest.mark.asyncio
async def test_testssl_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_testssl",
        {
            "target": "example.test",
            "input_file": "targets.txt",
            "mode": "parallel",
            "warnings": "batch",
            "connect_timeout": 5,
            "openssl_timeout": 6,
            "basic_auth": "user:pass",
            "req_header": "X-Test: 1",
            "mtls_file": "client.pem",
            "starttls": "smtp",
            "xmpp_host": "jabber.example",
            "mx": "example.test",
            "ip": "one",
            "proxy": "proxy.example:8080",
            "ipv6": True,
            "ssl_native": True,
            "openssl_path": "/usr/bin/openssl",
            "bugs": True,
            "assume_http": True,
            "no_dns": "min",
            "sneaky": True,
            "user_agent": "hacking-mcp",
            "ids_friendly": True,
            "phone_out": True,
            "add_ca": "ca.pem",
            "each_cipher": True,
            "cipher_per_proto": True,
            "categories": True,
            "forward_secrecy": True,
            "protocols": True,
            "server_preference": True,
            "server_defaults": True,
            "single_cipher": "AES",
            "check_headers": True,
            "client_simulation": True,
            "grease": True,
            "vulnerabilities": True,
            "quiet": True,
            "wide": True,
            "mapping": "iana",
            "show_each": True,
            "color": 1,
            "colorblind": True,
            "debug": 2,
            "disable_rating": True,
            "log": True,
            "logfile": "testssl.log",
            "json_output": True,
            "jsonfile": "out.json",
            "json_pretty": True,
            "jsonfile_pretty": "out.pretty.json",
            "csv_output": True,
            "csvfile": "out.csv",
            "html_output": True,
            "htmlfile": "out.html",
            "out_file": "all",
            "outfile": "flat",
            "severity": "HIGH",
            "append": True,
            "overwrite": True,
            "outprefix": "scan",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "testssl"
    assert request.options_before_target is True
    assert request.options == (
        "--file targets.txt --mode parallel --warnings batch "
        "--connect-timeout 5 --openssl-timeout 6 --basicauth user:pass "
        "--reqheader 'X-Test: 1' --mtls client.pem -t smtp "
        "--xmpphost jabber.example --mx example.test --ip one "
        "--proxy proxy.example:8080 -6 --ssl-native --openssl /usr/bin/openssl "
        "--bugs --assuming-http --nodns min --sneaky --user-agent hacking-mcp "
        "--ids-friendly --phone-out --add-ca ca.pem -e -E -s -f -p -P -S "
        "-x AES -h -c -g -U -q --wide --mapping iana --show-each "
        "--color 1 --colorblind --debug 2 --disable-rating --log "
        "--logfile testssl.log --json --jsonfile out.json --json-pretty "
        "--jsonfile-pretty out.pretty.json --csv --csvfile out.csv --html "
        "--htmlfile out.html --outFile all --outfile flat --severity HIGH "
        "--append --overwrite --outprefix scan"
    )


@pytest.mark.asyncio
async def test_wafw00f_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_wafw00f",
        {
            "target": "https://example.test",
            "verbosity": 2,
            "find_all": True,
            "no_redirect": True,
            "test_waf": "Cloudflare",
            "output_file": "-",
            "output_format": "json",
            "input_file": "targets.txt",
            "list_wafs": True,
            "proxy": "http://127.0.0.1:8080",
            "version": True,
            "headers_file": "headers.txt",
            "timeout": 12,
            "no_color": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "wafw00f"
    assert request.options == (
        "-v -v -a -r -t Cloudflare -o - -f json -i targets.txt -l "
        "-p http://127.0.0.1:8080 -V -H headers.txt -T 12 --no-colors"
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
async def test_whatweb_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_whatweb",
        {
            "target": "https://example.test",
            "input_file": "targets.txt",
            "url_prefix": "https://",
            "url_suffix": "/robots.txt",
            "url_pattern": "https://example.test/%insert%",
            "aggression": 3,
            "user_agent": "hacking-mcp",
            "header": "X-Test:1",
            "follow_redirect": "same-site",
            "max_redirects": 5,
            "basic_auth": "user:pass",
            "cookie": "sid=abc",
            "cookiejar": "cookies.txt",
            "no_cookies": True,
            "proxy": "127.0.0.1:8080",
            "proxy_user": "proxy:pass",
            "list_plugins": True,
            "info_plugin_search": "phpBB",
            "search_plugins": "wordpress",
            "plugins": "title,md5",
            "grep": "/hello/",
            "custom_plugin": "title",
            "dorks": "wordpress",
            "verbose": 2,
            "color": "never",
            "quiet": True,
            "no_errors": True,
            "log_brief": "brief.log",
            "log_verbose": "verbose.log",
            "log_errors": "errors.log",
            "log_xml": "out.xml",
            "log_json": "out.json",
            "log_sql": "out.sql",
            "log_sql_create": "schema.sql",
            "log_json_verbose": "out.verbose.json",
            "log_magictree": "out.magictree.xml",
            "log_object": "out.object",
            "log_mongo_database": "whatweb",
            "log_mongo_collection": "scans",
            "log_mongo_host": "127.0.0.1",
            "log_mongo_username": "mongo",
            "log_mongo_password": "secret",
            "log_elastic_index": "whatweb",
            "log_elastic_host": "127.0.0.1:9200",
            "max_threads": 50,
            "open_timeout": 10,
            "read_timeout": 20,
            "wait": 1,
            "output_sync": True,
            "output_buffer_size": 0,
            "short_help": True,
            "debug": True,
            "version": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "whatweb"
    assert request.options == (
        "--input-file targets.txt --url-prefix https:// "
        "--url-suffix /robots.txt --url-pattern https://example.test/%insert% "
        "--aggression 3 --user-agent hacking-mcp --header X-Test:1 "
        "--follow-redirect same-site --max-redirects 5 --user user:pass "
        "--cookie sid=abc --cookiejar cookies.txt --no-cookies "
        "--proxy 127.0.0.1:8080 --proxy-user proxy:pass --list-plugins "
        "--info-plugins phpBB --search-plugins wordpress --plugins title,md5 "
        "--grep /hello/ --custom-plugin title --dorks wordpress -v -v "
        "--color never --quiet --no-errors --log-brief brief.log "
        "--log-verbose verbose.log --log-errors errors.log --log-xml out.xml "
        "--log-json out.json --log-sql out.sql --log-sql-create schema.sql "
        "--log-json-verbose out.verbose.json --log-magictree out.magictree.xml "
        "--log-object out.object --log-mongo-database whatweb "
        "--log-mongo-collection scans --log-mongo-host 127.0.0.1 "
        "--log-mongo-username mongo --log-mongo-password secret "
        "--log-elastic-index whatweb --log-elastic-host 127.0.0.1:9200 "
        "--max-threads 50 --open-timeout 10 --read-timeout 20 --wait 1 "
        "--output-sync --output-buffer-size 0 --short-help --debug --version"
    )


@pytest.mark.asyncio
async def test_binwalk_source_reviewed_parameters_build_cli_options(registry, safety):
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
            "quiet": True,
            "verbose": True,
            "extract": True,
            "carve": True,
            "matryoshka": True,
            "search_all": True,
            "log_file": "binwalk.json",
            "threads": 4,
            "exclude": "gzip,zlib",
            "output_dir": "out",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "binwalk"
    assert request.options == (
        "--quiet --verbose --extract --carve --matryoshka --search-all "
        "--log binwalk.json --threads 4 --exclude gzip,zlib --directory out"
    )


@pytest.mark.asyncio
async def test_volatility3_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_volatility3",
        {
            "target": "memory.dmp",
            "config_file": "vol.json",
            "parallelism": "threads",
            "extend": "plugins.Test.option=value",
            "plugin_dirs": "plugins",
            "symbol_dirs": "symbols",
            "verbosity": 3,
            "log_file": "vol.log",
            "output_dir": "vol-out",
            "quiet": True,
            "renderer": "json",
            "write_config": True,
            "save_config": "saved.json",
            "clear_cache": True,
            "cache_path": "cache",
            "offline": True,
            "filters": "+Pid,4",
            "hide_columns": "Offset Hex",
            "single_location": "file:///memory.dmp",
            "stackers": "windows.WindowsIntel32e",
            "single_swap_locations": "swap.sys,pagefile.sys",
            "plugin": "windows.info",
            "options": "--dump",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "volatility3"
    assert request.target == "memory.dmp"
    assert request.options == (
        "--config vol.json --parallelism threads --extend "
        "plugins.Test.option=value --plugin-dirs plugins --symbol-dirs symbols "
        "-v -v -v --log vol.log --output-dir vol-out --quiet --renderer json "
        "--write-config --save-config saved.json --clear-cache "
        "--cache-path cache --offline --filters +Pid,4 "
        "--hide-columns 'Offset Hex' --single-location file:///memory.dmp "
        "--stackers windows.WindowsIntel32e --single-swap-locations "
        "swap.sys,pagefile.sys windows.info --dump"
    )


@pytest.mark.asyncio
async def test_pspy_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_pspy",
        {
            "procevents": False,
            "fsevents": True,
            "recursive_dirs": "/usr,/tmp",
            "dirs": "/opt/app",
            "interval": 1000,
            "color": False,
            "debug": True,
            "ppid": True,
            "truncate": 4096,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "pspy"
    assert request.target == ""
    assert request.options == (
        "--procevents=false --fsevents --recursive_dirs /usr "
        "--recursive_dirs /tmp --dirs /opt/app --interval 1000 "
        "--color=false --debug --ppid --truncate 4096"
    )


@pytest.mark.asyncio
async def test_haiti_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_haiti",
        {
            "target": "d41d8cd98f00b204e9800998ecf8427e",
            "no_color": True,
            "extended": True,
            "short": True,
            "hashcat_only": True,
            "john_only": True,
            "debug": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "haiti"
    assert request.target == "d41d8cd98f00b204e9800998ecf8427e"
    assert request.options == (
        "--no-color --extended --short --hashcat-only --john-only --debug"
    )


@pytest.mark.asyncio
async def test_hashcat_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_hashcat",
        {
            "target": "hashes.txt",
            "hash_type": "0",
            "attack_mode": "3",
            "wordlist": "rockyou.txt",
            "mask": "?a?a?a?a",
            "rules": "rules/best64.rule",
            "rule_left": "c",
            "session": "audit",
            "output_file": "cracked.txt",
            "outfile_format": "1,2",
            "separator": ":",
            "show": True,
            "username": True,
            "potfile_path": "audit.pot",
            "increment": True,
            "increment_min": 4,
            "increment_max": 8,
            "custom_charset1": "?l?d",
            "workload_profile": 3,
            "optimized_kernel": True,
            "backend_devices": "1",
            "opencl_device_types": "2",
            "status": True,
            "status_json": True,
            "status_timer": 10,
            "runtime": 60,
            "skip": 100,
            "limit": 1000,
            "identify": True,
            "quiet": True,
            "force": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "hashcat"
    assert request.target == "hashes.txt"
    assert request.options == (
        "-m 0 -a 3 -r rules/best64.rule -j c --session audit "
        "-o cracked.txt --outfile-format 1,2 -p : --show --username "
        "--potfile-path audit.pot -i --increment-min 4 --increment-max 8 "
        "-1 '?l?d' -w 3 -O -d 1 -D 2 --status --status-json "
        "--status-timer 10 --runtime 60 -s 100 -l 1000 --identify "
        "--quiet --force rockyou.txt '?a?a?a?a'"
    )


@pytest.mark.asyncio
async def test_john_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_john",
        {
            "target": "hashes.txt",
            "wordlist": "rockyou.txt",
            "rules": "Wordlist",
            "rules_stack": "best64",
            "rules_skip_nop": True,
            "incremental": "ASCII",
            "mask": "?l?l?d?d",
            "custom_charset1": "?l?d",
            "stdout_length": 8,
            "session": "audit",
            "show_mode": "left",
            "test_time": "0",
            "no_mask": True,
            "users": "alice",
            "format": "raw-md5",
            "pot": "john.pot",
            "min_length": 4,
            "max_length": 12,
            "max_run_time": "-60",
            "fork": 2,
            "node": "1-2/4",
            "devices": "1,2",
            "verbosity": 4,
            "no_log": True,
            "log_stderr": True,
            "keep_guessing": True,
            "force_tty": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "john"
    assert request.target == "hashes.txt"
    assert request.options == (
        "--wordlist=rockyou.txt --rules=Wordlist --rules-stack best64 "
        "--rules-skip-nop --incremental=ASCII --mask '?l?l?d?d' "
        "--1 '?l?d' --stdout=8 --session audit --show=left --test=0 "
        "--no-mask --users alice --format raw-md5 --pot john.pot "
        "--min-length 4 --max-length 12 --max-run-time -60 --fork 2 "
        "--node 1-2/4 --devices 1,2 --verbosity 4 --no-log --log-stderr "
        "--keep-guessing --force-tty"
    )


@pytest.mark.asyncio
async def test_jadx_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_jadx",
        {
            "target": "app.apk",
            "output_dir": "out",
            "output_dir_src": "src-out",
            "output_dir_res": "res-out",
            "no_resources": True,
            "threads_count": 4,
            "single_class": "com.example.Main",
            "single_class_output": "Main.java",
            "output_format": "json",
            "export_gradle": True,
            "export_gradle_type": "simple-java",
            "decompilation_mode": "simple",
            "show_bad_code": True,
            "no_imports": True,
            "no_debug_info": True,
            "add_debug_lines": True,
            "escape_unicode": True,
            "respect_bytecode_access_modifiers": True,
            "deobf": True,
            "deobf_min": 2,
            "deobf_max": 32,
            "deobf_whitelist": "com.keep.*",
            "rename_flags": "case,valid",
            "integer_format": "hexadecimal",
            "cfg": True,
            "raw_cfg": True,
            "use_dx": True,
            "comments_level": "debug",
            "log_level": "info",
            "verbose": True,
            "disable_plugins": "plugin.one,plugin.two",
            "config": "none",
            "plugin_options": "foo=bar;baz=qux",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "jadx"
    assert request.target == "app.apk"
    assert request.options_before_target is True
    assert request.options == (
        "-d out -ds src-out -dr res-out -r -j 4 "
        "--single-class com.example.Main --single-class-output Main.java "
        "--output-format json -e --export-gradle-type simple-java -m simple "
        "--show-bad-code --no-imports --no-debug-info --add-debug-lines "
        "--escape-unicode --respect-bytecode-access-modifiers --deobf "
        "--deobf-min 2 --deobf-max 32 --deobf-whitelist 'com.keep.*' "
        "--rename-flags case,valid --integer-format hexadecimal --cfg "
        "--raw-cfg --use-dx --comments-level debug --log-level info -v "
        "--disable-plugins plugin.one,plugin.two --config none "
        "-Pfoo=bar -Pbaz=qux"
    )


@pytest.mark.asyncio
async def test_apk2gold_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_apk2gold",
        {
            "apk_file": "sample.apk",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "apk2gold"
    assert request.target == "sample.apk"
    assert request.options == ""


@pytest.mark.asyncio
async def test_androguard_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_androguard",
        {
            "command": "decompile",
            "input_file": "sample.apk",
            "output_dir": "out",
            "graph_format": "png",
            "jar": True,
            "limit": "Lcom/example/.*",
            "decompiler": "dex2fernflower",
            "verbose": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "androguard"
    assert request.target == "sample.apk"
    assert request.options == (
        "--verbose decompile --output out --format png --jar "
        "--limit 'Lcom/example/.*' --decompiler dex2fernflower sample.apk"
    )

    await mcp.call_tool(
        "security_tool_androguard",
        {
            "command": "cg",
            "input_file": "classes.dex",
            "output_file": "callgraph.gml",
            "output_type": "gml",
            "classname": "Lcom/example/.*",
            "methodname": "onCreate",
            "descriptor": ".*",
            "accessflag": "public",
            "no_isolated": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "androguard"
    assert request.target == "classes.dex"
    assert request.options == (
        "cg --output callgraph.gml --output-type gml --classname 'Lcom/example/.*' "
        "--methodname onCreate --descriptor '.*' --accessflag public "
        "--no-isolated classes.dex"
    )


@pytest.mark.asyncio
async def test_radare2_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_radare2",
        {
            "target": "firmware.bin",
            "arch": "x86",
            "bits": "64",
            "base_addr": "0x400000",
            "analyze": True,
            "command": "afl",
            "debug": True,
            "eval_config": "scr.color=false",
            "script": "init.r2",
            "pre_script": "pre.r2",
            "json": True,
            "list_core_plugins": True,
            "no_scripts_plugins": True,
            "bin_structures_only": True,
            "project": "audit",
            "quit_after_commands": True,
            "write": True,
            "load_strings": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "radare2"
    assert request.target == "firmware.bin"
    assert request.options_before_target is True
    assert request.options == (
        "-a x86 -A -b 64 -B 0x400000 -c afl -d -e scr.color=false "
        "-i init.r2 -I pre.r2 -j -LL -NN -nn -p audit -qq -w -zz"
    )


@pytest.mark.asyncio
async def test_ghidra_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_ghidra",
        {
            "target": "/tmp/ghidra-projects",
            "project_name": "firmware",
            "folder_path": "imports",
            "import_path": "firmware.bin",
            "pre_script": "Setup.java",
            "pre_script_args": "--mode fast",
            "post_script": "Report.java",
            "post_script_args": "out.json",
            "script_path": "scripts",
            "properties_path": "props",
            "script_log": "script.log",
            "log_file": "ghidra.log",
            "overwrite": True,
            "recursive": True,
            "recursive_depth": 2,
            "read_only": True,
            "processor": "x86:LE:64:default",
            "cspec": "gcc",
            "analysis_timeout_per_file": 300,
            "connect_user": "analyst",
            "commit_comment": "import firmware",
            "max_cpu": 4,
            "library_search_paths": "libs",
            "loader": "ElfLoader",
            "loader_args": "imagebase=0x400000,applyLabels=true",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "ghidra"
    assert request.target == "/tmp/ghidra-projects"
    assert request.options_before_target is False
    assert request.options == (
        "firmware/imports -import firmware.bin -preScript Setup.java "
        "--mode fast -postScript Report.java out.json -scriptPath scripts "
        "-propertiesPath props -scriptlog script.log -log ghidra.log "
        "-overwrite -recursive 2 -readOnly -processor x86:LE:64:default "
        "-cspec gcc -analysisTimeoutPerFile 300 -connect analyst "
        "-commit 'import firmware' -max-cpu 4 -librarySearchPaths libs "
        "-loader ElfLoader -loader-imagebase 0x400000 -loader-applyLabels true"
    )


@pytest.mark.asyncio
async def test_mobsf_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_mobsf",
        {
            "bind_host": "127.0.0.1",
            "bind_port": 8080,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "mobsf"
    assert request.target == ""
    assert request.options == "127.0.0.1:8080"


@pytest.mark.asyncio
async def test_frida_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_frida",
        {
            "target": "com.example.app",
            "usb": True,
            "spawn_file": "com.example.app",
            "load_script": "hook.js",
            "parameters_json": '{"mode":"test"}',
            "eval_code": "console.log(1)",
            "quiet": True,
            "timeout": 10,
            "pause": True,
            "output_file": "frida.log",
            "runtime": "v8",
            "debug": True,
            "exit_on_error": True,
            "no_auto_reload": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "frida"
    assert request.target == "com.example.app"
    assert request.options_before_target is True
    assert request.options == (
        "-U -f com.example.app --runtime v8 --debug -l hook.js "
        "-P '{\"mode\":\"test\"}' -e 'console.log(1)' -q -t 10 --pause "
        "-o frida.log --exit-on-error --no-auto-reload"
    )


@pytest.mark.asyncio
async def test_objection_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_objection",
        {
            "target": "com.example.app",
            "network": True,
            "host": "127.0.0.1",
            "port": 27042,
            "api_host": "0.0.0.0",
            "api_port": 9999,
            "spawn": True,
            "no_pause": True,
            "quiet": True,
            "startup_command": "android sslpinning disable",
            "file_commands": "commands.txt",
            "startup_script": "startup.js",
            "enable_api": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "objection"
    assert request.target == "com.example.app"
    assert request.options == (
        "--network --host 127.0.0.1 --port 27042 --api-host 0.0.0.0 "
        "--api-port 9999 --name com.example.app --spawn --no-pause start "
        "--quiet --startup-command 'android sslpinning disable' "
        "--file-commands commands.txt --startup-script startup.js --enable-api"
    )

    await mcp.call_tool(
        "security_tool_objection",
        {
            "command": "patchapk",
            "source": "app.apk",
            "architecture": "arm64-v8a",
            "gadget_version": "16.2.1",
            "enable_debug": True,
            "network_security_config": True,
            "target_class": "com.example.MainActivity",
            "gadget_config": "gadget.config",
            "script_source": "script.js",
            "ignore_nativelibs": True,
            "manifest": "AndroidManifest.xml",
            "only_main_classes": True,
            "fix_concurrency_to": 1,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "objection"
    assert request.target == "app.apk"
    assert request.options == (
        "patchapk --source app.apk --architecture arm64-v8a "
        "--gadget-version 16.2.1 --enable-debug --network-security-config "
        "--target-class com.example.MainActivity --gadget-config gadget.config "
        "--script-source script.js --ignore-nativelibs "
        "--manifest AndroidManifest.xml --only-main-classes --fix-concurrency-to 1"
    )


@pytest.mark.asyncio
async def test_steghide_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_steghide",
        {
            "target": "picture.jpg",
            "command": "embed",
            "embed_file": "secret.txt",
            "stego_file": "out.jpg",
            "encryption": "rijndael-128",
            "compression_level": 9,
            "no_checksum": True,
            "no_embed_name": True,
            "passphrase": "pass word",
            "verbose": True,
            "force": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "steghide"
    assert request.target == "picture.jpg"
    assert request.options == (
        "embed --embedfile secret.txt --coverfile picture.jpg --stegofile "
        "out.jpg --encryption rijndael-128 --compress 9 --nochecksum "
        "--dontembedname --passphrase 'pass word' --verbose --force"
    )


@pytest.mark.asyncio
async def test_stegcracker_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_stegcracker",
        {
            "target": "picture.jpg",
            "wordlist": "words.txt",
            "output_file": "secret.out",
            "threads": 8,
            "chunk_size": 128,
            "quiet": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "stegcracker"
    assert request.target == "picture.jpg"
    assert request.options == (
        "words.txt --output secret.out --threads 8 --chunk-size 128 --quiet"
    )


@pytest.mark.asyncio
async def test_stegocracker_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_stegocracker",
        {
            "target": "cover.png",
            "encode": True,
            "message": "secret",
            "output_image": "out.png",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "stegocracker"
    assert request.target == "cover.png"
    assert request.options == "--input cover.png --output out.png --message secret --encode"


@pytest.mark.asyncio
async def test_whitespace_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_whitespace",
        {
            "compress": True,
            "message": "I am lying",
            "password": "hello world",
            "line_length": 72,
            "input_file": "infile.txt",
            "output_file": "outfile.txt",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "whitespace"
    assert request.target == ""
    assert request.options == (
        "-C -p 'hello world' -l 72 -m 'I am lying' infile.txt outfile.txt"
    )


@pytest.mark.asyncio
async def test_host2ip_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_host2ip",
        {
            "hostname": "example.com",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "host2ip"
    assert request.target == "example.com"
    assert request.options == ""


@pytest.mark.asyncio
async def test_portscan_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_portscan",
        {
            "host": "192.0.2.10",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "portscan"
    assert request.target == "192.0.2.10"
    assert request.options == ""


@pytest.mark.asyncio
async def test_rang3r_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_rang3r",
        {
            "ip": "192.0.2.0/24",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "rang3r"
    assert request.target == "192.0.2.0/24"
    assert request.options == ""


@pytest.mark.asyncio
async def test_striker_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_striker",
        {
            "domain": "example.com",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "striker"
    assert request.target == "example.com"
    assert request.options == ""


@pytest.mark.asyncio
async def test_recondog_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_recondog",
        {
            "target": "example.com",
            "choice": "0",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "recondog"
    assert request.target == "example.com"
    assert request.options == "-c 0"


@pytest.mark.asyncio
async def test_isitdown_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_isitdown",
        {
            "url": "example.com",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "isitdown"
    assert request.target == "example.com"
    assert request.options == ""


@pytest.mark.asyncio
async def test_hatcloud_source_reviewed_parameters_build_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_hatcloud",
        {
            "domain": "example.com",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "hatcloud"
    assert request.target == "example.com"
    assert request.options == ""


@pytest.mark.asyncio
async def test_gospider_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_gospider",
        {
            "site": "https://example.test",
            "output_dir": "out",
            "concurrent": 10,
            "depth": 2,
            "other_source": True,
            "include_subs": True,
            "cookie": "a=b",
            "header": "Accept: */*",
            "blacklist": ".(jpg|png)",
            "json_output": True,
            "quiet": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "gospider"
    assert request.target == "https://example.test"
    assert request.options == (
        "-o out --cookie a=b -H 'Accept: */*' --blacklist '.(jpg|png)' "
        "-c 10 -d 2 -a -w --json -q"
    )


@pytest.mark.asyncio
async def test_dirb_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_dirb",
        {
            "target": "https://example.test",
            "wordlist": "words.txt",
            "user_agent": "Agent/1.0",
            "cookie": "a=b",
            "header": "X-Test: 1",
            "ignore_code": 404,
            "output_file": "dirb.txt",
            "proxy": "127.0.0.1:8080",
            "no_recursive": True,
            "silent": True,
            "extensions": "php,txt",
            "delay_ms": 100,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "dirb"
    assert request.target == "https://example.test"
    assert request.options == (
        "words.txt -a Agent/1.0 -c a=b -H 'X-Test: 1' -N 404 "
        "-o dirb.txt -p 127.0.0.1:8080 -r -S -X php,txt -z 100"
    )


@pytest.mark.asyncio
async def test_takeover_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_takeover",
        {
            "target": "example.com",
            "proxy": "http://127.0.0.1:8080",
            "output_file": "takeover.json",
            "threads": 8,
            "timeout": 20,
            "user_agent": "takeover-bot",
            "process_200": True,
            "verbose": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "takeover"
    assert request.target == "example.com"
    assert request.options == (
        "-p http://127.0.0.1:8080 -o takeover.json -t 8 -T 20 "
        "-u takeover-bot -k -v"
    )


@pytest.mark.asyncio
async def test_skipfish_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_skipfish",
        {
            "target": "https://example.test",
            "output_dir": "out",
            "write_wordlist": "words.wl",
            "auth": "user:pass",
            "cookie": "a=b",
            "header": "X-Test: 1",
            "max_depth": 3,
            "max_children": 20,
            "include_url": "/admin",
            "exclude_url": "logout",
            "skip_param": "token",
            "crawl_domain": "example.org",
            "skip_5xx": True,
            "no_forms": True,
            "log_mixed_content": True,
            "suppress_duplicates": True,
            "quiet": True,
            "verbose": True,
            "max_connections": 20,
            "host_connections": 5,
            "request_timeout": 10,
            "max_requests_per_second": 30,
            "config_file": "skipfish.conf",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "skipfish"
    assert request.target == "https://example.test"
    assert request.options_before_target is True
    assert request.options == (
        "-o out -W words.wl -A user:pass -C a=b -H 'X-Test: 1' "
        "-d 3 -c 20 -I /admin -X logout -K token -D example.org "
        "-Z -O -M -Q -u -v -g 20 -m 5 -t 10 -l 30 --config skipfish.conf"
    )


@pytest.mark.asyncio
async def test_caido_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_caido",
        {
            "help": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "caido"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_mitmproxy_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_mitmproxy",
        {
            "version": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "mitmproxy"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_terminal_multiplexer_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_terminal_multiplexer",
        {
            "version": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "terminal-multiplexer"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_allinone_socialmedia_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_allinone_socialmedia",
        {
            "help": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "allinone-socialmedia"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_faceshell_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_faceshell",
        {
            "target": "alice",
            "wordlist": "passwords.txt",
            "proxy_file": "proxies.txt",
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "faceshell"
    assert request.target == "alice"
    assert request.options == "-l passwords.txt -X proxies.txt"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_hashbuster_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_hashbuster",
        {
            "target": "hashes.txt",
            "input_type": "file",
            "threads": 8,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "hashbuster"
    assert request.target == "hashes.txt"
    assert request.options == "-t 8 -f"
    assert request.options_before_target is True
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_evilurl_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_evilurl",
        {
            "target": "example.com",
            "generate": True,
            "check_connection": True,
            "output_file": "evil.txt",
            "check_availability": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "evilurl"
    assert request.target == "example.com"
    assert request.options == "-g -c -o evil.txt -a"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_knockmail_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_knockmail",
        {
            "target": "user@example.com",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "knockmail"
    assert request.target == ""
    assert request.options == "--email user@example.com"
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_socialscan_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_socialscan",
        {
            "target": "alice",
            "platforms": "github,instagram",
            "view_by": "platform",
            "available_only": True,
            "cache_tokens": True,
            "proxy_list": "proxies.txt",
            "verbose": True,
            "show_urls": True,
            "json_file": "social.json",
            "debug": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "socialscan"
    assert request.target == "alice"
    assert request.options == (
        "-p github instagram --view-by platform -a -c --proxy-list proxies.txt "
        "-v --show-urls --json social.json --debug"
    )
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_appcheck_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_appcheck",
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "appcheck"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_showme_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_showme",
        {
            "target": "ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "showme"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_goblin_wordgenerator_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_goblin_wordgenerator",
        {
            "target": "ignored",
            "interactive": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "goblin-wordgenerator"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_redhawk_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_redhawk",
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "redhawk"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_xerosploit_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xerosploit",
        {
            "target": "ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xerosploit"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_xssfinder_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xssfinder",
        {
            "target": "https://ignored.example",
            "config_driven": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xssfinder"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True


@pytest.mark.asyncio
async def test_xss_payload_generator_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xss_payload_generator",
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xss-payload-generator"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_xss_freak_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_xss_freak",
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "xss-freak"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_rvuln_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_rvuln",
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "rvuln"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_dracnmap_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_dracnmap",
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "dracnmap"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_reconspider_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_reconspider",
        {
            "target": "ignored.example",
            "interactive": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "reconspider"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_checkurl_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_checkurl",
        {
            "target": "example.com",
            "check_url": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "checkurl"
    assert request.target == "example.com"
    assert request.options == "--check-url"
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_blazy_source_reviewed_policy_only_endpoint_does_not_execute(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock()

    register(mcp, orchestrator, registry, safety)
    content, metadata = await mcp.call_tool(
        "security_tool_blazy",
        {
            "target": "https://example.test/login",
            "json_output": "blazy.json",
            "timeout": 15,
        },
    )

    assert "does not run the tool" in metadata["result"]
    assert content
    orchestrator.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_web2attack_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_web2attack",
        {
            "target": "ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "web2attack"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_wireshark_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_wireshark",
        {
            "target": "ignored.pcapng",
            "interactive": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "wireshark"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_autopsy_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_autopsy",
        {
            "use_cookies": True,
            "evidence_locker": "/cases",
            "live_device": "/dev/sda1",
            "live_filesystem": "ext4",
            "live_mount": "/mnt/root",
            "port": 8888,
            "remote_addr": "10.1.34.19",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "autopsy"
    assert request.target == "10.1.34.19"
    assert request.options == "-c -d /cases -i /dev/sda1 ext4 /mnt/root -p 8888"
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_guymager_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_guymager",
        {
            "target": "ignored.raw",
            "log_file": "guymager.log",
            "config_file": "guymager.cfg",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "guymager"
    assert request.target == ""
    assert request.options == "log=guymager.log cfg=guymager.cfg"
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_bulk_extractor_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_bulk_extractor",
        {
            "target": "evidence.E01",
            "output_dir": "case-out",
            "enabled_scanners": "email url",
            "disabled_scanners": "gps",
            "threads": 4,
            "recursive": True,
            "settings": "hash_alg=sha1",
            "quiet": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "bulk-extractor"
    assert request.target == "evidence.E01"
    assert request.options == (
        "-o case-out -j 4 -R -S hash_alg=sha1 -e email -e url -x gps -q"
    )
    assert request.options_before_target is True
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_toolsley_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_toolsley",
        {
            "text": "hello",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "toolsley"
    assert request.target == "hello"
    assert request.options == ""
    assert request.require_confirmation is False


@pytest.mark.asyncio
async def test_leviathan_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_leviathan",
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "leviathan"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_routersploit_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_routersploit",
        {
            "target": "192.0.2.10",
            "module": "exploits/routers/example",
            "set_options": "port 80;ssl true",
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "routersploit"
    assert request.target == ""
    assert request.options == (
        "-m exploits/routers/example -s 'target 192.0.2.10' "
        "-s 'port 80' -s 'ssl true'"
    )
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_websploit_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_websploit",
        {
            "target": "https://ignored.example",
            "interactive": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "websploit"
    assert request.target == ""
    assert request.options == ""
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_pwncat_cs_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_pwncat_cs",
        {
            "target": "10.10.10.10",
            "port": 4444,
            "platform": "windows",
            "ssl": True,
            "ssl_cert": "cert.pem",
            "ssl_key": "key.pem",
            "identity_file": "id_rsa",
            "verbose": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "pwncat-cs"
    assert request.target == "10.10.10.10"
    assert request.options == (
        "-p 4444 -m windows -S --ssl-cert cert.pem "
        "--ssl-key key.pem -i id_rsa -V"
    )
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_sliver_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_sliver",
        {
            "target": "ignored-local-host",
            "command": "mcp",
            "enable_wg": True,
            "mcp_config": "root_127.0.0.1.cfg",
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "sliver"
    assert request.target == ""
    assert request.options == "--enable-wg mcp --config root_127.0.0.1.cfg"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_havoc_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_havoc",
        {
            "target": "ignored-local-host",
            "command": "server",
            "default_profile": True,
            "debug": True,
            "send_logs": True,
            "verbose": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "havoc"
    assert request.target == ""
    assert request.options == "server --default --debug --send-logs --verbose"
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_evil_winrm_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_evil_winrm",
        {
            "target": "192.0.2.10",
            "username": "Administrator",
            "password": "Passw0rd!",
            "port": 5986,
            "ssl": True,
            "scripts_path": "/opt/ps1",
            "executables_path": "/opt/exe",
            "user_agent": "Microsoft WinRM Client",
            "no_colors": True,
            "no_rpath_completion": True,
            "log_session": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "evil-winrm"
    assert request.target == "192.0.2.10"
    assert request.options == (
        "-u Administrator -p 'Passw0rd!' -P 5986 -S -s /opt/ps1 "
        "-e /opt/exe -a 'Microsoft WinRM Client' -n -N -l"
    )
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_chisel_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_chisel",
        {
            "target": "https://chisel.example:443",
            "command": "client",
            "remotes": "R:2222:127.0.0.1:22;socks",
            "fingerprint": "fp123",
            "auth": "user:pass",
            "proxy": "http://proxy.example:8080",
            "header": "X-Test: 1",
            "hostname": "front.example",
            "sni": "tls.example",
            "tls_skip_verify": True,
            "verbose": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "chisel"
    assert request.target == ""
    assert request.options == (
        "client --fingerprint fp123 --auth user:pass "
        "--proxy http://proxy.example:8080 --header 'X-Test: 1' "
        "--hostname front.example --sni tls.example --tls-skip-verify "
        "https://chisel.example:443 R:2222:127.0.0.1:22 socks -v"
    )
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


@pytest.mark.asyncio
async def test_peass_ng_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_peass_ng",
        {
            "target": "ignored-local-host",
            "all_checks": True,
            "regex_checks": True,
            "password": "Passw0rd!",
            "discover_net": "192.168.1.0/24",
            "ports": "22,80,443",
            "selected_checks": "system_information,interesting_files",
            "quiet": True,
            "no_color": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "peass-ng"
    assert request.target == ""
    assert request.options == (
        "-a -r -P 'Passw0rd!' -d 192.168.1.0/24 -p 22,80,443 "
        "-o system_information,interesting_files -q -N"
    )
    assert request.require_confirmation is True


@pytest.mark.asyncio
async def test_ligolo_ng_source_reviewed_parameters_build_cli_options(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_ligolo_ng",
        {
            "target": "ignored-local-host",
            "listen_addr": "127.0.0.1:11601",
            "selfcert": True,
            "cert_file": "cert.pem",
            "key_file": "key.pem",
            "allow_domains": "lab.example,alt.example",
            "selfcert_domain": "lab.example",
            "config_file": "ligolo.yaml",
            "daemon": True,
            "api_listen_addr": "127.0.0.1:8080",
            "verbose": True,
            "no_banner": True,
            "confirm_authorized": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "ligolo-ng"
    assert request.target == ""
    assert request.options == (
        "-v -laddr 127.0.0.1:11601 -selfcert -certfile cert.pem "
        "-keyfile key.pem -allow-domains lab.example,alt.example "
        "-selfcert-domain lab.example -config ligolo.yaml -daemon "
        "-api-laddr 127.0.0.1:8080 -nobanner"
    )
    assert request.require_confirmation is True
    assert request.confirm_authorized is True


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
            "os_cmd": "whoami",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "commix"
    assert request.options == "--batch --method POST -p x --delay 5 --os-cmd whoami"


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


def test_anonymity_and_wordlist_source_reviewed_previews(registry, safety):
    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}

    anonsurf = adapter_request_preview(
        registry.get_tool("anonsurf"),
        specs["anonsurf"],
        {"action": "change"},
    )
    assert anonsurf["target"] == ""
    assert anonsurf["options"] == "change"

    multitor = adapter_request_preview(
        registry.get_tool("multitor"),
        specs["multitor"],
        {
            "init_instances": 2,
            "user": "debian-tor",
            "socks_port": "9000",
            "control_port": 9900,
            "proxy": "privoxy",
            "haproxy": True,
        },
    )
    assert multitor["options"] == (
        "--init 2 --user debian-tor --socks-port 9000 "
        "--control-port 9900 --proxy privoxy --haproxy"
    )

    cupp = adapter_request_preview(
        registry.get_tool("cupp"),
        specs["cupp"],
        {"quiet": True, "improve_file": "base.txt"},
    )
    assert cupp["options"] == "-q -w base.txt"

    wlcreator = adapter_request_preview(
        registry.get_tool("wlcreator"),
        specs["wlcreator"],
        {"length": 8},
    )
    assert wlcreator["options"] == "8"


def test_cloud_security_adapters_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    for tool_name in {"prowler", "scoutsuite", "pacu", "trivy"}:
        assert records[tool_name].source_status == "source-reviewed"
        assert records[tool_name].unverified_parameters == ()
        assert records[tool_name].gap == ""

    assert any("prowler-cloud/prowler" in item for item in records["prowler"].evidence)
    assert any("nccgroup/ScoutSuite" in item for item in records["scoutsuite"].evidence)
    assert any("RhinoSecurityLabs/pacu" in item for item in records["pacu"].evidence)
    assert any("aquasecurity/trivy" in item for item in records["trivy"].evidence)

    assert "provider" not in adapter_parameter_names(
        registry.get_tool("prowler"),
        specs["prowler"],
    )
    assert "region" not in adapter_parameter_names(
        registry.get_tool("scoutsuite"),
        specs["scoutsuite"],
    )
    assert "profile" not in adapter_parameter_names(
        registry.get_tool("trivy"),
        specs["trivy"],
    )
    assert "rhost" not in adapter_parameter_names(
        registry.get_tool("pacu"),
        specs["pacu"],
    )


def test_cloud_security_source_reviewed_previews(registry, safety):
    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}

    prowler = adapter_request_preview(
        registry.get_tool("prowler"),
        specs["prowler"],
        {
            "target": "aws",
            "profile": "prod",
            "region": "us-east-1",
            "services": "s3,ec2",
            "severity": "high critical",
            "checks": "iam_user_no_policies",
            "excluded_checks": "s3_bucket_public_access",
            "excluded_services": "cloudtrail",
            "output_formats": "json,csv",
            "output_directory": "out",
            "output_filename": "report",
            "list_services": True,
            "no_banner": True,
            "log_level": "INFO",
        },
    )
    assert prowler["target"] == "aws"
    assert prowler["options"] == (
        "--profile prod --region us-east-1 --service s3 ec2 "
        "--severity high critical --check iam_user_no_policies "
        "--excluded-check s3_bucket_public_access "
        "--excluded-service cloudtrail --output-formats json csv "
        "--output-directory out --output-filename report --list-services "
        "--no-banner --log-level INFO"
    )

    scoutsuite = adapter_request_preview(
        registry.get_tool("scoutsuite"),
        specs["scoutsuite"],
        {
            "target": "aws",
            "profile": "prod",
            "regions": "us-east-1,us-west-2",
            "excluded_regions": "eu-west-1",
            "services": "s3 iam",
            "skipped_services": "cloudtrail",
            "result_format": "json",
            "report_dir": "reports",
            "report_name": "aws-audit",
            "fetch_local": True,
            "force_write": True,
            "no_browser": True,
            "max_workers": 8,
            "max_rate": 10,
        },
    )
    assert scoutsuite["target"] == "aws"
    assert scoutsuite["options"] == (
        "--profile prod --regions us-east-1 us-west-2 "
        "--exclude-regions eu-west-1 --services s3 iam --skip cloudtrail "
        "--result-format json --report-dir reports --report-name aws-audit "
        "--local --force --no-browser --max-workers 8 --max-rate 10"
    )

    pacu = adapter_request_preview(
        registry.get_tool("pacu"),
        specs["pacu"],
        {
            "session": "lab",
            "module_name": "iam__enum_users_roles_policies_groups",
            "module_args": "--regions us-east-1",
            "execute_module": True,
            "set_regions": "us-east-1 us-west-2",
            "whoami": True,
            "quiet": True,
        },
    )
    assert pacu["target"] == ""
    assert pacu["options"] == (
        "--session lab --module-name iam__enum_users_roles_policies_groups "
        "--module-args '--regions us-east-1' --exec "
        "--set-regions us-east-1 us-west-2 --whoami --quiet"
    )

    trivy = adapter_request_preview(
        registry.get_tool("trivy"),
        specs["trivy"],
        {
            "target": "alpine:3.19",
            "severity": "HIGH,CRITICAL",
            "output_format": "json",
            "output_file": "trivy.json",
            "ignore_unfixed": True,
            "scanners": "vuln,secret",
            "skip_dirs": "vendor",
            "offline_scan": True,
            "timeout": "5m",
            "quiet": True,
        },
    )
    assert trivy["target"] == "alpine:3.19"
    assert trivy["options"] == (
        "image --severity HIGH,CRITICAL --format json --output trivy.json "
        "--ignore-unfixed --scanners vuln,secret --skip-dirs vendor "
        "--offline-scan --timeout 5m --quiet"
    )


def test_responder_kerbrute_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    for tool_name in {"responder", "kerbrute"}:
        assert records[tool_name].source_status == "source-reviewed"
        assert records[tool_name].unverified_parameters == ()
        assert records[tool_name].gap == ""

    assert any("lgandx/Responder" in item for item in records["responder"].evidence)
    assert any("ropnop/kerbrute" in item for item in records["kerbrute"].evidence)

    responder_params = adapter_parameter_names(
        registry.get_tool("responder"),
        specs["responder"],
    )
    assert "domain" not in responder_params
    assert "analyze" in responder_params
    assert "dhcpv6" in responder_params

    kerbrute_params = adapter_parameter_names(
        registry.get_tool("kerbrute"),
        specs["kerbrute"],
    )
    assert "passwords_file" not in kerbrute_params
    assert "dc" in kerbrute_params
    assert "users_file" in kerbrute_params

    responder = adapter_request_preview(
        registry.get_tool("responder"),
        specs["responder"],
        {
            "target": "eth0",
            "analyze": True,
            "external_ip": "10.0.0.5",
            "external_ipv6": "fe80::1",
            "rdnss": True,
            "dnssl_domain": "corp.local",
            "ttl": "1e",
            "answer_name": "wpad",
            "dhcp": True,
            "dhcp_dns": True,
            "dhcpv6": True,
            "wpad": True,
            "force_wpad_auth": True,
            "proxy_auth": True,
            "upstream_proxy": "127.0.0.1:8080",
            "basic": True,
            "lm": True,
            "disable_ess": True,
            "error_code": True,
            "verbose": True,
            "quiet": True,
            "local_ip": "10.0.0.20",
        },
    )
    assert responder["target"] == "eth0"
    assert responder["options"] == (
        "-A -e 10.0.0.5 -6 fe80::1 --rdnss --dnssl corp.local "
        "-t 1e -N wpad -d -D --dhcpv6 -w -F -P -u 127.0.0.1:8080 "
        "-b --lm --disable-ess -E -v -Q -i 10.0.0.20"
    )

    kerbrute = adapter_request_preview(
        registry.get_tool("kerbrute"),
        specs["kerbrute"],
        {
            "target": "corp.local",
            "dc": "dc.corp.local",
            "output_file": "kerbrute.log",
            "verbose": True,
            "safe": True,
            "threads": 20,
            "delay": 100,
            "downgrade": True,
            "hash_file": "asrep.txt",
            "users_file": "users.txt",
        },
    )
    assert kerbrute["target"] == "corp.local"
    assert kerbrute["options"] == (
        "--dc dc.corp.local -o kerbrute.log -v --safe -t 20 --delay 100 "
        "--downgrade --hash-file asrep.txt users.txt"
    )


def test_impacket_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["impacket"].source_status == "source-reviewed"
    assert records["impacket"].unverified_parameters == ()
    assert records["impacket"].gap == ""
    assert any("fortra/impacket" in item for item in records["impacket"].evidence)

    params = adapter_parameter_names(registry.get_tool("impacket"), specs["impacket"])
    assert "domain" not in params
    assert "collection_method" not in params
    assert "input_file" in params
    assert "aes_key" in params

    preview = adapter_request_preview(
        registry.get_tool("impacket"),
        specs["impacket"],
        {
            "target": "CORP/alice:Passw0rd@fileserver",
            "input_file": "commands.txt",
            "output_file": "smb.log",
            "debug": True,
            "timestamp": True,
            "hashes": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "no_pass": True,
            "kerberos": True,
            "aes_key": "001122",
            "dc_ip": "10.0.0.10",
            "target_ip": "10.0.0.20",
            "port": "445",
        },
    )
    assert preview["target"] == "CORP/alice:Passw0rd@fileserver"
    assert preview["options"] == (
        "-inputfile commands.txt -outputfile smb.log -debug -ts "
        "-hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c "
        "-no-pass -k -aesKey 001122 -dc-ip 10.0.0.10 -target-ip 10.0.0.20 "
        "-port 445"
    )


def test_certipy_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["certipy"].source_status == "source-reviewed"
    assert records["certipy"].unverified_parameters == ()
    assert records["certipy"].gap == ""
    assert any("ly4k/Certipy" in item for item in records["certipy"].evidence)

    params = adapter_parameter_names(registry.get_tool("certipy"), specs["certipy"])
    assert "domain" not in params
    assert "username" not in params
    assert "interface" not in params
    assert "collection_method" not in params
    assert "sources" not in params
    assert "passive" not in params
    assert "resolvers" not in params
    assert "api_key" not in params
    assert "output_file" not in params
    assert "users_file" not in params
    assert "passwords_file" not in params
    assert "local_auth" not in params
    assert "dc_host" in params
    assert "target_host" in params
    assert "ldap_simple_auth" in params
    assert "output_prefix" in params

    preview = adapter_request_preview(
        registry.get_tool("certipy"),
        specs["certipy"],
        {
            "target": "alice@corp.local",
            "password": "Passw0rd!",
            "hashes": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "kerberos": True,
            "aes_key": "001122",
            "no_pass": True,
            "dc_ip": "10.0.0.10",
            "dc_host": "dc.corp.local",
            "target_ip": "10.0.0.20",
            "target_host": "ca.corp.local",
            "nameserver": "10.0.0.53",
            "dns_tcp": True,
            "timeout": 15,
            "ldap_scheme": "ldap",
            "ldap_port": 389,
            "no_ldap_channel_binding": True,
            "no_ldap_signing": True,
            "ldap_simple_auth": True,
            "ldap_user_dn": "CN=Alice,CN=Users,DC=corp,DC=local",
            "text": True,
            "stdout": True,
            "json_output": True,
            "csv": True,
            "output_prefix": "certipy-find",
            "enabled": True,
            "dc_only": True,
            "vulnerable": True,
            "oids": True,
            "hide_admins": True,
            "sid": "S-1-5-21-1-2-3-1100",
            "dn": "CN=Alice,CN=Users,DC=corp,DC=local",
        },
    )
    assert preview["target"] == "alice@corp.local"
    assert preview["options"] == (
        "-p 'Passw0rd!' -hashes "
        "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c "
        "-k -aes 001122 -no-pass -dc-ip 10.0.0.10 -dc-host dc.corp.local "
        "-target-ip 10.0.0.20 -target ca.corp.local -ns 10.0.0.53 "
        "-dns-tcp -timeout 15 -ldap-scheme ldap -ldap-port 389 "
        "-no-ldap-channel-binding -no-ldap-signing -ldap-simple-auth "
        "-ldap-user-dn CN=Alice,CN=Users,DC=corp,DC=local -text -stdout "
        "-json -csv -output certipy-find -enabled -dc-only -vulnerable "
        "-oids -hide-admins -sid S-1-5-21-1-2-3-1100 "
        "-dn CN=Alice,CN=Users,DC=corp,DC=local"
    )


def test_bloodhound_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["bloodhound"].source_status == "source-reviewed"
    assert records["bloodhound"].unverified_parameters == ()
    assert records["bloodhound"].gap == ""
    assert any("dirkjanm/BloodHound.py" in item for item in records["bloodhound"].evidence)

    params = adapter_parameter_names(registry.get_tool("bloodhound"), specs["bloodhound"])
    assert "domain" not in params
    assert "dc_ip" not in params
    assert "interface" not in params
    assert "sources" not in params
    assert "passive" not in params
    assert "resolvers" not in params
    assert "api_key" not in params
    assert "output_file" not in params
    assert "json_output" not in params
    assert "ldap" not in params
    assert "smb" not in params
    assert "disable_llmnr" not in params
    assert "domain_controller" in params
    assert "auth_method" in params
    assert "zip_output" in params

    preview = adapter_request_preview(
        registry.get_tool("bloodhound"),
        specs["bloodhound"],
        {
            "target": "corp.local",
            "username": "alice",
            "password": "Passw0rd!",
            "kerberos": True,
            "hashes": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "no_pass": True,
            "aes_key": "001122",
            "auth_method": "kerberos",
            "collection_method": "Default",
            "verbose": True,
            "nameserver": "10.0.0.53",
            "dns_tcp": True,
            "dns_timeout": 5,
            "domain_controller": "dc.corp.local",
            "global_catalog": "gc.corp.local",
            "workers": 20,
            "exclude_dcs": True,
            "disable_pooling": True,
            "disable_autogc": True,
            "zip_output": True,
            "computerfile": "computers.txt",
            "cachefile": "cache.json",
            "ldap_channel_binding": True,
            "use_ldaps": True,
            "output_prefix": "bloodhound",
        },
    )
    assert preview["target"] == "corp.local"
    assert preview["options"] == (
        "-u alice -p 'Passw0rd!' -k --hashes "
        "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c "
        "-no-pass -aesKey 001122 --auth-method kerberos -c Default -v "
        "-ns 10.0.0.53 --dns-tcp --dns-timeout 5 -dc dc.corp.local "
        "-gc gc.corp.local -w 20 --exclude-dcs --disable-pooling "
        "--disable-autogc --zip --computerfile computers.txt --cachefile "
        "cache.json --ldap-channel-binding --use-ldaps -op bloodhound"
    )


def test_netexec_source_reviewed_and_previewable(registry, safety):
    from hacking_mcp.mcp_tools.tool_adapters import adapter_parameter_names

    specs = {s.tool_name: s for s in build_adapter_specs(registry, safety)}
    records = {
        record.tool_name: record
        for record in build_adapter_research_records(registry, safety)
    }

    assert records["netexec"].source_status == "source-reviewed"
    assert records["netexec"].unverified_parameters == ()
    assert records["netexec"].gap == ""
    assert any("Pennyw0rth/NetExec" in item for item in records["netexec"].evidence)

    params = adapter_parameter_names(registry.get_tool("netexec"), specs["netexec"])
    assert "ports" not in params
    assert "scan_type" not in params
    assert "service_version" not in params
    assert "os_detection" not in params
    assert "default_scripts" not in params
    assert "timing" not in params
    assert "top_ports" not in params
    assert "rate" not in params
    assert "dc_ip" not in params
    assert "nameserver" not in params
    assert "interface" not in params
    assert "collection_method" not in params
    assert "lhost" not in params
    assert "lport" not in params
    assert "session_id" not in params
    assert "listener" not in params
    assert "protocol" not in params
    assert "users_file" not in params
    assert "passwords_file" not in params
    assert "target_ip" not in params
    assert "dns_server" in params
    assert "module_options" in params
    assert "execute_cmd" in params

    preview = adapter_request_preview(
        registry.get_tool("netexec"),
        specs["netexec"],
        {
            "target": "10.0.0.0/24",
            "username": "alice",
            "password": "Passw0rd!",
            "hashes": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "domain": "CORP",
            "local_auth": True,
            "kerberos": True,
            "use_kcache": True,
            "aes_key": "001122",
            "kdc_host": "dc.corp.local",
            "cred_id": "3",
            "ignore_pw_decoding": True,
            "no_bruteforce": True,
            "continue_on_success": True,
            "gfail_limit": 10,
            "ufail_limit": 3,
            "fail_limit": 2,
            "threads": 32,
            "timeout": 15,
            "jitter": "1s",
            "no_progress": True,
            "log_file": "nxc.log",
            "verbose": True,
            "force_ipv6": True,
            "dns_server": "10.0.0.53",
            "dns_tcp": True,
            "dns_timeout": 5,
            "module": "spooler",
            "module_options": "LISTENER=foo CMD=whoami",
            "list_modules": "smb",
            "show_module_options": True,
            "port": 445,
            "share": "C$",
            "smb_server_port": 445,
            "no_smbv1": True,
            "no_admin_check": True,
            "gen_relay_list": "relay.txt",
            "smb_timeout": 4,
            "shares": "read",
            "users": "alice",
            "groups": "Domain Admins",
            "pass_pol": True,
            "rid_brute": 500,
            "exec_method": "wmiexec",
            "execute_cmd": "whoami",
            "execute_ps": "Get-Process",
        },
    )
    assert preview["target"] == "10.0.0.0/24"
    assert preview["options"] == (
        "-u alice -p 'Passw0rd!' -H "
        "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c "
        "-d CORP --local-auth -k --use-kcache --aesKey 001122 "
        "--kdcHost dc.corp.local -id 3 --ignore-pw-decoding "
        "--no-bruteforce --continue-on-success --gfail-limit 10 "
        "--ufail-limit 3 --fail-limit 2 -t 32 --timeout 15 --jitter 1s "
        "--no-progress --log nxc.log --verbose -6 --dns-server 10.0.0.53 "
        "--dns-tcp --dns-timeout 5 -M spooler -o LISTENER=foo CMD=whoami "
        "-L smb --options --port 445 --share 'C$' --smb-server-port 445 "
        "--no-smbv1 --no-admin-check --gen-relay-list relay.txt "
        "--smb-timeout 4 --shares read --users alice --groups 'Domain Admins' "
        "--pass-pol --rid-brute 500 --exec-method wmiexec -x whoami "
        "-X Get-Process"
    )


@pytest.mark.asyncio
async def test_trivy_adapter_places_command_and_flags_before_target(registry, safety):
    from mcp.server.fastmcp import FastMCP
    from unittest.mock import AsyncMock, MagicMock

    mcp = FastMCP(name="adapter-test")
    response = MagicMock()
    response.format.return_value = "ok"
    orchestrator = MagicMock()
    orchestrator.execute = AsyncMock(return_value=response)

    register(mcp, orchestrator, registry, safety)
    await mcp.call_tool(
        "security_tool_trivy",
        {
            "target": "alpine:3.19",
            "command": "image",
            "severity": "HIGH,CRITICAL",
            "output_format": "json",
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "trivy"
    assert request.target == "alpine:3.19"
    assert request.options == "image --severity HIGH,CRITICAL --format json"
    assert request.options_before_target is True


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
            "username": "alice",
            "nameserver": "10.0.0.53",
            "domain_controller": "dc.corp.local",
            "collection_method": "Default",
            "zip_output": True,
        },
    )

    request = orchestrator.execute.await_args.args[0]
    assert request.tool_name == "bloodhound"
    assert request.target == "corp.local"
    assert request.options == "-u alice -c Default -ns 10.0.0.53 -dc dc.corp.local --zip"


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
        {"target": "example.com", "action": "inject", "backdoor_path": "rootkit.bin"},
    )

    assert "classified DANGEROUS" in metadata["result"]
    assert "does not run the tool" in metadata["result"]
    assert content
    orchestrator.execute.assert_not_awaited()
