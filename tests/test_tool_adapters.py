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
    assert {"provider", "checks", "excluded_checks", "output_format"}.issubset(
        prowler_schema
    )

    netexec_schema = tools["security_tool_netexec"].inputSchema["properties"]
    assert {"users_file", "passwords_file", "kerberos", "local_auth"}.issubset(
        netexec_schema
    )

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
