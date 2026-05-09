"""Per-tool MCP adapters generated from the tool registry.

The grouped endpoints stay available for broad workflows. This module adds one
dedicated MCP tool per catalog tool. Executable adapters route through
ToolOrchestrator and SafetyPolicy; blocked adapters return policy information.
"""

import re
import shlex
from inspect import Parameter, Signature
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from hacking_mcp.ai_help import build_ai_help
from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters import split_adapter_options, split_adapter_parameters
from hacking_mcp.models import HackingToolDef, SafetyTier
from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy


MCP_TOOL_PREFIX = "security_tool_"

NAMED_OVERRIDE_TOOL_NAMES = frozenset(
    {
        "airgeddon",
        "amass",
        "anonsurf",
        "arjun",
        "bettercap",
        "binwalk",
        "blackeye",
        "blackphish",
        "blisqy",
        "bloodhound",
        "brutal",
        "certipy",
        "chisel",
        "commix",
        "dalfox",
        "dirsearch",
        "dsss",
        "evil-winrm",
        "evilginx3",
        "explo",
        "feroxbuster",
        "ffuf",
        "fluxion",
        "frida",
        "ghidra",
        "gitleaks",
        "gobuster",
        "hashcat",
        "havoc",
        "hcxdumptool",
        "hcxtools",
        "hiddeneye",
        "httpx",
        "impacket",
        "jadx",
        "john",
        "katana",
        "kerbrute",
        "leviathan",
        "ligolo-ng",
        "masscan",
        "maskphish",
        "mobdroid",
        "mobsf",
        "msfvenom",
        "multitor",
        "netexec",
        "nikto",
        "nmap",
        "nosqlmap",
        "nuclei",
        "objection",
        "owasp-zap",
        "pacu",
        "peass-ng",
        "prowler",
        "pwncat-cs",
        "pyphisher",
        "radare2",
        "responder",
        "routersploit",
        "rustscan",
        "scoutsuite",
        "setoolkit",
        "shellphish",
        "sherlock",
        "sliver",
        "sqlscan",
        "sqlmap",
        "steghide",
        "stegcracker",
        "subfinder",
        "testssl",
        "theHarvester",
        "thefatrat",
        "trivy",
        "trufflehog",
        "venom",
        "volatility3",
        "wafw00f",
        "websploit",
        "whatweb",
        "wifiphisher",
        "wifite",
        "xanxss",
        "xspear",
        "xsstrike",
        "xsscon",
    }
)

LOCAL_TARGET_CATEGORIES = {
    "Forensics",
    "Steganography",
    "Wordlist Generator",
    "Reverse Engineering",
    "Mobile Security",
}


@dataclass(frozen=True)
class ToolAdapterSpec:
    """A per-tool MCP adapter registration plan."""

    tool_name: str
    mcp_name: str
    title: str
    category: str
    description: str
    target_hint: str
    option_hint: str
    safety_tier: str
    target_required: bool
    validate_scope: bool
    requires_confirmation: bool
    exposed: bool
    blocked_reason: str = ""


def build_adapter_specs(
    registry: ToolRegistry,
    safety: SafetyPolicy,
) -> list[ToolAdapterSpec]:
    """Build adapter specs for every known tool.

    DANGEROUS, archived, disabled, and no-command tools are represented as
    non-exposed specs so the inventory remains complete without registering
    risky execution endpoints.
    """
    specs: list[ToolAdapterSpec] = []
    used_names: set[str] = set()

    for tool in registry.list_all_tools():
        ai_help = build_ai_help(tool)
        allowed, reason = safety.check_tool(tool)
        exposed = allowed and bool(tool.run_command)
        if not tool.run_command and not reason:
            reason = "No run command defined."

        spec = ToolAdapterSpec(
            tool_name=tool.name,
            mcp_name=_unique_mcp_name(tool.name, used_names),
            title=tool.title,
            category=tool.category,
            description=tool.description,
            target_hint=ai_help.target_hint,
            option_hint=ai_help.option_hint,
            safety_tier=tool.safety_tier.value,
            target_required="{target}" in tool.run_command,
            validate_scope=_should_validate_scope(tool),
            requires_confirmation=safety.requires_confirmation(tool),
            exposed=exposed,
            blocked_reason="" if exposed else reason,
        )
        specs.append(spec)

    return specs


def register(
    mcp: FastMCP,
    orchestrator: ToolOrchestrator,
    registry: ToolRegistry,
    safety: SafetyPolicy,
) -> list[ToolAdapterSpec]:
    """Register one MCP tool per known registry tool.

    Safety-eligible tools get executable adapters. Tools blocked by policy,
    missing run commands, or otherwise unavailable still get dedicated MCP
    entries that return a policy explanation without invoking the orchestrator.
    """
    specs = build_adapter_specs(registry, safety)
    for spec in specs:
        tool = registry.get_tool(spec.tool_name)
        if tool:
            _register_one(mcp, orchestrator, tool, spec)
    return specs


def _register_one(
    mcp: FastMCP,
    orchestrator: ToolOrchestrator,
    tool: HackingToolDef,
    spec: ToolAdapterSpec,
) -> None:
    description = _adapter_description(spec)
    signature = _adapter_signature(tool, spec)

    if not spec.exposed:
        async def blocked_tool(**kwargs) -> str:
            return _blocked_adapter_response(spec)

        blocked_tool.__name__ = spec.mcp_name
        blocked_tool.__signature__ = signature
        mcp.tool(name=spec.mcp_name, description=description)(blocked_tool)
        return

    async def run_tool(**kwargs) -> str:
        target, options, confirm_authorized = _request_parts(tool, spec, kwargs)
        response = await orchestrator.execute(
            ToolRequest(
                tool_name=spec.tool_name,
                target=target,
                options=options,
                target_required=spec.target_required,
                validate_scope=spec.validate_scope,
                require_confirmation=spec.requires_confirmation,
                confirm_authorized=confirm_authorized,
                confirmation_message=(
                    f"Tool '{spec.tool_name}' requires explicit authorization."
                ),
                options_before_target=_options_before_target(tool),
            ),
            ctx=None,
        )
        return response.format()

    run_tool.__name__ = spec.mcp_name
    run_tool.__signature__ = signature
    mcp.tool(name=spec.mcp_name, description=description)(run_tool)


def _adapter_description(spec: ToolAdapterSpec) -> str:
    if not spec.exposed:
        return (
            f"Dedicated adapter for {spec.title} ({spec.tool_name}). "
            f"Category: {spec.category}. Safety tier: {spec.safety_tier}. "
            "Execution is not available from MCP: "
            f"{spec.blocked_reason or 'not exposed by policy'}"
        )

    confirmation = (
        " Requires confirm_authorized=true before execution."
        if spec.requires_confirmation
        else ""
    )
    target = (
        f" Target: {spec.target_hint}."
        if spec.target_required
        else " Target is optional for this tool."
    )
    return (
        f"Dedicated adapter for {spec.title} ({spec.tool_name}). "
        f"Category: {spec.category}. Safety tier: {spec.safety_tier}."
        f"{target} Options: {spec.option_hint}.{confirmation}"
    )


def _blocked_adapter_response(spec: ToolAdapterSpec) -> str:
    reason = spec.blocked_reason or "This tool is not exposed for execution by policy."
    return "\n".join(
        [
            f"# {spec.title}",
            "",
            f"**Tool:** `{spec.tool_name}`",
            f"**Category:** {spec.category}",
            f"**Safety tier:** {spec.safety_tier}",
            f"**Dedicated endpoint:** `{spec.mcp_name}`",
            "",
            "## Execution",
            f"Blocked: {reason}",
            "",
            "This endpoint is registered for inventory completeness only. It does not "
            "run the tool or bypass the safety policy.",
        ]
    )


def _adapter_signature(tool: HackingToolDef, spec: ToolAdapterSpec) -> Signature:
    parameters = [
        Parameter(
            item.name,
            Parameter.KEYWORD_ONLY,
            default=item.default,
            annotation=item.annotation(),
        )
        for item in _adapter_parameters(tool, spec)
    ]
    return Signature(parameters=parameters, return_annotation=str)


def adapter_parameter_names(tool: HackingToolDef, spec: ToolAdapterSpec) -> list[str]:
    """Return generated MCP argument names for inventory/reporting."""
    return [param.name for param in _adapter_parameters(tool, spec)]


def adapter_parameter_specs(
    tool: HackingToolDef,
    spec: ToolAdapterSpec,
) -> list[AdapterParameterSpec]:
    """Return generated MCP argument specs for inventory/reporting."""
    return _adapter_parameters(tool, spec)


def adapter_request_preview(
    tool: HackingToolDef,
    spec: ToolAdapterSpec,
    kwargs: dict,
) -> dict:
    """Preview generated request parts without executing the adapter."""
    target, options, confirm_authorized = _request_parts(tool, spec, kwargs)
    return {
        "tool_name": spec.tool_name,
        "endpoint": spec.mcp_name,
        "target": target,
        "options": options,
        "confirm_authorized": confirm_authorized,
        "executable": spec.exposed,
        "blocked_reason": spec.blocked_reason,
    }


def adapter_example_arguments(tool: HackingToolDef, spec: ToolAdapterSpec) -> dict:
    """Build conservative example arguments for adapter documentation."""
    names = adapter_parameter_names(tool, spec)
    example: dict[str, Any] = {"target": _example_target(tool)}

    examples: dict[str, Any] = {
        "ports": "80,443",
        "scan_type": "tcp",
        "service_version": True,
        "severity": "low,medium",
        "tags": "exposure",
        "wordlist": "wordlist.txt",
        "threads": 10,
        "extensions": "php,js,txt",
        "data": "id=1",
        "dbms": "MySQL",
        "risk": 1,
        "level": 1,
        "parameter": "id",
        "sources": "all",
        "profile": "default",
        "region": "us-east-1",
        "domain": "example.local",
        "username": "alice",
        "dc_ip": "127.0.0.1",
        "output_dir": "output",
        "plugin": "windows.pslist",
        "extract": True,
        "hash_file": "hashes.txt",
        "hash_type": "0",
        "passphrase": "test-passphrase",
        "apk_path": "app.apk",
        "package_name": "com.example.app",
        "binary_path": "sample.bin",
        "lhost": "127.0.0.1",
        "lport": 4444,
        "interface": "eth0",
        "template": "training",
        "payload_type": "generic/shell_reverse_tcp",
        "format": "raw",
        "module": "scanner/example",
        "checks": "default",
        "scripts": "default",
        "timeout": 10,
        "headless": True,
        "input_file": "targets.txt",
        "rate_limit": 100,
        "rate_limits": "shodan=10/s",
        "filter_codes": "404,403",
        "headers": "X-Test: 1",
        "method": "GET",
        "path": "/login",
        "silent": True,
        "recursive": True,
        "all_sources": True,
        "exclude_sources": "shodan,censys",
        "resolver_file": "resolvers.txt",
        "output_dir": "output",
        "config_file": "config.yaml",
        "provider_config": "provider-config.yaml",
        "config_path": "gitleaks.toml",
        "baseline_path": "baseline.json",
        "ignore_path": ".gitleaksignore",
        "log_opts": "--since=2026-01-01",
        "report_format": "json",
        "report_path": "report.json",
        "log_level": "info",
        "results": "verified,unknown",
        "concurrency": 12,
        "filter_entropy": 3.0,
        "source_ip": "192.168.1.200",
        "source_port": 61000,
        "output_xml": "scan.xml",
        "include_file": "targets.txt",
        "readscan": "scan.bin",
        "port_range": "1-1000",
        "scan_order": "serial",
        "strategy": "depth-first",
        "delay": "1s",
        "crawl_duration": "5m",
        "field": "url",
        "output_json": "result.json",
        "output_text": "result.txt",
        "include_data": "api_key=test",
        "chunk_size": 250,
        "casing": "foo_bar",
        "cookies": "session=value",
        "status_codes": "200,301,302",
        "methods": "GET,POST",
        "query": "token=value",
        "filter_regex": "^ignore",
        "filter_lines": "20",
        "time_limit": "10m",
        "include_status": "200,301,302",
        "exclude_status": "404,403",
        "exclude_sizes": "0B",
        "exclude_text": "not found",
        "prefixes": "admin",
        "suffixes": "backup",
        "subdirs": "api,admin",
        "format": "json",
        "output_format": "json",
        "display": "V",
        "tuning": "x",
    }
    for name in names:
        if name in {"target", "options", "confirm_authorized"}:
            continue
        if name in examples:
            example[name] = examples[name]
        if len(example) >= 5:
            break

    if spec.requires_confirmation:
        example["confirm_authorized"] = False
    return example


def _adapter_parameters(
    tool: HackingToolDef,
    spec: ToolAdapterSpec,
) -> list[AdapterParameterSpec]:
    params = [
        AdapterParameterSpec(
            "target",
            str,
            "",
            spec.target_hint if spec.target_required else "Optional target or local input.",
        )
    ]
    tags = set(tool.tags)

    split_params = split_adapter_parameters(tool.name)
    if split_params is not None:
        params.extend(split_params)
        params.extend([
            AdapterParameterSpec("options", str, "", "Raw additional CLI options appended after generated options."),
            AdapterParameterSpec(
                "confirm_authorized",
                bool,
                False,
                "Set true only for targets you own or have explicit written authorization to test.",
            ),
        ])
        return _dedupe_parameters(params)

    if tool.name == "masscan":
        params.extend([
            AdapterParameterSpec("ports", str, "", "Ports or ranges to scan, for example 80,8000-8100."),
            AdapterParameterSpec("rate", int, 0, "Transmit rate in packets per second; 0 leaves default."),
            AdapterParameterSpec("config_file", str, "", "Masscan configuration file."),
            AdapterParameterSpec("echo", bool, False, "Dump current configuration and exit."),
            AdapterParameterSpec("banners", bool, False, "Grab simple banner information where supported."),
            AdapterParameterSpec("source_ip", str, "", "Source IP address for banner checks."),
            AdapterParameterSpec("source_port", int, 0, "Source port for banner checks; 0 leaves default."),
            AdapterParameterSpec("exclude_file", str, "", "File containing excluded IP ranges."),
            AdapterParameterSpec("include_file", str, "", "File containing included IP ranges."),
            AdapterParameterSpec("output_xml", str, "", "XML output file path."),
            AdapterParameterSpec("output_json", str, "", "JSON output file path."),
            AdapterParameterSpec("output_list", str, "", "List output file path."),
            AdapterParameterSpec("output_grepable", str, "", "Grepable output file path."),
            AdapterParameterSpec("output_format", str, "", "Output format, for example xml, json, list, grepable."),
            AdapterParameterSpec("output_filename", str, "", "Output filename when using output_format."),
            AdapterParameterSpec("readscan", str, "", "Read binary scan results from file."),
        ])
    elif tool.name == "rustscan":
        params.extend([
            AdapterParameterSpec("ports", str, "", "Comma-separated ports to scan."),
            AdapterParameterSpec("port_range", str, "", "Port range in start-end format."),
            AdapterParameterSpec("no_config", bool, False, "Ignore RustScan configuration file."),
            AdapterParameterSpec("no_banner", bool, False, "Hide the RustScan banner."),
            AdapterParameterSpec("config_path", str, "", "Custom config file path."),
            AdapterParameterSpec("greppable", bool, False, "Only output ports in greppable mode."),
            AdapterParameterSpec("accessible", bool, False, "Enable screen-reader friendly mode."),
            AdapterParameterSpec("resolver", str, "", "Comma-delimited list or file of DNS resolvers."),
            AdapterParameterSpec("batch_size", int, 0, "Batch size for port scanning; 0 leaves default."),
            AdapterParameterSpec("timeout", int, 0, "Timeout in milliseconds; 0 leaves default."),
            AdapterParameterSpec("tries", int, 0, "Number of tries before a port is assumed closed; 0 leaves default."),
            AdapterParameterSpec("ulimit", int, 0, "Automatically raise ULIMIT; 0 leaves default."),
            AdapterParameterSpec("scan_order", str, "", "Scan order: serial or random."),
            AdapterParameterSpec("scripts", str, "", "Script mode: none, default, or custom."),
            AdapterParameterSpec("top", bool, False, "Use the top 1000 ports."),
            AdapterParameterSpec("exclude_ports", str, "", "Comma-separated ports to exclude."),
            AdapterParameterSpec("exclude_addresses", str, "", "Comma-separated CIDRs, IPs, or hosts to exclude."),
            AdapterParameterSpec("udp", bool, False, "Enable UDP scanning mode."),
            AdapterParameterSpec("nmap_args", str, "", "Trailing nmap arguments appended after --."),
        ])
    elif "port-scan" in tags or "network" in tags:
        params.extend([
            AdapterParameterSpec("ports", str, "", "Ports or ranges, for example 80,443 or 1-1000."),
            AdapterParameterSpec(
                "scan_type",
                str,
                "",
                "Optional scan profile: syn, tcp, udp, ping, or empty for tool default.",
            ),
            AdapterParameterSpec("service_version", bool, False, "Request service/version detection when supported."),
            AdapterParameterSpec("os_detection", bool, False, "Request OS detection when supported."),
            AdapterParameterSpec("default_scripts", bool, False, "Run default safe scripts when supported."),
            AdapterParameterSpec("timing", int, 0, "Timing profile 0-5 when supported; 0 leaves default."),
            AdapterParameterSpec("top_ports", int, 0, "Scan top N ports when supported; 0 disables."),
            AdapterParameterSpec("rate", int, 0, "Packet/request rate limit when supported; 0 leaves default."),
        ])

    if tool.name == "nuclei":
        params.extend([
            AdapterParameterSpec("severity", str, "", "Comma-separated severities, for example critical,high."),
            AdapterParameterSpec("tags", str, "", "Comma-separated nuclei template tags."),
            AdapterParameterSpec("template_path", str, "", "Template file or directory path."),
            AdapterParameterSpec("rate_limit", int, 0, "Maximum requests per second; 0 leaves default."),
            AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        ])
    elif tool.name == "nikto":
        params.extend([
            AdapterParameterSpec("ask", str, "", "Interactive prompt behavior."),
            AdapterParameterSpec("cgi_dirs", str, "", "CGI directories to scan."),
            AdapterParameterSpec("config_file", str, "", "Nikto config file path."),
            AdapterParameterSpec("display", str, "", "Display selector."),
            AdapterParameterSpec("dbcheck", bool, False, "Check database and syntax errors."),
            AdapterParameterSpec("evasion", str, "", "IDS evasion technique."),
            AdapterParameterSpec("output_format", str, "", "Output format."),
            AdapterParameterSpec("auth", str, "", "Host authentication credential pair."),
            AdapterParameterSpec("list_plugins", bool, False, "List installed plugins."),
            AdapterParameterSpec("max_time", str, "", "Maximum testing time."),
            AdapterParameterSpec("mutate", str, "", "Guess additional file names."),
            AdapterParameterSpec("mutate_options", str, "", "Mutate option values."),
            AdapterParameterSpec("no_interactive", bool, False, "Disable interactive prompts."),
            AdapterParameterSpec("no_lookup", bool, False, "Disable DNS lookups."),
            AdapterParameterSpec("no_ssl", bool, False, "Disable SSL/TLS."),
            AdapterParameterSpec("no_404", bool, False, "Disable 404 checks."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("pause", int, 0, "Pause between tests in seconds; 0 leaves default."),
            AdapterParameterSpec("plugins", str, "", "Plugin selector."),
            AdapterParameterSpec("port", str, "", "Ports to scan."),
            AdapterParameterSpec("rsa_cert", str, "", "Client certificate file."),
            AdapterParameterSpec("root", str, "", "Prepend root path to requests."),
            AdapterParameterSpec("save_dir", str, "", "Directory to save positive responses."),
            AdapterParameterSpec("ssl", bool, False, "Force SSL/TLS mode."),
            AdapterParameterSpec("tuning", str, "", "Scan tuning selector."),
            AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
            AdapterParameterSpec("until", str, "", "Run until specified time or duration."),
            AdapterParameterSpec("update", bool, False, "Update plugins and databases."),
            AdapterParameterSpec("use_proxy", bool, False, "Use configured HTTP proxy."),
            AdapterParameterSpec("vhost", str, "", "Virtual host header."),
            AdapterParameterSpec("notfound_code", str, "", "Treat this HTTP code as 404."),
            AdapterParameterSpec("notfound_string", str, "", "Treat response body containing this string as 404."),
        ])
    elif tool.name == "katana":
        params.extend([
            AdapterParameterSpec("input_file", str, "", "Input file containing targets to crawl."),
            AdapterParameterSpec("depth", int, 0, "Maximum crawl depth; 0 leaves default."),
            AdapterParameterSpec("strategy", str, "", "Crawling strategy, for example depth-first or breadth-first."),
            AdapterParameterSpec("js_crawl", bool, False, "Enable JavaScript file crawling."),
            AdapterParameterSpec("known_files", str, "", "Known files to crawl, for example robots.txt,sitemap.xml."),
            AdapterParameterSpec("automatic_form_fill", bool, False, "Enable automatic form filling."),
            AdapterParameterSpec("form_extraction", bool, False, "Extract forms and inputs."),
            AdapterParameterSpec("headless", bool, False, "Enable headless browser crawling."),
            AdapterParameterSpec("headless_options", str, "", "Headless browser options."),
            AdapterParameterSpec("no_sandbox", bool, False, "Start Chrome without sandbox."),
            AdapterParameterSpec("system_chrome", bool, False, "Use locally installed Chrome."),
            AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
            AdapterParameterSpec("headers", str, "", "Custom HTTP header to send."),
            AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("retry", int, 0, "Number of retries; 0 leaves default."),
            AdapterParameterSpec("rate_limit", int, 0, "Maximum requests per second; 0 leaves default."),
            AdapterParameterSpec("concurrency", int, 0, "Number of concurrent fetchers; 0 leaves default."),
            AdapterParameterSpec("parallelism", int, 0, "Number of parallel input targets; 0 leaves default."),
            AdapterParameterSpec("delay", str, "", "Delay between requests, for example 1s."),
            AdapterParameterSpec("crawl_duration", str, "", "Maximum crawl duration, for example 5m."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("json_output", bool, False, "Write JSONL output."),
            AdapterParameterSpec("field", str, "", "Field to display, for example url or qurl."),
            AdapterParameterSpec("silent", bool, False, "Show only output."),
            AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
        ])
    elif tool.name == "arjun":
        params.extend([
            AdapterParameterSpec("input_file", str, "", "Targets file, Burp export, or raw request file."),
            AdapterParameterSpec("output_json", str, "", "JSON output file path."),
            AdapterParameterSpec("output_burp", str, "", "BurpSuite output target/path."),
            AdapterParameterSpec("output_text", str, "", "Text output file path."),
            AdapterParameterSpec("method", str, "", "HTTP method: GET, POST, JSON, or XML."),
            AdapterParameterSpec("include_data", str, "", "Persistent data to include in each request."),
            AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
            AdapterParameterSpec("delay", int, 0, "Delay between requests in seconds; 0 leaves default."),
            AdapterParameterSpec("timeout", int, 0, "HTTP request timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("stable", bool, False, "Enable stable mode for rate-limited targets."),
            AdapterParameterSpec("rate_limit", int, 0, "Requests per second; 0 leaves default."),
            AdapterParameterSpec("wordlist", str, "", "Wordlist path or built-in size: small, medium, large."),
            AdapterParameterSpec("chunk_size", int, 0, "Parameters sent per request; 0 leaves default."),
            AdapterParameterSpec("disable_redirects", bool, False, "Disable HTTP redirects."),
            AdapterParameterSpec("passive", str, "", "Passive discovery domain, or '-' to use target URL domain."),
            AdapterParameterSpec("casing", str, "", "Parameter casing style."),
            AdapterParameterSpec("headers", str, "", "Custom HTTP headers."),
        ])
    elif tool.name == "gobuster":
        params.extend([
            AdapterParameterSpec("wordlist", str, "", "Wordlist path for directory enumeration."),
            AdapterParameterSpec("extensions", str, "", "Comma-separated extensions to append."),
            AdapterParameterSpec("headers", str, "", "Custom HTTP header."),
            AdapterParameterSpec("cookies", str, "", "Cookie header value."),
            AdapterParameterSpec("show_length", bool, False, "Show response length."),
            AdapterParameterSpec("status_codes", str, "", "Positive status codes or ranges."),
            AdapterParameterSpec("threads", int, 0, "Number of concurrent threads; 0 leaves default."),
            AdapterParameterSpec("delay", str, "", "Delay between requests, for example 1s."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
            AdapterParameterSpec("timeout", str, "", "HTTP timeout, for example 10s."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("quiet", bool, False, "Quiet output mode."),
            AdapterParameterSpec("no_progress", bool, False, "Disable progress output."),
            AdapterParameterSpec("expanded", bool, False, "Expanded mode: print full URLs."),
            AdapterParameterSpec("add_slash", bool, False, "Append slash to each request."),
        ])
    elif tool.name == "feroxbuster":
        params.extend([
            AdapterParameterSpec("wordlist", str, "", "Wordlist path or URL."),
            AdapterParameterSpec("extensions", str, "", "File extensions to search for."),
            AdapterParameterSpec("methods", str, "", "HTTP methods to send."),
            AdapterParameterSpec("data", str, "", "Request body data."),
            AdapterParameterSpec("headers", str, "", "Custom HTTP header."),
            AdapterParameterSpec("cookies", str, "", "HTTP cookies."),
            AdapterParameterSpec("query", str, "", "URL query parameter."),
            AdapterParameterSpec("add_slash", bool, False, "Append slash to request URLs."),
            AdapterParameterSpec("protocol", str, "", "Protocol for request-file/domain-only targets."),
            AdapterParameterSpec("dont_scan", str, "", "URL or regex pattern to exclude from scanning."),
            AdapterParameterSpec("scope", str, "", "Additional in-scope URL or domain."),
            AdapterParameterSpec("filter_size", str, "", "Filter responses by size."),
            AdapterParameterSpec("filter_regex", str, "", "Filter responses by regex."),
            AdapterParameterSpec("filter_words", str, "", "Filter responses by word count."),
            AdapterParameterSpec("filter_lines", str, "", "Filter responses by line count."),
            AdapterParameterSpec("filter_codes", str, "", "Filter/deny-list status codes."),
            AdapterParameterSpec("status_codes", str, "", "Allow-list status codes."),
            AdapterParameterSpec("unique", bool, False, "Only show unique responses."),
            AdapterParameterSpec("timeout", int, 0, "Client timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
            AdapterParameterSpec("insecure", bool, False, "Disable TLS certificate validation."),
            AdapterParameterSpec("threads", int, 0, "Number of concurrent threads; 0 leaves default."),
            AdapterParameterSpec("no_recursion", bool, False, "Disable recursive scanning."),
            AdapterParameterSpec("depth", int, 0, "Maximum recursion depth; 0 leaves default."),
            AdapterParameterSpec("force_recursion", bool, False, "Force recursion attempts."),
            AdapterParameterSpec("dont_extract_links", bool, False, "Disable link extraction from responses."),
            AdapterParameterSpec("scan_limit", int, 0, "Total concurrent scans; 0 leaves default."),
            AdapterParameterSpec("parallelism", int, 0, "Parallel feroxbuster child scans; 0 leaves default."),
            AdapterParameterSpec("rate_limit", int, 0, "Requests per second per directory; 0 leaves default."),
            AdapterParameterSpec("response_size_limit", str, "", "Limit response body read size."),
            AdapterParameterSpec("time_limit", str, "", "Total runtime limit, for example 10m."),
            AdapterParameterSpec("auto_tune", bool, False, "Automatically lower scan rate on errors."),
            AdapterParameterSpec("auto_bail", bool, False, "Stop scanning on excessive errors."),
            AdapterParameterSpec("dont_filter", bool, False, "Disable auto-filtering wildcard responses."),
            AdapterParameterSpec("collect_extensions", bool, False, "Discover and add extensions dynamically."),
            AdapterParameterSpec("collect_backups", str, "", "Backup extensions to request."),
            AdapterParameterSpec("collect_words", bool, False, "Discover words from responses."),
            AdapterParameterSpec("dont_collect", str, "", "Extensions to ignore during collection."),
            AdapterParameterSpec("verbosity", int, 0, "Verbosity level 1-3; 0 leaves default."),
            AdapterParameterSpec("silent", bool, False, "Only print URLs or JSON output."),
            AdapterParameterSpec("quiet", bool, False, "Hide progress bars and banner."),
            AdapterParameterSpec("json_output", bool, False, "Emit JSON logs."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("debug_log", str, "", "Debug log output path."),
            AdapterParameterSpec("no_state", bool, False, "Disable state output file."),
            AdapterParameterSpec("limit_bars", int, 0, "Maximum directory scan bars; 0 leaves default."),
        ])
    elif tool.name == "dirsearch":
        params.extend([
            AdapterParameterSpec("wordlist", str, "", "Wordlist path."),
            AdapterParameterSpec("extensions", str, "", "Comma-separated extensions."),
            AdapterParameterSpec("include_status", str, "", "Status codes to include."),
            AdapterParameterSpec("exclude_status", str, "", "Status codes to exclude."),
            AdapterParameterSpec("exclude_sizes", str, "", "Response sizes to exclude."),
            AdapterParameterSpec("exclude_text", str, "", "Text to exclude from responses."),
            AdapterParameterSpec("exclude_regex", str, "", "Regex to exclude from responses."),
            AdapterParameterSpec("prefixes", str, "", "Prefixes to add to paths."),
            AdapterParameterSpec("suffixes", str, "", "Suffixes to add to paths."),
            AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
            AdapterParameterSpec("recursive", bool, False, "Enable recursive scanning."),
            AdapterParameterSpec("deep_recursive", bool, False, "Enable deep recursive scanning."),
            AdapterParameterSpec("force_recursive", bool, False, "Force recursive scanning."),
            AdapterParameterSpec("recursion_depth", int, 0, "Maximum recursion depth; 0 leaves default."),
            AdapterParameterSpec("recursion_status", str, "", "Status codes that trigger recursion."),
            AdapterParameterSpec("subdirs", str, "", "Subdirectories to scan."),
            AdapterParameterSpec("exclude_subdirs", str, "", "Subdirectories to exclude."),
            AdapterParameterSpec("method", str, "", "HTTP method."),
            AdapterParameterSpec("data", str, "", "HTTP request body."),
            AdapterParameterSpec("headers", str, "", "Custom HTTP header."),
            AdapterParameterSpec("header_list", str, "", "File containing headers."),
            AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
            AdapterParameterSpec("random_agent", bool, False, "Use a random User-Agent."),
            AdapterParameterSpec("user_agent", str, "", "Custom HTTP User-Agent."),
            AdapterParameterSpec("cookies", str, "", "Cookie header value."),
            AdapterParameterSpec("proxy", str, "", "Proxy URL."),
            AdapterParameterSpec("proxy_list", str, "", "File containing proxies."),
            AdapterParameterSpec("timeout", int, 0, "Connection timeout; 0 leaves default."),
            AdapterParameterSpec("delay", str, "", "Delay between requests."),
            AdapterParameterSpec("max_rate", int, 0, "Maximum requests per second; 0 leaves default."),
            AdapterParameterSpec("retries", int, 0, "Number of retries; 0 leaves default."),
            AdapterParameterSpec("format", str, "", "Report format."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("json_report", str, "", "JSON report output path."),
            AdapterParameterSpec("plain_text_report", str, "", "Plain text report output path."),
            AdapterParameterSpec("csv_report", str, "", "CSV report output path."),
            AdapterParameterSpec("markdown_report", str, "", "Markdown report output path."),
            AdapterParameterSpec("xml_report", str, "", "XML report output path."),
            AdapterParameterSpec("sqlite_report", str, "", "SQLite report output path."),
            AdapterParameterSpec("quiet", bool, False, "Quiet mode."),
            AdapterParameterSpec("full_url", bool, False, "Show full URLs in output."),
            AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
        ])
    elif tool.name == "httpx":
        params.extend([
            AdapterParameterSpec("input_file", str, "", "Input file containing hosts to probe."),
            AdapterParameterSpec("status_code", bool, False, "Show HTTP status code."),
            AdapterParameterSpec("title", bool, False, "Show page title."),
            AdapterParameterSpec("tech_detect", bool, False, "Show technology detection."),
            AdapterParameterSpec("content_length", bool, False, "Show response content length."),
            AdapterParameterSpec("match_codes", str, "", "HTTP status codes to match."),
            AdapterParameterSpec("filter_codes", str, "", "HTTP status codes to filter."),
            AdapterParameterSpec("threads", int, 0, "Worker/thread count; 0 leaves default."),
            AdapterParameterSpec("rate_limit", int, 0, "Maximum requests per second; 0 leaves default."),
            AdapterParameterSpec("ports", str, "", "Ports to probe, for example http:80,https:8443."),
            AdapterParameterSpec("path", str, "", "Path or comma-separated paths to probe."),
            AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
            AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
            AdapterParameterSpec("headers", str, "", "Custom HTTP header to send."),
            AdapterParameterSpec("method", str, "", "HTTP method to probe, or all."),
            AdapterParameterSpec("timeout", int, 0, "Timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("json_output", bool, False, "Store output in JSONL format."),
            AdapterParameterSpec("silent", bool, False, "Enable silent output mode."),
        ])
    elif tool.name == "dalfox":
        params.extend([
            AdapterParameterSpec("blind_callback", str, "", "Blind XSS callback URL."),
            AdapterParameterSpec("config_file", str, "", "DalFox configuration file path."),
            AdapterParameterSpec("cookies", str, "", "Cookie header value."),
            AdapterParameterSpec("custom_alert_type", str, "", "Custom alert type, for example str or none."),
            AdapterParameterSpec("custom_alert_value", str, "", "Custom alert value."),
            AdapterParameterSpec("custom_payload", str, "", "Custom payload file path."),
            AdapterParameterSpec("data", str, "", "HTTP request body data."),
            AdapterParameterSpec("deep_domxss", bool, False, "Enable deep DOM XSS testing."),
            AdapterParameterSpec("delay", int, 0, "Delay between requests in milliseconds; 0 leaves default."),
            AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
            AdapterParameterSpec("force_headless_verification", bool, False, "Force headless payload verification."),
            AdapterParameterSpec("headers", str, "", "Additional HTTP header."),
            AdapterParameterSpec("ignore_param", str, "", "Parameter name to ignore."),
            AdapterParameterSpec("ignore_return", str, "", "HTTP status codes to ignore."),
            AdapterParameterSpec("method", str, "", "HTTP method to use."),
            AdapterParameterSpec("parameter", str, "", "Only test the named parameter."),
            AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
            AdapterParameterSpec("remote_payloads", str, "", "Remote payload list selectors."),
            AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
            AdapterParameterSpec("waf_evasion", bool, False, "Enable WAF evasion mode."),
            AdapterParameterSpec("max_cpu", int, 0, "Maximum CPU percentage; 0 leaves default."),
            AdapterParameterSpec("workers", int, 0, "Number of workers; 0 leaves default."),
            AdapterParameterSpec("mining_dict", bool, False, "Enable dictionary-based parameter mining."),
            AdapterParameterSpec("mining_dict_word", str, "", "Extra dictionary word for parameter mining."),
            AdapterParameterSpec("mining_dom", bool, False, "Enable DOM-based parameter mining."),
            AdapterParameterSpec("remote_wordlists", str, "", "Remote wordlist selectors."),
            AdapterParameterSpec("skip_mining_all", bool, False, "Skip all parameter mining."),
            AdapterParameterSpec("skip_mining_dict", bool, False, "Skip dictionary parameter mining."),
            AdapterParameterSpec("skip_mining_dom", bool, False, "Skip DOM parameter mining."),
            AdapterParameterSpec("only_custom_payload", bool, False, "Use only custom payloads."),
            AdapterParameterSpec("only_discovery", bool, False, "Only perform parameter analysis/discovery."),
            AdapterParameterSpec("skip_bav", bool, False, "Skip basic another verification checks."),
            AdapterParameterSpec("skip_discovery", bool, False, "Skip discovery phase."),
            AdapterParameterSpec("skip_grepping", bool, False, "Skip grepping phase."),
            AdapterParameterSpec("skip_headless", bool, False, "Skip headless browser verification."),
            AdapterParameterSpec("skip_xss_scanning", bool, False, "Skip XSS scanning phase."),
            AdapterParameterSpec("use_bav", bool, False, "Enable basic another verification."),
            AdapterParameterSpec("debug", bool, False, "Enable debug output."),
            AdapterParameterSpec("format", str, "", "Output format."),
            AdapterParameterSpec("found_action", str, "", "Command to run when a vulnerability is found."),
            AdapterParameterSpec("found_action_shell", str, "", "Shell to use for found_action."),
            AdapterParameterSpec("grep_file", str, "", "Custom grepping file."),
            AdapterParameterSpec("har_file_path", str, "", "HAR file output path."),
            AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
            AdapterParameterSpec("no_spinner", bool, False, "Disable spinner output."),
            AdapterParameterSpec("only_poc", str, "", "Only print selected PoC type."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("output_all", bool, False, "Write all logs to output."),
            AdapterParameterSpec("output_request", bool, False, "Include raw HTTP request in output."),
            AdapterParameterSpec("output_response", bool, False, "Include raw HTTP response in output."),
            AdapterParameterSpec("poc_type", str, "", "PoC type, for example plain or curl."),
            AdapterParameterSpec("report", bool, False, "Show detailed report output."),
            AdapterParameterSpec("report_format", str, "", "Report format."),
            AdapterParameterSpec("silence", bool, False, "Enable silent output."),
        ])
    elif tool.name == "xsstrike":
        params.extend([
            AdapterParameterSpec("data", str, "", "POST data to test."),
            AdapterParameterSpec("encode", str, "", "Payload encoding mode."),
            AdapterParameterSpec("fuzzer", bool, False, "Run the fuzzer."),
            AdapterParameterSpec("update", bool, False, "Update XSStrike."),
            AdapterParameterSpec("timeout", int, 0, "Request timeout; 0 leaves default."),
            AdapterParameterSpec("use_proxy", bool, False, "Use configured proxy/proxies."),
            AdapterParameterSpec("crawl", bool, False, "Enable crawling."),
            AdapterParameterSpec("json_data", bool, False, "Treat POST data as JSON."),
            AdapterParameterSpec("path_injection", bool, False, "Inject payloads into the URL path."),
            AdapterParameterSpec("seeds_file", str, "", "File containing crawling seeds."),
            AdapterParameterSpec("payload_file", str, "", "File containing payloads."),
            AdapterParameterSpec("level", int, 0, "Crawling level; 0 leaves default."),
            AdapterParameterSpec("headers", str, "", "Additional headers."),
            AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
            AdapterParameterSpec("delay", int, 0, "Delay between requests; 0 leaves default."),
            AdapterParameterSpec("skip", bool, False, "Do not prompt before continuing."),
            AdapterParameterSpec("skip_dom", bool, False, "Skip DOM checks."),
            AdapterParameterSpec("blind", bool, False, "Inject blind XSS payload while crawling."),
            AdapterParameterSpec("console_log_level", str, "", "Console logging level."),
            AdapterParameterSpec("file_log_level", str, "", "File logging level."),
            AdapterParameterSpec("log_file", str, "", "Log file name."),
        ])
    elif tool.name == "xspear":
        params.extend([
            AdapterParameterSpec("data", str, "", "POST body data."),
            AdapterParameterSpec("test_all_params", bool, False, "Test all parameters, including non-reflected ones."),
            AdapterParameterSpec("no_xss", bool, False, "Only perform parameter analysis without XSS tests."),
            AdapterParameterSpec("headers", str, "", "Additional HTTP headers."),
            AdapterParameterSpec("cookie", str, "", "Cookie header value."),
            AdapterParameterSpec("custom_payload", str, "", "Custom payload JSON file."),
            AdapterParameterSpec("raw_file", str, "", "Raw request file."),
            AdapterParameterSpec("parameter", str, "", "Specific parameter or parameters to test."),
            AdapterParameterSpec("blind_callback", str, "", "Blind XSS callback URL."),
            AdapterParameterSpec("threads", int, 0, "Thread count; 0 leaves default."),
            AdapterParameterSpec("output_format", str, "", "Output format, for example cli or json."),
            AdapterParameterSpec("config_file", str, "", "Config JSON file."),
            AdapterParameterSpec("verbose", int, 0, "Verbose level 0-3; 0 leaves default."),
        ])
    elif tool.name == "xsscon":
        params.extend([
            AdapterParameterSpec("depth", int, 0, "Crawl depth; 0 leaves default."),
            AdapterParameterSpec("payload_level", int, 0, "Generated payload level 1-7; 0 leaves default."),
            AdapterParameterSpec("payload", str, "", "Custom payload value."),
            AdapterParameterSpec("method", int, 0, "Method mode: 0 GET, 1 POST, 2 both; 0 leaves default."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
            AdapterParameterSpec("single_url", str, "", "Single URL to scan without crawling."),
            AdapterParameterSpec("proxy", str, "", "Proxy mapping string."),
            AdapterParameterSpec("about", bool, False, "Print XSSCon tool information."),
            AdapterParameterSpec("cookie", str, "", "Cookie mapping string."),
        ])
    elif tool.name == "xanxss":
        params.extend([
            AdapterParameterSpec("verification_amount", int, 0, "Verification steps; 0 leaves default."),
            AdapterParameterSpec("amount_to_find", int, 0, "Number of working payloads to try to find; 0 leaves default."),
            AdapterParameterSpec("test_time", int, 0, "Verification test time in seconds; 0 leaves default."),
            AdapterParameterSpec("payloads", str, "", "Comma-separated payloads or payload string list."),
            AdapterParameterSpec("payload_file", str, "", "Text file containing payloads."),
            AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
            AdapterParameterSpec("proxy", str, "", "Proxy URL in type://ip:port format."),
            AdapterParameterSpec("headers", str, "", "Custom headers in key=value,key:value format."),
            AdapterParameterSpec("throttle", int, 0, "Sleep time between requests in seconds; 0 leaves default."),
            AdapterParameterSpec("polyglot", bool, False, "Generate and test a polyglot payload."),
            AdapterParameterSpec("prefix", str, "", "Payload prefix."),
            AdapterParameterSpec("suffix", str, "", "Payload suffix."),
        ])
    elif tool.name == "dsss":
        params.extend([
            AdapterParameterSpec("data", str, "", "POST data, for example query=test."),
            AdapterParameterSpec("cookie", str, "", "HTTP Cookie header value."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent header value."),
            AdapterParameterSpec("referer", str, "", "HTTP Referer header value."),
            AdapterParameterSpec("proxy", str, "", "HTTP proxy address."),
        ])
    elif tool.name == "sqlscan":
        params.append(
            AdapterParameterSpec("scan", bool, True, "Run sqlscan scanner mode.")
        )
    elif tool.name == "testssl":
        params.extend([
            AdapterParameterSpec("input_file", str, "", "Mass testing input file."),
            AdapterParameterSpec("mode", str, "", "Mass testing mode: serial or parallel."),
            AdapterParameterSpec("warnings", str, "", "Warning handling: batch or off."),
            AdapterParameterSpec("connect_timeout", int, 0, "TCP connect timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("openssl_timeout", int, 0, "OpenSSL connect timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("basic_auth", str, "", "HTTP basic auth credentials user:pass."),
            AdapterParameterSpec("req_header", str, "", "Additional HTTP request header."),
            AdapterParameterSpec("mtls_file", str, "", "PEM file containing client certificate and private key."),
            AdapterParameterSpec("starttls", str, "", "STARTTLS protocol, for example smtp or imap."),
            AdapterParameterSpec("xmpp_host", str, "", "XMPP domain for STARTTLS XMPP checks."),
            AdapterParameterSpec("mx", str, "", "Domain or host whose MX records should be tested."),
            AdapterParameterSpec("ip", str, "", "IP address or resolver mode instead of resolving target host."),
            AdapterParameterSpec("proxy", str, "", "Proxy host:port or auto."),
            AdapterParameterSpec("ipv6", bool, False, "Also perform IPv6 checks."),
            AdapterParameterSpec("ssl_native", bool, False, "Use OpenSSL s_client for most checks."),
            AdapterParameterSpec("openssl_path", str, "", "Path to the OpenSSL binary to use."),
            AdapterParameterSpec("bugs", bool, False, "Enable OpenSSL bug workarounds for broken servers."),
            AdapterParameterSpec("assume_http", bool, False, "Assume HTTP when protocol detection cannot prove it."),
            AdapterParameterSpec("no_dns", str, "", "DNS lookup mode: min or none."),
            AdapterParameterSpec("sneaky", bool, False, "Use a less verbose browser-like HTTP user agent."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
            AdapterParameterSpec("ids_friendly", bool, False, "Skip selected offensive vulnerability probes."),
            AdapterParameterSpec("phone_out", bool, False, "Allow CRL and OCSP revocation lookups."),
            AdapterParameterSpec("add_ca", str, "", "Additional CA file, directory, or comma-separated list."),
            AdapterParameterSpec("each_cipher", bool, False, "Check each configured cipher."),
            AdapterParameterSpec("cipher_per_proto", bool, False, "Check ciphers per protocol."),
            AdapterParameterSpec("categories", bool, False, "Test cipher categories."),
            AdapterParameterSpec("forward_secrecy", bool, False, "Check forward secrecy."),
            AdapterParameterSpec("protocols", bool, False, "Check TLS/SSL protocols."),
            AdapterParameterSpec("server_preference", bool, False, "Display server cipher preferences."),
            AdapterParameterSpec("server_defaults", bool, False, "Display server defaults and certificate data."),
            AdapterParameterSpec("single_cipher", str, "", "Single cipher pattern to test."),
            AdapterParameterSpec("check_headers", bool, False, "Test HTTP response headers."),
            AdapterParameterSpec("client_simulation", bool, False, "Run browser/client handshake simulation."),
            AdapterParameterSpec("grease", bool, False, "Check GREASE tolerance."),
            AdapterParameterSpec("vulnerabilities", bool, False, "Run vulnerability checks."),
            AdapterParameterSpec("quiet", bool, False, "Suppress the banner."),
            AdapterParameterSpec("wide", bool, False, "Use wide output."),
            AdapterParameterSpec("mapping", str, "", "Cipher name mapping: openssl, iana, no-openssl, no-iana."),
            AdapterParameterSpec("show_each", bool, False, "Display all ciphers tested in wide modes."),
            AdapterParameterSpec("color", int, 0, "Color mode 0-3; 0 leaves default."),
            AdapterParameterSpec("colorblind", bool, False, "Swap colors for colorblind readability."),
            AdapterParameterSpec("debug", int, 0, "Debug level 0-6; 0 leaves default."),
            AdapterParameterSpec("disable_rating", bool, False, "Disable rating output."),
            AdapterParameterSpec("log", bool, False, "Write a log file using the default name."),
            AdapterParameterSpec("logfile", str, "", "Log output file or directory."),
            AdapterParameterSpec("json_output", bool, False, "Write flat JSON output using the default name."),
            AdapterParameterSpec("jsonfile", str, "", "Flat JSON output file or directory."),
            AdapterParameterSpec("json_pretty", bool, False, "Write pretty JSON output using the default name."),
            AdapterParameterSpec("jsonfile_pretty", str, "", "Pretty JSON output file or directory."),
            AdapterParameterSpec("csv_output", bool, False, "Write CSV output using the default name."),
            AdapterParameterSpec("csvfile", str, "", "CSV output file or directory."),
            AdapterParameterSpec("html_output", bool, False, "Write HTML output using the default name."),
            AdapterParameterSpec("htmlfile", str, "", "HTML output file or directory."),
            AdapterParameterSpec("out_file", str, "", "Base name or directory for all output formats."),
            AdapterParameterSpec("outfile", str, "", "Base name or directory for flat JSON plus other outputs."),
            AdapterParameterSpec("severity", str, "", "Minimum severity for CSV/JSON output."),
            AdapterParameterSpec("append", bool, False, "Append to existing output files."),
            AdapterParameterSpec("overwrite", bool, False, "Overwrite existing output files."),
            AdapterParameterSpec("outprefix", str, "", "Prefix for generated output filenames."),
        ])
    elif tool.name == "wafw00f":
        params.extend([
            AdapterParameterSpec("verbosity", int, 0, "Verbosity level 1-3; 0 leaves default."),
            AdapterParameterSpec("find_all", bool, False, "Find all matching WAF signatures."),
            AdapterParameterSpec("no_redirect", bool, False, "Do not follow HTTP 3xx redirects."),
            AdapterParameterSpec("test_waf", str, "", "Test for one specific WAF name."),
            AdapterParameterSpec("output_file", str, "", "Output file path, or - for stdout."),
            AdapterParameterSpec("output_format", str, "", "Force output format: csv, json, or text."),
            AdapterParameterSpec("input_file", str, "", "Input file containing targets."),
            AdapterParameterSpec("list_wafs", bool, False, "List detectable WAF names and exit."),
            AdapterParameterSpec("proxy", str, "", "HTTP or SOCKS proxy URL."),
            AdapterParameterSpec("version", bool, False, "Print WAFW00F version and exit."),
            AdapterParameterSpec("headers_file", str, "", "Text file containing custom headers."),
            AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
            AdapterParameterSpec("no_color", bool, False, "Disable ANSI colors in output."),
        ])
    elif tags & {"web", "http", "url", "discovery", "fuzzing"}:
        params.extend([
            AdapterParameterSpec("wordlist", str, "", "Wordlist path for discovery or fuzzing tools."),
            AdapterParameterSpec("threads", int, 0, "Worker/thread count when supported; 0 leaves default."),
            AdapterParameterSpec("extensions", str, "", "Comma-separated extensions such as php,js,txt."),
            AdapterParameterSpec("match_codes", str, "", "HTTP status codes to match or include."),
            AdapterParameterSpec("recursive", bool, False, "Enable recursive discovery when supported."),
            AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects when supported."),
            AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        ])

    if tags & {"sqli", "injection", "database"} and tool.name not in {"dsss", "sqlscan"}:
        params.extend([
            AdapterParameterSpec("data", str, "", "Optional POST body or data string."),
            AdapterParameterSpec("dbms", str, "", "Force DBMS fingerprint, for example MySQL or PostgreSQL."),
            AdapterParameterSpec("risk", int, 0, "Risk level 1-3 when supported; 0 leaves default."),
            AdapterParameterSpec("level", int, 0, "Test level 1-5 when supported; 0 leaves default."),
            AdapterParameterSpec("enumerate_databases", bool, False, "Request database enumeration when supported."),
        ])

    if "xss" in tags and tool.name not in {"dalfox", "xanxss", "xspear", "xsstrike", "xsscon"}:
        params.extend([
            AdapterParameterSpec("parameter", str, "", "Parameter name to test when supported."),
            AdapterParameterSpec("cookies", str, "", "Cookie header value when supported."),
            AdapterParameterSpec("blind_callback", str, "", "Blind XSS callback URL when supported."),
        ])

    if "email" in tags and tool.name not in {"theHarvester"}:
        params.append(AdapterParameterSpec("sources", str, "", "OSINT source selector when supported."))

    if tags & {"username", "social", "social-media"}:
        params.append(AdapterParameterSpec("timeout", int, 0, "Per-site timeout in seconds when supported."))

    if tool.name == "trufflehog":
        params.extend([
            AdapterParameterSpec("json_output", bool, False, "Output in JSON format."),
            AdapterParameterSpec("github_actions", bool, False, "Output in GitHub Actions format."),
            AdapterParameterSpec("concurrency", int, 0, "Number of concurrent workers; 0 leaves default."),
            AdapterParameterSpec("no_verification", bool, False, "Do not verify discovered results."),
            AdapterParameterSpec("results", str, "", "Result statuses to output, for example verified,unknown."),
            AdapterParameterSpec("no_color", bool, False, "Disable colorized output."),
            AdapterParameterSpec("allow_verification_overlap", bool, False, "Allow verification overlap across detectors."),
            AdapterParameterSpec("filter_unverified", bool, False, "Only output first unverified result per chunk/detector."),
            AdapterParameterSpec("filter_entropy", float, 0.0, "Filter unverified results by Shannon entropy; 0 leaves default."),
            AdapterParameterSpec("config_path", str, "", "Path to TruffleHog configuration file."),
            AdapterParameterSpec("print_avg_detector_time", bool, False, "Print average time spent on each detector."),
            AdapterParameterSpec("fail", bool, False, "Return TruffleHog leak-detected exit code when results are found."),
            AdapterParameterSpec("log_level", str, "", "Logging verbosity level; empty leaves default."),
        ])
    elif tool.name == "gitleaks":
        params.extend([
            AdapterParameterSpec("redact", bool, True, "Redact secrets in output."),
            AdapterParameterSpec("log_opts", str, "", "Git log options for detect scans."),
            AdapterParameterSpec("config_path", str, "", "Path to gitleaks config file."),
            AdapterParameterSpec("baseline_path", str, "", "Path to baseline report."),
            AdapterParameterSpec("ignore_path", str, "", "Path to .gitleaksignore file."),
            AdapterParameterSpec("enable_rule", str, "", "Only enable specific rule IDs."),
            AdapterParameterSpec("exit_code", int, 0, "Exit code when leaks are found; 0 leaves default."),
            AdapterParameterSpec("follow_symlinks", bool, False, "Scan files that are symlinks to other files."),
            AdapterParameterSpec("ignore_allow", bool, False, "Ignore gitleaks:allow comments."),
            AdapterParameterSpec("max_decode_depth", int, 0, "Recursive decode depth; 0 leaves default."),
            AdapterParameterSpec("max_archive_depth", int, 0, "Nested archive depth; 0 leaves default."),
            AdapterParameterSpec("max_target_mb", int, 0, "Maximum target file size in MB; 0 leaves default."),
            AdapterParameterSpec("report_format", str, "", "Report format, for example json, csv, junit, sarif."),
            AdapterParameterSpec("report_path", str, "", "Report output path."),
            AdapterParameterSpec("report_template", str, "", "Template file for report generation."),
            AdapterParameterSpec("log_level", str, "", "Log level: trace, debug, info, warn, error, fatal."),
            AdapterParameterSpec("no_banner", bool, False, "Suppress banner output."),
            AdapterParameterSpec("no_color", bool, False, "Disable color output."),
            AdapterParameterSpec("verbose", bool, False, "Show verbose output from scan."),
        ])
    elif tags & {"git", "secrets", "credentials"}:
        params.extend([
            AdapterParameterSpec("redact", bool, True, "Redact discovered secrets when supported."),
            AdapterParameterSpec("since_commit", str, "", "Only scan history since this commit when supported."),
        ])

    if "cloud" in tags or tool.category == "Cloud Security":
        params.extend([
            AdapterParameterSpec("profile", str, "", "Cloud credential profile when supported."),
            AdapterParameterSpec("region", str, "", "Cloud region when supported."),
            AdapterParameterSpec("services", str, "", "Comma-separated service names when supported."),
            AdapterParameterSpec("severity", str, "", "Severity filter when supported."),
        ])

    if "ad" in tags or tool.category == "Active Directory":
        params.extend([
            AdapterParameterSpec("domain", str, "", "Active Directory domain when supported."),
            AdapterParameterSpec("username", str, "", "Username for authorized AD assessment."),
            AdapterParameterSpec(
                "password",
                str,
                "",
                "Password for lab/authorized use; may be present in process/audit logs.",
            ),
            AdapterParameterSpec("hashes", str, "", "NTLM hashes when supported."),
            AdapterParameterSpec("dc_ip", str, "", "Domain controller IP address when supported."),
            AdapterParameterSpec("nameserver", str, "", "DNS nameserver when supported."),
            AdapterParameterSpec("interface", str, "", "Network interface name when supported."),
            AdapterParameterSpec("collection_method", str, "", "Collection method, for example All or Default."),
        ])

    if "forensics" in tags or tool.category == "Forensics":
        params.extend([
            AdapterParameterSpec("output_dir", str, "", "Output directory for extracted or report artifacts."),
            AdapterParameterSpec("plugin", str, "", "Analysis plugin or module when supported."),
            AdapterParameterSpec("extract", bool, False, "Extract embedded files or artifacts when supported."),
            AdapterParameterSpec("profile", str, "", "Memory/image profile when supported."),
        ])

    if tool.category == "Wordlist Generator" or tags & {"wordlist", "password", "hash"}:
        params.extend([
            AdapterParameterSpec("wordlist", str, "", "Wordlist path when supported."),
            AdapterParameterSpec("hash_file", str, "", "Hash file path when supported."),
            AdapterParameterSpec("hash_type", str, "", "Hash mode/type when supported."),
            AdapterParameterSpec("attack_mode", str, "", "Attack mode when supported."),
            AdapterParameterSpec("min_length", int, 0, "Minimum generated password length when supported."),
            AdapterParameterSpec("max_length", int, 0, "Maximum generated password length when supported."),
            AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        ])

    if "stegano" in tags or tool.category == "Steganography":
        params.extend([
            AdapterParameterSpec("passphrase", str, "", "Steganography passphrase when supported."),
            AdapterParameterSpec("wordlist", str, "", "Password wordlist path when supported."),
            AdapterParameterSpec("extract", bool, False, "Extract hidden payload when supported."),
            AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        ])

    if "mobile" in tags or tool.category == "Mobile Security":
        params.extend([
            AdapterParameterSpec("apk_path", str, "", "APK/IPA path when supported."),
            AdapterParameterSpec("package_name", str, "", "Mobile app package or bundle identifier."),
            AdapterParameterSpec("device_id", str, "", "Connected device identifier when supported."),
            AdapterParameterSpec("spawn", bool, False, "Spawn target app when supported."),
        ])

    if "reverse-engineering" in tags or tool.category == "Reverse Engineering":
        params.extend([
            AdapterParameterSpec("binary_path", str, "", "Binary/APK path when different from target."),
            AdapterParameterSpec("output_dir", str, "", "Output directory for decompilation artifacts."),
            AdapterParameterSpec("decompile", bool, False, "Request decompilation when supported."),
            AdapterParameterSpec("analysis_command", str, "", "Analysis command/script when supported."),
        ])

    if "ddos" in tags or tool.category == "DDOS Attack":
        params.extend([
            AdapterParameterSpec("method", str, "", "Stress-test method/profile when supported."),
            AdapterParameterSpec("port", int, 0, "Target port when supported; 0 leaves default."),
            AdapterParameterSpec("duration", int, 0, "Duration in seconds when supported; 0 leaves default."),
            AdapterParameterSpec("threads", int, 0, "Thread count when supported; 0 leaves default."),
            AdapterParameterSpec("connections", int, 0, "Connection count when supported; 0 leaves default."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value when supported."),
        ])

    if "phishing" in tags or tool.category == "Phishing Attack":
        params.extend([
            AdapterParameterSpec("template", str, "", "Template/site profile name when supported."),
            AdapterParameterSpec("landing_url", str, "", "Authorized training landing URL when supported."),
            AdapterParameterSpec("listener_host", str, "", "Listener host for lab use when supported."),
            AdapterParameterSpec("listener_port", int, 0, "Listener port when supported; 0 leaves default."),
            AdapterParameterSpec("tunnel", str, "", "Tunnel provider/profile when supported."),
            AdapterParameterSpec("domain", str, "", "Authorized domain when supported."),
            AdapterParameterSpec("output_dir", str, "", "Output directory when supported."),
        ])

    if ("payload" in tags or tool.category == "Payload Creation") and tool.name not in {"xanxss", "xsstrike"}:
        params.extend([
            AdapterParameterSpec("payload_type", str, "", "Payload identifier when supported."),
            AdapterParameterSpec("platform", str, "", "Target platform when supported."),
            AdapterParameterSpec("architecture", str, "", "Target architecture when supported."),
            AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
            AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
            AdapterParameterSpec("format", str, "", "Output format when supported."),
            AdapterParameterSpec("encoder", str, "", "Encoder when supported."),
            AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        ])

    if "wireless" in tags or tool.category == "Wireless Attack":
        params.extend([
            AdapterParameterSpec("interface", str, "", "Wireless interface name when supported."),
            AdapterParameterSpec("bssid", str, "", "Authorized AP BSSID when supported."),
            AdapterParameterSpec("essid", str, "", "Authorized AP ESSID when supported."),
            AdapterParameterSpec("channel", str, "", "Wireless channel when supported."),
            AdapterParameterSpec("wordlist", str, "", "Wordlist path when supported."),
            AdapterParameterSpec("handshake_file", str, "", "Handshake/capture file path when supported."),
            AdapterParameterSpec("monitor_mode", bool, False, "Request monitor mode when supported."),
        ])

    if "anonymity" in tags or tool.category == "Anonymously Hiding":
        params.extend([
            AdapterParameterSpec("tor_port", int, 0, "Tor SOCKS port when supported; 0 leaves default."),
            AdapterParameterSpec("control_port", int, 0, "Tor control port when supported; 0 leaves default."),
            AdapterParameterSpec("country", str, "", "Exit country selector when supported."),
            AdapterParameterSpec("instances", int, 0, "Number of Tor instances when supported; 0 leaves default."),
        ])

    if (
        "rat" in tags
        or "c2" in tags
        or "post-exploit" in tags
        or tool.category == "Remote Administration (RAT)"
    ) and tool.category != "Payload Creation":
        params.extend([
            AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
            AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
            AdapterParameterSpec("session_id", str, "", "Session identifier when supported."),
            AdapterParameterSpec("listener", str, "", "Listener/profile name when supported."),
            AdapterParameterSpec("protocol", str, "", "Protocol selector when supported."),
        ])

    if tool.name == "subfinder":
        params.extend([
            AdapterParameterSpec("input_file", str, "", "File containing domains to enumerate."),
            AdapterParameterSpec("sources", str, "", "Comma-separated sources to use."),
            AdapterParameterSpec("exclude_sources", str, "", "Comma-separated sources to exclude."),
            AdapterParameterSpec("all_sources", bool, False, "Use all sources for enumeration."),
            AdapterParameterSpec("recursive", bool, False, "Use only sources that can handle subdomains recursively."),
            AdapterParameterSpec("active", bool, False, "Display active sources in the result."),
            AdapterParameterSpec("match", str, "", "Subdomain or list to match."),
            AdapterParameterSpec("filter", str, "", "Subdomain or list to filter."),
            AdapterParameterSpec("resolvers", str, "", "Comma-separated resolver addresses."),
            AdapterParameterSpec("resolver_file", str, "", "File containing resolver addresses."),
            AdapterParameterSpec("rate_limit", int, 0, "Maximum HTTP requests per second; 0 leaves default."),
            AdapterParameterSpec("rate_limits", str, "", "Per-provider rate limits, for example shodan=10/s."),
            AdapterParameterSpec("threads", int, 0, "Number of concurrent goroutines; 0 leaves default."),
            AdapterParameterSpec("timeout", int, 0, "Seconds before subfinder timeout; 0 leaves default."),
            AdapterParameterSpec("max_time", int, 0, "Minutes to wait for enumeration; 0 leaves default."),
            AdapterParameterSpec("output_file", str, "", "Output file path."),
            AdapterParameterSpec("json_output", bool, False, "Write JSONL output."),
            AdapterParameterSpec("output_dir", str, "", "Directory for per-host JSON output."),
            AdapterParameterSpec("collect_sources", bool, False, "Include all sources in JSON output."),
            AdapterParameterSpec("include_ip", bool, False, "Include host IPs in output."),
            AdapterParameterSpec("exclude_ip", bool, False, "Exclude IPs from JSON output."),
            AdapterParameterSpec("config_file", str, "", "Subfinder config file path."),
            AdapterParameterSpec("provider_config", str, "", "Provider config file path."),
            AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
            AdapterParameterSpec("silent", bool, False, "Show only subdomains in output."),
            AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        ])
    elif tool.name == "amass":
        params.extend([
            AdapterParameterSpec("config_file", str, "", "Path to Amass YAML configuration file."),
            AdapterParameterSpec("output_dir", str, "", "Directory containing the graph database and output files."),
            AdapterParameterSpec("no_color", bool, False, "Disable colorized output."),
            AdapterParameterSpec("silent", bool, False, "Disable all output during execution."),
            AdapterParameterSpec("active", bool, False, "Enable active reconnaissance methods."),
            AdapterParameterSpec("passive", bool, False, "Run purely passive enumeration."),
            AdapterParameterSpec("alts", bool, False, "Enable altered-name generation."),
            AdapterParameterSpec("alteration_wordlist", str, "", "Wordlist file for alterations."),
            AdapterParameterSpec("alteration_masks", str, "", "Hashcat-style masks for name alterations."),
            AdapterParameterSpec("blacklist", str, "", "Blacklisted subdomain names."),
            AdapterParameterSpec("blacklist_file", str, "", "File containing blacklisted subdomains."),
            AdapterParameterSpec("brute", bool, False, "Perform brute-force subdomain enumeration."),
            AdapterParameterSpec("domain_file", str, "", "File providing root domain names."),
            AdapterParameterSpec("exclude_sources", str, "", "Data sources to exclude."),
            AdapterParameterSpec("exclude_file", str, "", "File containing data sources to exclude."),
            AdapterParameterSpec("include_sources", str, "", "Data sources to include."),
            AdapterParameterSpec("include_file", str, "", "File containing data sources to include."),
            AdapterParameterSpec("interface", str, "", "Network interface to send traffic through."),
            AdapterParameterSpec("include_ip", bool, False, "Show IP addresses for discovered names."),
            AdapterParameterSpec("ipv4", bool, False, "Show IPv4 addresses for discovered names."),
            AdapterParameterSpec("ipv6", bool, False, "Show IPv6 addresses for discovered names."),
            AdapterParameterSpec("list_sources", bool, False, "Print available data sources."),
            AdapterParameterSpec("log_file", str, "", "Path to log file for errors."),
            AdapterParameterSpec("max_depth", int, 0, "Maximum subdomain labels for brute forcing; 0 leaves default."),
            AdapterParameterSpec("min_for_recursive", int, 0, "Discoveries before recursive brute forcing; 0 leaves default."),
            AdapterParameterSpec("known_names_file", str, "", "File providing already known subdomain names."),
            AdapterParameterSpec("no_recursive", bool, False, "Turn off recursive brute forcing."),
            AdapterParameterSpec("output_file", str, "", "Text output file path."),
            AdapterParameterSpec("output_prefix", str, "", "Path prefix for all output files."),
            AdapterParameterSpec("ports", str, "", "Ports for active certificate/crawl checks."),
            AdapterParameterSpec("resolvers", str, "", "Untrusted DNS resolver IPs."),
            AdapterParameterSpec("resolver_file", str, "", "File containing untrusted DNS resolvers."),
            AdapterParameterSpec("dns_qps", int, 0, "Maximum DNS queries per second; 0 leaves default."),
            AdapterParameterSpec("resolver_qps", int, 0, "Maximum queries per untrusted resolver; 0 leaves default."),
            AdapterParameterSpec("scripts_dir", str, "", "Directory containing ADS scripts."),
            AdapterParameterSpec("timeout", int, 0, "Minutes to execute enumeration; 0 leaves default."),
            AdapterParameterSpec("trusted_resolvers", str, "", "Trusted DNS resolver IPs."),
            AdapterParameterSpec("trusted_resolver_file", str, "", "File containing trusted DNS resolvers."),
            AdapterParameterSpec("trusted_qps", int, 0, "Maximum queries per trusted resolver; 0 leaves default."),
            AdapterParameterSpec("verbose", bool, False, "Output status, debug, and troubleshooting info."),
            AdapterParameterSpec("wordlist", str, "", "Wordlist file for brute forcing."),
            AdapterParameterSpec("wordlist_masks", str, "", "Hashcat-style masks for DNS brute forcing."),
        ])
    elif (
        tags & {"osint", "subdomain", "dns", "enum", "threat-intel", "shodan"}
        and tool.name not in {"gobuster", "theHarvester"}
    ):
        params.extend([
            AdapterParameterSpec("sources", str, "", "Comma-separated OSINT sources when supported."),
            AdapterParameterSpec("passive", bool, False, "Use passive enumeration when supported."),
            AdapterParameterSpec("resolvers", str, "", "Resolver file path when supported."),
            AdapterParameterSpec("api_key", str, "", "API key/profile name when supported."),
            AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
            AdapterParameterSpec("json_output", bool, False, "Request JSON output when supported."),
        ])

    if tags & {"exploit", "iot", "router", "embedded"}:
        params.extend([
            AdapterParameterSpec("module", str, "", "Exploit/module path when supported."),
            AdapterParameterSpec("rhost", str, "", "Remote host when supported."),
            AdapterParameterSpec("rport", int, 0, "Remote port when supported; 0 leaves default."),
            AdapterParameterSpec("username", str, "", "Username for authorized lab use."),
            AdapterParameterSpec(
                "password",
                str,
                "",
                "Password for lab/authorized use; may be present in process/audit logs.",
            ),
            AdapterParameterSpec("payload", str, "", "Payload/profile selector when supported."),
        ])

    if tags & {"android", "keylogger", "reverse-shell"}:
        params.extend([
            AdapterParameterSpec("apk_path", str, "", "APK path when supported."),
            AdapterParameterSpec("package_name", str, "", "Android package name when supported."),
            AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
            AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
            AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        ])

    if tags & {"utility", "terminal", "multiplexer"}:
        params.extend([
            AdapterParameterSpec("command", str, "", "Command or shell profile when supported."),
            AdapterParameterSpec("session_name", str, "", "Terminal/session name when supported."),
            AdapterParameterSpec("layout", str, "", "Layout/profile name when supported."),
        ])

    if (
        tags & {"scanner", "vuln", "recon", "app", "check"}
        and tool.name not in {"dalfox", "dsss", "owasp-zap", "sqlscan", "theHarvester", "whatweb", "xanxss", "xspear", "xsstrike", "xsscon", "nmap", "nuclei", "httpx", "amass", "masscan", "rustscan", "nikto", "testssl", "wafw00f"}
    ):
        params.extend([
            AdapterParameterSpec("scan_depth", int, 0, "Scan depth when supported; 0 leaves default."),
            AdapterParameterSpec("timeout", int, 0, "Timeout in seconds when supported; 0 leaves default."),
            AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value when supported."),
            AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
            AdapterParameterSpec("json_output", bool, False, "Request JSON output when supported."),
        ])

    if tool.name == "nmap":
        params.extend([
            AdapterParameterSpec("scripts", str, "", "Nmap NSE script selector, for example default,vuln."),
            AdapterParameterSpec("script_args", str, "", "Nmap NSE script arguments."),
            AdapterParameterSpec("exclude_hosts", str, "", "Comma-separated hosts to exclude."),
        ])

    if tool.name == "sqlmap":
        params.extend([
            AdapterParameterSpec("cookie", str, "", "Cookie header for authorized testing."),
            AdapterParameterSpec("headers", str, "", "Additional HTTP headers, newline or semicolon separated."),
            AdapterParameterSpec("tamper", str, "", "Comma-separated sqlmap tamper scripts."),
            AdapterParameterSpec("technique", str, "", "SQLi techniques, for example BEUSTQ."),
            AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
            AdapterParameterSpec("random_agent", bool, False, "Use a random User-Agent."),
        ])

    if tool.name == "ffuf":
        params.extend([
            AdapterParameterSpec("fuzz_keyword", str, "", "Fuzz marker keyword when supported, for example FUZZ."),
            AdapterParameterSpec("host_header", str, "", "Host header for vhost fuzzing when supported."),
            AdapterParameterSpec("recursion_depth", int, 0, "Recursive discovery depth when supported; 0 leaves default."),
        ])

    if tool.name == "nuclei":
        params.extend([
            AdapterParameterSpec("workflows", str, "", "Nuclei workflow file or directory."),
            AdapterParameterSpec("exclude_templates", str, "", "Comma-separated templates to exclude."),
            AdapterParameterSpec("headless", bool, False, "Enable headless browser templates."),
            AdapterParameterSpec("interactsh", bool, False, "Enable interactsh/OAST interaction support."),
        ])

    if tool.name == "sherlock":
        params.extend([
            AdapterParameterSpec("site_list", str, "", "Comma-separated site list when supported."),
            AdapterParameterSpec("csv_output", bool, False, "Request CSV output when supported."),
            AdapterParameterSpec("print_found", bool, False, "Only print found accounts when supported."),
            AdapterParameterSpec("browse", bool, False, "Open found results in browser when supported."),
        ])

    if tool.name in {"prowler", "trivy"}:
        params.extend([
            AdapterParameterSpec("provider", str, "", "Cloud/provider selector when supported."),
            AdapterParameterSpec("checks", str, "", "Comma-separated checks to include when supported."),
            AdapterParameterSpec("excluded_checks", str, "", "Comma-separated checks to exclude when supported."),
            AdapterParameterSpec("output_format", str, "", "Output format when supported."),
            AdapterParameterSpec("ignore_unfixed", bool, False, "Ignore unfixed vulnerabilities when supported."),
        ])

    if tool.name in {"netexec", "certipy", "kerbrute"}:
        params.extend([
            AdapterParameterSpec("users_file", str, "", "Username list path when supported."),
            AdapterParameterSpec("passwords_file", str, "", "Password list path when supported."),
            AdapterParameterSpec("kerberos", bool, False, "Use Kerberos authentication when supported."),
            AdapterParameterSpec("local_auth", bool, False, "Use local authentication when supported."),
            AdapterParameterSpec("target_ip", str, "", "Target/DC IP override when supported."),
        ])

    if tool.name == "volatility3":
        params.extend([
            AdapterParameterSpec("symbol_dir", str, "", "Volatility symbol directory when supported."),
            AdapterParameterSpec("renderer", str, "", "Renderer/output format when supported."),
            AdapterParameterSpec("dump_files", bool, False, "Dump referenced files when supported."),
        ])

    if tool.name == "binwalk":
        params.extend([
            AdapterParameterSpec("signature_scan", bool, False, "Run signature scan when supported."),
            AdapterParameterSpec("entropy", bool, False, "Run entropy analysis when supported."),
            AdapterParameterSpec("matryoshka", bool, False, "Recursively scan extracted files when supported."),
            AdapterParameterSpec("carve", bool, False, "Carve files without full extraction when supported."),
        ])

    if tool.name in {"steghide", "stegcracker"}:
        params.extend([
            AdapterParameterSpec("cover_file", str, "", "Cover file path when supported."),
            AdapterParameterSpec("embed_file", str, "", "File to embed when supported."),
            AdapterParameterSpec("compression_level", int, 0, "Compression level when supported; 0 leaves default."),
            AdapterParameterSpec("encryption", str, "", "Encryption algorithm when supported."),
        ])

    if tool.name in {"hashcat", "john"}:
        params.extend([
            AdapterParameterSpec("rules", str, "", "Rule file/name when supported."),
            AdapterParameterSpec("mask", str, "", "Mask attack pattern when supported."),
            AdapterParameterSpec("session", str, "", "Session name when supported."),
            AdapterParameterSpec("show", bool, False, "Show cracked hashes when supported."),
            AdapterParameterSpec("potfile_path", str, "", "Potfile path when supported."),
        ])

    if tool.name in {"mobsf", "frida", "objection"}:
        params.extend([
            AdapterParameterSpec("server_url", str, "", "Mobile analysis server URL when supported."),
            AdapterParameterSpec("api_key", str, "", "API key/profile when supported."),
            AdapterParameterSpec("frida_script", str, "", "Frida script path or snippet when supported."),
            AdapterParameterSpec("runtime_command", str, "", "Runtime command when supported."),
        ])

    if tool.name in {"jadx", "radare2", "ghidra"}:
        params.extend([
            AdapterParameterSpec("project_name", str, "", "Project name when supported."),
            AdapterParameterSpec("analysis_level", str, "", "Analysis depth/profile when supported."),
            AdapterParameterSpec("entrypoint", str, "", "Entrypoint/address when supported."),
            AdapterParameterSpec("headless", bool, False, "Run in headless mode when supported."),
        ])

    if tool.name == "ffuf":
        params.extend([
            AdapterParameterSpec("filter_codes", str, "", "HTTP status codes to filter out."),
            AdapterParameterSpec("filter_size", str, "", "Response size filter when supported."),
            AdapterParameterSpec("filter_words", str, "", "Word-count filter when supported."),
            AdapterParameterSpec("add_slash", bool, False, "Append trailing slash to discovered paths when supported."),
        ])

    if tool.name in {"bloodhound", "impacket", "responder"}:
        params.extend([
            AdapterParameterSpec("ldap", bool, False, "Use LDAP collection/protocol mode when supported."),
            AdapterParameterSpec("smb", bool, False, "Use SMB protocol mode when supported."),
            AdapterParameterSpec("no_pass", bool, False, "Use no-password auth mode when supported."),
            AdapterParameterSpec("output_prefix", str, "", "Output prefix/path when supported."),
            AdapterParameterSpec("disable_llmnr", bool, False, "Disable LLMNR poisoning when supported."),
        ])

    if tool.name in {"evil-winrm", "pwncat-cs"}:
        params.extend([
            AdapterParameterSpec("ssl", bool, False, "Use SSL/TLS when supported."),
            AdapterParameterSpec("key_file", str, "", "Private key path when supported."),
            AdapterParameterSpec("cert_file", str, "", "Certificate path when supported."),
            AdapterParameterSpec("upload", str, "", "Upload file path when supported."),
            AdapterParameterSpec("download", str, "", "Download path when supported."),
        ])

    if tool.name in {"sliver", "havoc", "ligolo-ng", "chisel"}:
        params.extend([
            AdapterParameterSpec("mode", str, "", "Mode such as server/client/proxy/agent when supported."),
            AdapterParameterSpec("listen_addr", str, "", "Listen address when supported."),
            AdapterParameterSpec("connect_addr", str, "", "Connect address when supported."),
            AdapterParameterSpec("auth_token", str, "", "Auth token/profile when supported."),
            AdapterParameterSpec("tun_name", str, "", "Tunnel interface name when supported."),
        ])

    if tool.name == "peass-ng":
        params.extend([
            AdapterParameterSpec("peas_variant", str, "", "PEASS variant such as linpeas or winpeas."),
            AdapterParameterSpec("checks", str, "", "Checks/profile selector when supported."),
            AdapterParameterSpec("quiet", bool, False, "Reduce output when supported."),
        ])

    if tool.name in {"commix", "nosqlmap", "blisqy", "leviathan", "explo"}:
        params.extend([
            AdapterParameterSpec("parameter", str, "", "Parameter to test when supported."),
            AdapterParameterSpec("method", str, "", "HTTP method when supported."),
            AdapterParameterSpec("delay", int, 0, "Time delay for blind testing when supported; 0 leaves default."),
            AdapterParameterSpec("os_shell", bool, False, "Request OS shell mode when supported."),
            AdapterParameterSpec("batch", bool, True, "Non-interactive/batch mode when supported."),
        ])

    if tool.name in {"routersploit", "websploit"}:
        params.extend([
            AdapterParameterSpec("module", str, "", "Framework module path when supported."),
            AdapterParameterSpec("set_options", str, "", "Comma/semicolon-separated framework option assignments."),
            AdapterParameterSpec("check_only", bool, False, "Check vulnerability without exploitation when supported."),
            AdapterParameterSpec("resource_file", str, "", "Resource/script file when supported."),
        ])

    if tool.name in {"pacu", "scoutsuite"}:
        params.extend([
            AdapterParameterSpec("session", str, "", "Cloud assessment session/profile when supported."),
            AdapterParameterSpec("module", str, "", "Cloud module/service module when supported."),
            AdapterParameterSpec("regions", str, "", "Comma-separated cloud regions when supported."),
            AdapterParameterSpec("report_dir", str, "", "Report directory when supported."),
        ])

    if tool.name in {
        "setoolkit", "pyphisher", "hiddeneye", "blackeye", "shellphish",
        "evilginx3", "maskphish", "blackphish",
    }:
        params.extend([
            AdapterParameterSpec("site", str, "", "Template/site selector when supported."),
            AdapterParameterSpec("redirect_url", str, "", "Redirect URL for authorized training when supported."),
            AdapterParameterSpec("custom_domain", str, "", "Authorized custom domain when supported."),
            AdapterParameterSpec("phishlet", str, "", "Phishlet/profile selector when supported."),
            AdapterParameterSpec("capture_path", str, "", "Capture/output path when supported."),
        ])

    if tool.name in {"msfvenom", "thefatrat", "venom", "mobdroid", "brutal"}:
        params.extend([
            AdapterParameterSpec("stager", str, "", "Stager/profile selector when supported."),
            AdapterParameterSpec("listener_name", str, "", "Listener/profile name when supported."),
            AdapterParameterSpec("apk_name", str, "", "APK/app output name when supported."),
            AdapterParameterSpec("bundle_id", str, "", "Mobile bundle/package id when supported."),
            AdapterParameterSpec("sign_apk", bool, False, "Sign APK output when supported."),
        ])

    if tool.name in {
        "wifite", "airgeddon", "hcxdumptool", "hcxtools", "bettercap",
        "wifiphisher", "fluxion",
    }:
        params.extend([
            AdapterParameterSpec("pmkid", bool, False, "Enable PMKID workflow when supported."),
            AdapterParameterSpec("deauth_count", int, 0, "Deauth packet count when supported; 0 leaves default."),
            AdapterParameterSpec("capture_file", str, "", "Capture/handshake file path when supported."),
            AdapterParameterSpec("target_essid", str, "", "Target ESSID override when supported."),
            AdapterParameterSpec("ble", bool, False, "Enable BLE mode when supported."),
        ])

    if tool.name in {"anonsurf", "multitor"}:
        params.extend([
            AdapterParameterSpec("action", str, "", "Action such as start, stop, restart, or status."),
            AdapterParameterSpec("new_identity", bool, False, "Request a new Tor identity when supported."),
            AdapterParameterSpec("dns_only", bool, False, "Only route DNS when supported."),
        ])

    params.extend([
        AdapterParameterSpec("options", str, "", "Raw additional CLI options appended after generated options."),
        AdapterParameterSpec(
            "confirm_authorized",
            bool,
            False,
            "Set true only for targets you own or have explicit written authorization to test.",
        ),
    ])
    return _dedupe_parameters(params)


def _example_target(tool: HackingToolDef) -> str:
    tags = set(tool.tags)
    if "email" in tags:
        return "user@example.com"
    if tags & {"username", "social", "social-media"}:
        return "testuser"
    if tags & {"web", "http", "url", "xss", "sqli", "injection"}:
        return "http://127.0.0.1:8000"
    if tags & {"subdomain", "dns", "osint"}:
        return "example.com"
    if tags & {"forensics", "reverse", "binary", "hash", "mobile", "stegano"}:
        return "local-test"
    if tool.category == "Cloud Security":
        return ""
    return "localhost"


def _dedupe_parameters(params: list[AdapterParameterSpec]) -> list[AdapterParameterSpec]:
    result: list[AdapterParameterSpec] = []
    seen: set[str] = set()
    for param in params:
        if param.name in seen:
            continue
        seen.add(param.name)
        result.append(param)
    return result


def _request_parts(
    tool: HackingToolDef,
    spec: ToolAdapterSpec,
    kwargs: dict,
) -> tuple[str, str, bool]:
    target = str(kwargs.get("target") or "")
    structured_options = shlex.join(_structured_options(tool, kwargs))
    raw_options = str(kwargs.get("options") or "").strip()
    options = " ".join(item for item in (structured_options, raw_options) if item)
    return target, options, bool(kwargs.get("confirm_authorized", False))


def _structured_options(tool: HackingToolDef, kwargs: dict) -> list[str]:
    tokens: list[str] = []
    tags = set(tool.tags)

    split_options = split_adapter_options(tool.name, kwargs)
    if split_options is not None:
        return split_options

    if tool.name == "masscan":
        _add_value(tokens, kwargs, "ports", "-p")
        _add_value(tokens, kwargs, "rate", "--rate")
        _add_value(tokens, kwargs, "config_file", "-c")
        _add_bool(tokens, kwargs, "echo", "--echo")
        _add_bool(tokens, kwargs, "banners", "--banners")
        _add_value(tokens, kwargs, "source_ip", "--source-ip")
        _add_value(tokens, kwargs, "source_port", "--source-port")
        _add_value(tokens, kwargs, "exclude_file", "--excludefile")
        _add_value(tokens, kwargs, "include_file", "--includefile")
        _add_value(tokens, kwargs, "output_xml", "-oX")
        _add_value(tokens, kwargs, "output_json", "-oJ")
        _add_value(tokens, kwargs, "output_list", "-oL")
        _add_value(tokens, kwargs, "output_grepable", "-oG")
        _add_value(tokens, kwargs, "output_format", "--output-format")
        _add_value(tokens, kwargs, "output_filename", "--output-filename")
        _add_value(tokens, kwargs, "readscan", "--readscan")
    elif tool.name == "rustscan":
        _add_value(tokens, kwargs, "ports", "-p")
        _add_value(tokens, kwargs, "port_range", "-r")
        _add_bool(tokens, kwargs, "no_config", "--no-config")
        _add_bool(tokens, kwargs, "no_banner", "--no-banner")
        _add_value(tokens, kwargs, "config_path", "--config-path")
        _add_bool(tokens, kwargs, "greppable", "-g")
        _add_bool(tokens, kwargs, "accessible", "--accessible")
        _add_value(tokens, kwargs, "resolver", "--resolver")
        _add_value(tokens, kwargs, "batch_size", "-b")
        _add_value(tokens, kwargs, "timeout", "-t")
        _add_value(tokens, kwargs, "tries", "--tries")
        _add_value(tokens, kwargs, "ulimit", "-u")
        _add_value(tokens, kwargs, "scan_order", "--scan-order")
        _add_value(tokens, kwargs, "scripts", "--scripts")
        _add_bool(tokens, kwargs, "top", "--top")
        _add_value(tokens, kwargs, "exclude_ports", "--exclude-ports")
        _add_value(tokens, kwargs, "exclude_addresses", "--exclude-addresses")
        _add_bool(tokens, kwargs, "udp", "--udp")
        nmap_args = str(kwargs.get("nmap_args") or "").strip()
        if nmap_args:
            tokens.append("--")
            tokens.extend(shlex.split(nmap_args))
    elif "port-scan" in tags or "network" in tags:
        _add_value(tokens, kwargs, "ports", "-p")
        _add_scan_type(tokens, kwargs)
        _add_bool(tokens, kwargs, "service_version", "-sV")
        _add_bool(tokens, kwargs, "os_detection", "-O")
        _add_bool(tokens, kwargs, "default_scripts", "-sC")
        timing = _int_value(kwargs, "timing")
        if timing:
            tokens.append(f"-T{timing}")
        _add_value(tokens, kwargs, "top_ports", "--top-ports")
        _add_value(tokens, kwargs, "rate", "--rate")

    if tool.name == "nuclei":
        _add_value(tokens, kwargs, "severity", "-severity")
        _add_value(tokens, kwargs, "tags", "-tags")
        _add_value(tokens, kwargs, "template_path", "-t")
        _add_value(tokens, kwargs, "rate_limit", "-rate-limit")
        _add_value(tokens, kwargs, "proxy", "-proxy")
    elif tool.name == "nikto":
        _add_value(tokens, kwargs, "ask", "-ask")
        _add_value(tokens, kwargs, "cgi_dirs", "-Cgidirs")
        _add_value(tokens, kwargs, "config_file", "-config")
        _add_value(tokens, kwargs, "display", "-Display")
        _add_bool(tokens, kwargs, "dbcheck", "-dbcheck")
        _add_value(tokens, kwargs, "evasion", "-evasion")
        _add_value(tokens, kwargs, "output_format", "-Format")
        _add_value(tokens, kwargs, "auth", "-id")
        _add_bool(tokens, kwargs, "list_plugins", "-list-plugins")
        _add_value(tokens, kwargs, "max_time", "-maxtime")
        _add_value(tokens, kwargs, "mutate", "-mutate")
        _add_value(tokens, kwargs, "mutate_options", "-mutate-options")
        _add_bool(tokens, kwargs, "no_interactive", "-nointeractive")
        _add_bool(tokens, kwargs, "no_lookup", "-nolookup")
        _add_bool(tokens, kwargs, "no_ssl", "-nossl")
        _add_bool(tokens, kwargs, "no_404", "-no404")
        _add_value(tokens, kwargs, "output_file", "-output")
        _add_value(tokens, kwargs, "pause", "-Pause")
        _add_value(tokens, kwargs, "plugins", "-Plugins")
        _add_value(tokens, kwargs, "port", "-port")
        _add_value(tokens, kwargs, "rsa_cert", "-RSAcert")
        _add_value(tokens, kwargs, "root", "-root")
        _add_value(tokens, kwargs, "save_dir", "-Save")
        _add_bool(tokens, kwargs, "ssl", "-ssl")
        _add_value(tokens, kwargs, "tuning", "-Tuning")
        _add_value(tokens, kwargs, "timeout", "-timeout")
        _add_value(tokens, kwargs, "user_agent", "-useragent")
        _add_value(tokens, kwargs, "until", "-until")
        _add_bool(tokens, kwargs, "update", "-update")
        _add_bool(tokens, kwargs, "use_proxy", "-useproxy")
        _add_value(tokens, kwargs, "vhost", "-vhost")
        _add_value(tokens, kwargs, "notfound_code", "-404code")
        _add_value(tokens, kwargs, "notfound_string", "-404string")
    elif tool.name == "katana":
        _add_value(tokens, kwargs, "input_file", "-list")
        _add_value(tokens, kwargs, "depth", "-d")
        _add_value(tokens, kwargs, "strategy", "-strategy")
        _add_bool(tokens, kwargs, "js_crawl", "-jc")
        _add_value(tokens, kwargs, "known_files", "-kf")
        _add_bool(tokens, kwargs, "automatic_form_fill", "-aff")
        _add_bool(tokens, kwargs, "form_extraction", "-fx")
        _add_bool(tokens, kwargs, "headless", "-headless")
        _add_value(tokens, kwargs, "headless_options", "-ho")
        _add_bool(tokens, kwargs, "no_sandbox", "-nos")
        _add_bool(tokens, kwargs, "system_chrome", "-system-chrome")
        _add_value(tokens, kwargs, "proxy", "-proxy")
        _add_value(tokens, kwargs, "headers", "-H")
        _add_value(tokens, kwargs, "timeout", "-timeout")
        _add_value(tokens, kwargs, "retry", "-retry")
        _add_value(tokens, kwargs, "rate_limit", "-rl")
        _add_value(tokens, kwargs, "concurrency", "-c")
        _add_value(tokens, kwargs, "parallelism", "-p")
        _add_value(tokens, kwargs, "delay", "-delay")
        _add_value(tokens, kwargs, "crawl_duration", "-ct")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "json_output", "-jsonl")
        _add_value(tokens, kwargs, "field", "-field")
        _add_bool(tokens, kwargs, "silent", "-silent")
        _add_bool(tokens, kwargs, "no_color", "-no-color")
    elif tool.name == "arjun":
        _add_value(tokens, kwargs, "input_file", "-i")
        _add_value(tokens, kwargs, "output_json", "-oJ")
        _add_value(tokens, kwargs, "output_burp", "-oB")
        _add_value(tokens, kwargs, "output_text", "-oT")
        _add_value(tokens, kwargs, "method", "-m")
        _add_value(tokens, kwargs, "include_data", "--include")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_value(tokens, kwargs, "delay", "-d")
        _add_value(tokens, kwargs, "timeout", "-T")
        _add_bool(tokens, kwargs, "stable", "--stable")
        _add_value(tokens, kwargs, "rate_limit", "--ratelimit")
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "chunk_size", "-c")
        _add_bool(tokens, kwargs, "disable_redirects", "--disable-redirects")
        _add_value(tokens, kwargs, "passive", "--passive")
        _add_value(tokens, kwargs, "casing", "--casing")
        _add_value(tokens, kwargs, "headers", "--headers")
    elif tool.name == "gobuster":
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "extensions", "-x")
        _add_value(tokens, kwargs, "headers", "-H")
        _add_value(tokens, kwargs, "cookies", "-c")
        _add_bool(tokens, kwargs, "show_length", "-l")
        _add_value(tokens, kwargs, "status_codes", "-s")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_value(tokens, kwargs, "delay", "--delay")
        _add_value(tokens, kwargs, "user_agent", "-a")
        _add_value(tokens, kwargs, "timeout", "--timeout")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "quiet", "-q")
        _add_bool(tokens, kwargs, "no_progress", "--no-progress")
        _add_bool(tokens, kwargs, "expanded", "-e")
        _add_bool(tokens, kwargs, "add_slash", "-f")
    elif tool.name == "feroxbuster":
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "extensions", "-x")
        _add_value(tokens, kwargs, "methods", "-m")
        _add_value(tokens, kwargs, "data", "--data")
        _add_value(tokens, kwargs, "headers", "-H")
        _add_value(tokens, kwargs, "cookies", "-b")
        _add_value(tokens, kwargs, "query", "-Q")
        _add_bool(tokens, kwargs, "add_slash", "-f")
        _add_value(tokens, kwargs, "protocol", "--protocol")
        _add_value(tokens, kwargs, "dont_scan", "--dont-scan")
        _add_value(tokens, kwargs, "scope", "--scope")
        _add_value(tokens, kwargs, "filter_size", "-S")
        _add_value(tokens, kwargs, "filter_regex", "-X")
        _add_value(tokens, kwargs, "filter_words", "-W")
        _add_value(tokens, kwargs, "filter_lines", "-N")
        _add_value(tokens, kwargs, "filter_codes", "-C")
        _add_value(tokens, kwargs, "status_codes", "-s")
        _add_bool(tokens, kwargs, "unique", "--unique")
        _add_value(tokens, kwargs, "timeout", "-T")
        _add_bool(tokens, kwargs, "follow_redirects", "-r")
        _add_bool(tokens, kwargs, "insecure", "-k")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_bool(tokens, kwargs, "no_recursion", "-n")
        _add_value(tokens, kwargs, "depth", "-d")
        _add_bool(tokens, kwargs, "force_recursion", "--force-recursion")
        _add_bool(tokens, kwargs, "dont_extract_links", "--dont-extract-links")
        _add_value(tokens, kwargs, "scan_limit", "-L")
        _add_value(tokens, kwargs, "parallelism", "--parallel")
        _add_value(tokens, kwargs, "rate_limit", "--rate-limit")
        _add_value(tokens, kwargs, "response_size_limit", "--response-size-limit")
        _add_value(tokens, kwargs, "time_limit", "--time-limit")
        _add_bool(tokens, kwargs, "auto_tune", "--auto-tune")
        _add_bool(tokens, kwargs, "auto_bail", "--auto-bail")
        _add_bool(tokens, kwargs, "dont_filter", "-D")
        _add_bool(tokens, kwargs, "collect_extensions", "-E")
        _add_value(tokens, kwargs, "collect_backups", "-B")
        _add_bool(tokens, kwargs, "collect_words", "-g")
        _add_value(tokens, kwargs, "dont_collect", "-I")
        verbosity = _int_value(kwargs, "verbosity")
        if verbosity:
            tokens.append("-" + ("v" * min(verbosity, 3)))
        _add_bool(tokens, kwargs, "silent", "--silent")
        _add_bool(tokens, kwargs, "quiet", "-q")
        _add_bool(tokens, kwargs, "json_output", "--json")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_value(tokens, kwargs, "debug_log", "--debug-log")
        _add_bool(tokens, kwargs, "no_state", "--no-state")
        _add_value(tokens, kwargs, "limit_bars", "--limit-bars")
    elif tool.name == "dirsearch":
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "extensions", "-e")
        _add_value(tokens, kwargs, "include_status", "-i")
        _add_value(tokens, kwargs, "exclude_status", "-x")
        _add_value(tokens, kwargs, "exclude_sizes", "-X")
        _add_value(tokens, kwargs, "exclude_text", "--exclude-text")
        _add_value(tokens, kwargs, "exclude_regex", "--exclude-regex")
        _add_value(tokens, kwargs, "prefixes", "--prefixes")
        _add_value(tokens, kwargs, "suffixes", "--suffixes")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_bool(tokens, kwargs, "recursive", "-r")
        _add_bool(tokens, kwargs, "deep_recursive", "--deep-recursive")
        _add_bool(tokens, kwargs, "force_recursive", "--force-recursive")
        _add_value(tokens, kwargs, "recursion_depth", "-R")
        _add_value(tokens, kwargs, "recursion_status", "--recursion-status")
        _add_value(tokens, kwargs, "subdirs", "--subdirs")
        _add_value(tokens, kwargs, "exclude_subdirs", "--exclude-subdirs")
        _add_value(tokens, kwargs, "method", "-m")
        _add_value(tokens, kwargs, "data", "-d")
        _add_value(tokens, kwargs, "headers", "-H")
        _add_value(tokens, kwargs, "header_list", "--header-list")
        _add_bool(tokens, kwargs, "follow_redirects", "-F")
        _add_bool(tokens, kwargs, "random_agent", "--random-agent")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")
        _add_value(tokens, kwargs, "cookies", "--cookie")
        _add_value(tokens, kwargs, "proxy", "--proxy")
        _add_value(tokens, kwargs, "proxy_list", "--proxy-list")
        _add_value(tokens, kwargs, "timeout", "--timeout")
        _add_value(tokens, kwargs, "delay", "--delay")
        _add_value(tokens, kwargs, "max_rate", "--max-rate")
        _add_value(tokens, kwargs, "retries", "--retries")
        _add_value(tokens, kwargs, "format", "--format")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_value(tokens, kwargs, "json_report", "--json-report")
        _add_value(tokens, kwargs, "plain_text_report", "--plain-text-report")
        _add_value(tokens, kwargs, "csv_report", "--csv-report")
        _add_value(tokens, kwargs, "markdown_report", "--md-report")
        _add_value(tokens, kwargs, "xml_report", "--xml-report")
        _add_value(tokens, kwargs, "sqlite_report", "--sqlite-report")
        _add_bool(tokens, kwargs, "quiet", "--quiet")
        _add_bool(tokens, kwargs, "full_url", "--full-url")
        _add_bool(tokens, kwargs, "no_color", "--no-color")
    elif tool.name == "httpx":
        _add_value(tokens, kwargs, "input_file", "-l")
        _add_bool(tokens, kwargs, "status_code", "-sc")
        _add_bool(tokens, kwargs, "title", "-title")
        _add_bool(tokens, kwargs, "tech_detect", "-td")
        _add_bool(tokens, kwargs, "content_length", "-cl")
        _add_value(tokens, kwargs, "match_codes", "-mc")
        _add_value(tokens, kwargs, "filter_codes", "-fc")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_value(tokens, kwargs, "rate_limit", "-rl")
        _add_value(tokens, kwargs, "ports", "-p")
        _add_value(tokens, kwargs, "path", "-path")
        _add_bool(tokens, kwargs, "follow_redirects", "-fr")
        _add_value(tokens, kwargs, "proxy", "-proxy")
        _add_value(tokens, kwargs, "headers", "-H")
        _add_value(tokens, kwargs, "method", "-x")
        _add_value(tokens, kwargs, "timeout", "-timeout")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "json_output", "-json")
        _add_bool(tokens, kwargs, "silent", "-silent")
    elif tool.name == "dalfox":
        _add_value(tokens, kwargs, "blind_callback", "-b")
        _add_value(tokens, kwargs, "config_file", "--config")
        _add_value(tokens, kwargs, "cookies", "-C")
        _add_value(tokens, kwargs, "custom_alert_type", "--custom-alert-type")
        _add_value(tokens, kwargs, "custom_alert_value", "--custom-alert-value")
        _add_value(tokens, kwargs, "custom_payload", "--custom-payload")
        _add_value(tokens, kwargs, "data", "-d")
        _add_bool(tokens, kwargs, "deep_domxss", "--deep-domxss")
        _add_value(tokens, kwargs, "delay", "--delay")
        _add_bool(tokens, kwargs, "follow_redirects", "--follow-redirects")
        _add_bool(tokens, kwargs, "force_headless_verification", "--force-headless-verification")
        _add_value(tokens, kwargs, "headers", "-H")
        _add_value(tokens, kwargs, "ignore_param", "--ignore-param")
        _add_value(tokens, kwargs, "ignore_return", "--ignore-return")
        _add_value(tokens, kwargs, "method", "-X")
        _add_value(tokens, kwargs, "parameter", "-p")
        _add_value(tokens, kwargs, "proxy", "--proxy")
        _add_value(tokens, kwargs, "remote_payloads", "--remote-payloads")
        _add_value(tokens, kwargs, "timeout", "--timeout")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")
        _add_bool(tokens, kwargs, "waf_evasion", "--waf-evasion")
        _add_value(tokens, kwargs, "max_cpu", "--max-cpu")
        _add_value(tokens, kwargs, "workers", "-w")
        _add_bool(tokens, kwargs, "mining_dict", "--mining-dict")
        _add_value(tokens, kwargs, "mining_dict_word", "--mining-dict-word")
        _add_bool(tokens, kwargs, "mining_dom", "--mining-dom")
        _add_value(tokens, kwargs, "remote_wordlists", "--remote-wordlists")
        _add_bool(tokens, kwargs, "skip_mining_all", "--skip-mining-all")
        _add_bool(tokens, kwargs, "skip_mining_dict", "--skip-mining-dict")
        _add_bool(tokens, kwargs, "skip_mining_dom", "--skip-mining-dom")
        _add_bool(tokens, kwargs, "only_custom_payload", "--only-custom-payload")
        _add_bool(tokens, kwargs, "only_discovery", "--only-discovery")
        _add_bool(tokens, kwargs, "skip_bav", "--skip-bav")
        _add_bool(tokens, kwargs, "skip_discovery", "--skip-discovery")
        _add_bool(tokens, kwargs, "skip_grepping", "--skip-grepping")
        _add_bool(tokens, kwargs, "skip_headless", "--skip-headless")
        _add_bool(tokens, kwargs, "skip_xss_scanning", "--skip-xss-scanning")
        _add_bool(tokens, kwargs, "use_bav", "--use-bav")
        _add_bool(tokens, kwargs, "debug", "--debug")
        _add_value(tokens, kwargs, "format", "--format")
        _add_value(tokens, kwargs, "found_action", "--found-action")
        _add_value(tokens, kwargs, "found_action_shell", "--found-action-shell")
        _add_value(tokens, kwargs, "grep_file", "--grep")
        _add_value(tokens, kwargs, "har_file_path", "--har-file-path")
        _add_bool(tokens, kwargs, "no_color", "--no-color")
        _add_bool(tokens, kwargs, "no_spinner", "--no-spinner")
        _add_value(tokens, kwargs, "only_poc", "--only-poc")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "output_all", "--output-all")
        _add_bool(tokens, kwargs, "output_request", "--output-request")
        _add_bool(tokens, kwargs, "output_response", "--output-response")
        _add_value(tokens, kwargs, "poc_type", "--poc-type")
        _add_bool(tokens, kwargs, "report", "--report")
        _add_value(tokens, kwargs, "report_format", "--report-format")
        _add_bool(tokens, kwargs, "silence", "--silence")
    elif tool.name == "xsstrike":
        _add_value(tokens, kwargs, "data", "--data")
        _add_value(tokens, kwargs, "encode", "-e")
        _add_bool(tokens, kwargs, "fuzzer", "--fuzzer")
        _add_bool(tokens, kwargs, "update", "--update")
        _add_value(tokens, kwargs, "timeout", "--timeout")
        _add_bool(tokens, kwargs, "use_proxy", "--proxy")
        _add_bool(tokens, kwargs, "crawl", "--crawl")
        _add_bool(tokens, kwargs, "json_data", "--json")
        _add_bool(tokens, kwargs, "path_injection", "--path")
        _add_value(tokens, kwargs, "seeds_file", "--seeds")
        _add_value(tokens, kwargs, "payload_file", "-f")
        _add_value(tokens, kwargs, "level", "-l")
        _add_value(tokens, kwargs, "headers", "--headers")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_value(tokens, kwargs, "delay", "-d")
        _add_bool(tokens, kwargs, "skip", "--skip")
        _add_bool(tokens, kwargs, "skip_dom", "--skip-dom")
        _add_bool(tokens, kwargs, "blind", "--blind")
        _add_value(tokens, kwargs, "console_log_level", "--console-log-level")
        _add_value(tokens, kwargs, "file_log_level", "--file-log-level")
        _add_value(tokens, kwargs, "log_file", "--log-file")
    elif tool.name == "xspear":
        _add_value(tokens, kwargs, "data", "-d")
        _add_bool(tokens, kwargs, "test_all_params", "-a")
        _add_bool(tokens, kwargs, "no_xss", "--no-xss")
        _add_value(tokens, kwargs, "headers", "--headers")
        _add_value(tokens, kwargs, "cookie", "--cookie")
        _add_value(tokens, kwargs, "custom_payload", "--custom-payload")
        _add_value(tokens, kwargs, "raw_file", "--raw")
        _add_value(tokens, kwargs, "parameter", "-p")
        _add_value(tokens, kwargs, "blind_callback", "-b")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_value(tokens, kwargs, "output_format", "-o")
        _add_value(tokens, kwargs, "config_file", "-c")
        verbosity = _int_value(kwargs, "verbose")
        if verbosity:
            tokens.append("-" + ("v" * min(verbosity, 3)))
    elif tool.name == "xsscon":
        _add_value(tokens, kwargs, "depth", "--depth")
        _add_value(tokens, kwargs, "payload_level", "--payload-level")
        _add_value(tokens, kwargs, "payload", "--payload")
        _add_value(tokens, kwargs, "method", "--method")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")
        _add_value(tokens, kwargs, "single_url", "--single")
        _add_value(tokens, kwargs, "proxy", "--proxy")
        _add_bool(tokens, kwargs, "about", "--about")
        _add_value(tokens, kwargs, "cookie", "--cookie")
    elif tool.name == "xanxss":
        _add_value(tokens, kwargs, "verification_amount", "-a")
        _add_value(tokens, kwargs, "amount_to_find", "-f")
        _add_value(tokens, kwargs, "test_time", "-t")
        _add_value(tokens, kwargs, "payloads", "-p")
        _add_value(tokens, kwargs, "payload_file", "-F")
        _add_bool(tokens, kwargs, "verbose", "-v")
        _add_value(tokens, kwargs, "proxy", "--proxy")
        _add_value(tokens, kwargs, "headers", "--headers")
        _add_value(tokens, kwargs, "throttle", "--throttle")
        _add_bool(tokens, kwargs, "polyglot", "--polyglot")
        _add_value(tokens, kwargs, "prefix", "--prefix")
        _add_value(tokens, kwargs, "suffix", "--suffix")
    elif tool.name == "dsss":
        _add_value(tokens, kwargs, "data", "--data")
        _add_value(tokens, kwargs, "cookie", "--cookie")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")
        _add_value(tokens, kwargs, "referer", "--referer")
        _add_value(tokens, kwargs, "proxy", "--proxy")
    elif tool.name == "sqlscan":
        if kwargs.get("scan", True):
            tokens.append("--scan")
    elif tool.name == "testssl":
        _add_value(tokens, kwargs, "input_file", "--file")
        _add_value(tokens, kwargs, "mode", "--mode")
        _add_value(tokens, kwargs, "warnings", "--warnings")
        _add_value(tokens, kwargs, "connect_timeout", "--connect-timeout")
        _add_value(tokens, kwargs, "openssl_timeout", "--openssl-timeout")
        _add_value(tokens, kwargs, "basic_auth", "--basicauth")
        _add_value(tokens, kwargs, "req_header", "--reqheader")
        _add_value(tokens, kwargs, "mtls_file", "--mtls")
        _add_value(tokens, kwargs, "starttls", "-t")
        _add_value(tokens, kwargs, "xmpp_host", "--xmpphost")
        _add_value(tokens, kwargs, "mx", "--mx")
        _add_value(tokens, kwargs, "ip", "--ip")
        _add_value(tokens, kwargs, "proxy", "--proxy")
        _add_bool(tokens, kwargs, "ipv6", "-6")
        _add_bool(tokens, kwargs, "ssl_native", "--ssl-native")
        _add_value(tokens, kwargs, "openssl_path", "--openssl")
        _add_bool(tokens, kwargs, "bugs", "--bugs")
        _add_bool(tokens, kwargs, "assume_http", "--assuming-http")
        _add_value(tokens, kwargs, "no_dns", "--nodns")
        _add_bool(tokens, kwargs, "sneaky", "--sneaky")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")
        _add_bool(tokens, kwargs, "ids_friendly", "--ids-friendly")
        _add_bool(tokens, kwargs, "phone_out", "--phone-out")
        _add_value(tokens, kwargs, "add_ca", "--add-ca")
        _add_bool(tokens, kwargs, "each_cipher", "-e")
        _add_bool(tokens, kwargs, "cipher_per_proto", "-E")
        _add_bool(tokens, kwargs, "categories", "-s")
        _add_bool(tokens, kwargs, "forward_secrecy", "-f")
        _add_bool(tokens, kwargs, "protocols", "-p")
        _add_bool(tokens, kwargs, "server_preference", "-P")
        _add_bool(tokens, kwargs, "server_defaults", "-S")
        _add_value(tokens, kwargs, "single_cipher", "-x")
        _add_bool(tokens, kwargs, "check_headers", "-h")
        _add_bool(tokens, kwargs, "client_simulation", "-c")
        _add_bool(tokens, kwargs, "grease", "-g")
        _add_bool(tokens, kwargs, "vulnerabilities", "-U")
        _add_bool(tokens, kwargs, "quiet", "-q")
        _add_bool(tokens, kwargs, "wide", "--wide")
        _add_value(tokens, kwargs, "mapping", "--mapping")
        _add_bool(tokens, kwargs, "show_each", "--show-each")
        _add_value(tokens, kwargs, "color", "--color")
        _add_bool(tokens, kwargs, "colorblind", "--colorblind")
        _add_value(tokens, kwargs, "debug", "--debug")
        _add_bool(tokens, kwargs, "disable_rating", "--disable-rating")
        _add_bool(tokens, kwargs, "log", "--log")
        _add_value(tokens, kwargs, "logfile", "--logfile")
        _add_bool(tokens, kwargs, "json_output", "--json")
        _add_value(tokens, kwargs, "jsonfile", "--jsonfile")
        _add_bool(tokens, kwargs, "json_pretty", "--json-pretty")
        _add_value(tokens, kwargs, "jsonfile_pretty", "--jsonfile-pretty")
        _add_bool(tokens, kwargs, "csv_output", "--csv")
        _add_value(tokens, kwargs, "csvfile", "--csvfile")
        _add_bool(tokens, kwargs, "html_output", "--html")
        _add_value(tokens, kwargs, "htmlfile", "--htmlfile")
        _add_value(tokens, kwargs, "out_file", "--outFile")
        _add_value(tokens, kwargs, "outfile", "--outfile")
        _add_value(tokens, kwargs, "severity", "--severity")
        _add_bool(tokens, kwargs, "append", "--append")
        _add_bool(tokens, kwargs, "overwrite", "--overwrite")
        _add_value(tokens, kwargs, "outprefix", "--outprefix")
    elif tool.name == "wafw00f":
        verbosity = _int_value(kwargs, "verbosity")
        if verbosity:
            tokens.extend(["-v"] * min(verbosity, 3))
        _add_bool(tokens, kwargs, "find_all", "-a")
        _add_bool(tokens, kwargs, "no_redirect", "-r")
        _add_value(tokens, kwargs, "test_waf", "-t")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_value(tokens, kwargs, "output_format", "-f")
        _add_value(tokens, kwargs, "input_file", "-i")
        _add_bool(tokens, kwargs, "list_wafs", "-l")
        _add_value(tokens, kwargs, "proxy", "-p")
        _add_bool(tokens, kwargs, "version", "-V")
        _add_value(tokens, kwargs, "headers_file", "-H")
        _add_value(tokens, kwargs, "timeout", "-T")
        _add_bool(tokens, kwargs, "no_color", "--no-colors")
    elif tags & {"web", "http", "url", "discovery", "fuzzing"}:
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_extensions(tokens, tool, kwargs)
        _add_value(tokens, kwargs, "match_codes", "-mc")
        _add_bool(tokens, kwargs, "recursive", "-recursion")
        _add_bool(tokens, kwargs, "follow_redirects", "-r")
        _add_value(tokens, kwargs, "proxy", "-proxy")

    if tags & {"sqli", "injection", "database"} and tool.name not in {"dsss", "sqlscan"}:
        _add_value(tokens, kwargs, "data", "--data")
        _add_value(tokens, kwargs, "dbms", "--dbms")
        _add_value(tokens, kwargs, "risk", "--risk")
        _add_value(tokens, kwargs, "level", "--level")
        _add_bool(tokens, kwargs, "enumerate_databases", "--dbs")

    if "xss" in tags and tool.name not in {"dalfox", "xanxss", "xspear", "xsstrike", "xsscon"}:
        _add_value(tokens, kwargs, "parameter", "-p")
        _add_value(tokens, kwargs, "cookies", "--cookie")
        _add_value(tokens, kwargs, "blind_callback", "-b")

    if "email" in tags and tool.name not in {"theHarvester"}:
        _add_value(tokens, kwargs, "sources", "-b")

    if tags & {"username", "social", "social-media"}:
        _add_value(tokens, kwargs, "timeout", "--timeout")

    if tool.name == "trufflehog":
        _add_bool(tokens, kwargs, "json_output", "--json")
        _add_bool(tokens, kwargs, "github_actions", "--github-actions")
        _add_value(tokens, kwargs, "concurrency", "--concurrency")
        _add_bool(tokens, kwargs, "no_verification", "--no-verification")
        _add_value(tokens, kwargs, "results", "--results")
        _add_bool(tokens, kwargs, "no_color", "--no-color")
        _add_bool(tokens, kwargs, "allow_verification_overlap", "--allow-verification-overlap")
        _add_bool(tokens, kwargs, "filter_unverified", "--filter-unverified")
        _add_value(tokens, kwargs, "filter_entropy", "--filter-entropy")
        _add_value(tokens, kwargs, "config_path", "--config")
        _add_bool(tokens, kwargs, "print_avg_detector_time", "--print-avg-detector-time")
        _add_bool(tokens, kwargs, "fail", "--fail")
        _add_value(tokens, kwargs, "log_level", "--log-level")
    elif tool.name == "gitleaks":
        if kwargs.get("redact", True):
            tokens.append("--redact")
        _add_value(tokens, kwargs, "log_opts", "--log-opts")
        _add_value(tokens, kwargs, "config_path", "--config")
        _add_value(tokens, kwargs, "baseline_path", "--baseline-path")
        _add_value(tokens, kwargs, "ignore_path", "--gitleaks-ignore-path")
        _add_value(tokens, kwargs, "enable_rule", "--enable-rule")
        _add_value(tokens, kwargs, "exit_code", "--exit-code")
        _add_bool(tokens, kwargs, "follow_symlinks", "--follow-symlinks")
        _add_bool(tokens, kwargs, "ignore_allow", "--ignore-gitleaks-allow")
        _add_value(tokens, kwargs, "max_decode_depth", "--max-decode-depth")
        _add_value(tokens, kwargs, "max_archive_depth", "--max-archive-depth")
        _add_value(tokens, kwargs, "max_target_mb", "--max-target-megabytes")
        _add_value(tokens, kwargs, "report_format", "--report-format")
        _add_value(tokens, kwargs, "report_path", "--report-path")
        _add_value(tokens, kwargs, "report_template", "--report-template")
        _add_value(tokens, kwargs, "log_level", "--log-level")
        _add_bool(tokens, kwargs, "no_banner", "--no-banner")
        _add_bool(tokens, kwargs, "no_color", "--no-color")
        _add_bool(tokens, kwargs, "verbose", "--verbose")
    elif tags & {"git", "secrets", "credentials"}:
        if kwargs.get("redact", True):
            tokens.append("--redact")
        _add_value(tokens, kwargs, "since_commit", "--log-opts")

    if "cloud" in tags or tool.category == "Cloud Security":
        _add_value(tokens, kwargs, "profile", "--profile")
        _add_value(tokens, kwargs, "region", "--region")
        _add_value(tokens, kwargs, "services", "--services")
        _add_value(tokens, kwargs, "severity", "--severity")

    if "ad" in tags or tool.category == "Active Directory":
        _add_value(tokens, kwargs, "domain", "-d")
        _add_value(tokens, kwargs, "username", "-u")
        _add_value(tokens, kwargs, "password", "-p")
        _add_value(tokens, kwargs, "hashes", "-H")
        _add_value(tokens, kwargs, "dc_ip", "-dc-ip")
        _add_value(tokens, kwargs, "nameserver", "-ns")
        _add_value(tokens, kwargs, "interface", "-I")
        _add_value(tokens, kwargs, "collection_method", "-c")

    if "forensics" in tags or tool.category == "Forensics":
        _add_value(tokens, kwargs, "output_dir", "-o")
        _add_value(tokens, kwargs, "plugin", "--plugin")
        _add_bool(tokens, kwargs, "extract", "-e")
        _add_value(tokens, kwargs, "profile", "--profile")

    if tool.category == "Wordlist Generator" or tags & {"wordlist", "password", "hash"}:
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "hash_file", "-h")
        _add_value(tokens, kwargs, "hash_type", "-m")
        _add_value(tokens, kwargs, "attack_mode", "-a")
        _add_value(tokens, kwargs, "min_length", "--increment-min")
        _add_value(tokens, kwargs, "max_length", "--increment-max")
        _add_value(tokens, kwargs, "output_file", "-o")

    if "stegano" in tags or tool.category == "Steganography":
        _add_value(tokens, kwargs, "passphrase", "-p")
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_bool(tokens, kwargs, "extract", "extract")
        _add_value(tokens, kwargs, "output_file", "-xf")

    if "mobile" in tags or tool.category == "Mobile Security":
        _add_value(tokens, kwargs, "apk_path", "--apk")
        _add_value(tokens, kwargs, "package_name", "-g")
        _add_value(tokens, kwargs, "device_id", "-D")
        _add_bool(tokens, kwargs, "spawn", "--spawn")

    if "reverse-engineering" in tags or tool.category == "Reverse Engineering":
        _add_value(tokens, kwargs, "binary_path", "-b")
        _add_value(tokens, kwargs, "output_dir", "-d")
        _add_bool(tokens, kwargs, "decompile", "--decompile")
        _add_value(tokens, kwargs, "analysis_command", "-c")

    if "ddos" in tags or tool.category == "DDOS Attack":
        _add_value(tokens, kwargs, "method", "--method")
        _add_value(tokens, kwargs, "port", "-p")
        _add_value(tokens, kwargs, "duration", "--duration")
        _add_value(tokens, kwargs, "threads", "--threads")
        _add_value(tokens, kwargs, "connections", "--connections")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")

    if "phishing" in tags or tool.category == "Phishing Attack":
        _add_value(tokens, kwargs, "template", "--template")
        _add_value(tokens, kwargs, "landing_url", "--url")
        _add_value(tokens, kwargs, "listener_host", "--host")
        _add_value(tokens, kwargs, "listener_port", "--port")
        _add_value(tokens, kwargs, "tunnel", "--tunnel")
        _add_value(tokens, kwargs, "domain", "--domain")
        _add_value(tokens, kwargs, "output_dir", "-o")

    if ("payload" in tags or tool.category == "Payload Creation") and tool.name not in {"xanxss", "xsstrike"}:
        _add_value(tokens, kwargs, "payload_type", "-p")
        _add_value(tokens, kwargs, "platform", "--platform")
        _add_value(tokens, kwargs, "architecture", "-a")
        _add_assignment(tokens, kwargs, "lhost", "LHOST")
        _add_assignment(tokens, kwargs, "lport", "LPORT")
        _add_value(tokens, kwargs, "format", "-f")
        _add_value(tokens, kwargs, "encoder", "-e")
        _add_value(tokens, kwargs, "output_file", "-o")

    if "wireless" in tags or tool.category == "Wireless Attack":
        _add_value(tokens, kwargs, "interface", "-i")
        _add_value(tokens, kwargs, "bssid", "--bssid")
        _add_value(tokens, kwargs, "essid", "--essid")
        _add_value(tokens, kwargs, "channel", "-c")
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "handshake_file", "-r")
        _add_bool(tokens, kwargs, "monitor_mode", "--monitor")

    if "anonymity" in tags or tool.category == "Anonymously Hiding":
        _add_value(tokens, kwargs, "tor_port", "--tor-port")
        _add_value(tokens, kwargs, "control_port", "--control-port")
        _add_value(tokens, kwargs, "country", "--country")
        _add_value(tokens, kwargs, "instances", "--instances")

    if (
        "rat" in tags
        or "c2" in tags
        or "post-exploit" in tags
        or tool.category == "Remote Administration (RAT)"
    ) and tool.category != "Payload Creation":
        _add_value(tokens, kwargs, "lhost", "--lhost")
        _add_value(tokens, kwargs, "lport", "--lport")
        _add_value(tokens, kwargs, "session_id", "--session")
        _add_value(tokens, kwargs, "listener", "--listener")
        _add_value(tokens, kwargs, "protocol", "--protocol")

    if tool.name == "subfinder":
        _add_value(tokens, kwargs, "input_file", "-dL")
        _add_value(tokens, kwargs, "sources", "-s")
        _add_value(tokens, kwargs, "exclude_sources", "-es")
        _add_bool(tokens, kwargs, "all_sources", "-all")
        _add_bool(tokens, kwargs, "recursive", "-recursive")
        _add_bool(tokens, kwargs, "active", "-active")
        _add_value(tokens, kwargs, "match", "-m")
        _add_value(tokens, kwargs, "filter", "-f")
        _add_value(tokens, kwargs, "resolvers", "-r")
        _add_value(tokens, kwargs, "resolver_file", "-rL")
        _add_value(tokens, kwargs, "rate_limit", "-rl")
        _add_value(tokens, kwargs, "rate_limits", "-rls")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_value(tokens, kwargs, "timeout", "-timeout")
        _add_value(tokens, kwargs, "max_time", "-max-time")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "json_output", "-oJ")
        _add_value(tokens, kwargs, "output_dir", "-oD")
        _add_bool(tokens, kwargs, "collect_sources", "-cs")
        _add_bool(tokens, kwargs, "include_ip", "-oI")
        _add_bool(tokens, kwargs, "exclude_ip", "-ei")
        _add_value(tokens, kwargs, "config_file", "-config")
        _add_value(tokens, kwargs, "provider_config", "-pc")
        _add_value(tokens, kwargs, "proxy", "-proxy")
        _add_bool(tokens, kwargs, "silent", "-silent")
        _add_bool(tokens, kwargs, "verbose", "-v")
    elif tool.name == "amass":
        _add_value(tokens, kwargs, "config_file", "-config")
        _add_value(tokens, kwargs, "output_dir", "-dir")
        _add_bool(tokens, kwargs, "no_color", "-nocolor")
        _add_bool(tokens, kwargs, "silent", "-silent")
        _add_bool(tokens, kwargs, "active", "-active")
        _add_bool(tokens, kwargs, "passive", "-passive")
        _add_bool(tokens, kwargs, "alts", "-alts")
        _add_value(tokens, kwargs, "alteration_wordlist", "-aw")
        _add_value(tokens, kwargs, "alteration_masks", "-awm")
        _add_value(tokens, kwargs, "blacklist", "-bl")
        _add_value(tokens, kwargs, "blacklist_file", "-blf")
        _add_bool(tokens, kwargs, "brute", "-brute")
        _add_value(tokens, kwargs, "domain_file", "-df")
        _add_value(tokens, kwargs, "exclude_sources", "-exclude")
        _add_value(tokens, kwargs, "exclude_file", "-ef")
        _add_value(tokens, kwargs, "include_sources", "-include")
        _add_value(tokens, kwargs, "include_file", "-if")
        _add_value(tokens, kwargs, "interface", "-iface")
        _add_bool(tokens, kwargs, "include_ip", "-ip")
        _add_bool(tokens, kwargs, "ipv4", "-ipv4")
        _add_bool(tokens, kwargs, "ipv6", "-ipv6")
        _add_bool(tokens, kwargs, "list_sources", "-list")
        _add_value(tokens, kwargs, "log_file", "-log")
        _add_value(tokens, kwargs, "max_depth", "-max-depth")
        _add_value(tokens, kwargs, "min_for_recursive", "-min-for-recursive")
        _add_value(tokens, kwargs, "known_names_file", "-nf")
        _add_bool(tokens, kwargs, "no_recursive", "-norecursive")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_value(tokens, kwargs, "output_prefix", "-oA")
        _add_value(tokens, kwargs, "ports", "-p")
        _add_value(tokens, kwargs, "resolvers", "-r")
        _add_value(tokens, kwargs, "resolver_file", "-rf")
        _add_value(tokens, kwargs, "dns_qps", "-dns-qps")
        _add_value(tokens, kwargs, "resolver_qps", "-rqps")
        _add_value(tokens, kwargs, "scripts_dir", "-scripts")
        _add_value(tokens, kwargs, "timeout", "-timeout")
        _add_value(tokens, kwargs, "trusted_resolvers", "-tr")
        _add_value(tokens, kwargs, "trusted_resolver_file", "-trf")
        _add_value(tokens, kwargs, "trusted_qps", "-trqps")
        _add_bool(tokens, kwargs, "verbose", "-v")
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "wordlist_masks", "-wm")
    elif (
        tags & {"osint", "subdomain", "dns", "enum", "threat-intel", "shodan"}
        and tool.name not in {"gobuster", "theHarvester"}
    ):
        if "email" not in tags:
            _add_value(tokens, kwargs, "sources", "-sources")
        _add_bool(tokens, kwargs, "passive", "-passive")
        _add_value(tokens, kwargs, "resolvers", "-r")
        _add_value(tokens, kwargs, "api_key", "--api-key")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "json_output", "-json")

    if tags & {"exploit", "iot", "router", "embedded"}:
        _add_value(tokens, kwargs, "module", "--module")
        _add_assignment(tokens, kwargs, "rhost", "RHOST")
        _add_assignment(tokens, kwargs, "rport", "RPORT")
        _add_value(tokens, kwargs, "username", "-u")
        _add_value(tokens, kwargs, "password", "-p")
        _add_value(tokens, kwargs, "payload", "--payload")

    if tags & {"android", "keylogger", "reverse-shell"}:
        _add_value(tokens, kwargs, "apk_path", "--apk")
        _add_value(tokens, kwargs, "package_name", "--package")
        _add_assignment(tokens, kwargs, "lhost", "LHOST")
        _add_assignment(tokens, kwargs, "lport", "LPORT")
        _add_value(tokens, kwargs, "output_file", "-o")

    if tags & {"utility", "terminal", "multiplexer"}:
        _add_value(tokens, kwargs, "command", "-c")
        _add_value(tokens, kwargs, "session_name", "-s")
        _add_value(tokens, kwargs, "layout", "-l")

    if (
        tags & {"scanner", "vuln", "recon", "app", "check"}
        and tool.name not in {"dalfox", "dsss", "owasp-zap", "sqlscan", "theHarvester", "whatweb", "xanxss", "xspear", "xsstrike", "xsscon", "nmap", "nuclei", "httpx", "amass", "masscan", "rustscan", "nikto", "testssl", "wafw00f"}
    ):
        _add_value(tokens, kwargs, "scan_depth", "--depth")
        _add_value(tokens, kwargs, "timeout", "--timeout")
        _add_value(tokens, kwargs, "user_agent", "--user-agent")
        _add_value(tokens, kwargs, "output_file", "-o")
        _add_bool(tokens, kwargs, "json_output", "--json")

    if tool.name == "nmap":
        _add_value(tokens, kwargs, "scripts", "--script")
        _add_value(tokens, kwargs, "script_args", "--script-args")
        _add_value(tokens, kwargs, "exclude_hosts", "--exclude")

    if tool.name == "sqlmap":
        _add_value(tokens, kwargs, "cookie", "--cookie")
        _add_value(tokens, kwargs, "headers", "--headers")
        _add_value(tokens, kwargs, "tamper", "--tamper")
        _add_value(tokens, kwargs, "technique", "--technique")
        _add_value(tokens, kwargs, "proxy", "--proxy")
        _add_bool(tokens, kwargs, "random_agent", "--random-agent")

    if tool.name == "ffuf":
        _add_value(tokens, kwargs, "host_header", "-H")
        _add_value(tokens, kwargs, "recursion_depth", "-recursion-depth")

    if tool.name == "nuclei":
        _add_value(tokens, kwargs, "workflows", "-w")
        _add_value(tokens, kwargs, "exclude_templates", "-exclude-templates")
        _add_bool(tokens, kwargs, "headless", "-headless")
        _add_bool(tokens, kwargs, "interactsh", "-interactsh-server")

    if tool.name == "sherlock":
        _add_value(tokens, kwargs, "site_list", "--site")
        _add_bool(tokens, kwargs, "csv_output", "--csv")
        _add_bool(tokens, kwargs, "print_found", "--print-found")
        _add_bool(tokens, kwargs, "browse", "--browse")

    if tool.name in {"prowler", "trivy"}:
        _add_value(tokens, kwargs, "provider", "--provider")
        _add_value(tokens, kwargs, "checks", "--checks")
        _add_value(tokens, kwargs, "excluded_checks", "--excluded-checks")
        _add_value(tokens, kwargs, "output_format", "--output")
        _add_bool(tokens, kwargs, "ignore_unfixed", "--ignore-unfixed")

    if tool.name in {"netexec", "certipy", "kerbrute"}:
        _add_value(tokens, kwargs, "users_file", "-U")
        _add_value(tokens, kwargs, "passwords_file", "-P")
        _add_bool(tokens, kwargs, "kerberos", "-k")
        _add_bool(tokens, kwargs, "local_auth", "--local-auth")
        _add_value(tokens, kwargs, "target_ip", "--target-ip")

    if tool.name == "volatility3":
        _add_value(tokens, kwargs, "symbol_dir", "--symbol-dirs")
        _add_value(tokens, kwargs, "renderer", "--renderer")
        _add_bool(tokens, kwargs, "dump_files", "--dump")

    if tool.name == "binwalk":
        _add_bool(tokens, kwargs, "signature_scan", "-B")
        _add_bool(tokens, kwargs, "entropy", "-E")
        _add_bool(tokens, kwargs, "matryoshka", "-M")
        _add_bool(tokens, kwargs, "carve", "--carve")

    if tool.name in {"steghide", "stegcracker"}:
        _add_value(tokens, kwargs, "cover_file", "-cf")
        _add_value(tokens, kwargs, "embed_file", "-ef")
        _add_value(tokens, kwargs, "compression_level", "-z")
        _add_value(tokens, kwargs, "encryption", "-e")

    if tool.name in {"hashcat", "john"}:
        _add_value(tokens, kwargs, "rules", "-r")
        _add_value(tokens, kwargs, "mask", "--mask")
        _add_value(tokens, kwargs, "session", "--session")
        _add_bool(tokens, kwargs, "show", "--show")
        _add_value(tokens, kwargs, "potfile_path", "--potfile-path")

    if tool.name in {"mobsf", "frida", "objection"}:
        _add_value(tokens, kwargs, "server_url", "--server")
        _add_value(tokens, kwargs, "api_key", "--api-key")
        _add_value(tokens, kwargs, "frida_script", "-l")
        _add_value(tokens, kwargs, "runtime_command", "-c")

    if tool.name in {"jadx", "radare2", "ghidra"}:
        _add_value(tokens, kwargs, "project_name", "--project")
        _add_value(tokens, kwargs, "analysis_level", "--analysis")
        _add_value(tokens, kwargs, "entrypoint", "--entrypoint")
        _add_bool(tokens, kwargs, "headless", "--headless")

    if tool.name == "ffuf":
        _add_value(tokens, kwargs, "filter_codes", "-fc")
        _add_value(tokens, kwargs, "filter_size", "-fs")
        _add_value(tokens, kwargs, "filter_words", "-fw")
        _add_bool(tokens, kwargs, "add_slash", "--add-slash")

    if tool.name in {"bloodhound", "impacket", "responder"}:
        _add_bool(tokens, kwargs, "ldap", "--ldap")
        _add_bool(tokens, kwargs, "smb", "--smb")
        _add_bool(tokens, kwargs, "no_pass", "--no-pass")
        _add_value(tokens, kwargs, "output_prefix", "-o")
        _add_bool(tokens, kwargs, "disable_llmnr", "-d")

    if tool.name in {"evil-winrm", "pwncat-cs"}:
        _add_bool(tokens, kwargs, "ssl", "-S")
        _add_value(tokens, kwargs, "key_file", "-k")
        _add_value(tokens, kwargs, "cert_file", "-c")
        _add_value(tokens, kwargs, "upload", "--upload")
        _add_value(tokens, kwargs, "download", "--download")

    if tool.name in {"sliver", "havoc", "ligolo-ng", "chisel"}:
        _add_value(tokens, kwargs, "mode", "--mode")
        _add_value(tokens, kwargs, "listen_addr", "--listen")
        _add_value(tokens, kwargs, "connect_addr", "--connect")
        _add_value(tokens, kwargs, "auth_token", "--auth")
        _add_value(tokens, kwargs, "tun_name", "--tun")

    if tool.name == "peass-ng":
        _add_value(tokens, kwargs, "peas_variant", "--variant")
        _add_value(tokens, kwargs, "checks", "--checks")
        _add_bool(tokens, kwargs, "quiet", "-q")

    if tool.name in {"commix", "nosqlmap", "blisqy", "leviathan", "explo"}:
        _add_value(tokens, kwargs, "parameter", "-p")
        _add_value(tokens, kwargs, "method", "--method")
        _add_value(tokens, kwargs, "delay", "--time-sec")
        _add_bool(tokens, kwargs, "os_shell", "--os-shell")
        if kwargs.get("batch", True):
            tokens.append("--batch")

    if tool.name in {"routersploit", "websploit"}:
        _add_value(tokens, kwargs, "set_options", "--set")
        _add_bool(tokens, kwargs, "check_only", "--check")
        _add_value(tokens, kwargs, "resource_file", "-r")

    if tool.name in {"pacu", "scoutsuite"}:
        _add_value(tokens, kwargs, "session", "--session")
        if tool.name != "pacu":
            _add_value(tokens, kwargs, "module", "--module")
        _add_value(tokens, kwargs, "regions", "--regions")
        _add_value(tokens, kwargs, "report_dir", "--report-dir")

    if tool.name in {
        "setoolkit", "pyphisher", "hiddeneye", "blackeye", "shellphish",
        "evilginx3", "maskphish", "blackphish",
    }:
        _add_value(tokens, kwargs, "site", "--site")
        _add_value(tokens, kwargs, "redirect_url", "--redirect")
        _add_value(tokens, kwargs, "custom_domain", "--domain")
        _add_value(tokens, kwargs, "phishlet", "--phishlet")
        _add_value(tokens, kwargs, "capture_path", "--capture-path")

    if tool.name in {"msfvenom", "thefatrat", "venom", "mobdroid", "brutal"}:
        _add_value(tokens, kwargs, "stager", "--stager")
        _add_value(tokens, kwargs, "listener_name", "--listener")
        _add_value(tokens, kwargs, "apk_name", "--apk-name")
        _add_value(tokens, kwargs, "bundle_id", "--bundle-id")
        _add_bool(tokens, kwargs, "sign_apk", "--sign")

    if tool.name in {
        "wifite", "airgeddon", "hcxdumptool", "hcxtools", "bettercap",
        "wifiphisher", "fluxion",
    }:
        _add_bool(tokens, kwargs, "pmkid", "--pmkid")
        _add_value(tokens, kwargs, "deauth_count", "--deauth")
        _add_value(tokens, kwargs, "capture_file", "--capture")
        _add_value(tokens, kwargs, "target_essid", "--essid")
        _add_bool(tokens, kwargs, "ble", "--ble")

    if tool.name in {"anonsurf", "multitor"}:
        _add_value(tokens, kwargs, "action", "--action")
        _add_bool(tokens, kwargs, "new_identity", "--new-identity")
        _add_bool(tokens, kwargs, "dns_only", "--dns-only")

    return tokens


def _add_value(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    value = kwargs.get(key)
    if value in (None, "", 0, False):
        return
    tokens.extend([flag, str(value)])


def _add_bool(tokens: list[str], kwargs: dict, key: str, flag: str) -> None:
    if kwargs.get(key):
        tokens.append(flag)


def _add_assignment(tokens: list[str], kwargs: dict, key: str, name: str) -> None:
    value = kwargs.get(key)
    if value in (None, "", 0, False):
        return
    tokens.append(f"{name}={value}")


def _add_scan_type(tokens: list[str], kwargs: dict) -> None:
    scan_type = str(kwargs.get("scan_type") or "").lower()
    scan_flags = {
        "syn": "-sS",
        "tcp": "-sT",
        "udp": "-sU",
        "ping": "-sn",
    }
    if scan_type in scan_flags:
        tokens.append(scan_flags[scan_type])


def _add_extensions(tokens: list[str], tool: HackingToolDef, kwargs: dict) -> None:
    extensions = kwargs.get("extensions")
    if not extensions:
        return
    flag = "-x" if tool.name == "gobuster" else "-e"
    tokens.extend([flag, str(extensions)])


def _int_value(kwargs: dict, key: str) -> int:
    try:
        return int(kwargs.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _unique_mcp_name(tool_name: str, used_names: set[str]) -> str:
    base = MCP_TOOL_PREFIX + re.sub(r"[^a-zA-Z0-9_]+", "_", tool_name).strip("_").lower()
    if not base or base == MCP_TOOL_PREFIX:
        base = MCP_TOOL_PREFIX + "tool"
    candidate = base
    index = 2
    while candidate in used_names:
        candidate = f"{base}_{index}"
        index += 1
    used_names.add(candidate)
    return candidate


def _should_validate_scope(tool: HackingToolDef) -> bool:
    if tool.category in LOCAL_TARGET_CATEGORIES:
        return False
    if tool.category == "Cloud Security":
        return False
    if "{target}" not in tool.run_command:
        return False
    tags = set(tool.tags)
    if tags & {"forensics", "hash", "password", "reverse", "binary", "mobile", "stego"}:
        return False
    if tool.safety_tier == SafetyTier.SAFE and tags & {"git", "secrets"}:
        return False
    return True


def _options_before_target(tool: HackingToolDef) -> bool:
    return tool.name == "testssl"
