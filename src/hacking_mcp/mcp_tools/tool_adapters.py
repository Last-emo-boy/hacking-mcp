"""Per-tool MCP adapters generated from the tool registry.

The grouped endpoints stay available for broad workflows. This module adds one
dedicated MCP tool per catalog tool. Executable adapters route through
ToolOrchestrator and SafetyPolicy; blocked adapters return policy information.
"""

import re
import shlex
from inspect import Parameter, Signature
from dataclasses import dataclass
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from hacking_mcp.ai_help import build_ai_help
from hacking_mcp.models import HackingToolDef, SafetyTier
from hacking_mcp.orchestrator import ToolOrchestrator, ToolRequest
from hacking_mcp.registry import ToolRegistry
from hacking_mcp.safety import SafetyPolicy


MCP_TOOL_PREFIX = "security_tool_"

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


@dataclass(frozen=True)
class AdapterParameterSpec:
    """A generated MCP argument for a per-tool adapter."""

    name: str
    typ: type
    default: Any
    description: str

    def annotation(self) -> Any:
        return Annotated[self.typ, Field(description=self.description)]


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

    if "port-scan" in tags or "network" in tags:
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

    if tags & {"sqli", "injection", "database"}:
        params.extend([
            AdapterParameterSpec("data", str, "", "Optional POST body or data string."),
            AdapterParameterSpec("dbms", str, "", "Force DBMS fingerprint, for example MySQL or PostgreSQL."),
            AdapterParameterSpec("risk", int, 0, "Risk level 1-3 when supported; 0 leaves default."),
            AdapterParameterSpec("level", int, 0, "Test level 1-5 when supported; 0 leaves default."),
            AdapterParameterSpec("enumerate_databases", bool, False, "Request database enumeration when supported."),
        ])

    if "xss" in tags:
        params.extend([
            AdapterParameterSpec("parameter", str, "", "Parameter name to test when supported."),
            AdapterParameterSpec("cookies", str, "", "Cookie header value when supported."),
            AdapterParameterSpec("blind_callback", str, "", "Blind XSS callback URL when supported."),
        ])

    if "email" in tags:
        params.append(AdapterParameterSpec("sources", str, "", "OSINT source selector when supported."))

    if tags & {"username", "social", "social-media"}:
        params.append(AdapterParameterSpec("timeout", int, 0, "Per-site timeout in seconds when supported."))

    if tags & {"git", "secrets", "credentials"}:
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

    if "payload" in tags or tool.category == "Payload Creation":
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

    if "port-scan" in tags or "network" in tags:
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
    elif tags & {"web", "http", "url", "discovery", "fuzzing"}:
        _add_value(tokens, kwargs, "wordlist", "-w")
        _add_value(tokens, kwargs, "threads", "-t")
        _add_extensions(tokens, tool, kwargs)
        _add_value(tokens, kwargs, "match_codes", "-mc")
        _add_bool(tokens, kwargs, "recursive", "-recursion")
        _add_bool(tokens, kwargs, "follow_redirects", "-r")
        _add_value(tokens, kwargs, "proxy", "-proxy")

    if tags & {"sqli", "injection", "database"}:
        _add_value(tokens, kwargs, "data", "--data")
        _add_value(tokens, kwargs, "dbms", "--dbms")
        _add_value(tokens, kwargs, "risk", "--risk")
        _add_value(tokens, kwargs, "level", "--level")
        _add_bool(tokens, kwargs, "enumerate_databases", "--dbs")

    if "xss" in tags:
        _add_value(tokens, kwargs, "parameter", "-p")
        _add_value(tokens, kwargs, "cookies", "--cookie")
        _add_value(tokens, kwargs, "blind_callback", "-b")

    if "email" in tags:
        _add_value(tokens, kwargs, "sources", "-b")

    if tags & {"username", "social", "social-media"}:
        _add_value(tokens, kwargs, "timeout", "--timeout")

    if tags & {"git", "secrets", "credentials"}:
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

    if "payload" in tags or tool.category == "Payload Creation":
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
