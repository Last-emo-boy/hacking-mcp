"""Dedicated adapter metadata for Bettercap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value
from hacking_mcp.mcp_tools.adapters.wifite import _wireless_options, _wireless_parameters


def parameters() -> list[AdapterParameterSpec]:
    return [
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
        *_wireless_parameters(),
        AdapterParameterSpec("scan_depth", int, 0, "Scan depth when supported; 0 leaves default."),
        AdapterParameterSpec("timeout", int, 0, "Timeout in seconds when supported; 0 leaves default."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value when supported."),
        AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        AdapterParameterSpec("json_output", bool, False, "Request JSON output when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "ports", "-p")
    _add_scan_type(tokens, kwargs)
    add_bool(tokens, kwargs, "service_version", "-sV")
    add_bool(tokens, kwargs, "os_detection", "-O")
    add_bool(tokens, kwargs, "default_scripts", "-sC")
    timing = int_value(kwargs, "timing")
    if timing:
        tokens.append(f"-T{timing}")
    add_value(tokens, kwargs, "top_ports", "--top-ports")
    add_value(tokens, kwargs, "rate", "--rate")
    tokens.extend(_wireless_options(kwargs))
    add_value(tokens, kwargs, "scan_depth", "--depth")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "json_output", "--json")
    return tokens


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
