"""Dedicated adapter metadata for Nmap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


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
        AdapterParameterSpec("scripts", str, "", "Nmap NSE script selector, for example default,vuln."),
        AdapterParameterSpec("script_args", str, "", "Nmap NSE script arguments."),
        AdapterParameterSpec("exclude_hosts", str, "", "Comma-separated hosts to exclude."),
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
    add_value(tokens, kwargs, "scripts", "--script")
    add_value(tokens, kwargs, "script_args", "--script-args")
    add_value(tokens, kwargs, "exclude_hosts", "--exclude")
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
