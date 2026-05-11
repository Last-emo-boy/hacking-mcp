"""Dedicated adapter metadata for Crivo."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_mode", str, "file", "Input mode: file, webpage, or webpage_list."),
        AdapterParameterSpec("input_file", str, "", "Input text file for -f/--file."),
        AdapterParameterSpec("webpage", str, "", "Single webpage URL for -w/--webpage."),
        AdapterParameterSpec("webpage_list", str, "", "File containing webpage URLs for -W/--webpage-list."),
        AdapterParameterSpec("output_file", str, "", "Output file path for -o/--output."),
        AdapterParameterSpec("scope", str, "", "Comma-separated filters: ips, urls, domains, subdomains."),
        AdapterParameterSpec("ip", bool, False, "Filter only IP addresses."),
        AdapterParameterSpec("ipv4", bool, False, "Filter only IPv4 addresses."),
        AdapterParameterSpec("ipv6", bool, False, "Filter only IPv6 addresses."),
        AdapterParameterSpec("domain", bool, False, "Filter only domains and subdomains."),
        AdapterParameterSpec("url", bool, False, "Filter only URLs."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("version", bool, False, "Show Crivo version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "version", "-V")
    if "version" not in tokens:
        _add_input(tokens, kwargs)
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "scope", "-s")
    add_bool(tokens, kwargs, "ip", "--ip")
    add_bool(tokens, kwargs, "ipv4", "--ipv4")
    add_bool(tokens, kwargs, "ipv6", "--ipv6")
    add_bool(tokens, kwargs, "domain", "--domain")
    add_bool(tokens, kwargs, "url", "--url")
    add_bool(tokens, kwargs, "verbose", "-v")
    return tokens


def _add_input(tokens: list[str], kwargs: dict) -> None:
    mode = str(kwargs.get("input_mode") or "file").strip().lower()
    target = str(kwargs.get("target") or "").strip()
    if mode in {"webpage", "web", "url"}:
        value = str(kwargs.get("webpage") or target).strip()
        if value:
            tokens.extend(["-w", value])
        return
    if mode in {"webpage_list", "webpage-list", "web_list", "list"}:
        value = str(kwargs.get("webpage_list") or target).strip()
        if value:
            tokens.extend(["-W", value])
        return
    value = str(kwargs.get("input_file") or target).strip()
    if value:
        tokens.extend(["-f", value])
