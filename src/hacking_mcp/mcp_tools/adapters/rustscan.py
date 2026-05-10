"""Dedicated adapter metadata for RustScan."""

import shlex

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
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
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "ports", "-p")
    add_value(tokens, kwargs, "port_range", "-r")
    add_bool(tokens, kwargs, "no_config", "--no-config")
    add_bool(tokens, kwargs, "no_banner", "--no-banner")
    add_value(tokens, kwargs, "config_path", "--config-path")
    add_bool(tokens, kwargs, "greppable", "-g")
    add_bool(tokens, kwargs, "accessible", "--accessible")
    add_value(tokens, kwargs, "resolver", "--resolver")
    add_value(tokens, kwargs, "batch_size", "-b")
    add_value(tokens, kwargs, "timeout", "-t")
    add_value(tokens, kwargs, "tries", "--tries")
    add_value(tokens, kwargs, "ulimit", "-u")
    add_value(tokens, kwargs, "scan_order", "--scan-order")
    add_value(tokens, kwargs, "scripts", "--scripts")
    add_bool(tokens, kwargs, "top", "--top")
    add_value(tokens, kwargs, "exclude_ports", "--exclude-ports")
    add_value(tokens, kwargs, "exclude_addresses", "--exclude-addresses")
    add_bool(tokens, kwargs, "udp", "--udp")
    nmap_args = str(kwargs.get("nmap_args") or "").strip()
    if nmap_args:
        tokens.append("--")
        tokens.extend(shlex.split(nmap_args))
    return tokens
