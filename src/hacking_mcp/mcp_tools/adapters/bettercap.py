"""Dedicated adapter metadata for Bettercap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("iface", str, "", "Network interface to bind to."),
        AdapterParameterSpec("gateway_override", str, "", "Gateway IP override."),
        AdapterParameterSpec("autostart", str, "", "Comma-separated modules to auto start."),
        AdapterParameterSpec("caplet", str, "", "Caplet file to execute in the interactive session."),
        AdapterParameterSpec("eval_commands", str, "", "Commands separated by semicolons to evaluate in the session."),
        AdapterParameterSpec("debug", bool, False, "Print debug messages."),
        AdapterParameterSpec("silent", bool, False, "Suppress logs that are not errors."),
        AdapterParameterSpec("no_colors", bool, False, "Disable output color effects."),
        AdapterParameterSpec("no_history", bool, False, "Disable interactive session history file."),
        AdapterParameterSpec("env_file", str, "", "Environment file path, or empty to use upstream default."),
        AdapterParameterSpec("cpu_profile", str, "", "CPU profile output file."),
        AdapterParameterSpec("mem_profile", str, "", "Memory profile output file."),
        AdapterParameterSpec("caplets_path", str, "", "Alternative base path for caplets."),
        AdapterParameterSpec("script", str, "", "Session script to load."),
        AdapterParameterSpec("pcap_buf_size", int, 0, "PCAP buffer size; 0 leaves upstream default."),
        AdapterParameterSpec("version", bool, False, "Print the version and exit."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "iface", "-iface")
    add_value(tokens, kwargs, "gateway_override", "-gateway-override")
    add_value(tokens, kwargs, "autostart", "-autostart")
    add_value(tokens, kwargs, "caplet", "-caplet")
    add_value(tokens, kwargs, "eval_commands", "-eval")
    add_bool(tokens, kwargs, "debug", "-debug")
    add_bool(tokens, kwargs, "silent", "-silent")
    add_bool(tokens, kwargs, "no_colors", "-no-colors")
    add_bool(tokens, kwargs, "no_history", "-no-history")
    add_value(tokens, kwargs, "env_file", "-env-file")
    add_value(tokens, kwargs, "cpu_profile", "-cpu-profile")
    add_value(tokens, kwargs, "mem_profile", "-mem-profile")
    add_value(tokens, kwargs, "caplets_path", "-caplets-path")
    add_value(tokens, kwargs, "script", "-script")
    pcap_buf_size = int_value(kwargs, "pcap_buf_size")
    if pcap_buf_size:
        tokens.extend(["-pcap-buf-size", str(pcap_buf_size)])
    add_bool(tokens, kwargs, "version", "-version")
    return tokens
