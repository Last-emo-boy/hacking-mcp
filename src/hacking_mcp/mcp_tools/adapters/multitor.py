"""Dedicated adapter metadata for Multitor."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("init_instances", int, 0, "Initialize this many Tor instances; 0 leaves unset."),
        AdapterParameterSpec("user", str, "", "User used with --init."),
        AdapterParameterSpec("socks_port", str, "", "SOCKS port number or all."),
        AdapterParameterSpec("control_port", int, 0, "Tor control port; 0 leaves unset."),
        AdapterParameterSpec("proxy", str, "", "Proxy type: socks, polipo, privoxy, or hpts."),
        AdapterParameterSpec("haproxy", bool, False, "Use HAProxy as a frontend for HTTP proxies."),
        AdapterParameterSpec("kill", bool, False, "Kill all multitor processes."),
        AdapterParameterSpec("show_id", bool, False, "Show Tor process IDs."),
        AdapterParameterSpec("new_id", bool, False, "Regenerate Tor circuits."),
        AdapterParameterSpec("debug", bool, False, "Display debug information."),
        AdapterParameterSpec("verbose", bool, False, "Display more Tor process information."),
        AdapterParameterSpec("help", bool, False, "Show multitor help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "help", "--help")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_value(tokens, kwargs, "init_instances", "--init")
    add_bool(tokens, kwargs, "kill", "--kill")
    add_bool(tokens, kwargs, "show_id", "--show-id")
    add_bool(tokens, kwargs, "new_id", "--new-id")
    add_value(tokens, kwargs, "user", "--user")
    add_value(tokens, kwargs, "socks_port", "--socks-port")
    add_value(tokens, kwargs, "control_port", "--control-port")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_bool(tokens, kwargs, "haproxy", "--haproxy")
    return tokens
