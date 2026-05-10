"""Dedicated adapter metadata for Chisel."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
        AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
        AdapterParameterSpec("session_id", str, "", "Session identifier when supported."),
        AdapterParameterSpec("listener", str, "", "Listener/profile name when supported."),
        AdapterParameterSpec("protocol", str, "", "Protocol selector when supported."),
        AdapterParameterSpec("mode", str, "", "Mode such as server/client/proxy/agent when supported."),
        AdapterParameterSpec("listen_addr", str, "", "Listen address when supported."),
        AdapterParameterSpec("connect_addr", str, "", "Connect address when supported."),
        AdapterParameterSpec("auth_token", str, "", "Auth token/profile when supported."),
        AdapterParameterSpec("tun_name", str, "", "Tunnel interface name when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "lhost", "--lhost")
    add_value(tokens, kwargs, "lport", "--lport")
    add_value(tokens, kwargs, "session_id", "--session")
    add_value(tokens, kwargs, "listener", "--listener")
    add_value(tokens, kwargs, "protocol", "--protocol")
    add_value(tokens, kwargs, "mode", "--mode")
    add_value(tokens, kwargs, "listen_addr", "--listen")
    add_value(tokens, kwargs, "connect_addr", "--connect")
    add_value(tokens, kwargs, "auth_token", "--auth")
    add_value(tokens, kwargs, "tun_name", "--tun")
    return tokens
