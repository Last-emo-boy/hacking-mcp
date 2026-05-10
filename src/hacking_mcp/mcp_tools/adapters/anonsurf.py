"""Dedicated adapter metadata for Anonsurf."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return _anonymity_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _anonymity_options(kwargs)


def _anonymity_parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("tor_port", int, 0, "Tor SOCKS port when supported; 0 leaves default."),
        AdapterParameterSpec("control_port", int, 0, "Tor control port when supported; 0 leaves default."),
        AdapterParameterSpec("country", str, "", "Exit country selector when supported."),
        AdapterParameterSpec("instances", int, 0, "Number of Tor instances when supported; 0 leaves default."),
        AdapterParameterSpec("action", str, "", "Action such as start, stop, restart, or status."),
        AdapterParameterSpec("new_identity", bool, False, "Request a new Tor identity when supported."),
        AdapterParameterSpec("dns_only", bool, False, "Only route DNS when supported."),
    ]


def _anonymity_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "tor_port", "--tor-port")
    add_value(tokens, kwargs, "control_port", "--control-port")
    add_value(tokens, kwargs, "country", "--country")
    add_value(tokens, kwargs, "instances", "--instances")
    add_value(tokens, kwargs, "action", "--action")
    add_bool(tokens, kwargs, "new_identity", "--new-identity")
    add_bool(tokens, kwargs, "dns_only", "--dns-only")
    return tokens
