"""Dedicated adapter metadata for Evilginx3."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("phishlets_dir", str, "", "Phishlets directory path for -p."),
        AdapterParameterSpec("redirectors_dir", str, "", "HTML redirector pages directory path for -t."),
        AdapterParameterSpec("config_dir", str, "", "Configuration directory path for -c."),
        AdapterParameterSpec("debug", bool, False, "Enable debug output."),
        AdapterParameterSpec("developer", bool, False, "Enable developer mode with self-signed certificates."),
        AdapterParameterSpec("version", bool, False, "Show Evilginx version and exit."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "phishlets_dir", "-p")
    add_value(tokens, kwargs, "redirectors_dir", "-t")
    add_value(tokens, kwargs, "config_dir", "-c")
    add_bool(tokens, kwargs, "debug", "-debug")
    add_bool(tokens, kwargs, "developer", "-developer")
    add_bool(tokens, kwargs, "version", "-v")
    return tokens
