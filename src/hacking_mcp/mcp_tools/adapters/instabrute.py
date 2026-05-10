"""Dedicated adapter metadata for Instabrute."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("user_file", str, "", "Legacy instaBrute username file option (-f/--file)."),
        AdapterParameterSpec("dictionary", str, "", "Legacy instaBrute password dictionary option (-d/--dictionary)."),
        AdapterParameterSpec("username", str, "", "Legacy instaBrute single username option (-u/--username)."),
        AdapterParameterSpec("delay", int, 0, "Legacy instaBrute delay in seconds (-t/--time); 0 leaves unset."),
        AdapterParameterSpec("proxy", bool, False, "Legacy instaBrute proxy toggle (-p/--proxy)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "user_file", "-f")
    add_value(tokens, kwargs, "dictionary", "-d")
    add_value(tokens, kwargs, "username", "-u")
    add_value(tokens, kwargs, "delay", "-t")
    add_bool(tokens, kwargs, "proxy", "-p")
    return tokens
