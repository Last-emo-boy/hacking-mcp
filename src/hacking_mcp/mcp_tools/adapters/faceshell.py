"""Dedicated adapter metadata for Faceshell."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "wordlist.txt", "Password list for Facebook mode (-l/--list)."),
        AdapterParameterSpec("password", str, "", "Single password for Facebook mode (-p/--password)."),
        AdapterParameterSpec("proxy_file", str, "", "Proxy list for Facebook mode (-X/--proxy)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    password = str(kwargs.get("password") or "").strip()
    if password:
        add_value(tokens, kwargs, "password", "-p")
    else:
        tokens.extend(["-l", str(kwargs.get("wordlist") or "wordlist.txt")])
    add_value(tokens, kwargs, "proxy_file", "-X")
    return tokens
