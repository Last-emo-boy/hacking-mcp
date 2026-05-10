"""Dedicated adapter metadata for Wlcreator."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("length", int, 5, "Password length positional argument."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "length", "")
    return [token for token in tokens if token]
