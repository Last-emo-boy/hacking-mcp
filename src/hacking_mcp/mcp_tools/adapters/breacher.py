"""Dedicated adapter metadata for Breacher."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("path", str, "", "Scan a specific path prefix using upstream --path."),
        AdapterParameterSpec("panel_type", str, "", "Panel type for upstream --type, such as php, asp, or html."),
        AdapterParameterSpec("fast", bool, False, "Use upstream --fast mode to scan a shorter path list."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "path", "--path")
    add_value(tokens, kwargs, "panel_type", "--type")
    add_bool(tokens, kwargs, "fast", "--fast")
    return tokens
