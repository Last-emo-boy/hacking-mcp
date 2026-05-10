"""Dedicated adapter metadata for Blazy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("json_output", str, "", "Write JSON output to this path (-oJ)."),
        AdapterParameterSpec("timeout", int, 0, "HTTP timeout in seconds (-t); 0 leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "json_output", "-oJ")
    add_value(tokens, kwargs, "timeout", "-t")
    return tokens
