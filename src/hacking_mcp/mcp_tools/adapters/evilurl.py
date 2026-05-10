"""Dedicated adapter metadata for EvilURL."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("generate", bool, False, "Generate homograph domains for the target (-g)."),
        AdapterParameterSpec("check_connection", bool, False, "Check generated/input domain connectivity (-c)."),
        AdapterParameterSpec("output_file", str, "", "Save output to a file (-o)."),
        AdapterParameterSpec("check_availability", bool, False, "Check generated domain availability (-a)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "generate", "-g")
    add_bool(tokens, kwargs, "check_connection", "-c")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "check_availability", "-a")
    return tokens
