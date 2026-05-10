"""Dedicated adapter metadata for ReconDog."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "choice",
            str,
            "",
            "ReconDog module choice for -c, for example 0 for all modules.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "choice", "-c")
    return tokens
