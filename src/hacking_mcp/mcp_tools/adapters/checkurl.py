"""Dedicated adapter metadata for checkURL."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "check_url",
            bool,
            False,
            "Check socket connectivity for the target URL (--check-url).",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "check_url", "--check-url")
    return tokens
