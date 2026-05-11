"""Dedicated adapter metadata for MySMS."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "MySMS starts an interactive Android SMS capture build/server flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
