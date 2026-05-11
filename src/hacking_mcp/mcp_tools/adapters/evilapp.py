"""Dedicated adapter metadata for EvilApp."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "EvilApp starts an interactive Android session-hijack build/server flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
