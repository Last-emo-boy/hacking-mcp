"""Dedicated adapter metadata for Spycam."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Spycam is an interactive payload builder.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
