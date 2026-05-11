"""Dedicated adapter metadata for Enigma."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Enigma is an interactive multiplatform dropper builder.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
