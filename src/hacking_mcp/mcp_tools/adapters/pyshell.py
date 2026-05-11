"""Dedicated adapter metadata for Pyshell."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Pyshell starts an interactive RAT payload/listener prompt.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
