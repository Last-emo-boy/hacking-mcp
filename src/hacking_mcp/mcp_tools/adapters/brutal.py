"""Dedicated adapter metadata for Brutal."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Brutal is an interactive menu-driven Bash toolkit.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
