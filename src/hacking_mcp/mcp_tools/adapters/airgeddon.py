"""Dedicated adapter metadata for airgeddon."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "airgeddon starts an interactive wireless audit menu flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
