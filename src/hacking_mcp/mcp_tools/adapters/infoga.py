"""Dedicated adapter metadata for Infoga."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("archived_reference", bool, True, "Infoga upstream/source is unavailable; adapter is reference-only."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
