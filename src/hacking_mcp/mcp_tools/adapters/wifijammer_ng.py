"""Dedicated adapter metadata for WifiJammer-NG."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("archived_reference", bool, True, "WifiJammer-NG upstream/source is unavailable; adapter is reference-only."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
