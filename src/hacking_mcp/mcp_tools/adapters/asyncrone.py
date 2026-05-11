"""Dedicated adapter metadata for Asyncrone."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "archived_reference",
            bool,
            True,
            "Asyncrone upstream source is unavailable; adapter is reference-only.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
