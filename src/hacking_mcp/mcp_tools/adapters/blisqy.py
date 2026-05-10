"""Dedicated adapter metadata for Blisqy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "library_usage",
            bool,
            True,
            "Blisqy is library/example-script based; no executable CLI options are generated.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
