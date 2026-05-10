"""Dedicated adapter metadata for XSS-LOADER."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, True, "Start the upstream menu-driven XSS-LOADER console."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
