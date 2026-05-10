"""Dedicated adapter metadata for RVuln."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, True, "Start the upstream stdin-driven RVuln console."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
