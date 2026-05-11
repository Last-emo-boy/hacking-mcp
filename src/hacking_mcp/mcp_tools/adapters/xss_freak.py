"""Dedicated adapter metadata for XSS-Freak."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, True, "Run the interactive XSS-Freak prompt flow."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
