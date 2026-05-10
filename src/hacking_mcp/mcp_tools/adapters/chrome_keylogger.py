"""Dedicated adapter metadata for Hera Chrome Keylogger."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, True, "Run the interactive Hera prompt flow."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
