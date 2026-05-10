"""Dedicated adapter metadata for sqlscan."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("scan", bool, True, "Run sqlscan scanner mode."),
    ]


def build_options(kwargs: dict) -> list[str]:
    if kwargs.get("scan", True):
        return ["--scan"]
    return []
