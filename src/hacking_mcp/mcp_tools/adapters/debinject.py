"""Dedicated adapter metadata for Debinject."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, True, "Debinject reads package path, LHOST/LPORT, architecture, payload, persistence, and listener choices interactively."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
