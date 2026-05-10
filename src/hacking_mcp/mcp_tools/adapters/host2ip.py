"""Dedicated adapter metadata for Host2IP."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "hostname",
            str,
            "",
            "Hostname to resolve; used as target when target is empty.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
