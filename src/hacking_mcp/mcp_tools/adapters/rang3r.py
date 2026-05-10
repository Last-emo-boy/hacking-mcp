"""Dedicated adapter metadata for rang3r."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "ip",
            str,
            "",
            "IP address or range for rang3r's --ip option; used as target when target is empty.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
