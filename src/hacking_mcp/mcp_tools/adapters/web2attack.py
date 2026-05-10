"""Dedicated adapter metadata for Web2Attack."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Web2Attack starts an interactive console; no CLI module options are generated.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
