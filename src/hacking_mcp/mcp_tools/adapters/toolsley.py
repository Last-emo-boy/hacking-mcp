"""Dedicated adapter metadata for the built-in Toolsley hash wrapper."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "text",
            str,
            "",
            "Text to SHA-256 hash; used as target when target is empty.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
