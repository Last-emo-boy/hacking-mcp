"""Dedicated adapter metadata for Terminal Multiplexer."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "version",
            bool,
            True,
            "This adapter is intentionally version-only and runs the registry command tilix --version.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
