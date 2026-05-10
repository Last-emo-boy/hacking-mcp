"""Dedicated adapter metadata for mitmproxy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "version",
            bool,
            True,
            "This adapter is intentionally version-only and runs the registry command mitmproxy --version.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
