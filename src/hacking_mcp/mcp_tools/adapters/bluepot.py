"""Dedicated adapter metadata for BluePot."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "BluePot starts a Java GUI Bluetooth honeypot.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
