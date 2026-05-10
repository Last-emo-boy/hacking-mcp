"""Dedicated adapter metadata for Wireshark."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Wireshark starts its GUI for interactive capture/file analysis.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
