"""Dedicated adapter metadata for KawaiiDeauther."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interactive", bool, True, "KawaiiDeauther reads attack mode, interface, SSID/channel, and fake-AP inputs from an interactive menu."),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
