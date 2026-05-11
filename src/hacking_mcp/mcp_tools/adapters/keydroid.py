"""Dedicated adapter metadata for Keydroid."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Keydroid starts an interactive Android keylogger build/listener flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
