"""Dedicated adapter metadata for Mob-Droid."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Mob-Droid is an interactive Android payload menu.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
