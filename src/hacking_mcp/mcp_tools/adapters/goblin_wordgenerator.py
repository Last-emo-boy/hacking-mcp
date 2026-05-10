"""Dedicated adapter metadata for Goblin WordGenerator."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "This adapter is intentionally interactive-only; goblin.py reads all settings from stdin.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
