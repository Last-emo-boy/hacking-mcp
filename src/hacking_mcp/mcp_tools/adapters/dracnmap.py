"""Dedicated adapter metadata for Dracnmap."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "This adapter is intentionally interactive-only; dracnmap-v2.2.sh reads scan choices and targets from stdin.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
