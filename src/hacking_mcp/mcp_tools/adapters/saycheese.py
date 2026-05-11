"""Dedicated adapter metadata for SayCheese."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "This adapter is intentionally interactive-only; SayCheese reads forwarding choices from stdin.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
