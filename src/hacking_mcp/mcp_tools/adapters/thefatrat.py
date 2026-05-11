"""Dedicated adapter metadata for TheFatRat."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "This adapter is intentionally interactive-only; TheFatRat reads setup, payload, LHOST, LPORT, and listener choices from stdin.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
