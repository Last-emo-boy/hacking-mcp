"""Dedicated adapter metadata for I-See-You."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "This adapter is intentionally interactive-only; I-See-You prompts for the generated Serveo URL on stdin.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
