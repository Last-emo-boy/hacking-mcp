"""Dedicated adapter metadata for Venom."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Venom is an interactive Bash/zenity payload generator.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
