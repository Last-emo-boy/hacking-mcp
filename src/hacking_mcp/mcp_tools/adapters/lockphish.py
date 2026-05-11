"""Dedicated adapter metadata for Lockphish."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Lockphish starts an interactive phishing tunnel/template flow.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
