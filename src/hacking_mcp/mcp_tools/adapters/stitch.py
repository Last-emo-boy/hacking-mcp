"""Dedicated adapter metadata for Stitch."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters():
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "Stitch starts an interactive cmd.Cmd remote administration shell.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
