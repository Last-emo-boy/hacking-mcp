"""Dedicated adapter metadata for ReconSpider."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "interactive",
            bool,
            True,
            "This adapter is intentionally interactive-only; reconspider.py reads module choices and targets from stdin.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
