"""Dedicated adapter metadata for Extended XSS Searcher and Finder."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "config_driven",
            bool,
            True,
            "Uses upstream app-settings.conf and config/*.txt files; no CLI options are generated.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
