"""Dedicated adapter metadata for AllinOne SocialMedia."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "help",
            bool,
            True,
            "This adapter is intentionally help-only and runs the registry command Brute_Force.py -h.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
