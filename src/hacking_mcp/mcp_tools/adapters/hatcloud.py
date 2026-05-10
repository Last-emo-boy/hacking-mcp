"""Dedicated adapter metadata for HatCloud."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "domain",
            str,
            "",
            "Domain to pass to HatCloud's -b/--byp lookup; used as target when target is empty.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
