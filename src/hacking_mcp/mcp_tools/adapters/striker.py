"""Dedicated adapter metadata for Striker."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "domain",
            str,
            "",
            "Domain or host passed as Striker's positional target; used as target when target is empty.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
