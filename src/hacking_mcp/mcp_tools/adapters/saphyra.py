"""Dedicated adapter metadata for Saphyra."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "safe",
            bool,
            False,
            "Append the upstream safe positional argument after the target.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return ["safe"] if kwargs.get("safe") else []
