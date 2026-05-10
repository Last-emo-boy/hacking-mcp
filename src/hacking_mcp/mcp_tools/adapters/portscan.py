"""Dedicated adapter metadata for the built-in portscan wrapper."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec(
            "host",
            str,
            "",
            "Host or network target for the built-in nmap -O -Pn wrapper.",
        ),
    ]


def build_options(kwargs: dict) -> list[str]:
    return []
