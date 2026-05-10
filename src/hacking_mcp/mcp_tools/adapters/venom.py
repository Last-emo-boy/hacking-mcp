"""Dedicated adapter metadata for Venom."""

from hacking_mcp.mcp_tools.adapters.msfvenom import _payload_options, _payload_parameters


def parameters():
    return _payload_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _payload_options(kwargs)
