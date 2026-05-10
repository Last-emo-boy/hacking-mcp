"""Dedicated adapter metadata for Multitor."""

from hacking_mcp.mcp_tools.adapters.anonsurf import _anonymity_options, _anonymity_parameters


def parameters():
    return _anonymity_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _anonymity_options(kwargs)
