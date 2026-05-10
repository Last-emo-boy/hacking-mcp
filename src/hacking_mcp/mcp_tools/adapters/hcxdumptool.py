"""Dedicated adapter metadata for hcxdumptool."""

from hacking_mcp.mcp_tools.adapters.wifite import _wireless_options, _wireless_parameters


def parameters():
    return _wireless_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _wireless_options(kwargs)
