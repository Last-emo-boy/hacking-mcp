"""Dedicated adapter metadata for BlackPhish."""

from hacking_mcp.mcp_tools.adapters.setoolkit import _phishing_options, _phishing_parameters


def parameters():
    return _phishing_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _phishing_options(kwargs)
