"""Dedicated adapter metadata for BlackEye."""

from hacking_mcp.mcp_tools.adapters.phishing_common import phishing_options, phishing_parameters


def parameters():
    return phishing_parameters()


def build_options(kwargs: dict) -> list[str]:
    return phishing_options(kwargs)
