"""Dedicated adapter metadata for ShellPhish."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value
from hacking_mcp.mcp_tools.adapters.setoolkit import _phishing_options, _phishing_parameters


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("timeout", int, 0, "Per-site timeout in seconds when supported."),
        *_phishing_parameters(),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "timeout", "--timeout")
    tokens.extend(_phishing_options(kwargs))
    return tokens
