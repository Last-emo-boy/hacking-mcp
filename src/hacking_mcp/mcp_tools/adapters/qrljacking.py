"""Dedicated adapter metadata for QRLJacking."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("resource_file", str, "", "Execute commands from a QrlJacker resource/history file via -r."),
        AdapterParameterSpec("execute_command", str, "", "Execute one or more QrlJacker commands via -x; separate multiple commands with semicolons."),
        AdapterParameterSpec("debug", bool, False, "Enable QrlJacker debug mode."),
        AdapterParameterSpec("dev", bool, False, "Enable QrlJacker development mode."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("quiet", bool, False, "Quit/banner-suppressed mode via -q."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "resource_file", "-r")
    add_value(tokens, kwargs, "execute_command", "-x")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "dev", "--dev")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "quiet", "-q")
    return tokens
