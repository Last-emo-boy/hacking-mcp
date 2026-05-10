"""Dedicated adapter metadata for Holehe."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("only_used", bool, False, "Show only sites used by the target email."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored terminal output."),
        AdapterParameterSpec("no_clear", bool, False, "Do not clear the terminal while displaying results."),
        AdapterParameterSpec("no_password_recovery", bool, False, "Skip password-recovery checks."),
        AdapterParameterSpec("csv", bool, False, "Write results to CSV using upstream -C/--csv."),
        AdapterParameterSpec("timeout", int, 0, "Maximum timeout in seconds; 0 leaves upstream default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "only_used", "--only-used")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "no_clear", "--no-clear")
    add_bool(tokens, kwargs, "no_password_recovery", "--no-password-recovery")
    add_bool(tokens, kwargs, "csv", "--csv")
    add_value(tokens, kwargs, "timeout", "--timeout")
    return tokens
