"""Dedicated adapter metadata for haiti."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("no_color", bool, False, "Disable colorized output."),
        AdapterParameterSpec("extended", bool, False, "List algorithms including salted variants."),
        AdapterParameterSpec("short", bool, False, "Hide hashcat and John the Ripper references."),
        AdapterParameterSpec("hashcat_only", bool, False, "Show only hashcat references."),
        AdapterParameterSpec("john_only", bool, False, "Show only John the Ripper references."),
        AdapterParameterSpec("ascii_art", bool, False, "Display the colored ASCII art logo."),
        AdapterParameterSpec("debug", bool, False, "Display parsed arguments."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "no_color", "--no-color")
    add_bool(tokens, kwargs, "extended", "--extended")
    add_bool(tokens, kwargs, "short", "--short")
    add_bool(tokens, kwargs, "hashcat_only", "--hashcat-only")
    add_bool(tokens, kwargs, "john_only", "--john-only")
    add_bool(tokens, kwargs, "ascii_art", "--ascii-art")
    add_bool(tokens, kwargs, "debug", "--debug")
    return tokens
