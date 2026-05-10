"""Dedicated adapter metadata for Sublist3r."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("bruteforce", bool, False, "Enable the subbrute brute-force module."),
        AdapterParameterSpec("ports", str, "", "Comma-separated TCP ports to scan on found subdomains."),
        AdapterParameterSpec("verbose", bool, False, "Display results in real time."),
        AdapterParameterSpec("threads", int, 0, "Number of threads for subbrute; 0 leaves upstream default."),
        AdapterParameterSpec("engines", str, "", "Comma-separated search engines to use."),
        AdapterParameterSpec("output_file", str, "", "Save results to a text file."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "bruteforce", "--bruteforce")
    add_value(tokens, kwargs, "ports", "--ports")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_value(tokens, kwargs, "threads", "--threads")
    add_value(tokens, kwargs, "engines", "--engines")
    add_value(tokens, kwargs, "output_file", "--output")
    add_bool(tokens, kwargs, "no_color", "--no-color")
    return tokens
