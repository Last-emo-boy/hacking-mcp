"""Dedicated adapter metadata for WAFW00F."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("verbosity", int, 0, "Verbosity level 1-3; 0 leaves default."),
        AdapterParameterSpec("find_all", bool, False, "Find all matching WAF signatures."),
        AdapterParameterSpec("no_redirect", bool, False, "Do not follow HTTP 3xx redirects."),
        AdapterParameterSpec("test_waf", str, "", "Test for one specific WAF name."),
        AdapterParameterSpec("output_file", str, "", "Output file path, or - for stdout."),
        AdapterParameterSpec("output_format", str, "", "Force output format: csv, json, or text."),
        AdapterParameterSpec("input_file", str, "", "Input file containing targets."),
        AdapterParameterSpec("list_wafs", bool, False, "List detectable WAF names and exit."),
        AdapterParameterSpec("proxy", str, "", "HTTP or SOCKS proxy URL."),
        AdapterParameterSpec("version", bool, False, "Print WAFW00F version and exit."),
        AdapterParameterSpec("headers_file", str, "", "Text file containing custom headers."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("no_color", bool, False, "Disable ANSI colors in output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    verbosity = int_value(kwargs, "verbosity")
    if verbosity:
        tokens.extend(["-v"] * min(verbosity, 3))
    add_bool(tokens, kwargs, "find_all", "-a")
    add_bool(tokens, kwargs, "no_redirect", "-r")
    add_value(tokens, kwargs, "test_waf", "-t")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "output_format", "-f")
    add_value(tokens, kwargs, "input_file", "-i")
    add_bool(tokens, kwargs, "list_wafs", "-l")
    add_value(tokens, kwargs, "proxy", "-p")
    add_bool(tokens, kwargs, "version", "-V")
    add_value(tokens, kwargs, "headers_file", "-H")
    add_value(tokens, kwargs, "timeout", "-T")
    add_bool(tokens, kwargs, "no_color", "--no-colors")
    return tokens
