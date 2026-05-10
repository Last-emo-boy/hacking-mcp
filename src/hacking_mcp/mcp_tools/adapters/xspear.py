"""Dedicated adapter metadata for XSpear."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, int_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("data", str, "", "POST body data."),
        AdapterParameterSpec("test_all_params", bool, False, "Test all parameters, including non-reflected ones."),
        AdapterParameterSpec("no_xss", bool, False, "Only perform parameter analysis without XSS tests."),
        AdapterParameterSpec("headers", str, "", "Additional HTTP headers."),
        AdapterParameterSpec("cookie", str, "", "Cookie header value."),
        AdapterParameterSpec("custom_payload", str, "", "Custom payload JSON file."),
        AdapterParameterSpec("raw_file", str, "", "Raw request file."),
        AdapterParameterSpec("parameter", str, "", "Specific parameter or parameters to test."),
        AdapterParameterSpec("blind_callback", str, "", "Blind XSS callback URL."),
        AdapterParameterSpec("threads", int, 0, "Thread count; 0 leaves default."),
        AdapterParameterSpec("output_format", str, "", "Output format, for example cli or json."),
        AdapterParameterSpec("config_file", str, "", "Config JSON file."),
        AdapterParameterSpec("verbose", int, 0, "Verbose level 0-3; 0 leaves default."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "data", "-d")
    add_bool(tokens, kwargs, "test_all_params", "-a")
    add_bool(tokens, kwargs, "no_xss", "--no-xss")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "custom_payload", "--custom-payload")
    add_value(tokens, kwargs, "raw_file", "--raw")
    add_value(tokens, kwargs, "parameter", "-p")
    add_value(tokens, kwargs, "blind_callback", "-b")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "output_format", "-o")
    add_value(tokens, kwargs, "config_file", "-c")
    verbosity = int_value(kwargs, "verbose")
    if verbosity:
        tokens.append("-" + ("v" * min(verbosity, 3)))
    return tokens
