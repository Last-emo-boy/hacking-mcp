"""Dedicated adapter metadata for SecretFinder."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("extract", bool, False, "Extract JavaScript links from the input page."),
        AdapterParameterSpec("output_file", str, "", "Output mode or file for -o/--output, for example cli or result.html."),
        AdapterParameterSpec("regex", str, "", "Custom regex pattern for secret matching."),
        AdapterParameterSpec("burp", bool, False, "Use Burp input mode."),
        AdapterParameterSpec("cookie", str, "", "Cookie header value."),
        AdapterParameterSpec("ignore", str, "", "Text or pattern to ignore."),
        AdapterParameterSpec("only", str, "", "Only show matching names/patterns supported by upstream --only."),
        AdapterParameterSpec("headers", str, "", "Custom headers value for upstream --headers."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "extract", "--extract")
    add_value(tokens, kwargs, "output_file", "--output")
    add_value(tokens, kwargs, "regex", "--regex")
    add_bool(tokens, kwargs, "burp", "--burp")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "ignore", "--ignore")
    add_value(tokens, kwargs, "only", "--only")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "proxy", "--proxy")
    return tokens
