"""Dedicated adapter metadata for XanXSS."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("verification_amount", int, 0, "Verification steps; 0 leaves default."),
        AdapterParameterSpec("amount_to_find", int, 0, "Number of working payloads to try to find; 0 leaves default."),
        AdapterParameterSpec("test_time", int, 0, "Verification test time in seconds; 0 leaves default."),
        AdapterParameterSpec("payloads", str, "", "Comma-separated payloads or payload string list."),
        AdapterParameterSpec("payload_file", str, "", "Text file containing payloads."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL in type://ip:port format."),
        AdapterParameterSpec("headers", str, "", "Custom headers in key=value,key:value format."),
        AdapterParameterSpec("throttle", int, 0, "Sleep time between requests in seconds; 0 leaves default."),
        AdapterParameterSpec("polyglot", bool, False, "Generate and test a polyglot payload."),
        AdapterParameterSpec("prefix", str, "", "Payload prefix."),
        AdapterParameterSpec("suffix", str, "", "Payload suffix."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "verification_amount", "-a")
    add_value(tokens, kwargs, "amount_to_find", "-f")
    add_value(tokens, kwargs, "test_time", "-t")
    add_value(tokens, kwargs, "payloads", "-p")
    add_value(tokens, kwargs, "payload_file", "-F")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "throttle", "--throttle")
    add_bool(tokens, kwargs, "polyglot", "--polyglot")
    add_value(tokens, kwargs, "prefix", "--prefix")
    add_value(tokens, kwargs, "suffix", "--suffix")
    return tokens
