"""Dedicated adapter metadata for GoldenEye."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("useragents_file", str, "", "File containing user-agent strings."),
        AdapterParameterSpec("workers", int, 0, "Number of concurrent workers."),
        AdapterParameterSpec("sockets", int, 0, "Number of concurrent sockets per worker."),
        AdapterParameterSpec("method", str, "", "HTTP method: get, post, or random."),
        AdapterParameterSpec("debug", bool, False, "Enable debug output."),
        AdapterParameterSpec("no_ssl_check", bool, False, "Do not verify SSL certificates."),
        AdapterParameterSpec("help", bool, False, "Show GoldenEye help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "useragents_file", "--useragents")
    add_value(tokens, kwargs, "workers", "--workers")
    add_value(tokens, kwargs, "sockets", "--sockets")
    add_value(tokens, kwargs, "method", "--method")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_bool(tokens, kwargs, "no_ssl_check", "--nosslcheck")
    add_bool(tokens, kwargs, "help", "--help")
    return tokens
