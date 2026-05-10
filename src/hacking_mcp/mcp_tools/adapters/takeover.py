"""Dedicated adapter metadata for takeover."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("list_file", str, "", "File of domains for -l."),
        AdapterParameterSpec("proxy", str, "", "Proxy URL for -p."),
        AdapterParameterSpec("output_file", str, "", "Output path for -o; .txt and .json are supported upstream."),
        AdapterParameterSpec("threads", int, 0, "Thread count for -t; 0 leaves the upstream default."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds for -T; 0 leaves default."),
        AdapterParameterSpec("user_agent", str, "", "Custom User-Agent for -u."),
        AdapterParameterSpec("process_200", bool, False, "Process HTTP 200 responses with -k."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output with -v."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "list_file", "-l")
    add_value(tokens, kwargs, "proxy", "-p")
    add_value(tokens, kwargs, "output_file", "-o")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "timeout", "-T")
    add_value(tokens, kwargs, "user_agent", "-u")
    add_bool(tokens, kwargs, "process_200", "-k")
    add_bool(tokens, kwargs, "verbose", "-v")
    return tokens
