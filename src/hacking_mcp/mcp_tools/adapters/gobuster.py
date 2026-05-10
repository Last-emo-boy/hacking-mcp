"""Dedicated adapter metadata for Gobuster."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("wordlist", str, "", "Wordlist path for directory enumeration."),
        AdapterParameterSpec("extensions", str, "", "Comma-separated extensions to append."),
        AdapterParameterSpec("headers", str, "", "Custom HTTP header."),
        AdapterParameterSpec("cookies", str, "", "Cookie header value."),
        AdapterParameterSpec("show_length", bool, False, "Show response length."),
        AdapterParameterSpec("status_codes", str, "", "Positive status codes or ranges."),
        AdapterParameterSpec("threads", int, 0, "Number of concurrent threads; 0 leaves default."),
        AdapterParameterSpec("delay", str, "", "Delay between requests, for example 1s."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
        AdapterParameterSpec("timeout", str, "", "HTTP timeout, for example 10s."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("quiet", bool, False, "Quiet output mode."),
        AdapterParameterSpec("no_progress", bool, False, "Disable progress output."),
        AdapterParameterSpec("expanded", bool, False, "Expanded mode: print full URLs."),
        AdapterParameterSpec("add_slash", bool, False, "Append slash to each request."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "extensions", "-x")
    add_value(tokens, kwargs, "headers", "-H")
    add_value(tokens, kwargs, "cookies", "-c")
    add_bool(tokens, kwargs, "show_length", "-l")
    add_value(tokens, kwargs, "status_codes", "-s")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "delay", "--delay")
    add_value(tokens, kwargs, "user_agent", "-a")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "quiet", "-q")
    add_bool(tokens, kwargs, "no_progress", "--no-progress")
    add_bool(tokens, kwargs, "expanded", "-e")
    add_bool(tokens, kwargs, "add_slash", "-f")
    return tokens
