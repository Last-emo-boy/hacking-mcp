"""Dedicated adapter metadata for httpx."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "Input file containing hosts to probe."),
        AdapterParameterSpec("status_code", bool, False, "Show HTTP status code."),
        AdapterParameterSpec("title", bool, False, "Show page title."),
        AdapterParameterSpec("tech_detect", bool, False, "Show technology detection."),
        AdapterParameterSpec("content_length", bool, False, "Show response content length."),
        AdapterParameterSpec("match_codes", str, "", "HTTP status codes to match."),
        AdapterParameterSpec("filter_codes", str, "", "HTTP status codes to filter."),
        AdapterParameterSpec("threads", int, 0, "Worker/thread count; 0 leaves default."),
        AdapterParameterSpec("rate_limit", int, 0, "Maximum requests per second; 0 leaves default."),
        AdapterParameterSpec("ports", str, "", "Ports to probe, for example http:80,https:8443."),
        AdapterParameterSpec("path", str, "", "Path or comma-separated paths to probe."),
        AdapterParameterSpec("follow_redirects", bool, False, "Follow HTTP redirects."),
        AdapterParameterSpec("proxy", str, "", "Optional HTTP proxy URL."),
        AdapterParameterSpec("headers", str, "", "Custom HTTP header to send."),
        AdapterParameterSpec("method", str, "", "HTTP method to probe, or all."),
        AdapterParameterSpec("timeout", int, 0, "Timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("json_output", bool, False, "Store output in JSONL format."),
        AdapterParameterSpec("silent", bool, False, "Enable silent output mode."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "-l")
    add_bool(tokens, kwargs, "status_code", "-sc")
    add_bool(tokens, kwargs, "title", "-title")
    add_bool(tokens, kwargs, "tech_detect", "-td")
    add_bool(tokens, kwargs, "content_length", "-cl")
    add_value(tokens, kwargs, "match_codes", "-mc")
    add_value(tokens, kwargs, "filter_codes", "-fc")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "rate_limit", "-rl")
    add_value(tokens, kwargs, "ports", "-p")
    add_value(tokens, kwargs, "path", "-path")
    add_bool(tokens, kwargs, "follow_redirects", "-fr")
    add_value(tokens, kwargs, "proxy", "-proxy")
    add_value(tokens, kwargs, "headers", "-H")
    add_value(tokens, kwargs, "method", "-x")
    add_value(tokens, kwargs, "timeout", "-timeout")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "json_output", "-json")
    add_bool(tokens, kwargs, "silent", "-silent")
    return tokens
