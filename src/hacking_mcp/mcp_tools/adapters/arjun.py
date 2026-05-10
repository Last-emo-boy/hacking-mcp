"""Dedicated adapter metadata for Arjun."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "Targets file, Burp export, or raw request file."),
        AdapterParameterSpec("output_json", str, "", "JSON output file path."),
        AdapterParameterSpec("output_burp", str, "", "BurpSuite output target/path."),
        AdapterParameterSpec("output_text", str, "", "Text output file path."),
        AdapterParameterSpec("method", str, "", "HTTP method: GET, POST, JSON, or XML."),
        AdapterParameterSpec("include_data", str, "", "Persistent data to include in each request."),
        AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
        AdapterParameterSpec("delay", int, 0, "Delay between requests in seconds; 0 leaves default."),
        AdapterParameterSpec("timeout", int, 0, "HTTP request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("stable", bool, False, "Enable stable mode for rate-limited targets."),
        AdapterParameterSpec("rate_limit", int, 0, "Requests per second; 0 leaves default."),
        AdapterParameterSpec("wordlist", str, "", "Wordlist path or built-in size: small, medium, large."),
        AdapterParameterSpec("chunk_size", int, 0, "Parameters sent per request; 0 leaves default."),
        AdapterParameterSpec("disable_redirects", bool, False, "Disable HTTP redirects."),
        AdapterParameterSpec("passive", str, "", "Passive discovery domain, or '-' to use target URL domain."),
        AdapterParameterSpec("casing", str, "", "Parameter casing style."),
        AdapterParameterSpec("headers", str, "", "Custom HTTP headers."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "-i")
    add_value(tokens, kwargs, "output_json", "-oJ")
    add_value(tokens, kwargs, "output_burp", "-oB")
    add_value(tokens, kwargs, "output_text", "-oT")
    add_value(tokens, kwargs, "method", "-m")
    add_value(tokens, kwargs, "include_data", "--include")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "delay", "-d")
    add_value(tokens, kwargs, "timeout", "-T")
    add_bool(tokens, kwargs, "stable", "--stable")
    add_value(tokens, kwargs, "rate_limit", "--ratelimit")
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "chunk_size", "-c")
    add_bool(tokens, kwargs, "disable_redirects", "--disable-redirects")
    add_value(tokens, kwargs, "passive", "--passive")
    add_value(tokens, kwargs, "casing", "--casing")
    add_value(tokens, kwargs, "headers", "--headers")
    return tokens
