"""Dedicated adapter metadata for XSStrike."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("data", str, "", "POST data to test."),
        AdapterParameterSpec("encode", str, "", "Payload encoding mode."),
        AdapterParameterSpec("fuzzer", bool, False, "Run the fuzzer."),
        AdapterParameterSpec("update", bool, False, "Update XSStrike."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout; 0 leaves default."),
        AdapterParameterSpec("use_proxy", bool, False, "Use configured proxy/proxies."),
        AdapterParameterSpec("crawl", bool, False, "Enable crawling."),
        AdapterParameterSpec("json_data", bool, False, "Treat POST data as JSON."),
        AdapterParameterSpec("path_injection", bool, False, "Inject payloads into the URL path."),
        AdapterParameterSpec("seeds_file", str, "", "File containing crawling seeds."),
        AdapterParameterSpec("payload_file", str, "", "File containing payloads."),
        AdapterParameterSpec("level", int, 0, "Crawling level; 0 leaves default."),
        AdapterParameterSpec("headers", str, "", "Additional headers."),
        AdapterParameterSpec("threads", int, 0, "Number of threads; 0 leaves default."),
        AdapterParameterSpec("delay", int, 0, "Delay between requests; 0 leaves default."),
        AdapterParameterSpec("skip", bool, False, "Do not prompt before continuing."),
        AdapterParameterSpec("skip_dom", bool, False, "Skip DOM checks."),
        AdapterParameterSpec("blind", bool, False, "Inject blind XSS payload while crawling."),
        AdapterParameterSpec("console_log_level", str, "", "Console logging level."),
        AdapterParameterSpec("file_log_level", str, "", "File logging level."),
        AdapterParameterSpec("log_file", str, "", "Log file name."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "encode", "-e")
    add_bool(tokens, kwargs, "fuzzer", "--fuzzer")
    add_bool(tokens, kwargs, "update", "--update")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_bool(tokens, kwargs, "use_proxy", "--proxy")
    add_bool(tokens, kwargs, "crawl", "--crawl")
    add_bool(tokens, kwargs, "json_data", "--json")
    add_bool(tokens, kwargs, "path_injection", "--path")
    add_value(tokens, kwargs, "seeds_file", "--seeds")
    add_value(tokens, kwargs, "payload_file", "-f")
    add_value(tokens, kwargs, "level", "-l")
    add_value(tokens, kwargs, "headers", "--headers")
    add_value(tokens, kwargs, "threads", "-t")
    add_value(tokens, kwargs, "delay", "-d")
    add_bool(tokens, kwargs, "skip", "--skip")
    add_bool(tokens, kwargs, "skip_dom", "--skip-dom")
    add_bool(tokens, kwargs, "blind", "--blind")
    add_value(tokens, kwargs, "console_log_level", "--console-log-level")
    add_value(tokens, kwargs, "file_log_level", "--file-log-level")
    add_value(tokens, kwargs, "log_file", "--log-file")
    return tokens
