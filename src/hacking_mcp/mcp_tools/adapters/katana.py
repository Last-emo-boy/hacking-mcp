"""Dedicated adapter metadata for Katana."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("input_file", str, "", "Input file containing targets to crawl."),
        AdapterParameterSpec("depth", int, 0, "Maximum crawl depth; 0 leaves default."),
        AdapterParameterSpec("strategy", str, "", "Crawling strategy, for example depth-first or breadth-first."),
        AdapterParameterSpec("js_crawl", bool, False, "Enable JavaScript file crawling."),
        AdapterParameterSpec("known_files", str, "", "Known files to crawl, for example robots.txt,sitemap.xml."),
        AdapterParameterSpec("automatic_form_fill", bool, False, "Enable automatic form filling."),
        AdapterParameterSpec("form_extraction", bool, False, "Extract forms and inputs."),
        AdapterParameterSpec("headless", bool, False, "Enable headless browser crawling."),
        AdapterParameterSpec("headless_options", str, "", "Headless browser options."),
        AdapterParameterSpec("no_sandbox", bool, False, "Start Chrome without sandbox."),
        AdapterParameterSpec("system_chrome", bool, False, "Use locally installed Chrome."),
        AdapterParameterSpec("proxy", str, "", "HTTP proxy URL."),
        AdapterParameterSpec("headers", str, "", "Custom HTTP header to send."),
        AdapterParameterSpec("timeout", int, 0, "Request timeout in seconds; 0 leaves default."),
        AdapterParameterSpec("retry", int, 0, "Number of retries; 0 leaves default."),
        AdapterParameterSpec("rate_limit", int, 0, "Maximum requests per second; 0 leaves default."),
        AdapterParameterSpec("concurrency", int, 0, "Number of concurrent fetchers; 0 leaves default."),
        AdapterParameterSpec("parallelism", int, 0, "Number of parallel input targets; 0 leaves default."),
        AdapterParameterSpec("delay", str, "", "Delay between requests, for example 1s."),
        AdapterParameterSpec("crawl_duration", str, "", "Maximum crawl duration, for example 5m."),
        AdapterParameterSpec("output_file", str, "", "Output file path."),
        AdapterParameterSpec("json_output", bool, False, "Write JSONL output."),
        AdapterParameterSpec("field", str, "", "Field to display, for example url or qurl."),
        AdapterParameterSpec("silent", bool, False, "Show only output."),
        AdapterParameterSpec("no_color", bool, False, "Disable colored output."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "input_file", "-list")
    add_value(tokens, kwargs, "depth", "-d")
    add_value(tokens, kwargs, "strategy", "-strategy")
    add_bool(tokens, kwargs, "js_crawl", "-jc")
    add_value(tokens, kwargs, "known_files", "-kf")
    add_bool(tokens, kwargs, "automatic_form_fill", "-aff")
    add_bool(tokens, kwargs, "form_extraction", "-fx")
    add_bool(tokens, kwargs, "headless", "-headless")
    add_value(tokens, kwargs, "headless_options", "-ho")
    add_bool(tokens, kwargs, "no_sandbox", "-nos")
    add_bool(tokens, kwargs, "system_chrome", "-system-chrome")
    add_value(tokens, kwargs, "proxy", "-proxy")
    add_value(tokens, kwargs, "headers", "-H")
    add_value(tokens, kwargs, "timeout", "-timeout")
    add_value(tokens, kwargs, "retry", "-retry")
    add_value(tokens, kwargs, "rate_limit", "-rl")
    add_value(tokens, kwargs, "concurrency", "-c")
    add_value(tokens, kwargs, "parallelism", "-p")
    add_value(tokens, kwargs, "delay", "-delay")
    add_value(tokens, kwargs, "crawl_duration", "-ct")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "json_output", "-jsonl")
    add_value(tokens, kwargs, "field", "-field")
    add_bool(tokens, kwargs, "silent", "-silent")
    add_bool(tokens, kwargs, "no_color", "-no-color")
    return tokens
