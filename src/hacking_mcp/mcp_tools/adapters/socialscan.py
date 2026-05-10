"""Dedicated adapter metadata for Socialscan."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value, add_values


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("platforms", str, "", "Platforms to query, space or comma separated (-p/--platforms)."),
        AdapterParameterSpec("view_by", str, "", "Sort results by query or platform (--view-by)."),
        AdapterParameterSpec("available_only", bool, False, "Only print available usernames/emails (-a)."),
        AdapterParameterSpec("cache_tokens", bool, False, "Cache prerequest tokens (-c)."),
        AdapterParameterSpec("proxy_list", str, "", "File containing HTTP proxies (--proxy-list)."),
        AdapterParameterSpec("verbose", bool, False, "Show responses as they are received (-v)."),
        AdapterParameterSpec("show_urls", bool, False, "Display profile URLs where supported (--show-urls)."),
        AdapterParameterSpec("json_file", str, "", "Write JSON output to this file (--json)."),
        AdapterParameterSpec("debug", bool, False, "Output debug messages (--debug)."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_values(tokens, kwargs, "platforms", "-p")
    add_value(tokens, kwargs, "view_by", "--view-by")
    add_bool(tokens, kwargs, "available_only", "-a")
    add_bool(tokens, kwargs, "cache_tokens", "-c")
    add_value(tokens, kwargs, "proxy_list", "--proxy-list")
    add_bool(tokens, kwargs, "verbose", "-v")
    add_bool(tokens, kwargs, "show_urls", "--show-urls")
    add_value(tokens, kwargs, "json_file", "--json")
    add_bool(tokens, kwargs, "debug", "--debug")
    return tokens
