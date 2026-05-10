"""Dedicated adapter metadata for XSSCon."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("depth", int, 0, "Crawl depth; 0 leaves default."),
        AdapterParameterSpec("payload_level", int, 0, "Generated payload level 1-7; 0 leaves default."),
        AdapterParameterSpec("payload", str, "", "Custom payload value."),
        AdapterParameterSpec("method", int, 0, "Method mode: 0 GET, 1 POST, 2 both; 0 leaves default."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent value."),
        AdapterParameterSpec("single_url", str, "", "Single URL to scan without crawling."),
        AdapterParameterSpec("proxy", str, "", "Proxy mapping string."),
        AdapterParameterSpec("about", bool, False, "Print XSSCon tool information."),
        AdapterParameterSpec("cookie", str, "", "Cookie mapping string."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "depth", "--depth")
    add_value(tokens, kwargs, "payload_level", "--payload-level")
    add_value(tokens, kwargs, "payload", "--payload")
    add_value(tokens, kwargs, "method", "--method")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "single_url", "--single")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_bool(tokens, kwargs, "about", "--about")
    add_value(tokens, kwargs, "cookie", "--cookie")
    return tokens
