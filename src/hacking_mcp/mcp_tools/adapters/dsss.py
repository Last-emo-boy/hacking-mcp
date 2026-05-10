"""Dedicated adapter metadata for DSSS."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("data", str, "", "POST data, for example query=test."),
        AdapterParameterSpec("cookie", str, "", "HTTP Cookie header value."),
        AdapterParameterSpec("user_agent", str, "", "HTTP User-Agent header value."),
        AdapterParameterSpec("referer", str, "", "HTTP Referer header value."),
        AdapterParameterSpec("proxy", str, "", "HTTP proxy address."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "data", "--data")
    add_value(tokens, kwargs, "cookie", "--cookie")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "referer", "--referer")
    add_value(tokens, kwargs, "proxy", "--proxy")
    return tokens
