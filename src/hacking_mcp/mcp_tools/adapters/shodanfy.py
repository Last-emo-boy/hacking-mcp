"""Dedicated adapter metadata for Shodanfy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("get_ports", bool, False, "Show open ports from the Shodan host page."),
        AdapterParameterSpec("get_vuln", bool, False, "Show vulnerabilities/CVEs from the Shodan host page."),
        AdapterParameterSpec("get_info", bool, False, "Show basic host information."),
        AdapterParameterSpec("get_more_info", bool, False, "Show service port/protocol/state/version details."),
        AdapterParameterSpec("get_banner", bool, False, "Show service banners."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "get_ports", "--getports")
    add_bool(tokens, kwargs, "get_vuln", "--getvuln")
    add_bool(tokens, kwargs, "get_info", "--getinfo")
    add_bool(tokens, kwargs, "get_more_info", "--getmoreinfo")
    add_bool(tokens, kwargs, "get_banner", "--getbanner")
    return tokens
