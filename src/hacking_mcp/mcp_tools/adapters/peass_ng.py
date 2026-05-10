"""Dedicated adapter metadata for PEASS-ng."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
        AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
        AdapterParameterSpec("session_id", str, "", "Session identifier when supported."),
        AdapterParameterSpec("listener", str, "", "Listener/profile name when supported."),
        AdapterParameterSpec("protocol", str, "", "Protocol selector when supported."),
        AdapterParameterSpec("sources", str, "", "Comma-separated OSINT sources when supported."),
        AdapterParameterSpec("passive", bool, False, "Use passive enumeration when supported."),
        AdapterParameterSpec("resolvers", str, "", "Resolver file path when supported."),
        AdapterParameterSpec("api_key", str, "", "API key/profile name when supported."),
        AdapterParameterSpec("output_file", str, "", "Output file path when supported."),
        AdapterParameterSpec("json_output", bool, False, "Request JSON output when supported."),
        AdapterParameterSpec("peas_variant", str, "", "PEASS variant such as linpeas or winpeas."),
        AdapterParameterSpec("checks", str, "", "Checks/profile selector when supported."),
        AdapterParameterSpec("quiet", bool, False, "Reduce output when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "lhost", "--lhost")
    add_value(tokens, kwargs, "lport", "--lport")
    add_value(tokens, kwargs, "session_id", "--session")
    add_value(tokens, kwargs, "listener", "--listener")
    add_value(tokens, kwargs, "protocol", "--protocol")
    add_value(tokens, kwargs, "sources", "-sources")
    add_bool(tokens, kwargs, "passive", "-passive")
    add_value(tokens, kwargs, "resolvers", "-r")
    add_value(tokens, kwargs, "api_key", "--api-key")
    add_value(tokens, kwargs, "output_file", "-o")
    add_bool(tokens, kwargs, "json_output", "-json")
    add_value(tokens, kwargs, "peas_variant", "--variant")
    add_value(tokens, kwargs, "checks", "--checks")
    add_bool(tokens, kwargs, "quiet", "-q")
    return tokens
