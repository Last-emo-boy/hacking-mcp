"""Dedicated adapter metadata for Slowloris."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("port", int, 80, "Web server port."),
        AdapterParameterSpec("sockets", int, 150, "Number of sockets to use."),
        AdapterParameterSpec("verbose", bool, False, "Increase terminal logging."),
        AdapterParameterSpec("randuseragents", bool, False, "Randomize user-agent for each request."),
        AdapterParameterSpec("useproxy", bool, False, "Use a SOCKS5 proxy."),
        AdapterParameterSpec("proxy_host", str, "", "SOCKS5 proxy host."),
        AdapterParameterSpec("proxy_port", int, 0, "SOCKS5 proxy port."),
        AdapterParameterSpec("https", bool, False, "Use HTTPS for requests."),
        AdapterParameterSpec("sleeptime", int, 0, "Seconds to sleep between each header sent."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "port", "--port")
    add_value(tokens, kwargs, "sockets", "--sockets")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "randuseragents", "--randuseragents")
    add_bool(tokens, kwargs, "useproxy", "--useproxy")
    add_value(tokens, kwargs, "proxy_host", "--proxy-host")
    add_value(tokens, kwargs, "proxy_port", "--proxy-port")
    add_bool(tokens, kwargs, "https", "--https")
    add_value(tokens, kwargs, "sleeptime", "--sleeptime")
    return tokens
