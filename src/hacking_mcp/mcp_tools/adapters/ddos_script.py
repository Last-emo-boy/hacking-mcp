"""Dedicated adapter metadata for DDoS Script."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("method", str, "help", "Attack or utility method name."),
        AdapterParameterSpec("socks_type", str, "5", "Proxy type: 1 for HTTP, 4 for SOCKS4, or 5 for SOCKS5."),
        AdapterParameterSpec("threads", int, 0, "Thread count positional argument."),
        AdapterParameterSpec("proxylist", str, "", "Proxy list filename under files/proxys."),
        AdapterParameterSpec("multiple", int, 0, "Packets or requests per loop positional argument."),
        AdapterParameterSpec("timer", int, 0, "Run duration in seconds."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    for key in ("socks_type", "threads", "proxylist", "multiple", "timer"):
        value = kwargs.get(key)
        if value not in (None, "", 0, False):
            tokens.append(str(value))
    return tokens
