"""Dedicated adapter metadata for UFONet."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("gui", bool, True, "Start the UFONet web GUI."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose request output."),
        AdapterParameterSpec("examples", bool, False, "Print examples."),
        AdapterParameterSpec("timeline", bool, False, "Show program code timeline."),
        AdapterParameterSpec("update", bool, False, "Check for latest stable version."),
        AdapterParameterSpec("check_tor", bool, False, "Check whether Tor is used correctly."),
        AdapterParameterSpec("force_ssl", bool, False, "Force SSL/HTTPS requests."),
        AdapterParameterSpec("proxy", str, "", "Proxy server URL."),
        AdapterParameterSpec("user_agent", str, "", "Custom HTTP User-Agent header."),
        AdapterParameterSpec("referer", str, "", "Custom HTTP Referer header."),
        AdapterParameterSpec("host_header", str, "", "Custom HTTP Host header."),
        AdapterParameterSpec("x_forwarded_for", bool, False, "Set random X-Forwarded-For values."),
        AdapterParameterSpec("x_client_ip", bool, False, "Set random X-Client-IP values."),
        AdapterParameterSpec("timeout", int, 0, "Connection timeout."),
        AdapterParameterSpec("retries", int, 0, "Retry count after connection timeouts."),
        AdapterParameterSpec("threads", int, 0, "Maximum concurrent HTTP requests."),
        AdapterParameterSpec("delay", int, 0, "Delay between each HTTP request."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "gui", "--gui")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "examples", "--examples")
    add_bool(tokens, kwargs, "timeline", "--timeline")
    add_bool(tokens, kwargs, "update", "--update")
    add_bool(tokens, kwargs, "check_tor", "--check-tor")
    add_bool(tokens, kwargs, "force_ssl", "--force-ssl")
    add_value(tokens, kwargs, "proxy", "--proxy")
    add_value(tokens, kwargs, "user_agent", "--user-agent")
    add_value(tokens, kwargs, "referer", "--referer")
    add_value(tokens, kwargs, "host_header", "--host")
    add_bool(tokens, kwargs, "x_forwarded_for", "--xforw")
    add_bool(tokens, kwargs, "x_client_ip", "--xclient")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "retries", "--retries")
    add_value(tokens, kwargs, "threads", "--threads")
    add_value(tokens, kwargs, "delay", "--delay")
    return tokens
