"""Dedicated adapter metadata for msfvenom payload wrappers."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return _payload_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _payload_options(kwargs)


def _payload_parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("platform", str, "", "MSFPC payload type/format, for example windows, elf, apk, php, or py."),
        AdapterParameterSpec("lhost", str, "", "Listener host, domain, IP, interface, or wan."),
        AdapterParameterSpec("lport", int, 0, "Listener port; 0 leaves MSFPC default."),
        AdapterParameterSpec("shell", str, "", "Shell family, usually cmd/shell or msf/meterpreter."),
        AdapterParameterSpec("direction", str, "", "Connection direction, for example bind or reverse."),
        AdapterParameterSpec("stager", str, "", "Stage selector, for example staged or stageless."),
        AdapterParameterSpec("method", str, "", "Transport method, for example tcp, http, https, or find_port."),
        AdapterParameterSpec("batch", bool, False, "Generate as many combinations as MSFPC supports."),
        AdapterParameterSpec("loop", bool, False, "Generate one payload for each MSFPC type."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose MSFPC output."),
        AdapterParameterSpec("help", bool, False, "Show MSFPC help/options."),
    ]


def _payload_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "platform", "--platform")
    add_value(tokens, kwargs, "lhost", "--ip")
    add_value(tokens, kwargs, "lport", "--port")
    add_value(tokens, kwargs, "shell", "--shell")
    add_value(tokens, kwargs, "direction", "--direction")
    add_value(tokens, kwargs, "stager", "--stage")
    add_value(tokens, kwargs, "method", "--method")
    add_bool(tokens, kwargs, "batch", "--batch")
    add_bool(tokens, kwargs, "loop", "--loop")
    add_bool(tokens, kwargs, "verbose", "--verbose")
    add_bool(tokens, kwargs, "help", "--help")
    return tokens
