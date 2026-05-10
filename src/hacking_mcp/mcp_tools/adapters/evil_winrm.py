"""Dedicated adapter metadata for Evil-WinRM."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("lhost", str, "", "Listener host for authorized lab use."),
        AdapterParameterSpec("lport", int, 0, "Listener port when supported; 0 leaves default."),
        AdapterParameterSpec("session_id", str, "", "Session identifier when supported."),
        AdapterParameterSpec("listener", str, "", "Listener/profile name when supported."),
        AdapterParameterSpec("protocol", str, "", "Protocol selector when supported."),
        AdapterParameterSpec("ssl", bool, False, "Use SSL/TLS when supported."),
        AdapterParameterSpec("key_file", str, "", "Private key path when supported."),
        AdapterParameterSpec("cert_file", str, "", "Certificate path when supported."),
        AdapterParameterSpec("upload", str, "", "Upload file path when supported."),
        AdapterParameterSpec("download", str, "", "Download path when supported."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "lhost", "--lhost")
    add_value(tokens, kwargs, "lport", "--lport")
    add_value(tokens, kwargs, "session_id", "--session")
    add_value(tokens, kwargs, "listener", "--listener")
    add_value(tokens, kwargs, "protocol", "--protocol")
    add_bool(tokens, kwargs, "ssl", "-S")
    add_value(tokens, kwargs, "key_file", "-k")
    add_value(tokens, kwargs, "cert_file", "-c")
    add_value(tokens, kwargs, "upload", "--upload")
    add_value(tokens, kwargs, "download", "--download")
    return tokens
