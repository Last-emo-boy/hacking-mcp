"""Dedicated adapter metadata for pwncat-cs."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("listen", bool, False, "Enable bind/listen mode with -l/--listen."),
        AdapterParameterSpec("port", int, 0, "Alternative port for netcat-style syntax; 0 leaves default."),
        AdapterParameterSpec("platform", str, "", "Target platform name, for example linux or windows."),
        AdapterParameterSpec("ssl", bool, False, "Connect or listen with SSL/TLS."),
        AdapterParameterSpec("ssl_cert", str, "", "Certificate path for SSL-encrypted listeners."),
        AdapterParameterSpec("ssl_key", str, "", "Key path for SSL-encrypted listeners."),
        AdapterParameterSpec("identity_file", str, "", "Private key path for SSH authentication."),
        AdapterParameterSpec("list_implants", bool, False, "List installed implants with remote connection capability."),
        AdapterParameterSpec("version", bool, False, "Show version number and exit."),
        AdapterParameterSpec("download_plugins", bool, False, "Pre-download built-in Windows plugins and exit."),
        AdapterParameterSpec("config_file", str, "", "Custom pwncat configuration file."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose output for remote commands."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "listen", "-l")
    add_value(tokens, kwargs, "port", "-p")
    add_value(tokens, kwargs, "platform", "-m")
    add_bool(tokens, kwargs, "ssl", "-S")
    add_value(tokens, kwargs, "ssl_cert", "--ssl-cert")
    add_value(tokens, kwargs, "ssl_key", "--ssl-key")
    add_value(tokens, kwargs, "identity_file", "-i")
    add_bool(tokens, kwargs, "list_implants", "--list")
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "download_plugins", "--download-plugins")
    add_value(tokens, kwargs, "config_file", "--config")
    add_bool(tokens, kwargs, "verbose", "-V")
    return tokens
