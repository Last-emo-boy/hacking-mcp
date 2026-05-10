"""Dedicated adapter metadata for Chisel."""

import shlex
from typing import Any

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("command", str, "server", "Chisel subcommand: server or client."),
        AdapterParameterSpec("server", str, "", "Chisel server URL for client mode; falls back to target."),
        AdapterParameterSpec("remotes", str, "", "Semicolon-separated client remote definitions."),
        AdapterParameterSpec("host", str, "", "Server listening host."),
        AdapterParameterSpec("port", str, "", "Server listening port."),
        AdapterParameterSpec("key_seed", str, "", "Deprecated server key seed."),
        AdapterParameterSpec("keygen", str, "", "Write a generated server private key to this path."),
        AdapterParameterSpec("keyfile", str, "", "Server SSH private key file path."),
        AdapterParameterSpec("authfile", str, "", "Server users/remotes auth file path."),
        AdapterParameterSpec("auth", str, "", "User:password auth string for server or client mode."),
        AdapterParameterSpec("keepalive", str, "", "Keepalive interval, for example 25s."),
        AdapterParameterSpec("backend", str, "", "Backend HTTP server for non-chisel requests."),
        AdapterParameterSpec("socks5", bool, False, "Enable the server internal SOCKS5 proxy."),
        AdapterParameterSpec("reverse", bool, False, "Allow reverse port-forwarding remotes."),
        AdapterParameterSpec("tls_key", str, "", "TLS private key path."),
        AdapterParameterSpec("tls_cert", str, "", "TLS certificate path."),
        AdapterParameterSpec("tls_domain", str, "", "TLS domain for automatic LetsEncrypt certificates."),
        AdapterParameterSpec("tls_ca", str, "", "TLS CA bundle or directory path."),
        AdapterParameterSpec("fingerprint", str, "", "Client server public-key fingerprint."),
        AdapterParameterSpec("max_retry_count", int, 0, "Client maximum retry count; 0 leaves default."),
        AdapterParameterSpec("max_retry_interval", str, "", "Client maximum retry interval."),
        AdapterParameterSpec("proxy", str, "", "Client HTTP CONNECT or SOCKS5 proxy URL."),
        AdapterParameterSpec("header", str, "", "Semicolon-separated client custom HTTP headers."),
        AdapterParameterSpec("hostname", str, "", "Client Host header override."),
        AdapterParameterSpec("sni", str, "", "Client TLS ServerName override."),
        AdapterParameterSpec("tls_skip_verify", bool, False, "Skip server TLS certificate verification."),
        AdapterParameterSpec("pid", bool, False, "Generate a pid file."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose logging."),
        AdapterParameterSpec("version", bool, False, "Show version and exit."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    if kwargs.get("version"):
        return ["--version"]

    command = str(kwargs.get("command") or "server").strip() or "server"
    tokens.append(command)

    if command == "server":
        add_value(tokens, kwargs, "host", "--host")
        add_value(tokens, kwargs, "port", "--port")
        add_value(tokens, kwargs, "key_seed", "--key")
        add_value(tokens, kwargs, "keygen", "--keygen")
        add_value(tokens, kwargs, "keyfile", "--keyfile")
        add_value(tokens, kwargs, "authfile", "--authfile")
        add_value(tokens, kwargs, "auth", "--auth")
        add_value(tokens, kwargs, "keepalive", "--keepalive")
        add_value(tokens, kwargs, "backend", "--backend")
        add_bool(tokens, kwargs, "socks5", "--socks5")
        add_bool(tokens, kwargs, "reverse", "--reverse")
        add_value(tokens, kwargs, "tls_key", "--tls-key")
        add_value(tokens, kwargs, "tls_cert", "--tls-cert")
        for domain in _split_values(kwargs.get("tls_domain")):
            tokens.extend(["--tls-domain", domain])
        add_value(tokens, kwargs, "tls_ca", "--tls-ca")

    elif command == "client":
        add_value(tokens, kwargs, "fingerprint", "--fingerprint")
        add_value(tokens, kwargs, "auth", "--auth")
        add_value(tokens, kwargs, "keepalive", "--keepalive")
        add_value(tokens, kwargs, "max_retry_count", "--max-retry-count")
        add_value(tokens, kwargs, "max_retry_interval", "--max-retry-interval")
        add_value(tokens, kwargs, "proxy", "--proxy")
        for header in _split_delimited_values(kwargs.get("header")):
            tokens.extend(["--header", header])
        add_value(tokens, kwargs, "hostname", "--hostname")
        add_value(tokens, kwargs, "sni", "--sni")
        add_value(tokens, kwargs, "tls_ca", "--tls-ca")
        add_bool(tokens, kwargs, "tls_skip_verify", "--tls-skip-verify")
        add_value(tokens, kwargs, "tls_key", "--tls-key")
        add_value(tokens, kwargs, "tls_cert", "--tls-cert")
        server = str(kwargs.get("server") or kwargs.get("target") or "").strip()
        if server:
            tokens.append(server)
        tokens.extend(_split_values(kwargs.get("remotes")))

    add_bool(tokens, kwargs, "pid", "--pid")
    add_bool(tokens, kwargs, "verbose", "-v")
    return tokens


def _split_values(value: Any) -> list[str]:
    if value in (None, "", 0, False):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "", 0, False)]
    raw = str(value).replace("\n", ";")
    parts = [item.strip() for item in raw.split(";") if item.strip()]
    if len(parts) > 1:
        return parts
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()


def _split_delimited_values(value: Any) -> list[str]:
    if value in (None, "", 0, False):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "", 0, False)]
    raw = str(value).replace("\n", ";")
    return [item.strip() for item in raw.split(";") if item.strip()]
