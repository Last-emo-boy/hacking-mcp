"""Dedicated adapter metadata for Ligolo-ng."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("listen_addr", str, "", "Proxy listening address, such as 0.0.0.0:11601."),
        AdapterParameterSpec("autocert", bool, False, "Automatically request Let's Encrypt certificates."),
        AdapterParameterSpec("selfcert", bool, False, "Dynamically generate self-signed certificates."),
        AdapterParameterSpec("cert_file", str, "", "TLS server certificate path."),
        AdapterParameterSpec("key_file", str, "", "TLS server key path."),
        AdapterParameterSpec("allow_domains", str, "", "Comma-separated autocert domain allowlist."),
        AdapterParameterSpec("selfcert_domain", str, "", "Self-signed certificate TLS domain."),
        AdapterParameterSpec("config_file", str, "", "Proxy config file path."),
        AdapterParameterSpec("daemon", bool, False, "Run proxy in daemon mode without the interactive CLI."),
        AdapterParameterSpec("api_listen_addr", str, "", "API server listening address."),
        AdapterParameterSpec("cpu_profile", str, "", "Write CPU profile to this file."),
        AdapterParameterSpec("mem_profile", str, "", "Write memory profile to this file."),
        AdapterParameterSpec("verbose", bool, False, "Enable verbose mode."),
        AdapterParameterSpec("no_banner", bool, False, "Do not show the startup banner."),
        AdapterParameterSpec("version", bool, False, "Show the current version."),
        AdapterParameterSpec("help", bool, False, "Show proxy help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    if kwargs.get("version"):
        return ["-version"]
    if kwargs.get("help"):
        return ["-h"]

    tokens: list[str] = []
    add_bool(tokens, kwargs, "verbose", "-v")
    add_value(tokens, kwargs, "listen_addr", "-laddr")
    add_bool(tokens, kwargs, "autocert", "-autocert")
    add_bool(tokens, kwargs, "selfcert", "-selfcert")
    add_value(tokens, kwargs, "cert_file", "-certfile")
    add_value(tokens, kwargs, "key_file", "-keyfile")
    add_value(tokens, kwargs, "allow_domains", "-allow-domains")
    add_value(tokens, kwargs, "selfcert_domain", "-selfcert-domain")
    add_value(tokens, kwargs, "config_file", "-config")
    add_bool(tokens, kwargs, "daemon", "-daemon")
    add_value(tokens, kwargs, "api_listen_addr", "-api-laddr")
    add_value(tokens, kwargs, "cpu_profile", "-cpuprofile")
    add_value(tokens, kwargs, "mem_profile", "-memprofile")
    add_bool(tokens, kwargs, "no_banner", "-nobanner")
    return tokens
