"""Dedicated adapter metadata for Setoolkit."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_value


def parameters() -> list[AdapterParameterSpec]:
    return _phishing_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _phishing_options(kwargs)


def _phishing_parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("template", str, "", "Template/site profile name when supported."),
        AdapterParameterSpec("landing_url", str, "", "Authorized training landing URL when supported."),
        AdapterParameterSpec("listener_host", str, "", "Listener host for lab use when supported."),
        AdapterParameterSpec("listener_port", int, 0, "Listener port when supported; 0 leaves default."),
        AdapterParameterSpec("tunnel", str, "", "Tunnel provider/profile when supported."),
        AdapterParameterSpec("domain", str, "", "Authorized domain when supported."),
        AdapterParameterSpec("output_dir", str, "", "Output directory when supported."),
        AdapterParameterSpec("site", str, "", "Template/site selector when supported."),
        AdapterParameterSpec("redirect_url", str, "", "Redirect URL for authorized training when supported."),
        AdapterParameterSpec("custom_domain", str, "", "Authorized custom domain when supported."),
        AdapterParameterSpec("phishlet", str, "", "Phishlet/profile selector when supported."),
        AdapterParameterSpec("capture_path", str, "", "Capture/output path when supported."),
    ]


def _phishing_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "template", "--template")
    add_value(tokens, kwargs, "landing_url", "--url")
    add_value(tokens, kwargs, "listener_host", "--host")
    add_value(tokens, kwargs, "listener_port", "--port")
    add_value(tokens, kwargs, "tunnel", "--tunnel")
    add_value(tokens, kwargs, "domain", "--domain")
    add_value(tokens, kwargs, "output_dir", "-o")
    add_value(tokens, kwargs, "site", "--site")
    add_value(tokens, kwargs, "redirect_url", "--redirect")
    add_value(tokens, kwargs, "custom_domain", "--domain")
    add_value(tokens, kwargs, "phishlet", "--phishlet")
    add_value(tokens, kwargs, "capture_path", "--capture-path")
    return tokens
