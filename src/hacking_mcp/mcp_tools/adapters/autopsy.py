"""Dedicated adapter metadata for Autopsy."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("use_cookies", bool, False, "Force cookies even for localhost (-c)."),
        AdapterParameterSpec("no_cookies", bool, False, "Disable cookies even for remote hosts (-C)."),
        AdapterParameterSpec("evidence_locker", str, "", "Evidence locker directory (-d)."),
        AdapterParameterSpec("live_device", str, "", "Live-analysis raw device for -i device filesystem mnt."),
        AdapterParameterSpec("live_filesystem", str, "", "Live-analysis filesystem for -i device filesystem mnt."),
        AdapterParameterSpec("live_mount", str, "", "Live-analysis mount point for -i device filesystem mnt."),
        AdapterParameterSpec("port", int, 0, "TCP port for the Autopsy server (-p); 0 leaves default."),
        AdapterParameterSpec("remote_addr", str, "", "Optional investigator host/IP accepted by the server."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "use_cookies", "-c")
    add_bool(tokens, kwargs, "no_cookies", "-C")
    add_value(tokens, kwargs, "evidence_locker", "-d")
    live_device = str(kwargs.get("live_device") or "").strip()
    live_filesystem = str(kwargs.get("live_filesystem") or "").strip()
    live_mount = str(kwargs.get("live_mount") or "").strip()
    if live_device and live_filesystem and live_mount:
        tokens.extend(["-i", live_device, live_filesystem, live_mount])
    add_value(tokens, kwargs, "port", "-p")
    return tokens
