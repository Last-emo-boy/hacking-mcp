"""Dedicated adapter metadata for wireless attack tools."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters() -> list[AdapterParameterSpec]:
    return _wireless_parameters()


def build_options(kwargs: dict) -> list[str]:
    return _wireless_options(kwargs)


def _wireless_parameters() -> list[AdapterParameterSpec]:
    return [
        AdapterParameterSpec("interface", str, "", "Wireless interface name when supported."),
        AdapterParameterSpec("bssid", str, "", "Authorized AP BSSID when supported."),
        AdapterParameterSpec("essid", str, "", "Authorized AP ESSID when supported."),
        AdapterParameterSpec("channel", str, "", "Wireless channel when supported."),
        AdapterParameterSpec("wordlist", str, "", "Wordlist path when supported."),
        AdapterParameterSpec("handshake_file", str, "", "Handshake/capture file path when supported."),
        AdapterParameterSpec("monitor_mode", bool, False, "Request monitor mode when supported."),
        AdapterParameterSpec("pmkid", bool, False, "Enable PMKID workflow when supported."),
        AdapterParameterSpec("deauth_count", int, 0, "Deauth packet count when supported; 0 leaves default."),
        AdapterParameterSpec("capture_file", str, "", "Capture/handshake file path when supported."),
        AdapterParameterSpec("target_essid", str, "", "Target ESSID override when supported."),
        AdapterParameterSpec("ble", bool, False, "Enable BLE mode when supported."),
    ]


def _wireless_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "interface", "-i")
    add_value(tokens, kwargs, "bssid", "--bssid")
    add_value(tokens, kwargs, "essid", "--essid")
    add_value(tokens, kwargs, "channel", "-c")
    add_value(tokens, kwargs, "wordlist", "-w")
    add_value(tokens, kwargs, "handshake_file", "-r")
    add_bool(tokens, kwargs, "monitor_mode", "--monitor")
    add_bool(tokens, kwargs, "pmkid", "--pmkid")
    add_value(tokens, kwargs, "deauth_count", "--deauth")
    add_value(tokens, kwargs, "capture_file", "--capture")
    add_value(tokens, kwargs, "target_essid", "--essid")
    add_bool(tokens, kwargs, "ble", "--ble")
    return tokens
