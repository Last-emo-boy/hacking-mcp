"""Dedicated adapter metadata for WiFi-Pumpkin 3."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("interface", str, "", "Wireless interface used to create the AP."),
        AdapterParameterSpec("interface_net", str, "", "Interface used to share internet to the AP."),
        AdapterParameterSpec("session", str, "", "Session name/path to continue."),
        AdapterParameterSpec("pulp_file", str, "", "Script interactive sessions with a .pulp file."),
        AdapterParameterSpec("xpulp_commands", str, "", "Script interactive sessions with semicolon-separated commands."),
        AdapterParameterSpec("wireless_mode", str, "", "Wireless mode setting to enable."),
        AdapterParameterSpec("no_colors", bool, False, "Disable terminal colors and effects."),
        AdapterParameterSpec("rest", bool, False, "Run the Wp3 RESTful API."),
        AdapterParameterSpec("restport", int, 0, "REST API port; 0 leaves upstream default."),
        AdapterParameterSpec("username", str, "", "REST API username."),
        AdapterParameterSpec("password", str, "", "REST API password."),
        AdapterParameterSpec("ignore_networkmanager", str, "", "Interface to ignore from NetworkManager."),
        AdapterParameterSpec("remove_networkmanager", str, "", "Interface to remove from NetworkManager ignore list."),
        AdapterParameterSpec("version", bool, False, "Show WiFi-Pumpkin version."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "interface", "-i")
    add_value(tokens, kwargs, "interface_net", "-iNet")
    add_value(tokens, kwargs, "session", "-s")
    add_value(tokens, kwargs, "pulp_file", "-p")
    add_value(tokens, kwargs, "xpulp_commands", "-x")
    add_value(tokens, kwargs, "wireless_mode", "-m")
    add_bool(tokens, kwargs, "no_colors", "--no-colors")
    add_bool(tokens, kwargs, "rest", "--rest")
    add_value(tokens, kwargs, "restport", "--restport")
    add_value(tokens, kwargs, "username", "--username")
    add_value(tokens, kwargs, "password", "--password")
    add_value(tokens, kwargs, "ignore_networkmanager", "-iNM")
    add_value(tokens, kwargs, "remove_networkmanager", "-rNM")
    add_bool(tokens, kwargs, "version", "--version")
    return tokens
