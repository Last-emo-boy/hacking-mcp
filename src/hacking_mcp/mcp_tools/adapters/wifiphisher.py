"""Dedicated adapter metadata for Wifiphisher."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("interface", str, "", "Wireless interface to use."),
        AdapterParameterSpec("internet_interface", str, "", "Internet-facing interface."),
        AdapterParameterSpec("protect_interfaces", str, "", "Interfaces protected from NetworkManager, space/comma separated."),
        AdapterParameterSpec("mitm_interface", str, "", "Interface used for MITM mode."),
        AdapterParameterSpec("essid", str, "", "ESSID for the rogue AP."),
        AdapterParameterSpec("deauth_essid", str, "", "ESSID to deauth."),
        AdapterParameterSpec("deauth_channels", str, "", "Channels to deauth, space/comma separated."),
        AdapterParameterSpec("ap_interface", str, "", "Interface used for rogue AP."),
        AdapterParameterSpec("extensions_interface", str, "", "Interface used by extensions."),
        AdapterParameterSpec("no_mac_randomization", bool, False, "Disable MAC address randomization."),
        AdapterParameterSpec("keep_networkmanager", bool, False, "Do not kill NetworkManager."),
        AdapterParameterSpec("no_extensions", bool, False, "Disable extensions."),
        AdapterParameterSpec("no_deauth", bool, False, "Skip the deauthentication phase."),
        AdapterParameterSpec("phishing_scenario", str, "", "Phishing scenario name."),
        AdapterParameterSpec("preshared_key", str, "", "WPA/WPA2 key for the rogue AP."),
        AdapterParameterSpec("credential_log", str, "", "Credential log path."),
        AdapterParameterSpec("payload_path", str, "", "Payload path for compatible scenarios."),
        AdapterParameterSpec("handshake_capture", str, "", "Handshake capture path."),
        AdapterParameterSpec("quitonsuccess", bool, False, "Quit when credentials are captured."),
        AdapterParameterSpec("lure10_capture", bool, False, "Capture AP BSSIDs for Lure10."),
        AdapterParameterSpec("lure10_exploit", bool, False, "Enable Lure10 exploit mode."),
        AdapterParameterSpec("logging", bool, False, "Enable logging."),
        AdapterParameterSpec("disable_karma", bool, False, "Disable KARMA attack."),
        AdapterParameterSpec("log_path", str, "", "Log file path."),
        AdapterParameterSpec("channel_monitor", bool, False, "Monitor target AP channel changes."),
        AdapterParameterSpec("wps_pbc", bool, False, "Use WPS-PBC association mode."),
        AdapterParameterSpec("wpspbc_assoc_interface", str, "", "Interface used for WPS-PBC association."),
        AdapterParameterSpec("known_beacons", bool, False, "Use known beacon frames."),
        AdapterParameterSpec("force_hostapd", bool, False, "Force system hostapd usage."),
        AdapterParameterSpec("phishing_pages_directory", str, "", "Directory containing phishing pages."),
        AdapterParameterSpec("dnsmasq_conf", str, "", "Custom dnsmasq.conf path."),
        AdapterParameterSpec("phishing_essid", str, "", "ESSID shown on phishing page."),
        AdapterParameterSpec("mac_ap_interface", str, "", "MAC address for AP interface."),
        AdapterParameterSpec("mac_extensions_interface", str, "", "MAC address for extensions interface."),
        AdapterParameterSpec("help", bool, False, "Show help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_value(tokens, kwargs, "interface", "-i")
    add_value(tokens, kwargs, "internet_interface", "-iI")
    add_value(tokens, kwargs, "protect_interfaces", "-pI")
    add_value(tokens, kwargs, "mitm_interface", "-mI")
    add_value(tokens, kwargs, "essid", "-e")
    add_value(tokens, kwargs, "deauth_essid", "-dE")
    add_value(tokens, kwargs, "deauth_channels", "-dC")
    add_value(tokens, kwargs, "ap_interface", "-aI")
    add_value(tokens, kwargs, "extensions_interface", "-eI")
    add_bool(tokens, kwargs, "no_mac_randomization", "-iNM")
    add_bool(tokens, kwargs, "keep_networkmanager", "-kN")
    add_bool(tokens, kwargs, "no_extensions", "-nE")
    add_bool(tokens, kwargs, "no_deauth", "-nD")
    add_value(tokens, kwargs, "phishing_scenario", "-p")
    add_value(tokens, kwargs, "preshared_key", "-pK")
    add_value(tokens, kwargs, "credential_log", "-cP")
    add_value(tokens, kwargs, "payload_path", "--payload-path")
    add_value(tokens, kwargs, "handshake_capture", "-hC")
    add_bool(tokens, kwargs, "quitonsuccess", "-qS")
    add_bool(tokens, kwargs, "lure10_capture", "-lC")
    add_value(tokens, kwargs, "lure10_exploit", "-lE")
    add_bool(tokens, kwargs, "logging", "--logging")
    add_bool(tokens, kwargs, "disable_karma", "-dK")
    add_value(tokens, kwargs, "log_path", "-lP")
    add_bool(tokens, kwargs, "channel_monitor", "-cM")
    add_bool(tokens, kwargs, "wps_pbc", "-wP")
    add_value(tokens, kwargs, "wpspbc_assoc_interface", "-wAI")
    add_bool(tokens, kwargs, "known_beacons", "-kB")
    add_bool(tokens, kwargs, "force_hostapd", "-fH")
    add_value(tokens, kwargs, "phishing_pages_directory", "-pPD")
    add_value(tokens, kwargs, "dnsmasq_conf", "--dnsmasq-conf")
    add_value(tokens, kwargs, "phishing_essid", "-pE")
    add_value(tokens, kwargs, "mac_ap_interface", "-iAM")
    add_value(tokens, kwargs, "mac_extensions_interface", "-iEM")
    add_bool(tokens, kwargs, "help", "--help")
    return tokens
