"""Dedicated adapter metadata for Fluxion."""

from hacking_mcp.mcp_tools.adapter_types import AdapterParameterSpec
from hacking_mcp.mcp_tools.adapters.helpers import add_bool, add_value


def parameters():
    return [
        AdapterParameterSpec("bssid", str, "", "Target AP BSSID."),
        AdapterParameterSpec("essid", str, "", "Target AP ESSID."),
        AdapterParameterSpec("channel", int, 0, "Target channel; 0 leaves upstream default."),
        AdapterParameterSpec("language", str, "", "Fluxion language code."),
        AdapterParameterSpec("attack", str, "", "Fluxion attack workflow selector."),
        AdapterParameterSpec("interface", str, "", "Wireless interface hint for auto mode."),
        AdapterParameterSpec("jammer_interface", str, "", "Interface used for jamming."),
        AdapterParameterSpec("ap_interface", str, "", "Interface used for the rogue AP."),
        AdapterParameterSpec("tracker_interface", str, "", "Interface used for tracking."),
        AdapterParameterSpec("ap_service", str, "", "AP service implementation."),
        AdapterParameterSpec("debug", bool, False, "Enable debug mode."),
        AdapterParameterSpec("debug_log", str, "", "Debug log path."),
        AdapterParameterSpec("killer", bool, False, "Kill interfering wireless processes."),
        AdapterParameterSpec("reloader", bool, False, "Reload the wireless driver."),
        AdapterParameterSpec("airmon_ng", bool, False, "Use airmon-ng for monitor mode."),
        AdapterParameterSpec("multiplexer", bool, False, "Use terminal multiplexer mode."),
        AdapterParameterSpec("install", bool, False, "Run dependency installation flow."),
        AdapterParameterSpec("ratio", str, "", "Window ratio setting."),
        AdapterParameterSpec("auto", bool, False, "Run Fluxion auto mode."),
        AdapterParameterSpec("scan_time", int, 0, "Scan time in seconds; 0 leaves upstream default."),
        AdapterParameterSpec("scan_only", bool, False, "Only scan for targets."),
        AdapterParameterSpec("list_interfaces", bool, False, "List wireless interfaces."),
        AdapterParameterSpec("skip_dependencies", bool, False, "Skip dependency checks."),
        AdapterParameterSpec("timeout", int, 0, "Timeout value; 0 leaves upstream default."),
        AdapterParameterSpec("reg_domain", str, "", "Wireless regulatory domain."),
        AdapterParameterSpec("band", str, "", "Wireless band selector."),
        AdapterParameterSpec("version", bool, False, "Show Fluxion version."),
        AdapterParameterSpec("help", bool, False, "Show Fluxion help."),
    ]


def build_options(kwargs: dict) -> list[str]:
    tokens: list[str] = []
    add_bool(tokens, kwargs, "version", "--version")
    add_bool(tokens, kwargs, "help", "--help")
    add_bool(tokens, kwargs, "debug", "--debug")
    add_value(tokens, kwargs, "debug_log", "--debug-log")
    add_bool(tokens, kwargs, "killer", "--killer")
    add_bool(tokens, kwargs, "reloader", "--reloader")
    add_bool(tokens, kwargs, "airmon_ng", "--airmon-ng")
    add_bool(tokens, kwargs, "multiplexer", "--multiplexer")
    add_value(tokens, kwargs, "bssid", "--bssid")
    add_value(tokens, kwargs, "essid", "--essid")
    add_value(tokens, kwargs, "channel", "--channel")
    add_value(tokens, kwargs, "language", "--language")
    add_value(tokens, kwargs, "attack", "--attack")
    add_bool(tokens, kwargs, "install", "--install")
    add_value(tokens, kwargs, "ratio", "--ratio")
    add_bool(tokens, kwargs, "auto", "--auto")
    add_value(tokens, kwargs, "scan_time", "--scan-time")
    add_bool(tokens, kwargs, "scan_only", "--scan-only")
    add_bool(tokens, kwargs, "list_interfaces", "--list-interfaces")
    add_value(tokens, kwargs, "interface", "--interface")
    add_bool(tokens, kwargs, "skip_dependencies", "--skip-dependencies")
    add_value(tokens, kwargs, "jammer_interface", "--jammer-interface")
    add_value(tokens, kwargs, "ap_interface", "--ap-interface")
    add_value(tokens, kwargs, "tracker_interface", "--tracker-interface")
    add_value(tokens, kwargs, "ap_service", "--ap-service")
    add_value(tokens, kwargs, "timeout", "--timeout")
    add_value(tokens, kwargs, "reg_domain", "--reg-domain")
    add_value(tokens, kwargs, "band", "--band")
    return tokens
